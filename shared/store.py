"""WindowStore: the per-entity window state behind one interface, so the
behavioral detectors' state can be externalized (Redis) for durability, bounded
growth (TTL on every key), and horizontal scale, while unit tests and
single-process deploys keep an in-memory implementation.

detectors.py stays pure; app.py holds the wiring and calls this. The store is
selected by NDR_STATE_BACKEND=redis|memory (default redis in the production
compose; tests use memory). Both implementations honor the same contract, proven
by test_store.py running against each.

Design (KTD1-3 of the enterprise-hardening plan):
  - windows (beacon/dns callbacks) -> sorted set scored by event time, so
    time-pruning is `range(key, min_score)` / `prune(key, min_score)`, atomic in
    Redis, with a key-level TTL as a backstop against leaks.
  - running accumulators (exfil bytes, cumulative long-conn) -> hash counters + TTL.
  - baselines (known-dsts, fleet prevalence, rotating IPs) -> capped sets + TTL.
  - passive-DNS / dst-context -> key/value + TTL.
  - emit-once dedup -> set-if-absent with TTL.
Every operation takes a TTL, so nothing lives past its window. No accumulator can
grow unbounded (the leak the plan fixes), and a moved Kafka partition finds its
state already in Redis (the rebalance-safety HA depends on).
"""
from __future__ import annotations
import os
import time
import zlib


class WindowStore:
    """Interface. See InMemoryStore / RedisStore for the two implementations."""

    def window_add(self, key: str, score: float, value, ttl: float) -> None: ...
    def window_range(self, key: str, min_score: float) -> list[tuple[float, object]]: ...
    def window_add_indexed(self, key: str, idx_key: str, score: float, value, ttl: float) -> None: ...
    def window_add_indexed_batch(self, items) -> None: ...
    def pipeline_ops(self, ops) -> None: ...
    def zset_since(self, key: str, min_score: float) -> list: ...
    def zset_rank(self, key: str, member: str): ...
    def counter_add(self, key: str, field: str, delta: float, ttl: float) -> float: ...
    def counter_get(self, key: str, field: str) -> float: ...
    def counter_clear(self, key: str) -> None: ...
    def set_add(self, key: str, member: str, ttl: float, cap: int | None = None) -> None: ...
    def set_len(self, key: str) -> int: ...
    def set_contains(self, key: str, member: str) -> bool: ...
    def set_members(self, key: str) -> list[str]: ...
    def set_remove(self, key: str, member: str) -> None: ...
    def kv_set(self, key: str, value, ttl: float) -> None: ...
    def kv_get(self, key: str): ...
    def kv_prune(self) -> None: ...
    def dedup_seen(self, key: str, ttl: float) -> bool: ...
    def keys_matching(self, prefix: str) -> list[str]: ...


class InMemoryStore(WindowStore):
    """Single-process / test backend. Lazy TTL expiry on access; equivalent
    behavior to RedisStore for the contract in test_store.py."""

    def __init__(self, clock=time.time):
        self._now = clock
        self._z: dict = {}          # key -> list[(score, value, expiry)]  (sorted set)
        self._zs: dict = {}         # key -> {member: score}  (first-seen ZSET, plan 007)
        self._h: dict = {}          # key -> {field: value}, plus _exp
        self._s: dict = {}          # key -> set(members)
        self._kv: dict = {}         # key -> (value, expiry)
        self._exp: dict = {}        # key -> expiry (for h/s keys)
        self._dedup: dict = {}      # key -> expiry

    def _alive(self, key, table_exp):
        e = table_exp.get(key)
        return e is None or e > self._now()

    def window_add(self, key, score, value, ttl):
        z = self._z.setdefault(key, [])
        z.append((score, value, self._now() + ttl))
        self._exp[key] = self._now() + ttl

    def window_add_indexed(self, key, idx_key, score, value, ttl):
        self.window_add(key, score, value, ttl)
        self.set_add(idx_key, key, ttl)

    def window_add_indexed_batch(self, items):
        self.pipeline_ops([("win", k, idx, sc, v, ttl) for k, idx, sc, v, ttl in items])

    def pipeline_ops(self, ops):
        # ALL buffered writes for a poll-batch (plan 007). Op kinds:
        #   ("win",  key, idx|None, score, value, ttl)       zset window + index
        #   ("cnt",  key, field, delta, ttl, idx|None)       hash counter + index
        #   ("znx",  key, member, score, ttl, idx|None)      first-seen zset (NX) + index
        #   ("kv",   key, value, ttl)                         key/value
        #   ("sadd", key, member, ttl)                        set add (uncapped)
        for op in ops:
            kind = op[0]
            if kind == "win":
                _, key, idx, score, value, ttl = op
                self.window_add(key, score, value, ttl)
                if idx is not None:
                    self.set_add(idx, key, ttl)
            elif kind == "cnt":
                _, key, field, delta, ttl, idx = op
                self.counter_add(key, field, delta, ttl)
                if idx is not None:
                    self.set_add(idx, key, ttl)
            elif kind == "znx":
                _, key, member, score, ttl, idx = op
                if not self._alive(key, self._exp):
                    self._zs.pop(key, None)
                self._zs.setdefault(key, {}).setdefault(member, score)   # NX: keep earliest
                self._exp[key] = self._now() + ttl
                if idx is not None:
                    self.set_add(idx, key, ttl)
            elif kind == "kv":
                _, key, value, ttl = op
                self.kv_set(key, value, ttl)
            elif kind == "sadd":
                _, key, member, ttl = op
                self.set_add(key, member, ttl)

    def zset_since(self, key, min_score):
        # members with score > min_score, in (score, member) order -- so a caller can
        # read first-seen rank from enumeration order (matches Redis ZRANGEBYSCORE).
        if not self._alive(key, self._exp):
            self._zs.pop(key, None)
            return []
        return [m for _, m in sorted((sc, m) for m, sc in self._zs.get(key, {}).items() if sc > min_score)]

    def zset_rank(self, key, member):
        # count of members ordered before `member` by (score, member) -- matches Redis ZRANK
        if not self._alive(key, self._exp):
            return None
        z = self._zs.get(key, {})
        if member not in z:
            return None
        ms = z[member]
        return sum(1 for mm, s in z.items() if (s, mm) < (ms, member))

    def window_range(self, key, min_score):
        now = self._now()
        z = [t for t in self._z.get(key, []) if t[2] > now and t[0] >= min_score]
        self._z[key] = z
        return sorted((t[0], t[1]) for t in z)

    def counter_add(self, key, field, delta, ttl):
        if not self._alive(key, self._exp):
            self._h.pop(key, None)
        h = self._h.setdefault(key, {})
        h[field] = h.get(field, 0) + delta
        self._exp[key] = self._now() + ttl
        return h[field]

    def counter_get(self, key, field):
        if not self._alive(key, self._exp):
            return 0
        return self._h.get(key, {}).get(field, 0)

    def counter_clear(self, key):
        self._h.pop(key, None)
        self._exp.pop(key, None)

    def set_add(self, key, member, ttl, cap=None):
        if not self._alive(key, self._exp):
            self._s.pop(key, None)
        s = self._s.setdefault(key, set())
        if cap is None or len(s) <= cap:
            s.add(member)
        self._exp[key] = self._now() + ttl

    def set_len(self, key):
        return len(self._s.get(key, ())) if self._alive(key, self._exp) else 0

    def set_contains(self, key, member):
        return self._alive(key, self._exp) and member in self._s.get(key, ())

    def set_members(self, key):
        if not self._alive(key, self._exp):
            self._s.pop(key, None)
            return []
        return list(self._s.get(key, ()))

    def set_remove(self, key, member):
        # discard only; never create the key or (re)set a TTL (plan 004 U1)
        s = self._s.get(key)
        if s is not None:
            s.discard(member)

    def kv_set(self, key, value, ttl):
        self._kv[key] = (value, self._now() + ttl)

    def kv_get(self, key):
        v = self._kv.get(key)
        if v and v[1] > self._now():
            return v[0]
        self._kv.pop(key, None)
        return None

    def kv_prune(self):
        now = self._now()
        for k in [k for k, (_, e) in self._kv.items() if e <= now]:
            self._kv.pop(k, None)

    def dedup_seen(self, key, ttl):
        now = self._now()
        e = self._dedup.get(key)
        if e and e > now:
            return False
        self._dedup[key] = now + ttl
        return True

    def keys_matching(self, prefix):
        now = self._now()
        out = set()
        for tbl, exp in ((self._z, self._exp), (self._zs, self._exp), (self._h, self._exp), (self._s, self._exp)):
            out |= {k for k in tbl if k.startswith(prefix) and (exp.get(k) is None or exp[k] > now)}
        out |= {k for k, (_, e) in self._kv.items() if k.startswith(prefix) and e > now}
        return sorted(out)


class RedisStore(WindowStore):
    """Redis backend. Windows are sorted sets scored by event time; counters are
    hashes; baselines are sets; dst-context is a JSON value; dedup is SET NX EX.
    Every key gets a TTL so state is bounded and survives restart/rebalance.

    Scale note (plan 003 U2): on the single processing box Redis is local, so
    the URL is a `unix://` socket (redis.Redis.from_url handles it natively) and
    every write+TTL pair is issued in one pipeline round-trip instead of two.
    Semantics are identical to the pre-pipeline code (proven by
    test_contract_both_backends against a live Redis); only the round-trip count
    drops, which is the per-record cost that dominates at fleet ingest rate."""

    def __init__(self, url: str):
        import redis                     # imported lazily so `memory` needs no redis lib
        import json
        self._json = json
        # url may be redis://host:port/db (TCP) or unix:///path/to/sock?db=0
        # (local single-box, lower per-op latency). Both parsed by from_url.
        self._r = redis.Redis.from_url(url, decode_responses=True)

    def window_add(self, key, score, value, ttl):
        pipe = self._r.pipeline(transaction=False)   # zadd + expire in one round-trip
        pipe.zadd(key, {self._json.dumps([score, value]): score})
        pipe.expire(key, int(ttl) + 1)
        pipe.execute()

    def window_add_indexed(self, key, idx_key, score, value, ttl):
        # window write + partition-index add in ONE round-trip, and atomic-per-
        # connection so a crash cannot leave the window written but unindexed
        # (plan 004 review).
        pipe = self._r.pipeline(transaction=False)
        pipe.zadd(key, {self._json.dumps([score, value]): score})
        pipe.expire(key, int(ttl) + 1)
        pipe.sadd(idx_key, key)
        pipe.expire(idx_key, int(ttl) + 1)
        pipe.execute()

    def window_add_indexed_batch(self, items):
        self.pipeline_ops([("win", k, idx, sc, v, ttl) for k, idx, sc, v, ttl in items])

    def pipeline_ops(self, ops):
        # ALL buffered writes for a poll-batch in ONE round-trip (plan 007). The
        # per-record synchronous Redis round-trip is the throughput ceiling, so
        # every fire-and-forget write (windows + counters + first-seen zsets + kv
        # + set adds, each with its index/TTL) is pipelined together. Op kinds:
        #   ("win",  key, idx|None, score, value, ttl)
        #   ("cnt",  key, field, delta, ttl, idx|None)
        #   ("znx",  key, member, score, ttl, idx|None)   ZADD NX (keep earliest)
        #   ("kv",   key, value, ttl)
        #   ("sadd", key, member, ttl)
        if not ops:
            return
        pipe = self._r.pipeline(transaction=False)
        expd = set()                                         # dedup EXPIREs within the batch: all
        def _exp(k, ttl):                                    # ttls are WINDOW, so one per key suffices --
            if k not in expd:                                # index keys are shared across every entity
                pipe.expire(k, int(ttl) + 1); expd.add(k)    # on a partition, so this cuts the command
        for op in ops:                                       # count (the single-Redis ceiling, R7b) a lot.
            kind = op[0]
            if kind == "win":
                _, key, idx, score, value, ttl = op
                pipe.zadd(key, {self._json.dumps([score, value]): score}); _exp(key, ttl)
                if idx is not None:
                    pipe.sadd(idx, key); _exp(idx, ttl)
            elif kind == "cnt":
                _, key, field, delta, ttl, idx = op
                pipe.hincrbyfloat(key, field, delta); _exp(key, ttl)
                if idx is not None:
                    pipe.sadd(idx, key); _exp(idx, ttl)
            elif kind == "znx":
                _, key, member, score, ttl, idx = op
                pipe.zadd(key, {member: score}, nx=True); _exp(key, ttl)   # NX: keep earliest; TTL activity-refreshed
                if idx is not None:
                    pipe.sadd(idx, key); _exp(idx, ttl)
            elif kind == "kv":
                _, key, value, ttl = op
                pipe.set(key, self._json.dumps(value), ex=int(ttl) + 1)
            elif kind == "sadd":
                _, key, member, ttl = op
                pipe.sadd(key, member); _exp(key, ttl)
        pipe.execute()

    def zset_since(self, key, min_score):
        return list(self._r.zrangebyscore(key, f"({min_score}", "+inf"))

    def zset_rank(self, key, member):
        return self._r.zrank(key, member)   # 0-based: count of members ordered before it, or None

    def window_range(self, key, min_score):
        pipe = self._r.pipeline(transaction=False)   # prune + read in one round-trip
        pipe.zremrangebyscore(key, "-inf", f"({min_score}")
        pipe.zrange(key, 0, -1)
        rows = pipe.execute()[1]
        out = []
        for m in rows:
            try:
                sc, v = self._json.loads(m)
                out.append((sc, v))
            except Exception:
                pass
        return out

    def counter_add(self, key, field, delta, ttl):
        pipe = self._r.pipeline(transaction=False)   # incr + expire in one round-trip
        pipe.hincrbyfloat(key, field, delta)
        pipe.expire(key, int(ttl) + 1)
        return pipe.execute()[0]

    def counter_get(self, key, field):
        v = self._r.hget(key, field)
        return float(v) if v is not None else 0

    def counter_clear(self, key):
        self._r.delete(key)

    def set_add(self, key, member, ttl, cap=None):
        pipe = self._r.pipeline(transaction=False)   # sadd (+cap) + expire in one round-trip
        if cap is None or self._r.scard(key) <= cap:
            pipe.sadd(key, member)
        pipe.expire(key, int(ttl) + 1)
        pipe.execute()

    def set_len(self, key):
        return self._r.scard(key)

    def set_contains(self, key, member):
        return bool(self._r.sismember(key, member))

    def set_members(self, key):
        return list(self._r.smembers(key))          # empty for an expired/absent key

    def set_remove(self, key, member):
        self._r.srem(key, member)                   # SREM; no key create, no TTL touch

    def kv_set(self, key, value, ttl):
        self._r.set(key, self._json.dumps(value), ex=int(ttl) + 1)

    def kv_get(self, key):
        v = self._r.get(key)
        return self._json.loads(v) if v is not None else None

    def kv_prune(self):
        pass                             # Redis TTL evicts; nothing to do

    def dedup_seen(self, key, ttl):
        return bool(self._r.set(key, "1", nx=True, ex=int(ttl) + 1))

    def keys_matching(self, prefix):
        return sorted(self._r.scan_iter(match=prefix + "*"))



def _shard_of(key: str, n: int) -> int:
    """Which of n shards owns a key. Partition-tagged keys route by their partition
    so a partition's entity keys AND its index (idx:{prefix}:{part}) co-locate on
    one shard (window_add_indexed and scoped-evaluate stay single-shard); other
    keys (aux/dedup) route by a STABLE hash (crc32, so every replica agrees).
    Entity keys are prefix:partition:...; index keys are idx:prefix:partition."""
    parts = key.split(":")
    seg = parts[-1] if key.startswith("idx:") else (parts[1] if len(parts) > 1 else "")
    if seg.isdigit():
        return int(seg) % n
    return zlib.crc32(key.encode()) % n


class ShardedRedisStore(WindowStore):
    """Routes each key to one of N local Redis instances (each a RedisStore), so
    N single-threaded Redis processes on one box share the write load instead of
    one (plan 005: the measured single-Redis ceiling). Contract-identical to a
    single store; only throughput scales. A partition's keys + index land on one
    shard, so window_add_indexed stays atomic-per-shard and a scoped evaluate hits
    one shard; aux/dedup keys hash-route consistently across replicas."""

    def __init__(self, shards):
        self._shards = list(shards)
        self._n = len(self._shards)

    def _s(self, key):
        return self._shards[_shard_of(key, self._n)]

    def window_add(self, key, score, value, ttl):
        self._s(key).window_add(key, score, value, ttl)

    def window_add_indexed(self, key, idx_key, score, value, ttl):
        self._s(key).window_add_indexed(key, idx_key, score, value, ttl)   # key+idx share a shard

    def window_add_indexed_batch(self, items):
        by_shard = {}
        for it in items:
            by_shard.setdefault(_shard_of(it[0], self._n), []).append(it)
        for sidx, its in by_shard.items():
            self._shards[sidx].window_add_indexed_batch(its)

    def pipeline_ops(self, ops):
        by_shard = {}                                    # op[1] is the key -> shard (co-locates key + its index)
        for op in ops:
            by_shard.setdefault(_shard_of(op[1], self._n), []).append(op)
        for sidx, o in by_shard.items():
            self._shards[sidx].pipeline_ops(o)

    def zset_since(self, key, min_score):
        return self._s(key).zset_since(key, min_score)

    def zset_rank(self, key, member):
        return self._s(key).zset_rank(key, member)

    def window_range(self, key, min_score):
        return self._s(key).window_range(key, min_score)

    def counter_add(self, key, field, delta, ttl):
        return self._s(key).counter_add(key, field, delta, ttl)

    def counter_get(self, key, field):
        return self._s(key).counter_get(key, field)

    def counter_clear(self, key):
        self._s(key).counter_clear(key)

    def set_add(self, key, member, ttl, cap=None):
        self._s(key).set_add(key, member, ttl, cap)

    def set_len(self, key):
        return self._s(key).set_len(key)

    def set_contains(self, key, member):
        return self._s(key).set_contains(key, member)

    def set_members(self, key):
        return self._s(key).set_members(key)

    def set_remove(self, key, member):
        self._s(key).set_remove(key, member)

    def kv_set(self, key, value, ttl):
        self._s(key).kv_set(key, value, ttl)

    def kv_get(self, key):
        return self._s(key).kv_get(key)

    def kv_prune(self):
        for s in self._shards:
            s.kv_prune()

    def dedup_seen(self, key, ttl):
        return self._s(key).dedup_seen(key, ttl)

    def keys_matching(self, prefix):
        out = []
        for s in self._shards:
            out += s.keys_matching(prefix)
        return out


def make_store(backend: str = "memory", url: str = "redis://redis:6379/0") -> WindowStore:
    if backend == "sharded":
        urls = [u.strip() for u in os.environ.get("NDR_REDIS_URLS", url).split(",") if u.strip()]
        return ShardedRedisStore([RedisStore(u) for u in urls])
    return RedisStore(url) if backend == "redis" else InMemoryStore()
