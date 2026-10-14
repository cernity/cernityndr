"""WindowStore contract tests (plan U1). The SAME assertions run against
InMemoryStore and (when a Redis is reachable) RedisStore, proving the Redis
backend is equivalent to the in-memory one before app.py is switched over.
"""
import hashlib
import os
import sys
import time
import types

import store as st


def _backends():
    """Yield (name, store) for each available backend. Redis is included only
    when NDR_TEST_REDIS_URL is set and reachable, so the build gate stays offline."""
    yield "memory", st.InMemoryStore()
    url = os.environ.get("NDR_TEST_REDIS_URL")
    if url:
        try:
            r = st.RedisStore(url)
            r._r.ping()
            r._r.flushdb()
            yield "redis", r
        except Exception as e:
            print(f"  (redis backend skipped: {e})")


def _check(s, name):
    # window: time-ordered, prunes below min_score
    for i in range(5):
        s.window_add("w:a", float(i * 60), i, ttl=600)
    rng = s.window_range("w:a", min_score=0)
    assert [v for _, v in rng] == [0, 1, 2, 3, 4], f"{name}: window order"
    rng2 = s.window_range("w:a", min_score=180)     # prune older than score 180
    assert [sc for sc, _ in rng2] == [180.0, 240.0], f"{name}: window prune"

    # counter: accumulate + read back + clear
    assert s.counter_add("c:x", "bytes", 100, ttl=600) == 100
    assert s.counter_add("c:x", "bytes", 50, ttl=600) == 150
    assert s.counter_get("c:x", "bytes") == 150, f"{name}: counter"
    s.counter_clear("c:x")
    assert s.counter_get("c:x", "bytes") == 0, f"{name}: counter clear"

    # capped set: never exceeds cap+1, membership + len
    for i in range(20):
        s.set_add("s:d", f"src{i}", ttl=600, cap=5)
    assert s.set_len("s:d") <= 6, f"{name}: set cap"
    s.set_add("s:known", "1.2.3.4", ttl=600)
    assert s.set_contains("s:known", "1.2.3.4") and not s.set_contains("s:known", "9.9.9.9"), f"{name}: set contains"

    # kv
    s.kv_set("kv:ip", ["evil.com", 123.0], ttl=600)
    assert s.kv_get("kv:ip") == ["evil.com", 123.0], f"{name}: kv"
    assert s.kv_get("kv:missing") is None, f"{name}: kv miss"

    # dedup: true once, false within ttl
    assert s.dedup_seen("dd:k", ttl=600) is True, f"{name}: dedup first"
    assert s.dedup_seen("dd:k", ttl=600) is False, f"{name}: dedup repeat"


def test_contract_both_backends():
    ran = 0
    for name, s in _backends():
        _check(s, name)
        print(f"ok  contract [{name}]")
        ran += 1
    assert ran >= 1


def test_inmemory_ttl_expiry():
    # a stale window key expires (lazy) rather than persisting forever (the leak fix)
    clk = [1000.0]
    s = st.InMemoryStore(clock=lambda: clk[0])
    s.window_add("w:t", 1000.0, "x", ttl=60)
    s.counter_add("c:t", "b", 5, ttl=60)
    clk[0] = 1200.0                                  # advance past ttl
    assert s.window_range("w:t", 0) == [], "expired window cleared"
    assert s.counter_get("c:t", "b") == 0, "expired counter cleared"


def test_set_members_age_individually_under_continuous_writes():
    # F05: an old member must expire on its OWN window even while new members keep the
    # key busy. The audit's leak: whole-key TTL refreshed on every write, so the set
    # (prevalence/spray/scan/known-dst baseline) grows without bound and never ages.
    clk = [1000.0]
    s = st.InMemoryStore(clock=lambda: clk[0])
    s.set_add("pv:t:dst", "old-src", ttl=600)
    for i in range(8):                              # continuous new members every 100s
        clk[0] += 100
        s.set_add("pv:t:dst", f"src{i}", ttl=600)
    assert not s.set_contains("pv:t:dst", "old-src"), "old member survived past its window"
    assert s.set_len("pv:t:dst") <= 7, "set cardinality not bounded to the window"


def test_counter_bounded_under_continuous_writes():
    # F05: a windowed counter must not carry a previous window's counts just because
    # new writes keep refreshing the key (ssh/icmp brute counters).
    clk = [1000.0]
    s = st.InMemoryStore(clock=lambda: clk[0])
    for _ in range(11):                             # 11 writes across 1000s, window 600s
        s.counter_add("ssh:t:a|b", "n", 1, ttl=600)
        clk[0] += 100
    assert s.counter_get("ssh:t:a|b", "n") <= 7, "counter accumulated past its window"


def test_redis_set_and_counter_age_by_window():
    # F05 on the PRODUCTION backend: per-member set aging + tumbling counter, proven with
    # a real short TTL. Skipped when no Redis is configured (the offline gate stays fast).
    url = os.environ.get("NDR_TEST_REDIS_URL")
    if not url:
        print("  (redis aging test skipped: no NDR_TEST_REDIS_URL)")
        return
    r = st.RedisStore(url)
    r._r.flushdb()
    r.set_add("agez", "old", ttl=1)
    r.counter_add("cagez", "n", 3, ttl=1)
    time.sleep(2.3)   # past both the member score (now+ttl) and the counter TTL (int(ttl)+1)
    r.set_add("agez", "new", ttl=60)                 # continuous write keeps the key busy
    assert r.set_members("agez") == ["new"], "redis: old set member did not age out"
    assert not r.set_contains("agez", "old")
    assert r.set_len("agez") == 1
    got = r.counter_add("cagez", "n", 1, ttl=60)     # window rolled -> fresh, not 4
    assert got == 1, f"redis: counter did not tumble ({got})"
    print("ok  redis set+counter age by window")


def test_inmemory_restart_survival_is_backend_property():
    # the in-memory store does NOT survive a handle drop (that is why redis exists);
    # this documents the contract: a fresh InMemoryStore starts empty.
    s1 = st.InMemoryStore(); s1.window_add("w:r", 1.0, "a", ttl=600)
    s2 = st.InMemoryStore()
    assert s2.window_range("w:r", 0) == []


def test_make_store_selects_backend():
    assert isinstance(st.make_store("memory"), st.InMemoryStore)


def test_set_members_and_remove():
    """set_members/set_remove (plan 004 U1) equivalent on both backends."""
    for name, s in _backends():
        s.set_add("t4:idx", "a", 60)
        s.set_add("t4:idx", "b", 60)
        assert set(s.set_members("t4:idx")) == {"a", "b"}, name
        s.set_remove("t4:idx", "a")
        assert set(s.set_members("t4:idx")) == {"b"}, name
        s.set_remove("t4:idx", "missing")                     # absent member: no error
        assert s.set_members("t4:neverwritten") == [], name   # unwritten key: [] (no create)
        s.set_add("t4:idx", "2001:db8::1|2001:db8::2", 60)    # ':' and '|' members
        assert "2001:db8::1|2001:db8::2" in s.set_members("t4:idx"), name
        print(f"  ok set_members/set_remove [{name}]")


def test_window_add_indexed():
    """window_add_indexed (plan 004 review): one call writes the window AND the
    index member, equivalent on both backends."""
    for name, s in _backends():
        s.window_add_indexed("bc:0:t:a|b", "idx:bc:0", 100.0, 1, 60)
        assert s.window_range("bc:0:t:a|b", 0) == [(100.0, 1)], name
        assert s.set_members("idx:bc:0") == ["bc:0:t:a|b"], name
        print(f"  ok window_add_indexed [{name}]")


def test_shard_routing():
    for n in (2, 3, 4):                                        # partition + its index co-locate
        assert st._shard_of("bc:3:homelab:a|b", n) == st._shard_of("idx:bc:3", n), n
        assert st._shard_of("nx:5:homelab:c", n) == st._shard_of("idx:nx:5", n), n
        assert st._shard_of("pv:homelab:1.2.3.4", n) == st._shard_of("pv:homelab:1.2.3.4", n)
    assert st._shard_of("bc:7:homelab:2001:db8::1|2001:db8::2", 4) == 7 % 4   # IPv6 routes by partition
    print("  ok shard routing")


def test_sharded_contract():
    sh = st.ShardedRedisStore([st.InMemoryStore() for _ in range(3)])
    sh.window_add_indexed("bc:2:t:a|b", "idx:bc:2", 100.0, 5, 60)
    assert sh.window_range("bc:2:t:a|b", 0) == [(100.0, 5)]
    assert sh.set_members("idx:bc:2") == ["bc:2:t:a|b"]       # index co-located + readable
    assert sh.counter_add("ex:t:x|y", "b", 10, 60) == 10
    assert sh.counter_get("ex:t:x|y", "b") == 10
    assert sh.dedup_seen("emit:t:d:1:9", 60) is True
    assert sh.dedup_seen("emit:t:d:1:9", 60) is False
    sh.window_add("bc:0:t:c|d", 1.0, 1, 60)
    ks = set(sh.keys_matching("bc:"))
    assert "bc:2:t:a|b" in ks and "bc:0:t:c|d" in ks          # union across shards
    print("  ok sharded contract")


def test_window_add_indexed_batch():
    """Batched window writes (plan 006) == individual, on both backends + sharded."""
    stores = [("memory", st.InMemoryStore()),
              ("sharded-mem", st.ShardedRedisStore([st.InMemoryStore() for _ in range(3)]))]
    for name, s in stores:
        items = [(f"bc:{p}:t:e{p}", f"idx:bc:{p}", 100.0 + p, p, 60) for p in range(6)]
        s.window_add_indexed_batch(items)
        for p in range(6):
            assert s.window_range(f"bc:{p}:t:e{p}", 0) == [(100.0 + p, p)], name
            assert f"bc:{p}:t:e{p}" in s.set_members(f"idx:bc:{p}"), name
        s.window_add_indexed_batch([])                       # empty -> no-op
        # idx_key=None -> plain window, no index
        s.window_add_indexed_batch([("bc:9:t:x", None, 1.0, 1, 60)])
        assert s.window_range("bc:9:t:x", 0) == [(1.0, 1)] and s.set_members("idx:bc:9") == [], name
        print(f"  ok window_add_indexed_batch [{name}]")


def test_pipeline_ops():
    """pipeline_ops (plan 007): every op kind lands like its individual equivalent,
    on both memory and sharded-mem, in ONE batch."""
    stores = [("memory", st.InMemoryStore()),
              ("sharded-mem", st.ShardedRedisStore([st.InMemoryStore() for _ in range(3)]))]
    for name, s in stores:
        s.pipeline_ops([
            ("win",  "bc:1:t:a|b", "idx:bc:1", 100.0, 7, 60),
            ("cnt",  "ex:1:t:a|b", "b", 500, 60, "idx:ex:1"),
            ("cnt",  "ex:1:t:a|b", "b", 200, 60, "idx:ex:1"),      # same key/field accumulates
            ("znx",  "kd:1:t:a", "dstX", 10.0, 60, "idx:kd:1"),
            ("znx",  "kd:1:t:a", "dstX", 99.0, 60, "idx:kd:1"),    # NX: keeps earliest 10.0
            ("kv",   "ctx:t:a|b", ["breed", ["r1"]], 60),
            ("sadd", "pv:t:b", "a", 60),
        ])
        assert s.window_range("bc:1:t:a|b", 0) == [(100.0, 7)], name
        assert "bc:1:t:a|b" in s.set_members("idx:bc:1"), name
        assert s.counter_get("ex:1:t:a|b", "b") == 700, name          # 500+200
        assert "ex:1:t:a|b" in s.set_members("idx:ex:1"), name
        assert s.zset_rank("kd:1:t:a", "dstX") == 0, name             # only member -> rank 0
        assert "kd:1:t:a" in s.set_members("idx:kd:1"), name
        assert s.kv_get("ctx:t:a|b") == ["breed", ["r1"]], name
        assert s.set_contains("pv:t:b", "a"), name
        s.pipeline_ops([])                                            # empty -> no-op
        print(f"  ok pipeline_ops [{name}]")


def test_field_set_is_last_write_wins_and_summable():
    """ADR 011: field_set is a BLIND per-field set, so a replayed write is a no-op and a
    later cumulative value replaces the earlier one; fields_get returns everything to sum.
    Same assertions on both backends (and sharded) -- this is the property the exfil /
    long-connection aggregates now depend on for idempotency."""
    for name, s in _backends():
        s.field_set("fx:1:t:a|b", "flow-1", 100, ttl=600)
        s.field_set("fx:1:t:a|b", "flow-1", 100, ttl=600)          # replay: no-op
        s.field_set("fx:1:t:a|b", "flow-1", 900, ttl=600)          # later interim: overwrite
        s.field_set("fx:1:t:a|b", "flow-2", 50, ttl=600)           # distinct flow: adds
        s.field_set("fx:1:t:a|b", "flow-2", 5, ttl=600)            # counter reset: current truth
        vals, refused = s.fields_get("fx:1:t:a|b")
        assert vals == {"flow-1": 900.0, "flow-2": 5.0}, f"{name}: {vals}"
        assert sum(vals.values()) == 905.0 and len(vals) == 2, name
        assert refused == 0, name
        assert s.fields_get("fx:1:t:never") == ({}, 0), name       # unwritten key
        # counter_add still accumulates on its own key (ssh/icmp rate counters rely on it)
        assert s.counter_add("fx:cnt", "n", 1, 600) == 1 and s.counter_add("fx:cnt", "n", 1, 600) == 2, name
        print(f"  ok field_set/fields_get [{name}]")


def test_field_set_cap_reports_refused_writes():
    """The cap bounds fields per key, and a REFUSED WRITE is counted (never silently
    dropped) so the caller can say its aggregate is a floor. Writes, not identities: the
    write path takes no read, so re-writing an already-refused field is refused and counted
    again -- which is why callers must report refused updates, not a flow count (ADR 011).
    Equivalent on both backends."""
    for name, s in _backends():
        for i in range(10):
            s.field_set("fc:1:t:a|b", f"flow-{i}", 10, ttl=600, cap=4)
        vals, refused = s.fields_get("fc:1:t:a|b")
        assert len(vals) == 4, f"{name}: cap not enforced ({len(vals)})"
        assert refused == 6, f"{name}: refused {refused}"
        assert sum(vals.values()) == 40, name                      # a floor, not 100
        s.field_set("fc:1:t:a|b", "flow-0", 99, ttl=600, cap=4)    # an EXISTING field still updates
        vals2, refused2 = s.fields_get("fc:1:t:a|b")
        assert vals2["flow-0"] == 99.0 and len(vals2) == 4 and refused2 == 6, name
        s.field_set("fc:1:t:a|b", "flow-9", 10, ttl=600, cap=4)    # replay of a REFUSED field
        vals3, refused3 = s.fields_get("fc:1:t:a|b")
        assert vals3 == vals2 and refused3 == 7, f"{name}: {refused3}"   # aggregate steady, refusals rise
        print(f"  ok field_set cap [{name}]")


def test_field_set_via_pipeline_ops():
    """The fset op lands like the individual call (app.py buffers every write into ONE
    pipelined round-trip per poll-batch, so the batched path is the production path)."""
    stores = [("memory", st.InMemoryStore()),
              ("sharded-mem", st.ShardedRedisStore([st.InMemoryStore() for _ in range(3)]))]
    url = os.environ.get("NDR_TEST_REDIS_URL")
    if url:
        try:
            r = st.RedisStore(url); r._r.ping(); r._r.flushdb(); stores.append(("redis", r))
        except Exception as e:
            print(f"  (redis backend skipped: {e})")
    for name, s in stores:
        s.pipeline_ops([
            ("fset", "exf:1:t:a|b", "flow-1", 500, 60, "idx:exf:1", 2),
            ("fset", "exf:1:t:a|b", "flow-1", 500, 60, "idx:exf:1", 2),   # replay: still 500
            ("fset", "exf:1:t:a|b", "flow-2", 200, 60, "idx:exf:1", 2),
            ("fset", "exf:1:t:a|b", "flow-3", 900, 60, "idx:exf:1", 2),   # beyond the cap
        ])
        vals, refused = s.fields_get("exf:1:t:a|b")
        assert vals == {"flow-1": 500.0, "flow-2": 200.0}, f"{name}: {vals}"
        assert refused == 1, f"{name}: {refused}"
        assert "exf:1:t:a|b" in s.set_members("idx:exf:1"), name     # indexed like cnt/win
        print(f"  ok pipeline fset [{name}]")


def test_redis_fset_is_one_round_trip_per_batch():
    """Plan 007's invariant asserted at the COMMAND level, not by inspection: a poll-batch
    containing fset ops is ONE pipeline execute with no immediate (out-of-pipeline) command.
    redis-py's register_script helper breaks exactly that -- a registered Script queued on a
    pipeline makes Pipeline.execute issue an immediate SCRIPT EXISTS first (client.py
    load_scripts), i.e. a second synchronous round-trip per batch -- so the cap script is
    queued as one SCRIPT LOAD followed by EVALSHA instead, which also rules out NOSCRIPT
    after a Redis restart or SCRIPT FLUSH. A fake client records what RedisStore issues."""
    log = []

    class _Pipe:
        def __getattr__(self, name):                       # any queued command
            def q(*a, **k):
                log.append((name.upper(),) + a)
                return self
            return q

        def execute(self, *a, **k):
            log.append(("EXECUTE",))
            return []

        def immediate_execute_command(self, *a, **k):      # what register_script would use
            raise AssertionError(f"extra synchronous round-trip: {a}")

    class _Client:
        def pipeline(self, transaction=False):
            return _Pipe()

        def register_script(self, script):
            raise AssertionError("register_script costs a SCRIPT EXISTS preflight per execute")

    fake = types.ModuleType("redis")
    fake.Redis = type("Redis", (), {"from_url": staticmethod(lambda url, **kw: _Client())})
    real = sys.modules.get("redis")
    sys.modules["redis"] = fake
    try:
        s = st.RedisStore("redis://fake/0")
        s.pipeline_ops([("fset", "exf:1:t:a|b", f"flow-{i}", 100 * i, 60, "idx:exf:1", 8)
                        for i in range(3)]
                       + [("win", "bc:1:t:a|b", "idx:bc:1", 1.0, 0, 60)])
    finally:
        if real is None:
            del sys.modules["redis"]
        else:
            sys.modules["redis"] = real
    cmds = [c[0] for c in log]
    assert cmds.count("EXECUTE") == 1, f"not one round-trip: {cmds}"
    assert cmds.count("SCRIPT_LOAD") == 1, f"script load per op or missing: {cmds}"
    assert cmds.index("SCRIPT_LOAD") < cmds.index("EVALSHA"), cmds      # cached before first use
    assert cmds.count("EVALSHA") == 3, cmds                              # one per fset op
    assert not [c for c in cmds if "EXISTS" in c], cmds                  # no preflight
    sha = hashlib.sha1(st._FIELD_SET_LUA.encode()).hexdigest()
    ev = next(c for c in log if c[0] == "EVALSHA")
    assert ev[1] == sha and ev[2] == 1 and ev[3] == "exf:1:t:a|b", ev
    assert ev[-1] == st.REFUSED_FIELD and ev[-2] == 8, ev                # cap + refusal field
    print("  ok redis fset round-trips [fake client]")


def test_field_set_window_is_tumbling():
    """TTL comes from the FIRST write and is not refreshed (F05, same as counter_add), so a
    pair's per-flow fields cannot carry a previous window's flows forever."""
    clk = [1000.0]
    s = st.InMemoryStore(clock=lambda: clk[0])
    s.field_set("fx:t:a|b", "flow-1", 10, ttl=60)
    clk[0] += 30
    s.field_set("fx:t:a|b", "flow-2", 10, ttl=60)        # continuous activity
    clk[0] += 40                                         # past the FIRST write's ttl
    assert s.fields_get("fx:t:a|b") == ({}, 0), "per-flow fields outlived their window"
    s.field_set("fx:t:a|b", "flow-3", 7, ttl=60)         # fresh window starts clean
    assert s.fields_get("fx:t:a|b") == ({"flow-3": 7.0}, 0)


def test_zset_first_seen():
    """First-seen ZSET (plan 007, rare-dest): NX keeps earliest, since = strictly
    newer, rank = count ordered before (score, member)."""
    for name, s in _backends():
        for m, sc in (("d1", 10.0), ("d2", 20.0), ("d3", 30.0)):
            s.pipeline_ops([("znx", "kd:z", m, sc, 600, None)])
        s.pipeline_ops([("znx", "kd:z", "d2", 999.0, 600, None)])     # NX: d2 stays 20.0
        assert s.zset_since("kd:z", 0.0) == ["d1", "d2", "d3"], name  # score-ascending order
        assert s.zset_since("kd:z", 15.0) == ["d2", "d3"], name       # strictly > 15, ordered
        assert s.zset_since("kd:z", 20.0) == ["d3"], name             # boundary excluded
        assert s.zset_rank("kd:z", "d1") == 0, name                   # earliest -> 0 predecessors
        assert s.zset_rank("kd:z", "d3") == 2, name                   # two arrived before
        assert s.zset_rank("kd:z", "missing") is None, name
        print(f"  ok zset_first_seen [{name}]")


if __name__ == "__main__":
    import inspect
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        if inspect.getfullargspec(fn).args:
            continue
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall store contract tests passed")
