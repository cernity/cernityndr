"""Behavioral detectors service (plan U8; enterprise-hardened U1-U3): beacon /
strobe / exfil / DNS-tunnel / long-conn / rare-dest, RITA-method.

Consumes suricata.flow.v1 + suricata.dns.v1, keeps rolling per-entity windows in
a WindowStore (store.py: Redis in production for durable/bounded/HA-ready state,
in-memory for single-process/tests), and emits ndr.finding.candidate.v1 when a
scoring function (detectors.py, pure + covered by test_detectors.py) fires.

State keys are `<prefix>:<tenant>:<entity>` with `|` separating a src/dst pair
(IPs and domains never contain `|` or `:`... IPv6 does contain `:`, so the tenant
segment is split off with a fixed maxsplit and the entity is kept verbatim). Every
key carries a WINDOW TTL, so nothing grows unbounded and a moved Kafka partition
finds its state already in the store (rebalance-safety the HA unit relies on).
Tenant is resolved per record (U2), so two tenants never share a window.
"""
import hashlib
import json
import logging
import os
import signal
import time
from datetime import datetime

import ndr_runtime                      # shared tuned consumer/producer + metrics (plan 003 U1)

import detectors as det
import store as store_mod
import metrics
import config_source

log = ndr_runtime.setup_logging("behavioral-detectors")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
TENANT = os.environ.get("NDR_TENANT", "default")
WINDOW = float(os.environ.get("WINDOW_SECS", "600"))
EVAL_EVERY = float(os.environ.get("EVAL_SECS", "30"))
CUM_LONGCONN_SECS = float(os.environ.get("LONGCONN_CUM_SECS", str(0.5 * WINDOW)))
CANDIDATE_TOPIC = os.environ.get("NDR_CANDIDATE_TOPIC", "ndr.finding.candidate.v1")
GROUP_ID = os.environ.get("NDR_GROUP_ID", "ndr-behavioral-detectors")
OFFSET_RESET = os.environ.get("NDR_OFFSET_RESET", "latest")
STATE_BACKEND = os.environ.get("NDR_STATE_BACKEND", "memory")
REDIS_URL = os.environ.get("NDR_REDIS_URL", "redis://redis:6379/0")
PREV_CAP = 9
I2D_TTL = float(os.environ.get("I2D_CACHE_TTL", str(WINDOW)))    # positive (hit) cache staleness bound (plan 007 U3)
I2D_NEG_TTL = float(os.environ.get("I2D_NEG_CACHE_TTL", "5"))    # negative (miss) cache TTL: SHORT so a domain resolved
                                                                 # on another replica is visible within seconds, not a
                                                                 # full WINDOW (review: avoid suppressing FQDN-beacon)
I2D_CACHE_MAX = int(os.environ.get("I2D_CACHE_MAX", "50000"))    # bounded in-process cache size

def _stable(s: str) -> int:
    """Cross-process-stable hash. Python's hash() is PYTHONHASHSEED-randomized, so
    it must NOT key the shared-Redis dedup (replicas would compute different keys
    and both emit). SHA1 is stable across replicas -> dedup works under HA."""
    return int(hashlib.sha1(s.encode()).hexdigest()[:15], 16)


_store = store_mod.make_store(STATE_BACKEND, REDIS_URL)
_running = True


def _stop(*_):
    global _running
    _running = False


def _tenant_of(e) -> str:
    """Resolve the tenant/site for a record. A multi-tenant deployment stamps a
    trusted `tenant`/`site` field upstream (Vector, from authenticated sensor
    identity); single-tenant deploys fall back to NDR_TENANT. Deriving tenant
    from a trusted signal (not a producer-set free field) is a security property
    the multi-tenant rollout must uphold."""
    for k in ("tenant", "site"):
        v = e.get(k)
        if v:
            return str(v)
    return TENANT


def _ndpi_risks(n):
    """Normalize the nDPI risk set to a list of risk strings. Suricata's nDPI
    plugin emits it as `flow_risk` (older/custom builds use `risk`); accept both.
    A dict may be {id: name} or {name: true}, so fold in keys and values."""
    rk = n.get("risk") or n.get("flow_risk")
    if isinstance(rk, dict):
        return [str(k) for k in rk.keys()] + [str(v) for v in rk.values()]
    if isinstance(rk, list):
        return rk
    return [rk] if rk else []


def _event_epoch(e) -> float:
    ts = e.get("timestamp") or (e.get("flow") or {}).get("start")
    if ts:
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
        except (ValueError, TypeError):
            pass
    return time.time()


def _key_parts(key: str):
    """`prefix:partition:tenant:entity` -> (tenant, entity). Entity kept verbatim
    (may hold ':' for IPv6 and '|' for a src/dst pair). The partition segment
    (plan 003 U4) lets evaluate() scan only this replica's assigned partitions;
    the maxsplit keeps an IPv6 entity's colons intact."""
    _, _part, tenant, entity = key.split(":", 3)
    return tenant, entity


def _pair(entity: str):
    a, _, b = entity.partition("|")
    return a, b


def _timing_evidence(ts):
    """Transparency: surface the beacon's own timing math (mean interval + jitter +
    connection count) as evidence entities, so an analyst sees *why* it scored, not
    just that it did. Cheap to compute from the window timestamps already in hand."""
    ts = sorted(float(t) for t in ts)
    if len(ts) < 2:
        return [{"type": "connections", "value": len(ts)}]
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    mean = sum(gaps) / len(gaps)
    jitter = (sum((g - mean) ** 2 for g in gaps) / len(gaps)) ** 0.5
    return [{"type": "interval_s", "value": round(mean, 1)},
            {"type": "jitter_s", "value": round(jitter, 1)},
            {"type": "connections", "value": len(ts)}]


def _candidate(detector_id, category, severity, confidence, entities, tenant):
    bucket = int(time.time() // WINDOW)
    if not _store.dedup_seen(f"emit:{tenant}:{detector_id}:{_stable(entities) % 10**12}:{bucket}", WINDOW):
        return None
    metrics.finding(detector_id, tenant)
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    return {"finding_id": f"{detector_id}-{_stable(entities) % 10**10}-{bucket}",
            "tenant_id": tenant, "detector_id": detector_id, "detector_version": "1.0",
            "category": category, "severity": severity, "confidence": confidence,
            "first_seen": now, "last_seen": now, "entities": entities, "state": "CANDIDATE"}


# Enumerate assigned-partition keys via the per-partition index by default;
# NDR_ENUM_INDEX=0 falls back to the U4 scan-plus-filter (plan 004 U3/KTD4).
ENUM_INDEX = os.environ.get("NDR_ENUM_INDEX", "1") not in ("0", "false", "False", "")


def _part_of(key):
    """Partition segment of a scanned key `prefix:partition:tenant:entity`."""
    return key.split(":", 2)[1]


def _index_key(prefix, part):
    """Per-partition index SET for a scanned prefix (plan 004 U2): idx:bc:{part}.
    Holds the live window keys on that partition so evaluate() can SMEMBERS its
    own partitions instead of SCANning the whole prefix."""
    return f"idx:{prefix}{part}"


def _scoped_keys(prefix, parts):
    """Keys under prefix for this replica's assigned partitions, or ALL keys
    under prefix when parts is None (single-process / validation). ONE keyspace
    traversal, filtered to the assigned partitions client-side: Redis SCAN walks
    the whole keyspace regardless of MATCH, so a SCAN per partition would multiply
    the traversal load on the shared store by the partition count (plan 003 U4
    review). This preserves the partition-scoped PROCESSING win (each replica only
    window_ranges + scores its own entities); shrinking the traversal itself would
    need a per-partition key index (follow-up). Keys whose partition segment is not
    an integer (a stray pre-U4 key mid-format-migration) are skipped; they expire.
    """
    if parts is None:
        return _store.keys_matching(prefix)              # single-process / validation: full scan
    if ENUM_INDEX:
        out = []
        for p in parts:
            out += _store.set_members(_index_key(prefix, p))   # O(this replica's entities)
        return out
    # fallback (NDR_ENUM_INDEX=0): one keyspace SCAN + client-side partition filter
    return [k for k in _store.keys_matching(prefix)
            if (seg := k.split(":", 2)[1]).isdigit() and int(seg) in parts]


def _prune_index(key):
    """Self-clean (plan 004 U3): an empty window_range means this entity expired,
    so drop it from its partition index. Piggybacks on the window_range evaluate
    already performed (the SREM itself is one round-trip). Prefix + partition come from the
    key. No-op when enumerating via scan (the index is unused / TTL-bounded then)."""
    if ENUM_INDEX:
        _store.set_remove(_index_key(key.split(":", 1)[0] + ":", _part_of(key)), key)


_pending = []                            # buffered per-poll-batch writes (plan 006/007)


def _flush_pending():
    """Flush the poll-batch's buffered writes in ONE Redis round-trip (plan 007):
    the per-record synchronous round-trip was the throughput ceiling. _handle is
    now write-only -- windows, counters, first-seen zsets, kv and set adds all
    buffer here and land together via pipeline_ops."""
    if _pending:
        _store.pipeline_ops(_pending)
        _pending.clear()


def _idx(prefix, part):
    return _index_key(prefix, part) if ENUM_INDEX else None


def _win_add(prefix, part, key, score, value):
    _pending.append(("win", key, _idx(prefix, part), score, value, WINDOW))


def _cnt_add(prefix, part, key, field, delta):
    _pending.append(("cnt", key, field, delta, WINDOW, _idx(prefix, part)))


def _znx_add(prefix, part, key, member, score):
    _pending.append(("znx", key, member, score, WINDOW, _idx(prefix, part)))


def _kv_add(key, value):
    _pending.append(("kv", key, value, WINDOW))


def _sadd_add(key, member):
    _pending.append(("sadd", key, member, WINDOW))


_i2d_cache = {}                          # dst-ip key -> (value, inserted_ts, ttl): read-through cache (plan 007 U3)
_rare_last_eval = 0.0                     # wall-clock of the last evaluate() -- rare-dest emits only dsts first-seen since


def _i2d_put(key, val, ttl, now):
    """Insert into the i2d cache under a shared size bound (both the read-through
    populate and the DNS-answer populate go through here, so neither can grow the
    cache past I2D_CACHE_MAX)."""
    if len(_i2d_cache) >= I2D_CACHE_MAX:
        _i2d_cache.clear()               # bounded reset (ponytail: simple > LRU at this size)
    _i2d_cache[key] = (val, now, ttl)


def _i2d_get(key, now):
    """Read-through cache for the DNS->domain (i2d) map. The FQDN-beacon path reads
    i2d:{dst} per flow; caching it -- populated on the DNS-answer write and on cold
    misses -- makes that read a Redis round-trip ONLY on a cold miss, so _handle has
    zero synchronous per-flow reads in steady state (plan 007). Hits are cached for
    I2D_TTL (passive DNS is slowly-changing); MISSES are cached only for I2D_NEG_TTL
    (a few seconds) so that when the DNS answer for this dst lands on a DIFFERENT
    replica (dns and flow partitions assign independently), this flow replica re-reads
    Redis within seconds and starts populating bf:/fi: -- rather than returning a stale
    None for a full WINDOW and suppressing FQDN-beacon (review fix)."""
    hit = _i2d_cache.get(key)
    if hit is not None and now - hit[1] < hit[2]:        # (value, inserted_ts, ttl)
        return hit[0]
    v = _store.kv_get(key)
    _i2d_put(key, v, I2D_TTL if v is not None else I2D_NEG_TTL, now)
    return v


def evaluate(producer, flow_parts=None, dns_parts=None):
    # flow_parts/dns_parts = the partition numbers this replica owns on
    # suricata.flow.v1 / suricata.dns.v1 (plan 003 U4). None => scan unscoped.
    _flush_pending()                        # persist buffered window writes before enumerating (plan 006)
    cfg = config_source.current()
    floor = time.time() - WINDOW
    # beacon + strobe
    for key in _scoped_keys("bc:", flow_parts):
        ten, entity = _key_parts(key); src, dst = _pair(entity)
        rng = _store.window_range(key, floor)
        if not rng:
            _prune_index(key)          # self-clean expired index member (plan 004 U3)
            continue
        ts = [s for s, _ in rng]; sizes = [v for _, v in rng]
        env = _store.set_len(f"pv:{ten}:{dst}")
        breed, risks = _store.kv_get(f"ctx:{ten}:{src}|{dst}") or ["", []]
        is_b, score = det.beacon_score(ts, sizes, threshold=cfg["beacon_threshold"], count_target=cfg["beacon_count_target"])
        if is_b:
            sev = det.gated_severity(7, breed, risks, env_assets=env)
            ent = json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "ip", "role": "dst", "value": dst}]
                             + _timing_evidence(ts))
            c = _candidate("beacon", "c2", sev, score, ent, ten)
            if c:
                producer.send(CANDIDATE_TOPIC, c); log.info("BEACON %s->%s sev=%s score=%s", src, dst, sev, score)
        is_s, sscore = det.strobe_check(len(rng), dst, is_beacon=is_b, min_conns=cfg["strobe_min_conns"])
        if is_s:
            ent = json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "ip", "role": "dst", "value": dst},
                              {"type": "connections", "value": len(rng)}])
            c = _candidate("strobe", "c2", det.gated_severity(5, breed, risks, env_assets=env), sscore, ent, ten)
            if c:
                producer.send(CANDIDATE_TOPIC, c); log.info("STROBE %s->%s conns=%d", src, dst, len(rng))
    # FQDN / SNI beacon
    for key in _scoped_keys("bf:", flow_parts):
        ten, entity = _key_parts(key); src, dom = _pair(entity)
        rng = _store.window_range(key, floor)
        if not rng:
            _prune_index(key)          # self-clean expired index member (plan 004 U3)
            continue
        n_ips = _store.set_len(f"fi:{ten}:{src}|{dom}")
        is_fb, fscore = det.fqdn_beacon([s for s, _ in rng], [v for _, v in rng], n_ips)
        if is_fb:
            ent = json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "domain", "role": "c2", "value": dom},
                              {"type": "rotating_ips", "value": n_ips}])
            c = _candidate("beacon_fqdn", "c2", det.gated_severity(8, "", []), fscore, ent, ten)
            if c:
                producer.send(CANDIDATE_TOPIC, c); log.info("BEACON_FQDN %s->%s ips=%d score=%s", src, dom, n_ips, fscore)
    # DNS tunnel + exploded DNS
    for key in _scoped_keys("dn:", dns_parts):
        ten, client = _key_parts(key)
        rng = _store.window_range(key, floor)
        if not rng:
            _prune_index(key)          # self-clean expired index member (plan 004 U3)
            continue
        qnames = [v for _, v in rng]
        is_t, tscore = det.dns_tunnel_score(qnames, min_queries=cfg["dns_min_queries"], len_threshold=cfg["dns_len_threshold"], entropy_threshold=cfg["dns_entropy_threshold"])
        if is_t:
            ent = json.dumps([{"type": "ip", "role": "client", "value": client}])
            c = _candidate("dns_tunnel", "dns_tunnel", 6, tscore, ent, ten)
            if c:
                producer.send(CANDIDATE_TOPIC, c); log.info("DNS_TUNNEL %s score=%s", client, tscore)
        is_x, xscore, parent = det.dns_exploded_score(qnames, min_subdomains=cfg["exploded_min_subdomains"])
        if is_x:
            ent = json.dumps([{"type": "ip", "role": "client", "value": client},
                              {"type": "domain", "role": "tunnel_parent", "value": parent}])
            c = _candidate("dns_exploded", "dns_tunnel", 6, xscore, ent, ten)
            if c:
                producer.send(CANDIDATE_TOPIC, c); log.info("DNS_EXPLODED %s parent=%s score=%s", client, parent, xscore)
    # exfil: the ex: byte counter accrues per flow (write-only in _handle, plan 007);
    # the threshold check + emit run here. Severity reuses ctx: (breed/risks) + pv:
    # prevalence, exactly as the inline path did.
    for key in _scoped_keys("ex:", flow_parts):
        ten, entity = _key_parts(key); src, dst = _pair(entity)
        total = _store.counter_get(key, "b")
        if not total:
            _prune_index(key); continue
        is_e, escore = det.exfil_check(int(total), dst, threshold_bytes=cfg["exfil_bytes"])
        if is_e:
            breed, risks = _store.kv_get(f"ctx:{ten}:{src}|{dst}") or ["", []]
            sev = det.gated_severity(8, breed, risks, env_assets=_store.set_len(f"pv:{ten}:{dst}"))
            ent = json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "ip", "role": "dst", "value": dst},
                              {"type": "bytes", "value": int(total)}])
            c = _candidate("exfil", "exfil", sev, escore, ent, ten)
            if c:
                producer.send(CANDIDATE_TOPIC, c); log.info("EXFIL %s->%s bytes=%d", src, dst, int(total))
    # cumulative long-connection (moved from _handle, plan 007)
    for key in _scoped_keys("lc:", flow_parts):
        ten, entity = _key_parts(key); src, dst = _pair(entity)
        secs = _store.counter_get(key, "s")
        if not secs:
            _prune_index(key); continue
        nconn = _store.counter_get(key, "n")
        is_lc, lcs = det.longconn_cumulative_check(secs, int(nconn), dst,
                                                   threshold_secs=(cfg["longconn_cum_secs"] or CUM_LONGCONN_SECS),
                                                   min_conns=cfg["longconn_cum_min_conns"])
        if is_lc:
            breed, risks = _store.kv_get(f"ctx:{ten}:{src}|{dst}") or ["", []]
            sev = det.gated_severity(5, breed, risks, env_assets=_store.set_len(f"pv:{ten}:{dst}"))
            ent = json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "ip", "role": "dst", "value": dst},
                              {"type": "total_duration_s", "value": int(secs)},
                              {"type": "connections", "value": int(nconn)}])
            c = _candidate("long_connection_cumulative", "c2", sev, lcs, ent, ten)
            if c:
                producer.send(CANDIDATE_TOPIC, c); log.info("LONG_CONN_CUM %s->%s total=%ds conns=%d", src, dst, int(secs), int(nconn))
    # rare destination (moved, plan 007): first-seen ZSET. Emit ONCE per (src, new-dst),
    # matching the inline "set_len(kd)>=15 AND dst not yet known at arrival" -- NOT once
    # per WINDOW bucket. Only dsts first-seen SINCE the last evaluate (rare_since) are
    # candidates; a dst's zset_rank (count of dsts first-seen before it) is its baseline-
    # at-arrival, so rank>=15 == the inline set_len>=15 crossing. This holds equivalence
    # ACROSS windows (not just the single cycle the R3 gate proves) and avoids re-alerting
    # an active fan-out host every bucket. A FRESH process starts rare_since=0.0 so it fires
    # every current rank>=15 dst once (shared emit-dedup backstops any a prior owner emitted);
    # a running process that GAINS a partition on rebalance uses its already-advanced cursor,
    # so it does not re-emit the moved partition's dsts and a not-yet-evaluated one is a bounded
    # one-cycle miss -- the accepted plan-003 rebalance semantics.
    global _rare_last_eval
    rare_since = _rare_last_eval
    _rare_last_eval = time.time()
    for key in _scoped_keys("kd:", flow_parts):
        news = _store.zset_since(key, rare_since)      # dsts first-seen since the last evaluate cycle
        if news:
            ten, src = _key_parts(key)
            for dst in news:
                rank = _store.zset_rank(key, dst)      # count of dsts first-seen before it (None if it just expired)
                if rank is not None and rank >= 15:    # baseline-at-arrival >= 15 == inline set_len>=15
                    ent = json.dumps([{"type": "ip", "role": "src", "value": src},
                                      {"type": "ip", "role": "new_dst", "value": dst}])
                    c = _candidate("rare_destination", "anomaly", 4, 0.5, ent, ten)
                    if c:
                        producer.send(CANDIDATE_TOPIC, c); log.info("RARE_DEST %s->%s", src, dst)
        elif not _store.zset_since(key, 0.0):          # no new dsts AND the zset is empty -> self-clean index
            _prune_index(key)
    _store.kv_prune()


def _handle(e, producer, now, part=0, cfg=None):
    # part = the Kafka partition this record arrived on; the three scanned
    # windows (bc/bf/dn) are tagged with it so evaluate() can scope by
    # assignment. cfg is snapshotted once per poll-batch in main() (plan 003
    # U4); None => fetch here (single-process / validation).
    et = e.get("event_type")
    metrics.record(et)
    if cfg is None:
        cfg = config_source.current()
    if et == "flow":
        src, dst = e.get("src_ip"), e.get("dest_ip")
        if not (src and dst):
            return
        ten = _tenant_of(e)
        evt = _event_epoch(e)
        n = e.get("ndpi") or {}
        risks = _ndpi_risks(n)
        breed = n.get("breed") or ""
        f = e.get("flow", {}) or {}
        b2s = int(f.get("bytes_toserver", 0) or 0)
        b2c = int(f.get("bytes_toclient", 0) or 0)
        # Per-flow state is now WRITE-ONLY (plan 007): every write is buffered into
        # _pending and flushed in ONE pipelined round-trip per poll-batch, and the
        # three threshold checks that used to read-then-emit inline (exfil, cumulative
        # long-conn, rare-destination) run in the partition-scoped evaluate() instead.
        # So _handle issues zero synchronous Redis round-trips per flow in steady state
        # (the sole per-flow read, i2d, is served by _i2d_get's read-through cache).
        #   - ex:/lc:/kd: are src-keyed -> co-partitioned -> now partition-tagged AND
        #     indexed, so evaluate() enumerates only this replica's assigned partitions.
        #     All three (and exfil/longconn-cum/rare-dest) gate on is_external, so they
        #     are written only for external dsts -- no indexing of internal traffic.
        #   - ctx/fi/pv/i2d stay UN-tagged: read by exact key or genuinely cross-
        #     partition (pv is a global per-dst prevalence set; i2d is written from a
        #     DNS answer and read from a flow on a different src-keyed partition). Do
        #     NOT tag them -- it breaks the exact-key reads in evaluate()/_handle.
        age = float((f.get("age") or 0))
        if det.is_external(dst):
            _kv_add(f"ctx:{ten}:{src}|{dst}", [breed, risks])                # dst-context for severity (read in evaluate)
            _sadd_add(f"pv:{ten}:{dst}", src)                               # fleet prevalence (uncapped; env bucket unaffected)
            _cnt_add("ex:", part, f"ex:{part}:{ten}:{src}|{dst}", "b", b2s)  # exfil bytes -> threshold in evaluate()
            _cnt_add("lc:", part, f"lc:{part}:{ten}:{src}|{dst}", "s", age)  # cumulative long-conn secs -> evaluate()
            _cnt_add("lc:", part, f"lc:{part}:{ten}:{src}|{dst}", "n", 1)    # ... and conn count
            _znx_add("kd:", part, f"kd:{part}:{ten}:{src}", dst, time.time())  # first-seen dst -> rare-dest in evaluate().
            # score = PROCESSING wall-clock, NOT event-time evt: the evaluate rare-dest cursor is wall-clock, so kd: scores
            # must share that clock domain -- else under consumer lag (event-time trails wall-time) the cursor excludes
            # newly-processed dsts and silently drops rare_destination. Processing order also matches the inline set-add
            # baseline, and one box means all replicas share the clock (so a rebalanced partition's scores stay comparable).
            if not det.beacon_noise_dst(dst):
                _win_add("bc:", part, f"bc:{part}:{ten}:{src}|{dst}", evt, b2s + b2c)
                dom = _i2d_get(f"i2d:{ten}:{dst}", now)                      # read-through cache: round-trip only on cold miss
                if dom:
                    _win_add("bf:", part, f"bf:{part}:{ten}:{src}|{dom[0]}", evt, b2s + b2c)
                    _sadd_add(f"fi:{ten}:{src}|{dom[0]}", dst)
        # inline stateless detectors (no Redis state): ndpi risk + age-based long connection
        hit, matched = det.ndpi_risk_hit([str(r) for r in risks])
        if not hit and det.ndpi_breed_hit(breed):
            hit, matched = True, [f"breed:{breed} proto:{n.get('proto', '?')}"]
        if hit:
            ent = json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "ndpi_risk", "value": sorted(matched)}])
            c = _candidate("ndpi_risk", "malware", 6, 0.6, ent, ten)
            if c:
                producer.send(CANDIDATE_TOPIC, c); log.info("NDPI_RISK %s %s", src, matched)
        is_l, ls = det.longconn_check(age, dst)
        if is_l:
            ent = json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "ip", "role": "dst", "value": dst},
                              {"type": "duration_s", "value": int(age)}])
            c = _candidate("long_connection", "c2", 5, ls, ent, ten)
            if c:
                producer.send(CANDIDATE_TOPIC, c); log.info("LONG_CONN %s->%s age=%s", src, dst, age)
    elif et == "dns":
        d = e.get("dns", {}) or {}
        ten = _tenant_of(e)
        qs = d.get("queries") or [d]
        qn = (qs[0].get("rrname") if qs else None) or d.get("rrname")
        if e.get("src_ip") and qn:
            _win_add("dn:", part, f"dn:{part}:{ten}:{e['src_ip']}", _event_epoch(e), qn)
        for a in (d.get("answers") or []):
            if a.get("rrtype") in ("A", "AAAA") and a.get("rdata") and a.get("rrname"):
                i2dk = f"i2d:{ten}:{a['rdata']}"
                i2dv = [det.registered_parent(a["rrname"]), _event_epoch(e)]
                _store.kv_set(i2dk, i2dv, WINDOW)          # immediate: a same-batch flow read (via _i2d_get) must see it
                _i2d_put(i2dk, i2dv, I2D_TTL, now)         # keep the read-through cache fresh (positive TTL, bounded)


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    producer = ndr_runtime.make_producer()                       # tuned batch/linger/compression (U1)
    consumer = ndr_runtime.make_consumer("suricata.flow.v1", "suricata.dns.v1",
                                         group_id=GROUP_ID, auto_offset_reset=OFFSET_RESET)
    metrics.start(int(os.environ.get("NDR_METRICS_PORT", "9108")))
    metrics.set_ready("store", False)      # declare store so /readyz waits for it (plan 003 obs)
    metrics.set_ready("consumer")
    # Store readiness is (re)probed in the loop below, not once here: the local
    # Redis unix socket may not exist yet at startup, and a one-shot probe would
    # pin /readyz at 503 forever even after Redis comes up (plan 003 U4 review).
    config_source.start(BOOTSTRAP, det, on_reload=metrics.config_reloaded)
    log.info("behavioral-detectors up (state=%s window=%ss)", STATE_BACKEND, WINDOW)
    last_eval = time.time()
    while _running:
        now = time.time()
        if not metrics.is_ready():              # lazy store-readiness re-probe (U4 review)
            try:
                _store.dedup_seen("readyprobe", 1); metrics.set_ready("store")
            except Exception:
                pass
        cfg = config_source.current()          # snapshot once per poll-batch (plan 003 U4)
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=1000).items():
            for rec in records:
                try:
                    _handle(rec.value, producer, now, _tp.partition, cfg)
                except Exception as ex:
                    metrics.dropped("handler"); log.debug("skip record: %s", ex)
        try:
            _flush_pending()                    # one pipelined round-trip for the poll-batch (plan 006/007)
        except Exception as ex:                 # a Redis blip must not crash-loop the replica -- mirror the evaluate
            metrics.dropped("flush"); log.warning("flush failed: %s", ex)   # guard below. Drop this batch's buffered
            _pending.clear()                    # writes: windowed detectors (beacon/dns) repopulate from later flows;
            # the ex:/lc: accumulators just under-count this batch (a lone threshold-crossing flow here is missed for the
            # window -- offsets auto-commit at the next poll, no redelivery). metrics.dropped("flush") surfaces the rate.
        if now - last_eval >= EVAL_EVERY:
            # evaluate only the entities on this replica's assigned partitions
            fp = ndr_runtime.assigned_partitions(consumer, "suricata.flow.v1")
            dp = ndr_runtime.assigned_partitions(consumer, "suricata.dns.v1")
            try:
                _t = time.time(); evaluate(producer, fp, dp); metrics.observe_evaluate(time.time() - _t)
                producer.flush()
            except Exception as ex:             # a Redis blip must not crash-loop the replica (U4 review)
                metrics.dropped("evaluate"); log.warning("evaluate failed: %s", ex)
            last_eval = now
    consumer.close(); producer.close()


if __name__ == "__main__":
    main()
