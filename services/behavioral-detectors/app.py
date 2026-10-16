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
import os
import re
import signal
import time
from datetime import datetime, timezone
from statistics import median

import ndr_runtime                      # shared tuned consumer/producer + metrics (plan 003 U1)

import detectors as det
import store as store_mod
import metrics
import config_source
import ndpi_policy as ndpi_pol

log = ndr_runtime.setup_logging("behavioral-detectors")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
TENANT = os.environ.get("NDR_TENANT", "default")
WINDOW = float(os.environ.get("WINDOW_SECS", "600"))
EVAL_EVERY = float(os.environ.get("EVAL_SECS", "30"))
CUM_LONGCONN_SECS = float(os.environ.get("LONGCONN_CUM_SECS", str(0.5 * WINDOW)))
CANDIDATE_TOPIC = os.environ.get("NDR_CANDIDATE_TOPIC", "ndr.finding.candidate.v1")
NDPI_MODE = os.environ.get("NDR_NDPI_CLASSIFICATION_MODE", "legacy")   # plan 008: legacy | structured
GROUP_ID = os.environ.get("NDR_GROUP_ID", "ndr-behavioral-detectors")
OFFSET_RESET = os.environ.get("NDR_OFFSET_RESET") or "latest"   # empty (unset compose passthrough) -> default, never ""
STATE_BACKEND = os.environ.get("NDR_STATE_BACKEND", "memory")
REDIS_URL = os.environ.get("NDR_REDIS_URL", "redis://redis:6379/0")
PREV_CAP = 9
I2D_TTL = float(os.environ.get("I2D_CACHE_TTL", str(WINDOW)))    # positive (hit) cache staleness bound (plan 007 U3)
I2D_NEG_TTL = float(os.environ.get("I2D_NEG_CACHE_TTL", "5"))    # negative (miss) cache TTL: SHORT so a domain resolved
                                                                 # on another replica is visible within seconds, not a
                                                                 # full WINDOW (review: avoid suppressing FQDN-beacon)
I2D_CACHE_MAX = int(os.environ.get("I2D_CACHE_MAX", "50000"))    # bounded in-process cache size
FQDN_BEACON_MIN_IPS = int(os.environ.get("NDR_FQDN_BEACON_MIN_IPS", "2"))   # IP-rotation gate (fqdn_beacon)
# Jitter/gap-tolerant beacon fallback: autocorrelation over the SAME window, tried only
# when the regularity scorer did not fire (see evaluate()). NDR_BEACON_AUTOCORR=0 turns
# it off entirely.
AUTOCORR = os.environ.get("NDR_BEACON_AUTOCORR", "1") not in ("0", "false", "False", "")


def _env_kw(**names):
    """Kwargs from only the env vars that are actually SET, so an unset knob keeps the
    default in the pure function's signature (detectors.py) rather than duplicating it
    here, where the two could drift."""
    out = {}
    for kw, (var, cast) in names.items():
        v = os.environ.get(var)
        if v not in (None, ""):
            out[kw] = cast(v)
    return out


AUTOCORR_KW = _env_kw(threshold=("NDR_BEACON_AUTOCORR_THRESHOLD", float),
                      min_strength=("NDR_BEACON_AUTOCORR_MIN_STRENGTH", float),
                      min_conns=("NDR_BEACON_AUTOCORR_MIN_CONNS", int),
                      count_target=("NDR_BEACON_AUTOCORR_COUNT_TARGET", int),
                      min_cycles=("NDR_BEACON_AUTOCORR_MIN_CYCLES", float),
                      max_lag_fraction=("NDR_BEACON_AUTOCORR_MAX_LAG_FRACTION", float),
                      max_bins=("NDR_BEACON_AUTOCORR_MAX_BINS", int),
                      bins_per_period=("NDR_BEACON_AUTOCORR_BINS_PER_PERIOD", int))

# Per-flow aggregate state lives under its OWN key prefixes, NOT the ex:/lc: the accumulating
# counters used (ADR 015, rolling-upgrade note). The hash SHAPE is the same but the schema is
# not: a field is now a flow identity, so a pre-upgrade ex: hash still holding the counter
# fields b/c (or lc:'s s/n) would be read as two "flows" worth 30 MB and 1 second and could
# re-manufacture the very finding this fix removes. A new prefix means the two schemas never
# meet in one key, in EITHER direction (a rollback reads its own keys back), and the old keys
# and their idx: entries age out within one WINDOW on their existing TTL.
EX_PFX, LC_PFX = "exf:", "lcf:"
# Per-flow fields per (src,dst) pair per window (ADR 015). An accumulating counter was O(1)
# per pair; one field per flow is O(flows per pair per window), so it needs a ceiling. 2048 is
# ~3.4 flows/s sustained to ONE destination for a 600s window -- a pair that chatty is already
# strobe/beacon territory -- and bounds a pair's hash to roughly 100 KB. When the cap binds the
# derived aggregate becomes a FLOOR (see evaluate): the overflow is counted in the hash, logged,
# exported as a gauge, and carried on the finding, never silently dropped.
FLOW_CAP = int(os.environ.get("NDR_FLOW_IDENTITY_CAP", "2048"))


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
    """Resolve the tenant/site for a record. The Fluent Bit shipper stamps a trusted
    `tenant`/`site` at ingress (deploy/fluent-bit/route.lua) from the sensor's own
    configuration, OVERWRITING any value in the raw EVE record — so this field is the
    authenticated sensor identity, not an attacker-influenced free field (F08).
    Single-tenant deploys fall back to NDR_TENANT."""
    for k in ("tenant", "site"):
        v = e.get(k)
        if v:
            return str(v)
    return TENANT


def _ndpi_risks(n):
    """The flow's nDPI risk set, STRUCTURED — [{id, name, severity, score}, ...].
    Suricata emits `flow_risk` as {id: {risk, risk_score, severity}}, i.e. a risk is
    an object; the previous str() flattening shipped a Python repr of it to the SIEM,
    so severity and risk_score were unqueryable. Shape parsing lives in ndpi_policy
    and is shared by both NDPI_MODEs: `structured` consumes ndpi_policy's full
    entries directly, `legacy` (the default) consumes this projection — for the risk
    match, the ctx: severity gate, and the ndpi_risk entity on the finding. Each mode
    keeps its own field precedence (legacy: `risk` then `flow_risk`, unchanged since
    before the fix; structured: canonical `flow_risk` first) — see detectors."""
    return det.ndpi_risks(n)


_TZ_OFFSET = re.compile(r'([+-]\d{2})(\d{2})$')     # +0000 -> +00:00


def _epoch(ts):
    """Parse an RFC3339/EVE timestamp to epoch seconds, or None. Suricata emits a `+0000` offset with
    NO colon, which datetime.fromisoformat REJECTS on Python < 3.11. This service's image is
    python:3.12-slim (where fromisoformat accepts the compact form), so this normalisation is a
    defence-in-depth guard covering the offline/host feeder path and any older runtime — NOT the proven
    root cause of the §stage5 beacon false-negative (the container parses `+0000` natively). Normalise
    the offset regardless so timing never silently collapses to a time.time() fallback."""
    if not ts:
        return None
    s = _TZ_OFFSET.sub(r'\1:\2', str(ts).replace("Z", "+00:00"))
    try:
        return datetime.fromisoformat(s).timestamp()
    except (ValueError, TypeError):
        return None


def _event_epoch(e) -> float:
    # For a flow record prefer flow.start (when the connection happened) over the EVE
    # 'timestamp' (when Suricata emitted/flushed the record). Offline Suricata flushes every
    # open flow at EOF with one identical timestamp, which collapses beacon periodicity; the
    # real inter-arrival timing survives only in flow.start. dns/other events have no
    # flow.start and fall back to timestamp.
    ts = (e.get("flow") or {}).get("start") or e.get("timestamp")
    ep = _epoch(ts)
    return ep if ep is not None else time.time()


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


def _method_evidence(method, period_secs, ts):
    """Regularity reports its median interval; autocorrelation reports its lag.
    These are timing estimates, not evidence that the destination is malicious."""
    if method == "regularity":
        ordered = sorted(ts)
        gaps = [b - a for a, b in zip(ordered, ordered[1:]) if b > a]
        period_secs = median(gaps) if gaps else 0.0
    return [{"type": "method", "value": method},
            {"type": "period_secs", "value": period_secs}]


def _rfc3339(ep):
    """Epoch -> RFC3339 UTC preserving sub-second resolution (R06: keep timestamp resolution)."""
    return datetime.fromtimestamp(ep, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _candidate(detector_id, category, severity, confidence, entities, tenant, obs=(None, None),
               *, detector_version="1.0", identity=None):
    bucket = int(time.time() // WINDOW)
    # An explicit identity string (plan 008 KTD4) keeps mutable evidence in `entities` (scores,
    # timestamps, raw records) out of the finding identity; the digest is 128-bit. Legacy callers
    # pass no identity and keep the original entities hash.
    dedup_key = hashlib.sha256(identity.encode()).hexdigest()[:32] if identity is not None else str(_stable(entities) % 10**12)
    if not _store.dedup_seen(f"emit:{tenant}:{detector_id}:{dedup_key}:{bucket}", WINDOW):
        return None
    metrics.finding(detector_id, tenant)
    emitted = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())     # when the aggregate was EMITTED
    omin, omax = obs
    observed = omin is not None
    # first_seen/last_seen carry the OBSERVATION interval (event times) when we have one; `observed=False`
    # tells the scorer these are emission-derived so temporal attribution is unknown, never a fabricated
    # in-window match (R06/§33.3). `emitted_at` is the availability signal, kept separate from observation.
    fs = _rfc3339(omin) if observed else emitted
    ls = _rfc3339(omax if omax is not None else omin) if observed else emitted
    fid = f"{detector_id}-{dedup_key}-{bucket}" if identity is not None else f"{detector_id}-{_stable(entities) % 10**10}-{bucket}"
    return {"finding_id": fid,
            "tenant_id": tenant, "detector_id": detector_id, "detector_version": detector_version,
            "category": category, "severity": severity, "confidence": confidence,
            "first_seen": fs, "last_seen": ls, "observed": observed, "emitted_at": emitted,
            "entities": entities, "state": "CANDIDATE"}


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


def _fset_add(prefix, part, key, field, value):
    _pending.append(("fset", key, field, value, WINDOW, _idx(prefix, part), FLOW_CAP))


def _znx_add(prefix, part, key, member, score):
    _pending.append(("znx", key, member, score, WINDOW, _idx(prefix, part)))


def _kv_add(key, value):
    _pending.append(("kv", key, value, WINDOW))


def _sadd_add(key, member):
    _pending.append(("sadd", key, member, WINDOW))


def _flow_identity(e, f):
    """Identity of the FLOW a record describes. Used as the hash FIELD under the
    (src|dst) key, so repeated records for one flow overwrite one value instead of
    accumulating four (ADR 015). Resolution order, most to least specific:

      1. (sensor, flow_id), and ONLY when BOTH are present. Suricata's flow_id is
         INSTANCE-local -- two sensors can mint the same number for unrelated flows -- so
         flow_id alone is not an identity: a sensor-less record falls through to 2/3 rather
         than merging every sensor's flow_id 5 into one field (which would UNDER-count, the
         dangerous direction). The sensor comes from the fields the normalizer trusts
         (host / sensor_id, stamped by the shipper).
      2. (sensor, community_id, flow start, flow_id). community_id hashes the 5-TUPLE, so a
         pair that reconnects on the same ports REUSES it; the flow's own start time separates
         those genuinely distinct flows, and flow_id (when the record has one but no sensor)
         separates concurrent flows further -- it can only split, never merge. The sensor is
         carried here too even though it alone was not enough to reach 1: two sensors that
         both see the same 5-tuple (a span tap either side of a hop) mint the SAME
         community_id and start, so dropping the sensor would merge their records into one
         field and the second would OVERWRITE the first -- an under-count. Empty when the
         record has no sensor, which only ever splits. Interim records of one flow share all
         four, so they still collapse to one identity, which is the point.
      3. A synthetic digest over what the record does carry (sensor, 5-tuple, proto, flow
         start, flow_id). Deliberately conservative: including the start time means the
         worst case is treating one flow as two (over-count, i.e. today's behavior), never
         merging two flows into one (under-count, which would blind the detector).

    Nothing is fabricated: a record carrying no identifier lands on a digest of its OWN
    fields, not a generated id. Known ceiling: with neither flow_id nor flow.start the
    digest falls back to the EVE emit timestamp, so interim records of such a flow can
    still split -- that is the pre-fix behavior, for a record shape Suricata does not emit.
    """
    fid = e.get("flow_id")
    sensor = e.get("host") or e.get("sensor_id") or ""
    if sensor and fid is not None:
        return f"s|{sensor}|{fid}"
    started = f.get("start") or e.get("timestamp") or ""
    cid = e.get("community_id")
    if cid:
        return f"c|{sensor}|{cid}|{started}|{'' if fid is None else fid}"
    raw = "|".join(str(x) for x in (sensor, e.get("src_ip", ""), e.get("src_port", ""),
                                    e.get("dest_ip", ""), e.get("dest_port", ""),
                                    e.get("proto", ""), started, "" if fid is None else fid))
    return "x|" + hashlib.sha1(raw.encode()).hexdigest()[:20]


def _refused_evidence(n):
    """Evidence that the aggregate is a FLOOR because the per-pair flow cap bound. `n` is
    the number of per-flow WRITES the cap refused, not a count of distinct flows: the write
    path takes no read, so a redelivered refused record is refused again (store.REFUSED_FIELD).
    So it reads 'at least one flow is missing from this total', nothing more precise. Absent
    when nothing was refused, so a normal finding is unchanged."""
    return [{"type": "flow_updates_refused_at_cap", "value": int(n)}] if n else []


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
        method, period = "regularity", 0.0
        if not is_b and AUTOCORR:
            # Jitter/gap-tolerant FALLBACK, same window, same noise gating (this loop only
            # sees dsts that passed beacon_noise_dst at write time). It runs ONLY when the
            # regularity scorer did not fire and emits the SAME detector_id, so a dst can
            # produce at most one beacon finding and the correlation service's `temporal`
            # family cap still covers it.
            is_b, score, period = det.beacon_autocorr(ts, sizes, **AUTOCORR_KW)
            method = "autocorrelation"
        if is_b:
            sev = det.gated_severity(7, breed, risks, env_assets=env)
            ent = json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "ip", "role": "dst", "value": dst}]
                             + _timing_evidence(ts) + _method_evidence(method, period, ts))
            c = _candidate("beacon", "c2", sev, score, ent, ten, obs=(ts[0], ts[-1]))
            if c:
                producer.send(CANDIDATE_TOPIC, c); log.info("BEACON %s->%s sev=%s score=%s method=%s", src, dst, sev, score, method)
        # is_b includes a fallback hit on purpose: a dst reported as a beacon must not
        # ALSO be reported as a strobe, whichever method found the period.
        is_s, sscore = det.strobe_check(len(rng), dst, is_beacon=is_b, min_conns=cfg["strobe_min_conns"])
        if is_s:
            ent = json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "ip", "role": "dst", "value": dst},
                              {"type": "connections", "value": len(rng)}])
            c = _candidate("strobe", "c2", det.gated_severity(5, breed, risks, env_assets=env), sscore, ent, ten, obs=(ts[0], ts[-1]))
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
        fts = [s for s, _ in rng]
        is_fb, fscore = det.fqdn_beacon(fts, [v for _, v in rng], n_ips, min_ips=FQDN_BEACON_MIN_IPS)
        method, period = "regularity", 0.0
        if not is_fb and AUTOCORR and n_ips >= FQDN_BEACON_MIN_IPS:
            # Same fallback, same IP-rotation gate as fqdn_beacon — a single-IP domain is
            # beacon_score's case, so the gate must not re-open here either.
            is_fb, fscore, period = det.beacon_autocorr(fts, [v for _, v in rng], **AUTOCORR_KW)
            method = "autocorrelation"
        if is_fb:
            ent = json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "domain", "role": "c2", "value": dom},
                              {"type": "rotating_ips", "value": n_ips}]
                             + _method_evidence(method, period, fts))
            c = _candidate("beacon_fqdn", "c2", det.gated_severity(8, "", []), fscore, ent, ten, obs=(rng[0][0], rng[-1][0]))
            if c:
                producer.send(CANDIDATE_TOPIC, c); log.info("BEACON_FQDN %s->%s ips=%d score=%s method=%s", src, dom, n_ips, fscore, method)
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
            c = _candidate("dns_tunnel", "dns_tunnel", 6, tscore, ent, ten, obs=(rng[0][0], rng[-1][0]))
            if c:
                producer.send(CANDIDATE_TOPIC, c); log.info("DNS_TUNNEL %s score=%s", client, tscore)
        is_x, xscore, parent = det.dns_exploded_score(qnames, min_subdomains=cfg["exploded_min_subdomains"])
        if is_x:
            ent = json.dumps([{"type": "ip", "role": "client", "value": client},
                              {"type": "domain", "role": "tunnel_parent", "value": parent}])
            c = _candidate("dns_exploded", "dns_tunnel", 6, xscore, ent, ten, obs=(rng[0][0], rng[-1][0]))
            if c:
                producer.send(CANDIDATE_TOPIC, c); log.info("DNS_EXPLODED %s parent=%s score=%s", client, parent, xscore)
    # exfil: exf: holds one field per FLOW carrying that flow's latest cumulative
    # bytes_toserver (write-only in _handle, plan 007); the aggregate is DERIVED here,
    # where the threshold check + emit already live (ADR 015). Summing per-flow fields
    # instead of accumulating a counter is what makes replay and repeated interim records
    # harmless. Severity reuses ctx: (breed/risks) + pv: prevalence, as the inline path did.
    refused = {EX_PFX: 0, LC_PFX: 0}
    for key in _scoped_keys(EX_PFX, flow_parts):
        ten, entity = _key_parts(key); src, dst = _pair(entity)
        flows, capped = _store.fields_get(key)       # {flow identity: that flow's cumulative bytes}
        total, conns = sum(flows.values()), len(flows)
        # Refusals are reported BEFORE any early exit: a cap that bound while every admitted
        # flow happened to carry 0 bytes is still data loss, and the spec forbids losing it
        # silently (review fix). Likewise prune the index only when the key is ABSENT --
        # a zero SUM is live state, and dropping it would unindex a key the cap is refusing
        # writes against, hiding the overflow for the rest of the window.
        refused[EX_PFX] += capped
        if capped:
            log.warning("flow cap bound for %s->%s: %d per-flow writes refused (>=1 flow omitted), "
                        "exfil bytes/connections are a FLOOR", src, dst, capped)
        if not flows and not capped:
            _prune_index(key); continue
        if not total:
            continue
        exo = _store.window_range("exo:" + key[len(EX_PFX):], floor)         # R06: observed exfil event times
        obs = (exo[0][0], exo[-1][0]) if exo else (None, None)
        # §49.4: per-flow bytes ARE the exf: field values, so distributed-exfil evidence
        # needs no second structure and cannot be inflated by interim records.
        material_flows = sum(1 for v in flows.values() if v >= cfg.get("exfil_material_flow_bytes", 100_000))
        is_e, escore = det.exfil_check(int(total), dst, threshold_bytes=cfg["exfil_bytes"])
        if is_e:
            breed, risks = _store.kv_get(f"ctx:{ten}:{src}|{dst}") or ["", []]
            sev = det.gated_severity(8, breed, risks, env_assets=_store.set_len(f"pv:{ten}:{dst}"))
            ent = json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "ip", "role": "dst", "value": dst},
                              {"type": "bytes", "value": int(total)}] + _refused_evidence(capped))
            c = _candidate("exfil", "exfil", sev, escore, ent, ten, obs=obs)
            if c:
                producer.send(CANDIDATE_TOPIC, c); log.info("EXFIL %s->%s bytes=%d", src, dst, int(total))
        else:
            # low-and-slow exfil: sustained trickle below the burst ceiling (T1030)
            is_ls, lscore = det.low_slow_exfil(int(total), conns, dst, threshold_bytes=cfg["exfil_bytes"],
                                               material_flows=material_flows)   # §49.4: require distributed flows
            if is_ls:
                ent = json.dumps([{"type": "ip", "role": "src", "value": src},
                                  {"type": "ip", "role": "dst", "value": dst},
                                  {"type": "bytes", "value": int(total)},
                                  {"type": "connections", "value": conns}] + _refused_evidence(capped))
                c = _candidate("low_slow_exfil", "exfil", 6, lscore, ent, ten, obs=obs)
                if c:
                    producer.send(CANDIDATE_TOPIC, c); log.info("LOW_SLOW_EXFIL %s->%s bytes=%d conns=%d", src, dst, int(total), conns)
    # cumulative long-connection (moved from _handle, plan 007; per-flow seconds, ADR 015)
    for key in _scoped_keys(LC_PFX, flow_parts):
        ten, entity = _key_parts(key); src, dst = _pair(entity)
        flows, capped = _store.fields_get(key)       # {flow identity: that flow's cumulative age}
        secs, nconn = sum(flows.values()), len(flows)
        refused[LC_PFX] += capped            # before the early exits, same reason as exf: above
        if capped:
            log.warning("flow cap bound for %s->%s: %d per-flow writes refused (>=1 flow omitted), "
                        "cumulative seconds/connections are a FLOOR", src, dst, capped)
        if not flows and not capped:
            _prune_index(key); continue
        if not secs:
            continue
        is_lc, lcs = det.longconn_cumulative_check(secs, nconn, dst,
                                                   threshold_secs=(cfg["longconn_cum_secs"] or CUM_LONGCONN_SECS),
                                                   min_conns=cfg["longconn_cum_min_conns"])
        if is_lc:
            breed, risks = _store.kv_get(f"ctx:{ten}:{src}|{dst}") or ["", []]
            sev = det.gated_severity(5, breed, risks, env_assets=_store.set_len(f"pv:{ten}:{dst}"))
            ent = json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "ip", "role": "dst", "value": dst},
                              {"type": "total_duration_s", "value": int(secs)},
                              {"type": "connections", "value": nconn}] + _refused_evidence(capped))
            c = _candidate("long_connection_cumulative", "c2", sev, lcs, ent, ten)
            if c:
                producer.send(CANDIDATE_TOPIC, c); log.info("LONG_CONN_CUM %s->%s total=%ds conns=%d", src, dst, int(secs), nconn)
    for pfx, n in refused.items():       # explicit telemetry: 0 is published too, so the
        metrics.set_flow_cap_refused(pfx, n)    # series exists before a pair ever hits the cap
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
        #   - exf:/lcf:/kd: are src-keyed -> co-partitioned -> partition-tagged AND
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
            # One field per FLOW holding that flow's LATEST cumulative value, blindly
            # overwritten (ADR 015). bytes_toserver and age are cumulative per flow and
            # records are redelivered on restart/rebalance, so accumulating them with
            # HINCRBYFLOAT counted the same bytes and seconds repeatedly and manufactured
            # exfil / long-connection findings on benign traffic. evaluate() derives
            # bytes = SUM(fields), connections = COUNT(fields), seconds = SUM(fields), so
            # a replayed or interim record is absorbed and _handle still issues no read.
            flow_identity = _flow_identity(e, f)
            _fset_add(EX_PFX, part, f"{EX_PFX}{part}:{ten}:{src}|{dst}", flow_identity, b2s)
            _win_add("exo:", part, f"exo:{part}:{ten}:{src}|{dst}", evt, 0)  # R06: observed event times for the exfil interval
            _fset_add(LC_PFX, part, f"{LC_PFX}{part}:{ten}:{src}|{dst}", flow_identity, age)
            # §49.4's per-flow bytes evidence is these same exf: fields, so the separate
            # exb: window is gone: as a ZSET of (event time, bytes) it counted each interim
            # record of one flow as another "material flow". Reading it off exf: also aligns
            # the evidence with the total it qualifies (one tumbling window, not two).
            _znx_add("kd:", part, f"kd:{part}:{ten}:{src}", dst, time.time())  # first-seen dst -> rare-dest in evaluate().
            # score = PROCESSING wall-clock, NOT event-time evt: the evaluate rare-dest cursor is wall-clock, so kd: scores
            # must share that clock domain -- else under consumer lag (event-time trails wall-time) the cursor excludes
            # newly-processed dsts and silently drops rare_destination. Processing order also matches the inline set-add
            # baseline, and one box means all replicas share the clock (so a rebalanced partition's scores stay comparable).
            dom = _i2d_get(f"i2d:{ten}:{dst}", now)                          # read-through cache: round-trip only on cold miss
            # IP-beacon: skip pure CDN / keepalive noise (a raw-IP beacon with no domain).
            if not det.beacon_noise_dst(dst):
                _win_add("bc:", part, f"bc:{part}:{ten}:{src}|{dst}", evt, b2s + b2c)
            # FQDN-beacon: a beacon to a resolved DOMAIN is signal even when the IP is a
            # CDN — domain-fronting C2 rides CDN IPs with an attacker SNI — so it accumulates
            # regardless of the CDN-IP noise gate (F06). The domain, not the IP, is the key.
            if dom:
                _win_add("bf:", part, f"bf:{part}:{ten}:{src}|{dom[0]}", evt, b2s + b2c)
                _sadd_add(f"fi:{ten}:{src}|{dom[0]}", dst)
        # inline stateless detectors (no Redis state): ndpi risk + age-based long connection
        if NDPI_MODE == "structured":                        # plan 008: honest per-category classification
            for fnd in ndpi_pol.ndpi_findings(n, src, dst, ten):
                c = _candidate("ndpi_risk", fnd["category"], fnd["severity"], fnd["confidence"],
                               json.dumps(fnd["entities"]), ten,
                               detector_version=ndpi_pol.DETECTOR_VERSION, identity=fnd["identity"])
                if c:
                    producer.send(CANDIDATE_TOPIC, c)
                    log.info("NDPI %s %s->%s sev=%s rules=%s", fnd["category"], src, dst, fnd["severity"], fnd["rules"])
        else:                                                # legacy substring behavior (default; unchanged)
            hit, matched = det.ndpi_risk_hit(risks)
            if not hit and det.ndpi_breed_hit(breed):
                hit, matched = True, [f"breed:{breed} proto:{n.get('proto', '?')}"]
            if hit:
                # `value` keeps the legacy sorted risk NAMES; `risks` carries the parsed
                # objects (native severity tier + risk_score) so the SIEM can filter on
                # severity and threshold on score.total instead of regexing a blob. The
                # finding contract leaves entity items unconstrained objects, so the
                # structure rides on the entity itself — nothing is re-stringified.
                # Risk is evidence to assess, not proof: severity stays nDPI's own tier.
                # Keyed by nothing: one flow can carry two risk IDs with the SAME name
                # and different scores, so the matching records are filtered in emission
                # order rather than collapsed into a name->record map, which kept the last.
                ent = json.dumps([{"type": "ip", "role": "src", "value": src},
                                  {"type": "ndpi_risk", "value": sorted(matched),
                                   "risks": det.sorted_risks(
                                       [r for r in risks if det.ndpi_risk_hit([r])[0]])}])
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
    ack = ndr_runtime.EvalAckEmitter(producer, "behavioral-detectors", GROUP_ID, EVAL_EVERY)  # §stage3
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
            ack.seen(len(records))
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
            # the exf:/lcf: per-flow fields just miss this batch's flows (a lone threshold-crossing flow here is missed for
            # the window -- offsets auto-commit at the next poll, no redelivery). metrics.dropped("flush") surfaces the
            # rate. A redelivery that DOES happen is now harmless: the fields are last-write-wins, not accumulators.
        if now - last_eval >= EVAL_EVERY:
            # evaluate only the entities on this replica's assigned partitions
            fp = ndr_runtime.assigned_partitions(consumer, "suricata.flow.v1")
            dp = ndr_runtime.assigned_partitions(consumer, "suricata.dns.v1")
            try:
                _t = time.time(); evaluate(producer, fp, dp); metrics.observe_evaluate(time.time() - _t)
                ack.beat(consumer, force=True)      # §stage3: post-evaluate ack (loop ran past input)
                producer.flush()
            except Exception as ex:             # a Redis blip must not crash-loop the replica (U4 review)
                metrics.dropped("evaluate"); log.warning("evaluate failed: %s", ex)
            last_eval = now
    consumer.close(); producer.close()


if __name__ == "__main__":
    main()
