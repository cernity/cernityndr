"""Per-flow idempotency of the exfil / cumulative-long-connection aggregates.

The defect these pin: `ex:` bytes + `lc:` seconds were HINCRBYFLOAT accumulators, so
(a) a redelivered record (crash / restart / rebalance, with auto-commit offsets) and
(b) a second CUMULATIVE interim record for the same flow both added the same bytes and
the same seconds again. Over-counted aggregates push BENIGN traffic over the exfil and
cumulative-long-conn thresholds, so a FALSE finding is manufactured and then delivered
once (the emit dedup collapses duplicates, it cannot undo an inflated total).

The fix keys the per-flow CUMULATIVE value by flow identity in a hash and derives the
aggregate at read time, so a replayed or interim record overwrites instead of adding.
These tests assert the aggregates (and the findings derived from them) are unchanged by
replay — NOT that delivery is exactly-once, which it still is not.
Single-process, no broker, assert-based (no pytest)."""
import json
import os
import time

os.environ["NDR_TENANT"] = "homelab"

import app
import store


class _P:
    def __init__(self):
        self.sent = []

    def send(self, topic, msg):
        self.sent.append(msg)

    def flush(self):
        pass


def _fresh():
    app._store = store.make_store("memory")
    app._rare_last_eval = 0.0
    app._pending.clear()
    app._i2d_cache.clear()
    return app._store


def _flow(src, dst, b2s=0, age=0.0, start=None, **ids):
    """A suricata.flow.v1-shaped record. `ids` carries the identity fields under test
    (flow_id / community_id / host / src_port ...)."""
    f = {"bytes_toserver": b2s, "bytes_toclient": 0, "age": age}
    if start is not None:
        f["start"] = start
    return dict({"event_type": "flow", "src_ip": src, "dest_ip": dst, "flow": f}, **ids)


def _feed(recs, part=0):
    for e in recs:
        app._handle(e, _P(), time.time(), part=part)
    app._flush_pending()                       # _handle is write-only (plan 007)


def _agg(prefix, src, dst, part=0, ten="homelab"):
    """(total, n_flows, capped, per_flow) as evaluate() derives them."""
    flows, capped = app._store.fields_get(f"{prefix}{part}:{ten}:{src}|{dst}")
    return sum(flows.values()), len(flows), capped, flows


def _dets(sent, detector):
    return [m for m in sent if m["detector_id"] == detector]


def _ent(msg, typ):
    return next((e["value"] for e in json.loads(msg["entities"]) if e.get("type") == typ), None)


SRC, DST = "10.0.0.11", "203.0.113.9"


# --- the headline test the spec demands: replay changes nothing -----------------
def test_replay_leaves_aggregates_unchanged():
    _fresh()
    recs = [_flow(SRC, DST, b2s=20_000_000, age=120.0, flow_id=1000 + i, host="sensor-a",
                  start=app._rfc3339(time.time() - 300 + i))
            for i in range(4)]
    _feed(recs)
    ex_first, lc_first = _agg(app.EX_PFX, SRC, DST)[:2], _agg(app.LC_PFX, SRC, DST)[:2]
    assert ex_first == (80_000_000, 4), ex_first          # 4 distinct flows, 20MB each
    assert lc_first == (480.0, 4), lc_first               # 4 x 120s
    _feed(recs)                                          # IDENTICAL records redelivered
    assert _agg(app.EX_PFX, SRC, DST)[:2] == ex_first, "exfil bytes/conns inflated by replay"
    assert _agg(app.LC_PFX, SRC, DST)[:2] == lc_first, "long-conn seconds/conns inflated by replay"
    _feed(recs); _feed(recs)                             # and again, still stable
    assert _agg(app.EX_PFX, SRC, DST)[:2] == ex_first
    assert _agg(app.LC_PFX, SRC, DST)[:2] == lc_first


def test_cumulative_interim_records_count_once():
    # flow.bytes_toserver / flow.age are CUMULATIVE per flow: three interim records for
    # ONE flow contribute the LATEST value (900), not their sum (1500), and one connection.
    _fresh()
    _feed([_flow(SRC, DST, b2s=b, age=a, flow_id=7, host="sensor-a")
           for b, a in ((100, 10.0), (500, 50.0), (900, 90.0))])
    assert _agg(app.EX_PFX, SRC, DST)[:2] == (900, 1), _agg(app.EX_PFX, SRC, DST)
    assert _agg(app.LC_PFX, SRC, DST)[:2] == (90.0, 1), _agg(app.LC_PFX, SRC, DST)


def test_counter_reset_is_the_current_truth_not_an_addition():
    # A record whose cumulative value is LOWER than the last seen for the same flow
    # (Suricata counter reset / re-use) is simply the current truth: no negative
    # contribution, no spurious addition.
    _fresh()
    _feed([_flow(SRC, DST, b2s=5_000, age=500.0, flow_id=9, host="sensor-a")])
    _feed([_flow(SRC, DST, b2s=10, age=1.0, flow_id=9, host="sensor-a")])
    total, n, _, _ = _agg(app.EX_PFX, SRC, DST)
    assert (total, n) == (10, 1), (total, n)
    secs, n2, _, _ = _agg(app.LC_PFX, SRC, DST)
    assert (secs, n2) == (1.0, 1) and secs >= 0, (secs, n2)


def test_distinct_flows_still_sum():
    # The fix must not UNDER-count: two genuinely distinct flows between the same pair
    # contribute both their bytes and a connection count of 2.
    _fresh()
    _feed([_flow(SRC, DST, b2s=1_000, age=30.0, flow_id=1, host="sensor-a"),
           _flow(SRC, DST, b2s=3_000, age=70.0, flow_id=2, host="sensor-a")])
    assert _agg(app.EX_PFX, SRC, DST)[:2] == (4_000, 2)
    assert _agg(app.LC_PFX, SRC, DST)[:2] == (100.0, 2)


# --- flow identity -------------------------------------------------------------
def test_flow_identity_sources_and_ordering():
    # flow_id (sensor-scoped) > community_id (+ flow start) > synthetic digest.
    f = {"bytes_toserver": 1, "age": 1.0, "start": "2026-10-14T10:00:00.000000+0000"}
    e = {"src_ip": SRC, "dest_ip": DST, "flow_id": 42, "host": "sensor-a",
         "community_id": "1:abc="}
    assert app._flow_identity(e, f) == "s|sensor-a|42"
    e2 = {"src_ip": SRC, "dest_ip": DST, "community_id": "1:abc="}   # no sensor, no flow_id
    assert app._flow_identity(e2, f) == "c||1:abc=|" + f["start"] + "|"
    e2b = dict(e2, flow_id=42)                                       # flow_id but no sensor: fallback
    assert app._flow_identity(e2b, f) == "c||1:abc=|" + f["start"] + "|42"
    e2c = dict(e2, host="sensor-a")               # sensor but no flow_id: still scoped by sensor
    assert app._flow_identity(e2c, f) == "c|sensor-a|1:abc=|" + f["start"] + "|"
    e3 = {"src_ip": SRC, "dest_ip": DST, "src_port": 44321, "dest_port": 443, "proto": "TCP"}
    syn = app._flow_identity(e3, f)
    assert syn.startswith("x|") and len(syn) > 2                     # derived, never fabricated
    assert app._flow_identity(e3, f) == syn                # stable for the same record


def test_flow_id_without_a_sensor_does_not_claim_an_identity():
    # flow_id is Suricata-INSTANCE-local, so without a sensor it is NOT an identity: two
    # genuinely distinct flows that happen to share flow_id 5 must stay distinct (merging
    # them would UNDER-count and blind the detector). The fallback does that job.
    f0 = {"bytes_toserver": 1, "age": 1.0, "start": "2026-10-14T10:00:00.000000+0000"}
    f1 = {"bytes_toserver": 1, "age": 1.0, "start": "2026-10-14T10:05:00.000000+0000"}
    a = app._flow_identity({"flow_id": 5, "community_id": "1:aaa="}, f0)
    b = app._flow_identity({"flow_id": 5, "community_id": "1:bbb="}, f0)
    assert a != b and not a.startswith("s|") and not b.startswith("s|"), (a, b)
    # same community_id, different flow starts: still distinct
    assert app._flow_identity({"flow_id": 5, "community_id": "1:aaa="}, f1) != a
    # no sensor, no community_id -> synthetic digest, and distinct per 5-tuple/start
    c = app._flow_identity({"flow_id": 5, "src_port": 1111, "dest_port": 443}, f0)
    d = app._flow_identity({"flow_id": 5, "src_port": 2222, "dest_port": 443}, f0)
    assert c.startswith("x|") and c != d
    # and the aggregate agrees: two sensor-less flows sharing flow_id both count
    _fresh()
    recs = [_flow(SRC, DST, b2s=2_000, age=30.0, flow_id=5, community_id=f"1:{x}=") for x in ("aaa", "bbb")]
    _feed(recs)
    assert _agg(app.EX_PFX, SRC, DST)[:2] == (4_000, 2), _agg(app.EX_PFX, SRC, DST)
    _feed(recs)                                              # and replay still changes nothing
    assert _agg(app.EX_PFX, SRC, DST)[:2] == (4_000, 2)


def test_flow_identity_never_collapses_distinct_flows():
    f0 = {"bytes_toserver": 1, "age": 1.0, "start": "2026-10-14T10:00:00.000000+0000"}
    f1 = {"bytes_toserver": 1, "age": 1.0, "start": "2026-10-14T10:05:00.000000+0000"}
    # same instance-local flow_id on two DIFFERENT sensors: distinct identities
    a = app._flow_identity({"flow_id": 5, "host": "sensor-a"}, f0)
    b = app._flow_identity({"flow_id": 5, "host": "sensor-b"}, f0)
    assert a != b
    # same 5-tuple reconnecting -> same community_id, different flow start: distinct
    c0 = app._flow_identity({"community_id": "1:same="}, f0)
    c1 = app._flow_identity({"community_id": "1:same="}, f1)
    assert c0 != c1
    # ... but interim records of ONE flow share flow.start -> one identity
    assert app._flow_identity({"community_id": "1:same="}, dict(f0, bytes_toserver=999)) == c0
    # synthetic: different ports, and the same ports at a different start, stay distinct
    base = {"src_port": 1234, "dest_port": 443, "proto": "TCP"}
    assert app._flow_identity(base, f0) != app._flow_identity(dict(base, src_port=1235), f0)
    assert app._flow_identity(base, f0) != app._flow_identity(base, f1)


def test_community_id_fallback_is_sensor_scoped():
    # Two sensors taping either side of a hop see the SAME 5-tuple, so they mint the same
    # community_id AND the same flow start. Without the sensor in the fallback those two
    # records collapse to one field and the second OVERWRITES the first -- an UNDER-count,
    # the dangerous direction (review fix).
    f = {"bytes_toserver": 1, "age": 1.0, "start": "2026-10-14T10:00:00.000000+0000"}
    a = app._flow_identity({"community_id": "1:same=", "host": "a"}, f)
    b = app._flow_identity({"community_id": "1:same=", "host": "b"}, f)
    assert a != b, (a, b)
    assert a != app._flow_identity({"community_id": "1:same="}, f)   # sensor-less: a third
    _fresh()
    recs = [_flow(SRC, DST, b2s=2_000, age=30.0, community_id="1:same=", host=h,
                  start=f["start"]) for h in ("a", "b")]
    _feed(recs)
    assert _agg(app.EX_PFX, SRC, DST)[:2] == (4_000, 2), _agg(app.EX_PFX, SRC, DST)
    assert _agg(app.LC_PFX, SRC, DST)[:2] == (60.0, 2)
    _feed(recs)                                            # and replay still changes nothing
    assert _agg(app.EX_PFX, SRC, DST)[:2] == (4_000, 2)
    assert _agg(app.LC_PFX, SRC, DST)[:2] == (60.0, 2)


def test_identity_free_records_are_handled_per_flow():
    # Records with neither flow_id nor community_id still aggregate (synthetic identity):
    # two ports -> two flows; the same port replayed -> still one.
    _fresh()
    recs = [_flow(SRC, DST, b2s=2_000, age=40.0, src_port=p, dest_port=443, proto="TCP",
                  start="2026-10-14T10:00:00.000000+0000") for p in (5001, 5002)]
    _feed(recs)
    assert _agg(app.EX_PFX, SRC, DST)[:2] == (4_000, 2)
    _feed(recs)
    assert _agg(app.EX_PFX, SRC, DST)[:2] == (4_000, 2), "synthetic identity not replay-stable"


# --- the false-finding regression, end to end ----------------------------------
def test_benign_transfer_stays_under_exfil_threshold_after_replay():
    # 3 x 16MB = 48MB, just under the 50MB exfil threshold. Pre-fix, a replay doubled it
    # to 96MB and MANUFACTURED an exfil finding on benign traffic.
    _fresh()
    recs = [_flow(SRC, DST, b2s=16_000_000, age=20.0, flow_id=200 + i, host="sensor-a",
                  start=app._rfc3339(time.time() - 200 + i)) for i in range(3)]
    _feed(recs)
    p = _P(); app.evaluate(p, flow_parts={0}, dns_parts=set())
    assert not _dets(p.sent, "exfil"), "benign transfer already over threshold"
    _feed(recs)                                       # full replay of the same batch
    p2 = _P(); app.evaluate(p2, flow_parts={0}, dns_parts=set())
    assert not _dets(p2.sent, "exfil"), "replay manufactured a false exfil finding"
    assert not _dets(p2.sent, "low_slow_exfil")
    assert _agg(app.EX_PFX, SRC, DST)[:2] == (48_000_000, 3)


def test_benign_longconn_stays_under_cumulative_threshold_after_replay():
    # 4 connections x 70s = 280s, under the 300s cumulative threshold (0.5 * WINDOW).
    # Pre-fix, a replay doubled it to 560s over 8 "connections" and fired.
    _fresh()
    recs = [_flow(SRC, DST, b2s=100, age=70.0, flow_id=300 + i, host="sensor-a") for i in range(4)]
    _feed(recs)
    p = _P(); app.evaluate(p, flow_parts={0}, dns_parts=set())
    assert not _dets(p.sent, "long_connection_cumulative"), "already over threshold"
    _feed(recs)
    p2 = _P(); app.evaluate(p2, flow_parts={0}, dns_parts=set())
    assert not _dets(p2.sent, "long_connection_cumulative"), "replay manufactured a false long-conn finding"
    assert _agg(app.LC_PFX, SRC, DST)[:2] == (280.0, 4)


def test_real_exfil_still_fires_from_derived_aggregate():
    # The fix must not blind the detector: distinct flows summing over the threshold fire.
    _fresh()
    _feed([_flow(SRC, DST, b2s=30_000_000, age=10.0, flow_id=400 + i, host="sensor-a",
                 start=app._rfc3339(time.time() - 100 + i)) for i in range(3)])   # 90MB
    p = _P(); app.evaluate(p, flow_parts={0}, dns_parts=set())
    ex = _dets(p.sent, "exfil")
    assert len(ex) == 1 and _ent(ex[0], "bytes") == 90_000_000, [m["entities"] for m in ex]


def test_real_cumulative_longconn_still_fires():
    _fresh()
    _feed([_flow(SRC, DST, b2s=100, age=100.0, flow_id=500 + i, host="sensor-a") for i in range(5)])
    p = _P(); app.evaluate(p, flow_parts={0}, dns_parts=set())
    lc = _dets(p.sent, "long_connection_cumulative")
    assert len(lc) == 1, [m["entities"] for m in lc]
    assert _ent(lc[0], "total_duration_s") == 500 and _ent(lc[0], "connections") == 5


# --- low_slow_exfil per-flow evidence ------------------------------------------
def test_material_flows_evidence_not_inflated_by_interim_or_replay():
    # low_slow_exfil requires >= 5 flows each carrying material bytes. Pre-fix the
    # per-flow evidence came from a ZSET whose members were (event time, bytes), so two
    # interim records for ONE flow counted as two material flows and a replay doubled
    # them again. 2 material flows must stay 2 however often they are re-delivered.
    _fresh()
    recs = []
    for i in range(2):                                    # two flows, three interim records each
        for b in (200_000, 400_000, 600_000):
            recs.append(_flow(SRC, DST, b2s=b, age=5.0, flow_id=600 + i, host="sensor-a"))
    _feed(recs); _feed(recs)
    total, n, _, flows = _agg(app.EX_PFX, SRC, DST)
    material = sum(1 for v in flows.values() if v >= 100_000)
    assert (total, n, material) == (1_200_000, 2, 2), (total, n, material)
    p = _P(); app.evaluate(p, flow_parts={0}, dns_parts=set())
    assert not _dets(p.sent, "low_slow_exfil"), "inflated per-flow evidence fired low-and-slow"


def test_low_slow_exfil_still_fires_on_genuinely_distributed_flows():
    _fresh()
    _feed([_flow(SRC, DST, b2s=1_000_000, age=5.0, flow_id=700 + i, host="sensor-a",
                 start=app._rfc3339(time.time() - 100 + i)) for i in range(12)])   # 12MB over 12 flows
    p = _P(); app.evaluate(p, flow_parts={0}, dns_parts=set())
    ls = _dets(p.sent, "low_slow_exfil")
    assert len(ls) == 1 and _ent(ls[0], "connections") == 12, [m["entities"] for m in ls]


# --- cardinality cap -----------------------------------------------------------
def test_flow_cap_bounds_cardinality_and_reports_refused_writes():
    _fresh()
    saved = app.FLOW_CAP
    app.FLOW_CAP = 3                                    # small cap so the test is cheap
    try:
        _feed([_flow(SRC, DST, b2s=20_000_000, age=200.0, flow_id=800 + i, host="sensor-a")
               for i in range(5)])
        total, n, refused, _ = _agg(app.EX_PFX, SRC, DST)
        assert n == 3, f"cap not enforced: {n} fields"
        assert refused == 2, f"refusal not recorded: {refused}"   # explicit, not silent
        assert total == 60_000_000                                # a FLOOR, not the true 100MB
        _feed([_flow(SRC, DST, b2s=20_000_000, age=200.0, flow_id=900 + i, host="sensor-a")
               for i in range(3)])                                # beyond the cap: still bounded
        _, n2, refused2, _ = _agg(app.EX_PFX, SRC, DST)
        assert n2 == 3 and refused2 == 5, (n2, refused2)
        p = _P(); app.evaluate(p, flow_parts={0}, dns_parts=set())
        ex = _dets(p.sent, "exfil")
        assert len(ex) == 1 and _ent(ex[0], "flow_updates_refused_at_cap") == 5, [m["entities"] for m in ex]
    finally:
        app.FLOW_CAP = saved


def test_cap_refusals_count_writes_and_the_aggregate_stays_replay_stable():
    """What the cap counter means, asserted rather than implied: it counts REFUSED WRITES,
    so replaying a refused record raises it again (the write path takes no read and cannot
    recognise an identity it already refused). The derived AGGREGATE is what must not move
    under replay, and it doesn't -- so a finding may only claim '>=1 flow omitted', which is
    why the evidence is named flow_updates_refused_at_cap and not a flow count."""
    _fresh()
    saved = app.FLOW_CAP
    app.FLOW_CAP = 1
    try:
        admitted = [_flow(SRC, DST, b2s=1_000, age=10.0, flow_id=1, host="sensor-a")]
        omitted = [_flow(SRC, DST, b2s=9_000, age=90.0, flow_id=2, host="sensor-a")]
        _feed(admitted); _feed(omitted)
        assert _agg(app.EX_PFX, SRC, DST)[:3] == (1_000, 1, 1)
        _feed(omitted); _feed(omitted)                       # the SAME omitted flow, twice more
        total, n, refused, _ = _agg(app.EX_PFX, SRC, DST)
        assert (total, n) == (1_000, 1), "aggregate moved under replay at the cap"
        assert refused == 3, refused                         # 3 refused WRITES, 1 omitted flow
    finally:
        app.FLOW_CAP = saved


def test_cap_overflow_is_reported_even_when_the_admitted_flow_totals_zero():
    """A zero-byte / zero-age flow can be the one the cap ADMITS, after which every real
    flow is refused. The aggregate is then 0 and there is no finding to attach evidence to,
    so the gauge + log are the ONLY report of the loss -- they must still fire, and the key
    must stay indexed so the next cycle sees it (review fix)."""
    _fresh()
    saved = app.FLOW_CAP
    warns, gauges = [], []
    real_warn, real_gauge = app.log.warning, app.metrics.set_flow_cap_refused
    app.FLOW_CAP = 1
    app.log.warning = lambda m, *a: warns.append(m % a if a else m)
    app.metrics.set_flow_cap_refused = lambda pfx, n: gauges.append((pfx, n))
    try:
        _feed([_flow(SRC, DST, b2s=0, age=0.0, flow_id=1, host="sensor-a")])    # admitted, zero
        _feed([_flow(SRC, DST, b2s=40_000_000, age=400.0, flow_id=2, host="sensor-a")])  # refused
        assert _agg(app.EX_PFX, SRC, DST)[:3] == (0, 1, 1)
        assert _agg(app.LC_PFX, SRC, DST)[:3] == (0.0, 1, 1)
        p = _P(); app.evaluate(p, flow_parts={0}, dns_parts=set())
        assert dict(gauges) == {app.EX_PFX: 1, app.LC_PFX: 1}, gauges       # not silently 0
        assert sum("flow cap bound" in w for w in warns) == 2, warns        # exf: and lcf:
        for pfx in (app.EX_PFX, app.LC_PFX):                               # still enumerable
            assert app._scoped_keys(pfx, {0}) == [f"{pfx}0:homelab:{SRC}|{DST}"], pfx
    finally:
        app.FLOW_CAP = saved
        app.log.warning, app.metrics.set_flow_cap_refused = real_warn, real_gauge


def test_absent_state_is_pruned_from_its_index():
    # The flip side: a key whose state has EXPIRED (no fields, no refusals) is dropped from
    # the partition index, so the index does not grow without bound.
    _fresh()
    _feed([_flow(SRC, DST, b2s=1_000, age=10.0, flow_id=1, host="sensor-a")])
    key = f"{app.EX_PFX}0:homelab:{SRC}|{DST}"
    assert app._scoped_keys(app.EX_PFX, {0}) == [key]
    app._store.counter_clear(key)                           # window expiry, in effect
    app.evaluate(_P(), flow_parts={0}, dns_parts=set())
    assert app._scoped_keys(app.EX_PFX, {0}) == []


def test_uncapped_aggregate_carries_no_cap_evidence():
    _fresh()
    _feed([_flow(SRC, DST, b2s=30_000_000, age=10.0, flow_id=1_100 + i, host="sensor-a")
           for i in range(2)])
    p = _P(); app.evaluate(p, flow_parts={0}, dns_parts=set())
    ex = _dets(p.sent, "exfil")
    assert len(ex) == 1 and _ent(ex[0], "flow_updates_refused_at_cap") is None


# --- rolling upgrade: the pre-upgrade counter schema must not be read as flows ---
def test_legacy_counter_state_is_not_read_as_flow_identities():
    """The hash shape is unchanged but the SCHEMA is not: a field used to be a counter name
    (ex: b/c, lc: s/n) and is now a flow identity. Redis state outlives the deploy, so if the
    new code read the old keys it would see `b`=30MB as a 'flow' and `c`=1 as another, and
    re-manufacture the finding this fix removes. The new state lives under its own prefixes
    (exf:/lcf:), so the two schemas never meet; the old keys and index entries just expire."""
    _fresh()
    ttl = app.WINDOW
    for key, fields in ((f"ex:0:homelab:{SRC}|{DST}", {"b": 30_000_000, "c": 1}),
                        (f"lc:0:homelab:{SRC}|{DST}", {"s": 250.0, "n": 3})):
        for fld, val in fields.items():
            app._store.counter_add(key, fld, val, ttl)                 # pre-upgrade accumulators
        app._store.set_add(app._index_key(key.split(":", 1)[0] + ":", 0), key, ttl)   # and its index entry
    # post-upgrade traffic: one benign flow, well under both thresholds on its own
    rec = [_flow(SRC, DST, b2s=30_000_000, age=70.0, flow_id=1, host="sensor-a",
                 start=app._rfc3339(time.time() - 100))]
    _feed(rec)
    assert _agg(app.EX_PFX, SRC, DST)[:2] == (30_000_000, 1), "legacy counter fields leaked into the aggregate"
    assert _agg(app.LC_PFX, SRC, DST)[:2] == (70.0, 1)
    p = _P(); app.evaluate(p, flow_parts={0}, dns_parts=set())
    assert not _dets(p.sent, "exfil"), "legacy b/c counters read as flows: false exfil"
    assert not _dets(p.sent, "long_connection_cumulative"), "legacy s/n counters read as flows"
    _feed(rec)                                                        # replay across the upgrade
    p2 = _P(); app.evaluate(p2, flow_parts={0}, dns_parts=set())
    assert not _dets(p2.sent, "exfil") and not _dets(p2.sent, "low_slow_exfil")
    assert not _dets(p2.sent, "long_connection_cumulative")
    assert _agg(app.EX_PFX, SRC, DST)[:2] == (30_000_000, 1)
    # the legacy keys are neither read nor rewritten -- they age out on their own TTL
    assert app._store.counter_get(f"ex:0:homelab:{SRC}|{DST}", "b") == 30_000_000
    assert app._scoped_keys(app.EX_PFX, {0}) == [f"{app.EX_PFX}0:homelab:{SRC}|{DST}"]   # legacy key never enumerated
    assert app._scoped_keys(app.LC_PFX, {0}) == [f"{app.LC_PFX}0:homelab:{SRC}|{DST}"]


# --- the already-idempotent writes stay untouched -------------------------------
def test_idempotent_writes_unchanged_by_replay():
    # exo:/bc:/bf:/kd:/pv:/fi:/ctx: are out of this fix's scope -- their member or key is
    # deterministic, so a redelivered record re-writes the same thing. Replay a record and
    # assert each is behaviorally unchanged. Window entries are compared as a SET: a Redis
    # ZSET collapses the identical member, while InMemoryStore appends to a list (a
    # pre-existing backend divergence this task does not touch), so the DISTINCT entries
    # are the shared contract.
    _fresh()
    dom = "evil.example.com"
    app._store.kv_set(f"i2d:homelab:{DST}", [dom, time.time()], 600)
    rec = _flow(SRC, DST, b2s=5_000, age=10.0, flow_id=1, host="sensor-a",
                start=app._rfc3339(time.time() - 60))
    _feed([rec])
    win = lambda k: sorted(set(app._store.window_range(k, 0)))
    snap = {
        "exo": win(f"exo:0:homelab:{SRC}|{DST}"),
        "bc": win(f"bc:0:homelab:{SRC}|{DST}"),
        "bf": win(f"bf:0:homelab:{SRC}|{dom}"),
        "kd": app._store.zset_since(f"kd:0:homelab:{SRC}", 0.0),
        "pv": app._store.set_members(f"pv:homelab:{DST}"),
        "fi": app._store.set_members(f"fi:homelab:{SRC}|{dom}"),
        "ctx": app._store.kv_get(f"ctx:homelab:{SRC}|{DST}"),
    }
    assert all(snap.values()), snap                     # every one actually written
    _feed([rec])
    assert snap["exo"] == win(f"exo:0:homelab:{SRC}|{DST}")
    assert snap["bc"] == win(f"bc:0:homelab:{SRC}|{DST}")
    assert snap["bf"] == win(f"bf:0:homelab:{SRC}|{dom}")
    assert snap["kd"] == app._store.zset_since(f"kd:0:homelab:{SRC}", 0.0)
    assert snap["pv"] == app._store.set_members(f"pv:homelab:{DST}")
    assert snap["fi"] == app._store.set_members(f"fi:homelab:{SRC}|{dom}")
    assert snap["ctx"] == app._store.kv_get(f"ctx:homelab:{SRC}|{DST}")
    assert not app._store.keys_matching("exb:"), "exb: is gone; ex: fields carry per-flow bytes"


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f()
            print("ok ", _n)
    print("all flow-idempotency tests passed")
