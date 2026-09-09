"""Partition-scoped evaluate tests (plan 003 U4): each replica evaluates only the
entities on its assigned partitions, the union across replicas covers every entity
exactly once, and key parsing survives the new partition segment (incl. IPv6).
Single-process, no broker."""
import json
import os
import time
from datetime import datetime, timezone

# Pin the tenant this test constructs its keys with, so the test is independent
# of the deployment-neutral default tenant.
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
    app._rare_last_eval = 0.0                              # rare-dest emits dsts first-seen since last eval (plan 007)
    return app._store


def _plant_beacon(st, part, ten, src, dst):
    # ~12 evenly spaced, equal-size flows across the window -> a clean beacon.
    # Mirror _handle: index the window key so the default index-enumeration path
    # sees it (plan 004).
    now = time.time()
    key = f"bc:{part}:{ten}:{src}|{dst}"
    for i in range(12):
        st.window_add(key, now - 600 + i * 45, 500, 600)
    st.set_add(app._index_key("bc:", part), key, 600)


def _src_values(sent, detector="beacon"):
    return [e["value"] for m in sent if m["detector_id"] == detector
            for e in json.loads(m["entities"]) if e.get("role") == "src"]


def test_key_parts_parses_partition_and_ipv6():
    ten, ent = app._key_parts("bc:7:homelab:2001:db8::1|2001:db8::2")
    assert ten == "homelab"
    assert ent == "2001:db8::1|2001:db8::2"          # IPv6 colons preserved


def test_scoped_keys_only_assigned_partitions():
    st = _fresh()
    st.window_add("bc:0:homelab:a|b", time.time(), 1, 600)
    st.set_add(app._index_key("bc:", 0), "bc:0:homelab:a|b", 600)
    st.window_add("bc:5:homelab:c|d", time.time(), 1, 600)
    st.set_add(app._index_key("bc:", 5), "bc:5:homelab:c|d", 600)
    assert set(app._scoped_keys("bc:", {0})) == {"bc:0:homelab:a|b"}
    assert set(app._scoped_keys("bc:", {0, 5})) == {"bc:0:homelab:a|b", "bc:5:homelab:c|d"}
    assert set(app._scoped_keys("bc:", None)) == {"bc:0:homelab:a|b", "bc:5:homelab:c|d"}  # unscoped


def test_evaluate_scopes_to_assignment():
    _fresh()
    _plant_beacon(app._store, 0, "homelab", "10.0.0.1", "203.0.113.9")
    _plant_beacon(app._store, 5, "homelab", "10.0.0.2", "203.0.113.9")
    p = _P()
    app.evaluate(p, flow_parts={0}, dns_parts=set())          # replica owns partition 0
    srcs = _src_values(p.sent)
    assert "10.0.0.1" in srcs and "10.0.0.2" not in srcs
    p2 = _P()
    app.evaluate(p2, flow_parts={5}, dns_parts=set())         # replica owns partition 5
    srcs2 = _src_values(p2.sent)
    assert "10.0.0.2" in srcs2 and "10.0.0.1" not in srcs2


def test_union_covers_every_entity_exactly_once():
    _fresh()
    _plant_beacon(app._store, 0, "homelab", "10.0.0.1", "203.0.113.9")
    _plant_beacon(app._store, 5, "homelab", "10.0.0.2", "203.0.113.9")
    seen = []
    for parts in ({0}, {5}):                                  # two disjoint replicas
        p = _P()
        app.evaluate(p, flow_parts=parts, dns_parts=set())
        seen += _src_values(p.sent)
    assert sorted(seen) == ["10.0.0.1", "10.0.0.2"]           # each exactly once, none missed


def test_moved_state_partition_tagged_aux_not():
    """Plan 007: ex/lc/kd moved to evaluate() so they are now partition-tagged (and
    indexed, next test), enumerated per assignment. ctx/pv stay un-tagged -- read by
    exact key / genuinely cross-partition; tagging them silently breaks those reads.
    _handle is write-only now, so flush before inspecting the store."""
    _fresh()
    e = {"event_type": "flow", "src_ip": "10.0.0.1", "dest_ip": "203.0.113.9",
         "flow": {"bytes_toserver": 100, "bytes_toclient": 100, "age": 1}}
    app._handle(e, _P(), time.time(), part=7)          # partition 7
    app._flush_pending()                                # buffered writes land here (plan 007)
    for pfx in ("ex:", "lc:", "kd:"):                   # moved prefixes carry the partition segment
        ks = app._store.keys_matching(pfx)
        assert ks, f"expected {pfx} written for an external flow"
        for k in ks:
            assert app._part_of(k) == "7", f"{k} must be partition-tagged"
    un = set()                                          # exact-key aux stays un-tagged
    for prefix in ("pv:", "ctx:"):
        un |= set(app._store.keys_matching(prefix))
    assert un, "expected pv/ctx written for an external flow"
    for k in un:
        assert app._part_of(k) != "7", f"aux key {k} looks partition-tagged (must not be)"


def test_index_written_for_scanned_not_aux():
    """Plan 004/007: bc/bf/dn AND the moved ex/lc/kd writes populate their partition
    index; the exact-key aux keys (pv/ctx/fi) do not."""
    _fresh()
    e = {"event_type": "flow", "src_ip": "10.0.0.1", "dest_ip": "203.0.113.9",
         "flow": {"bytes_toserver": 100, "bytes_toclient": 100, "age": 1}}
    app._handle(e, _P(), time.time(), part=3)
    app._flush_pending()                                  # window writes are buffered now (plan 006/007)
    assert "bc:3:homelab:10.0.0.1|203.0.113.9" in app._store.set_members(app._index_key("bc:", 3))
    for pfx in ("ex:", "lc:", "kd:"):                        # moved prefixes ARE indexed (plan 007)
        assert app._store.set_members(app._index_key(pfx, 3)), f"moved {pfx} not indexed"
    for pfx in ("pv:", "ctx:", "fi:"):                       # exact-key aux never indexed
        assert app._store.set_members(app._index_key(pfx, 3)) == [], f"aux {pfx} indexed"


def _plant_flow(part, ten, src, dst, b2s=0, age=0.0):
    e = {"event_type": "flow", "src_ip": src, "dest_ip": dst,
         "flow": {"bytes_toserver": b2s, "bytes_toclient": 0, "age": age}}
    app._handle(e, _P(), time.time(), part=part)


def test_exfil_fires_from_evaluate():
    """Plan 007 U4: exfil moved from inline _handle to evaluate; a cumulative ex:
    byte total over threshold emits exactly once (dedup) from the scoped evaluate."""
    _fresh()
    _plant_flow(0, "homelab", "10.0.0.1", "203.0.113.9", b2s=100_000_000)
    _plant_flow(0, "homelab", "10.0.0.1", "203.0.113.9", b2s=100_000_000)   # 200MB total
    p = _P(); app.evaluate(p, flow_parts={0}, dns_parts=set())
    exfils = [m for m in p.sent if m["detector_id"] == "exfil"]
    assert len(exfils) == 1, exfils
    assert any(e.get("type") == "bytes" for e in json.loads(exfils[0]["entities"]))


def test_rare_dest_cold_burst_matches_inline():
    """Plan 007 U5 (the review's crux case): a src contacting many NEW external dsts
    in one window -- baseline accrued WITHIN the window -- must emit for every dst
    whose first-seen rank >= 15, exactly as the inline set_len>=15-at-arrival path.
    20 new dsts -> ranks 15..19 cross -> 5 emits."""
    _fresh()
    for i in range(20):
        _plant_flow(0, "homelab", "10.0.0.7", f"203.0.113.{i}", age=1.0)
    p = _P(); app.evaluate(p, flow_parts={0}, dns_parts=set())
    rare = [m for m in p.sent if m["detector_id"] == "rare_destination"]
    assert len(rare) == 5, [m["entities"] for m in rare]


def test_rare_dest_emits_once_across_windows_not_per_cycle():
    """Plan 007 (review): rare-dest emits once per (src,new-dst) matching the inline
    path -- NOT re-fired every evaluate cycle for a still-active fan-out host. A second
    evaluate with no new dsts emits nothing; a newly-arrived dst then emits just once."""
    _fresh()
    for i in range(20):
        _plant_flow(0, "homelab", "10.0.0.7", f"203.0.113.{i}", age=1.0)
    p1 = _P(); app.evaluate(p1, flow_parts={0}, dns_parts=set())
    assert len([m for m in p1.sent if m["detector_id"] == "rare_destination"]) == 5   # ranks 15-19
    p2 = _P(); app.evaluate(p2, flow_parts={0}, dns_parts=set())                       # no new dsts
    assert not [m for m in p2.sent if m["detector_id"] == "rare_destination"]          # NOT re-fired
    _plant_flow(0, "homelab", "10.0.0.7", "203.0.113.99")                              # one new dst (rank 20)
    p3 = _P(); app.evaluate(p3, flow_parts={0}, dns_parts=set())
    rare3 = [m for m in p3.sent if m["detector_id"] == "rare_destination"]
    assert len(rare3) == 1 and "203.0.113.99" in rare3[0]["entities"]                  # only the new one


def test_rare_dest_uses_processing_clock_not_event_time():
    """Plan 007 (final review): kd: scores are PROCESSING wall-clock, NOT the flow's event
    timestamp. Under consumer lag a flow's event-time trails wall-time; if kd: were scored by
    event-time it would fall behind the wall-clock 'since' cursor and silently drop rare_dest.
    Advance the cursor, then feed 20 dsts whose EVENT time is an hour old -- they must still emit."""
    _fresh()
    app.evaluate(_P(), flow_parts={0}, dns_parts=set())                # advances _rare_last_eval to ~now
    assert app._rare_last_eval > 0
    old_iso = datetime.fromtimestamp(time.time() - 3600, tz=timezone.utc).isoformat()   # event-time 1h ago
    for i in range(20):
        e = {"event_type": "flow", "src_ip": "10.0.0.44", "dest_ip": f"203.0.113.{i}",
             "timestamp": old_iso, "flow": {"bytes_toserver": 0, "bytes_toclient": 0, "age": 1.0}}
        app._handle(e, _P(), time.time(), part=0)
    p = _P(); app.evaluate(p, flow_parts={0}, dns_parts=set())
    rare = [m for m in p.sent if m["detector_id"] == "rare_destination"]
    assert len(rare) == 5, [m["entities"] for m in rare]               # ranks 15-19 emit despite stale event-time


def test_rare_dest_below_baseline_silent():
    """Fewer than 15 known dsts -> no rare-destination emit (cold-start guard)."""
    _fresh()
    for i in range(10):
        _plant_flow(0, "homelab", "10.0.0.8", f"203.0.113.{i}", age=1.0)
    p = _P(); app.evaluate(p, flow_parts={0}, dns_parts=set())
    assert not [m for m in p.sent if m["detector_id"] == "rare_destination"]


def test_i2d_negative_cache_short_ttl():
    """Plan 007 review fix: a cache MISS is held only I2D_NEG_TTL (short), so a domain
    resolved on ANOTHER replica becomes visible within seconds -- not suppressed for a
    full WINDOW. A positive hit stays cached for the long I2D_TTL."""
    _fresh(); app._i2d_cache.clear()
    k = "i2d:homelab:203.0.113.9"; t0 = time.time()
    assert app._i2d_get(k, t0) is None                              # cold miss -> None (cached short)
    app._store.kv_set(k, ["evil.com", t0], 600)                    # domain resolves (another replica wrote Redis)
    assert app._i2d_get(k, t0 + 1) is None                         # still within neg-ttl: cached None
    assert app._i2d_get(k, t0 + app.I2D_NEG_TTL + 1) == ["evil.com", t0]   # after neg-ttl: re-reads Redis
    assert app._i2d_get(k, t0 + app.I2D_NEG_TTL + 2)[0] == "evil.com"      # positive now cached (long ttl)


def test_index_scan_equivalence_and_fallback():
    """Plan 004 U3: evaluate via the index (default) and via scan (NDR_ENUM_INDEX=0)
    produce identical findings on the same planted state."""
    # index default (planted state includes the index via _plant_beacon)
    _fresh()
    _plant_beacon(app._store, 0, "homelab", "10.0.0.1", "203.0.113.9")
    p1 = _P(); app.evaluate(p1, flow_parts={0}, dns_parts=set())
    idx_srcs = _src_values(p1.sent)
    assert app.ENUM_INDEX is True and "10.0.0.1" in idx_srcs
    # scan fallback: same planted windows, enumeration via scan
    saved = app.ENUM_INDEX
    app.ENUM_INDEX = False
    try:
        _fresh()
        _plant_beacon(app._store, 0, "homelab", "10.0.0.1", "203.0.113.9")
        p2 = _P(); app.evaluate(p2, flow_parts={0}, dns_parts=set())
        scan_srcs = _src_values(p2.sent)
    finally:
        app.ENUM_INDEX = saved
    assert scan_srcs == idx_srcs                       # behavior-preserving


def test_index_self_cleans_expired_member():
    """Plan 004 U3: an index member whose window is empty is SREM'd during evaluate;
    a live member is retained. No extra store round-trip beyond window_range."""
    _fresh()
    st = app._store
    live = "bc:2:homelab:10.0.0.5|203.0.113.9"
    stale = "bc:2:homelab:10.0.0.6|203.0.113.9"
    for i in range(12):
        st.window_add(live, time.time() - 600 + i * 45, 500, 600)
    st.set_add(app._index_key("bc:", 2), live, 600)
    st.set_add(app._index_key("bc:", 2), stale, 600)   # stale: indexed but no live window
    app.evaluate(_P(), flow_parts={2}, dns_parts=set())
    members = set(st.set_members(app._index_key("bc:", 2)))
    assert stale not in members and live in members    # expired dropped, live kept


def test_index_warmup_then_appears():
    """Plan 004 U3: an empty index yields no candidates (bounded warm-up); once a
    write lands (via _plant_beacon which indexes), the entity is enumerated."""
    _fresh()
    assert app._scoped_keys("bc:", {4}) == []          # empty index -> nothing
    _plant_beacon(app._store, 4, "homelab", "10.0.0.9", "203.0.113.9")
    assert "bc:4:homelab:10.0.0.9|203.0.113.9" in app._scoped_keys("bc:", {4})


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f()
            print("ok", _n)
    print("all partition-scope tests passed")
