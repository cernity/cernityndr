"""U17 + U7 asset resolution tests (pure logic + fake ClickHouse + HTTP shell).

Covers the U7 reviewer scenarios explicitly:
  * canonical, durable observation identity — obs_id parity with the normalizer
    contract, exercised through observe();
  * time-bounded identity bindings (§13.5) — address reuse, lease expiry, delayed
    binding, IP-only uncertainty;
  * a changed fact opens a NEW validity interval (no silent overwrite);
  * conflict resolution across records is arrival-order independent and never
    creates inverted / zero-length / overlapping intervals (both permutations);
  * interval continuity is restored across a restart;
  * timeline orders by NORMALIZED ts as INSTANTS (fractional seconds / offsets);
  * reads select the authoritative interval version (open vs closed duplicates);
  * confidence/source present; the MAC timeline joins to bare-IP observations.
"""
import importlib.util
import json
from pathlib import Path

import resolution as r

FLOW = {"event_type": "flow", "src_ip": "10.0.0.5", "dest_ip": "1.1.1.1",
        "flow": {"pkts_toserver": 1}}
ARP = {"event_type": "arp", "arp": {"src_ip": "10.0.0.5", "src_mac": "AA:BB:CC:00:11:22"}}
DHCP = {"event_type": "dhcp", "dhcp": {"assigned_ip": "10.0.0.5",
        "client_mac": "aa:bb:cc:00:11:22", "hostname": "laptop-1", "lease_time": 3600}}

T0 = "2026-09-28T12:00:00Z"
T1 = "2026-09-28T12:05:00Z"
T2 = "2026-09-28T12:10:00Z"
MAC = "mac:aa:bb:cc:00:11:22"


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parent.joinpath(*rel))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _load_app():
    m = _load("asset_app", ["app.py"])
    m.resolution = r
    return m


def _load_normalizer():
    return _load("ndr_normalizer_models", ["..", "normalizer", "models.py"])


# ── U17 evidence extraction / keying ──────────────────────────────────────────

def test_flow_yields_two_ip_only_observations():
    obs = r.extract_evidence(FLOW)
    assert len(obs) == 2 and all(o["mac"] is None for o in obs)


def test_arp_yields_ip_and_mac():
    o = r.extract_evidence(ARP)[0]
    assert o["ip"] == "10.0.0.5" and o["mac"] == "AA:BB:CC:00:11:22"


def test_dhcp_yields_ip_mac_hostname_and_lease():
    o = r.extract_evidence(DHCP)[0]
    assert o["hostname"] == "laptop-1" and o["mac"].endswith("11:22")
    assert o["lease_secs"] == 3600                       # lease interval preserved (§13.5)


def test_mac_first_asset_key():
    assert r.asset_key(r.extract_evidence(ARP)[0], {}, T0) == MAC


def test_merge_accumulates_and_raises_confidence():
    a = r.merge(None, r.extract_evidence(ARP)[0], "t1")
    a = r.merge(a, r.extract_evidence(DHCP)[0], "t2")
    assert "laptop-1" in a["hostname_set"]
    assert "aa:bb:cc:00:11:22" in a["mac_set"] and a["confidence"] > 0.5 and a["last_seen"] == "t2"


# ── §13.5 time-bounded identity bindings ──────────────────────────────────────

def test_binding_address_reuse_not_attributed_to_previous_holder():
    b: dict = {}
    r.record_binding(b, "10.0.0.5", "AA", T0, r.lease_expiry(T0, 300))    # A leased 12:00–12:05
    r.record_binding(b, "10.0.0.5", "BB", T2, None)                       # B takes it at 12:10
    assert r.resolve_mac(b, "10.0.0.5", "2026-09-28T12:02:00Z") == "aa"   # within A's lease
    assert r.resolve_mac(b, "10.0.0.5", T2) == "bb"                       # B now holds it
    # the gap after A's lease expiry, before B: NOT attributed to A (or B).
    assert r.resolve_mac(b, "10.0.0.5", "2026-09-28T12:07:00Z") is None


def test_binding_resolves_regardless_of_record_order():
    b: dict = {}
    r.record_binding(b, "10.0.0.5", "BB", T2, None)                       # later binding first
    r.record_binding(b, "10.0.0.5", "AA", T0, r.lease_expiry(T0, 3600))   # earlier binding after
    assert r.resolve_mac(b, "10.0.0.5", T1) == "aa"                       # delayed obs still resolves
    assert r.resolve_mac(b, "10.0.0.5", T2) == "bb"


def test_asset_key_ip_only_is_uncertain_until_bound():
    b: dict = {}
    assert r.asset_key({"ip": "9.9.9.9", "mac": None}, b, T0) == "ip:9.9.9.9"   # uncertain
    r.record_binding(b, "10.0.0.5", "AA", T0, None)
    assert r.asset_key({"ip": "10.0.0.5", "mac": None}, b, T0) == "mac:aa"      # now bound
    assert r.asset_key({"ip": "10.0.0.5", "mac": "CC"}, b, T0) == "mac:cc"      # explicit mac wins


# ── §13.4 fact candidates ──────────────────────────────────────────────────────

def test_derive_facts_carry_confidence_and_evidence_source():
    facts = r.derive_facts(r.extract_evidence(DHCP)[0], "obs:abc", T0)
    by = {f["predicate"]: f for f in facts}
    assert by["hostname"]["value"] == "laptop-1" and by["mac"]["value"] == "aa:bb:cc:00:11:22"
    for f in facts:
        assert 0 < f["confidence"] <= 1                          # confidence present
        assert f["source"] == {"type": "dhcp", "observation_id": "obs:abc"}   # evidence-backed
        assert f["valid_from"] == r._iso(T0) and f["valid_to"] is None
        assert f["classifier_version"] == r.CLASSIFIER_VERSION


def test_no_new_fingerprint_sources_only_hostname_and_mac():
    # A flow obs (ip only) yields NO facts — U7 defers passive-fingerprint predicates.
    assert r.derive_facts(r.extract_evidence(FLOW)[0], "obs:x", T0) == []


def _host(v, ts, src="dhcp", conf=0.9):
    return {"predicate": "hostname", "value": v, "confidence": conf, "valid_from": ts,
            "valid_to": None, "expires": None, "source": {"type": src, "observation_id": "o"},
            "method": src, "classifier_version": r.CLASSIFIER_VERSION}


def test_changed_fact_opens_new_interval_no_overwrite():
    state: dict = {}
    r.fold_facts(state, MAC, [_host("laptop-1", T0)])
    same = r.fold_facts(state, MAC, [_host("laptop-1", T1)])       # unchanged
    assert len(same["hostname"]) == 1                              # NO new interval
    changed = r.fold_facts(state, MAC, [_host("desktop-9", T2)])   # changed value
    ivs = changed["hostname"]
    assert [i["value"] for i in ivs] == ["laptop-1", "desktop-9"]
    assert ivs[0]["valid_to"] == r._iso(T2) and ivs[1]["valid_to"] is None   # closed, not overwritten


def test_conflicting_facts_resolve_deterministically_per_135():
    arp_c = {"predicate": "hostname", "value": "z-host", "confidence": 0.8,
             "valid_from": T0, "valid_to": None, "source": {"type": "arp", "observation_id": "a"}}
    dhcp_c = {"predicate": "hostname", "value": "a-host", "confidence": 0.5,
              "valid_from": T0, "valid_to": None, "source": {"type": "dhcp", "observation_id": "d"}}
    assert r.resolve_conflict([arp_c, dhcp_c])["value"] == "a-host"   # dhcp beats arp on rank
    assert r.resolve_conflict([dhcp_c, arp_c])["value"] == "a-host"   # arrival order irrelevant
    lo, hi = {**arp_c, "value": "aaa"}, {**arp_c, "value": "bbb"}
    assert r.resolve_conflict([hi, lo])["value"] == "aaa"            # tie -> smallest value


def test_late_event_does_not_invert_intervals():
    state: dict = {}
    r.fold_facts(state, MAC, [_host("desktop-9", T2)])              # T2 arrives first
    ivs = r.fold_facts(state, MAC, [_host("laptop-1", T0)])["hostname"]   # T0 arrives late
    assert [i["value"] for i in ivs] == ["laptop-1", "desktop-9"]   # ordered by ts, not arrival
    assert ivs[0]["valid_from"] == r._iso(T0) and ivs[0]["valid_to"] == r._iso(T2)
    assert ivs[1]["valid_to"] is None


# ── conflict resolution ACROSS records, through observe() (both permutations) ──

def _dhcp(host):
    return {"event_type": "dhcp", "dhcp": {"assigned_ip": "10.0.0.5",
            "client_mac": "aa:bb:cc:00:11:22", "hostname": host}}


def _observe_two(host_first, host_second):
    """Two same-ts DHCP records for the same MAC through observe(); returns the
    resulting hostname intervals. Distinct bus offsets => distinct obs_ids."""
    app = _load_app()
    app.observe(_dhcp(host_first), "suricata.raw.v1", 0, 1, T0)
    app.observe(_dhcp(host_second), "suricata.raw.v1", 0, 2, T0)
    return app._pending_facts[(MAC, "hostname")]


def test_observe_same_ts_conflict_is_arrival_independent_no_zero_length():
    fwd = _observe_two("a", "z")
    rev = _observe_two("z", "a")
    assert len(fwd) == 1 and len(rev) == 1                # ONE interval, no zero-length prior
    assert fwd[0]["value"] == rev[0]["value"] == "a"      # deterministic winner (lexical tie-break)
    assert fwd[0]["valid_to"] is None


def test_observe_derives_canonical_obs_id_not_empty():
    app = _load_app()
    app.observe(_dhcp("laptop-1"), "suricata.raw.v1", 3, 77, T0)
    row = app._pending_facts[(MAC, "hostname")][0]
    assert row["source"]["observation_id"].startswith("obs:")   # canonical, not ''


# ── obs_id parity with the normalizer contract (real normalizer output) ────────

def test_obs_id_matches_normalizer_contract():
    models = _load_normalizer()
    eve = {"event_type": "flow", "timestamp": T0, "src_ip": "10.0.0.5",
           "dest_ip": "1.1.1.1", "flow": {"pkts_toserver": 1}}
    _t, _row, doc = models.observation(
        eve, "t1", "sensor-9", topic="suricata.flow.v1", partition=2, offset=42,
        ingested_at="2026-09-28T12:00:01Z")
    assert doc["obs_id"] == r.canonical_obs_id("t1", "sensor-9", "suricata.flow.v1", 2, 42)


# ── timeline builder: order by NORMALIZED ts as INSTANTS ──────────────────────

def test_timeline_orders_events_by_normalized_ts():
    observations = [{"obs_id": "obs:2", "ts_normalized": T2, "type": "dns"},
                    {"obs_id": "obs:0", "ts_normalized": T0, "type": "conn"}]
    fact_changes = [{"predicate": "hostname", "value": "h", "valid_from": T1, "valid_to": None,
                     "confidence": 0.9, "source": {"type": "dhcp", "observation_id": "obs:1"}}]
    tl = r.build_timeline(observations, fact_changes, entity=MAC)
    assert [e["ts"] for e in tl["events"]] == [r._iso(T0), r._iso(T1), r._iso(T2)]
    assert [e["kind"] for e in tl["events"]] == ["observation", "fact_change", "observation"]


def test_timeline_orders_fractional_seconds_by_instant_not_string():
    # string compare would place '...00.100Z' before '...00Z' ('.' < 'Z'); instants must not.
    obs = [{"obs_id": "hundredth", "ts_normalized": "2026-09-28T12:00:00.100Z", "type": "conn"},
           {"obs_id": "whole", "ts_normalized": "2026-09-28T12:00:00Z", "type": "conn"}]
    tl = r.build_timeline(obs, [])
    assert [e["obs_id"] for e in tl["events"]] == ["whole", "hundredth"]


def test_timeline_equivalent_instants_different_offsets():
    obs = [{"obs_id": "x", "ts_normalized": "2026-09-28T12:00:00+00:00", "type": "conn"}]
    fc = [{"predicate": "hostname", "value": "h", "valid_from": "2026-09-28T07:00:00-05:00",
           "valid_to": None, "confidence": 0.9, "source": {"type": "dhcp", "observation_id": "o"}}]
    tl = r.build_timeline(obs, fc)                      # 07:00-05:00 == 12:00Z
    assert tl["events"][0]["ts"] == tl["events"][1]["ts"] == "2026-09-28T12:00:00.000Z"
    assert [e["kind"] for e in tl["events"]] == ["observation", "fact_change"]   # obs precedes its fact


def test_timeline_reconstructs_fact_intervals_with_confidence_and_source():
    fact_changes = [
        {"predicate": "hostname", "value": "laptop-1", "valid_from": T0, "valid_to": T2,
         "confidence": 0.9, "source": {"type": "dhcp", "observation_id": "o1"}},
        {"predicate": "hostname", "value": "desktop-9", "valid_from": T2, "valid_to": None,
         "confidence": 0.9, "source": {"type": "dhcp", "observation_id": "o2"}}]
    ivs = r.build_timeline([], fact_changes)["facts"]["hostname"]
    assert [i["value"] for i in ivs] == ["laptop-1", "desktop-9"]
    assert ivs[0]["valid_to"] == r._iso(T2) and ivs[1]["valid_to"] is None
    assert ivs[0]["confidence"] == 0.9 and ivs[0]["source"]["type"] == "dhcp"


# ── fetch_timeline read path (fake ClickHouse) ────────────────────────────────

class _Result:
    def __init__(self, column_names, result_rows):
        self.column_names, self.result_rows = column_names, result_rows


class FakeCH:
    """Serves fetch_timeline's fact query (subject match, authoritative-versioned)
    and observation query (hasAny bare-IP entity_values), honoring the SINGLE tenant
    fetch_timeline queries with (it scopes per tenant — never IN a set of tenants)."""

    def __init__(self, obs_rows, fact_rows):
        self.obs_rows, self.fact_rows = obs_rows, fact_rows

    def query(self, sql, parameters):
        tenant = parameters["tenant"]                       # per-tenant scope (§21)
        if "asset_fact" in sql:
            entity = parameters["entity"]
            cols = ["tenant_id", "subject", "predicate", "value", "valid_from", "valid_to",
                    "confidence", "source_type", "observation_id", "is_deleted", "updated_at"]
            rows = [[f["tenant"], f["subject"], f["predicate"], f["value"], f["valid_from"],
                     f.get("valid_to"), f["confidence"], f["source_type"], f["observation_id"],
                     f.get("is_deleted", 0), f.get("updated_at")]
                    for f in self.fact_rows if f["tenant"] == tenant and f["subject"] == entity]
            return _Result(cols, rows)
        ips = set(parameters["ips"])
        cols = ["obs_id", "normalized_time", "type", "entity_values"]
        rows = [[o["obs_id"], o["normalized_time"], o["type"], o["entity_values"]]
                for o in self.obs_rows
                if o["tenant"] == tenant and set(o["entity_values"]) & ips]
        return _Result(cols, rows)


def test_fetch_timeline_joins_mac_to_bare_ip_observations_from_normalizer():
    # Observations are keyed by BARE IP (real normalizer output); the MAC timeline
    # joins them through its temporal IP-binding fact — not raw asset-key equality.
    models = _load_normalizer()
    eve = {"event_type": "flow", "timestamp": T1, "src_ip": "10.0.0.5",
           "dest_ip": "1.1.1.1", "flow": {"pkts_toserver": 1}}
    _t, _row, doc = models.observation(
        eve, "A", "sensor-1", topic="suricata.flow.v1", partition=0, offset=5,
        ingested_at=T1)
    ch = FakeCH(
        obs_rows=[{"tenant": "A", "obs_id": doc["obs_id"],
                   "normalized_time": doc["ts"]["normalized"], "type": doc["type"],
                   "entity_values": [e["value"] for e in doc["entities"]]}],
        fact_rows=[{"tenant": "A", "subject": MAC, "predicate": "ip", "value": "10.0.0.5",
                    "valid_from": T0, "valid_to": None, "confidence": 0.9,
                    "source_type": "dhcp", "observation_id": "obs:bind", "updated_at": T0}])
    tl = r.fetch_timeline(ch, ["A"], MAC)["tenants"]["A"]
    assert [e["obs_id"] for e in tl["events"] if e["kind"] == "observation"] == [doc["obs_id"]]
    assert tl["attribution"] == "mac-bound"
    assert "10.0.0.5" in doc["entities"][0]["value"]     # sanity: entity_values are bare IPs


def test_fetch_timeline_tenant_scoped_and_excludes_out_of_window_activity():
    ch = FakeCH(
        obs_rows=[
            {"tenant": "A", "obs_id": "in", "normalized_time": T1, "type": "conn",
             "entity_values": ["10.0.0.5"]},                       # within A's binding window
            {"tenant": "A", "obs_id": "reused", "normalized_time": "2026-09-28T13:00:00Z",
             "type": "conn", "entity_values": ["10.0.0.5"]},       # after lease -> excluded (§13.5)
            {"tenant": "B", "obs_id": "leak", "normalized_time": T1, "type": "conn",
             "entity_values": ["10.0.0.5"]}],                      # other tenant -> excluded
        fact_rows=[{"tenant": "A", "subject": MAC, "predicate": "ip", "value": "10.0.0.5",
                    "valid_from": T0, "valid_to": T2, "confidence": 0.9,
                    "source_type": "dhcp", "observation_id": "obs:b", "updated_at": T0}])
    ids = [e["obs_id"] for e in r.fetch_timeline(ch, ["A"], MAC)["tenants"]["A"]["events"]
           if e["kind"] == "observation"]
    assert ids == ["in"]                                  # reused (out of window) + leak both dropped


def test_fetch_timeline_ip_only_entity_flagged_uncertain():
    ch = FakeCH(
        obs_rows=[{"tenant": "A", "obs_id": "o", "normalized_time": T1, "type": "conn",
                   "entity_values": ["9.9.9.9"]}],
        fact_rows=[])
    tl = r.fetch_timeline(ch, ["A"], "ip:9.9.9.9")["tenants"]["A"]
    assert tl["attribution"] == "ip-only"                 # explicit uncertainty
    assert [e["obs_id"] for e in tl["events"]] == ["o"]


def test_fetch_timeline_selects_authoritative_interval_version():
    # ReplacingMergeTree can hold both the open and the later-closed row before merge;
    # only the closed version (newer updated_at) must surface — no duplicate.
    ch = FakeCH(obs_rows=[], fact_rows=[
        {"tenant": "A", "subject": MAC, "predicate": "hostname", "value": "laptop-1",
         "valid_from": T0, "valid_to": None, "confidence": 0.9, "source_type": "dhcp",
         "observation_id": "o1", "updated_at": "2026-09-28T12:00:00.000Z"},
        {"tenant": "A", "subject": MAC, "predicate": "hostname", "value": "laptop-1",
         "valid_from": T0, "valid_to": T2, "confidence": 0.9, "source_type": "dhcp",
         "observation_id": "o1", "updated_at": "2026-09-28T12:10:00.000Z"}])
    ivs = r.fetch_timeline(ch, ["A"], MAC)["tenants"]["A"]["facts"]["hostname"]
    assert len(ivs) == 1 and ivs[0]["valid_to"] == r._iso(T2)   # closed wins, no open dup


def test_authoritative_closed_wins_at_equal_updated_at():
    rows = [
        {"tenant_id": "A", "subject": MAC, "predicate": "hostname", "value": "h",
         "valid_from": T0, "valid_to": None, "updated_at": T1},
        {"tenant_id": "A", "subject": MAC, "predicate": "hostname", "value": "h",
         "valid_from": T0, "valid_to": T2, "updated_at": T1}]
    picked = r._authoritative(rows)
    assert len(picked) == 1 and picked[0]["valid_to"] == T2


# ── auth / entity-shape guards ────────────────────────────────────────────────

def test_validate_entity_and_grants():
    assert r.validate_entity("mac:aa:bb:cc:00:11:22") == "mac:aa:bb:cc:00:11:22"
    for bad in ("", "has space", "a" * 300):
        try:
            r.validate_entity(bad)
            raise AssertionError("expected ValueError")
        except ValueError:
            pass
    tokens = {"tok": ["A"]}
    assert r.grants_for_token(tokens, "Bearer tok") == ["A"]
    assert r.grants_for_token(tokens, "") is None and r.grants_for_token(tokens, "Bearer nope") is None


def test_http_timeline_endpoint_auth_and_tenant_binding():
    import http.client
    import json as _json
    import threading
    from http.server import ThreadingHTTPServer

    app = _load_app()
    ch = FakeCH(
        obs_rows=[{"tenant": "A", "obs_id": "obs:0", "normalized_time": T0,
                   "type": "conn", "entity_values": ["10.0.0.5"]}],
        fact_rows=[])
    events = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0),
                              app.make_handler(ch, {"s3cr3t": ["A"]}, audit=events.append))
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def get(path, token=None):
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1])
        c.request("GET", path, headers={"Authorization": f"Bearer {token}"} if token else {})
        resp = c.getresponse()
        body = resp.read()
        c.close()
        return resp.status, (_json.loads(body) if body else None)

    try:
        assert get("/healthz")[0] == 200
        assert get("/entity/ip:10.0.0.5/timeline")[0] == 401                 # no token
        assert get("/entity/ip:10.0.0.5/timeline", token="bogus")[0] == 401  # unknown token
        st, body = get("/entity/ip:10.0.0.5/timeline", token="s3cr3t")
        assert st == 200 and body["entity"] == "ip:10.0.0.5"
        assert [e["kind"] for e in body["tenants"]["A"]["events"]] == ["observation"]
    finally:
        srv.shutdown()
    assert any(e["outcome"] == "success" for e in events)                    # read is audited
    assert "s3cr3t" not in _json.dumps(events)                               # bearer never logged


# ── U7 blocking-defect regressions (one per fixed defect) ─────────────────────

class _CaptureCH:
    """Captures asset-service inserts per table (no query path exercised)."""

    def __init__(self):
        self.inserts: dict = {}

    def insert(self, table, rows, column_names):
        self.inserts.setdefault(table, []).append((column_names, rows))


def _fact_dicts(ch):
    out = []
    for cols, rows in ch.inserts.get("ndr.asset_fact", []):
        out += [dict(zip(cols, row)) for row in rows]
    return out


def _vv(entries):
    """(valid_from, value) projection of an _emitted entry set — drops the lease id
    (observation_id, an opaque sha256 obs_id) so assertions stay legible."""
    return {(vf, val) for vf, val, _oid in entries}


def test_ip_binding_not_coalesced_across_lease_gap_defect1():
    # An address RE-ACQUIRED after its lease expired must NOT merge with the prior
    # hold — the MAC did not own it during the gap (§13.5 lease-aware attribution).
    def ipf(ip, ts, secs):
        return {"predicate": "ip", "value": ip, "confidence": 0.9, "valid_from": ts,
                "valid_to": None, "expires": r.lease_expiry(ts, secs),
                "source": {"type": "dhcp", "observation_id": "o"}, "method": "dhcp",
                "classifier_version": r.CLASSIFIER_VERSION}
    state: dict = {}
    r.fold_facts(state, MAC, [ipf("10.0.0.5", T0, 300)])              # lease [12:00, 12:05)
    ivs = r.fold_facts(state, MAC, [ipf("10.0.0.5", T2, 300)])["ip"]  # re-acquired 12:10
    assert len(ivs) == 2                                             # NOT one merged interval
    assert ivs[0]["valid_to"] == r._iso(r.lease_expiry(T0, 300))     # closed at lease expiry
    assert ivs[1]["valid_from"] == r._iso(T2)                        # gap 12:05–12:10 preserved


def test_reassignment_caps_prior_holders_open_ip_interval_defect1():
    # Cross-subject reassignment: MAC-A holds an address (arp, no lease -> open); when
    # MAC-B acquires it, A's still-open IP interval MUST be capped at B's arrival — the
    # prior holder emits no new record, so per-subject rebuild alone never closes it.
    app = _load_app()
    arp_a = {"event_type": "arp", "arp": {"src_ip": "10.0.0.5", "src_mac": "aa:aa:aa:aa:aa:aa"}}
    arp_b = {"event_type": "arp", "arp": {"src_ip": "10.0.0.5", "src_mac": "bb:bb:bb:bb:bb:bb"}}
    app.observe(arp_a, "suricata.raw.v1", 0, 1, T0)
    app.observe(arp_b, "suricata.raw.v1", 0, 2, T2)                   # B takes .5 at 12:10
    ivs = app._pending_facts[("mac:aa:aa:aa:aa:aa:aa", "ip")]
    assert [(i["value"], i["valid_to"]) for i in ivs] == [("10.0.0.5", r._iso(T2))]
    assert app._pending_facts[("mac:bb:bb:bb:bb:bb:bb", "ip")][0]["valid_from"] == r._iso(T2)


def test_authoritative_drops_tombstoned_interval_defect2():
    # A later tombstone (is_deleted=1) for a valid_from REMOVES that interval on read.
    rows = [
        {"tenant_id": "A", "subject": MAC, "predicate": "hostname", "value": "b",
         "valid_from": T1, "valid_to": None, "is_deleted": 0, "updated_at": T0},
        {"tenant_id": "A", "subject": MAC, "predicate": "hostname", "value": "b",
         "valid_from": T1, "valid_to": None, "is_deleted": 1, "updated_at": T2}]  # same value -> same key
    assert r._authoritative(rows) == []                              # obsolete interval gone


def test_flush_emits_tombstone_for_dropped_interval_defect2():
    # A rebuild that DROPS an interval boundary must persist a tombstone so the stale
    # row is removed in ClickHouse, not left as a phantom interval.
    app = _load_app()
    app.observe(_dhcp("a"), "suricata.raw.v1", 0, 1, T0)
    app.observe(_dhcp("b"), "suricata.raw.v1", 0, 2, T1)             # [a T0–T1, b T1–open]
    app.flush(_CaptureCH())
    assert _vv(app._emitted[(MAC, "hostname")]) == {(r._iso(T0), "a"), (r._iso(T1), "b")}
    app.observe(_dhcp("a"), "suricata.raw.v1", 0, 3, T1)            # T1 re-resolves to "a"
    ch = _CaptureCH()                                               #   -> run merges, T1 dropped
    app.flush(ch)
    facts = _fact_dicts(ch)
    live = [f for f in facts if f["predicate"] == "hostname" and f["is_deleted"] == 0]
    tomb = [f for f in facts if f["predicate"] == "hostname" and f["is_deleted"] == 1]
    assert [f["value"] for f in live] == ["a"]                       # single merged interval
    assert len(tomb) == 1 and r._iso(tomb[0]["valid_from"]) == r._iso(T1)   # T1 tombstoned
    assert tomb[0]["value"] == "b"                                   # carries the retired value's key
    assert _vv(app._emitted[(MAC, "hostname")]) == {(r._iso(T0), "a")}    # emitted index shrank


def test_conflict_total_order_tiebreak_on_obs_id_defect3():
    # Candidates that tie on rank/confidence/value must still resolve to ONE winner
    # regardless of arrival order — the recorded obs_id/source is reproducible.
    base = {"predicate": "hostname", "value": "same", "confidence": 0.9, "valid_from": T0,
            "valid_to": None, "source": {"type": "dhcp", "observation_id": "obs:zzz"}}
    other = {**base, "source": {"type": "dhcp", "observation_id": "obs:aaa"}}
    assert r.resolve_conflict([base, other])["source"]["observation_id"] == "obs:aaa"
    assert r.resolve_conflict([other, base])["source"]["observation_id"] == "obs:aaa"


def test_fact_obs_id_references_stored_identity_observation_defect4():
    # A dhcp-derived fact's source.observation_id must point at an evidence row the
    # asset-service actually stores (arp/dhcp are not typed by the normalizer), not a
    # fabricated id.
    app = _load_app()
    app.observe(_dhcp("laptop-1"), "suricata.raw.v1", 4, 9, T0)
    fact = app._pending_facts[(MAC, "hostname")][0]
    oid = fact["source"]["observation_id"]
    assert oid.startswith("obs:") and oid in app._pending_obs         # references a real row
    obs = app._pending_obs[oid]
    assert obs["obs_id"] == oid
    assert "10.0.0.5" in obs["entity_values"] and "aa:bb:cc:00:11:22" in obs["entity_values"]
    ch = _CaptureCH()
    app.flush(ch)
    stored = ch.inserts["ndr.identity_observation"][0][1]            # (cols, rows) -> rows
    assert any(row[1] == oid for row in stored)                      # obs_id persisted


def test_fetch_timeline_never_merges_across_granted_tenants_defect5():
    # SAME subject in tenant A and B (same MAC, different hostname, same valid_from):
    # a reader granted BOTH gets two SEPARATE timelines, never a collapsed/merged one.
    ch = FakeCH(obs_rows=[], fact_rows=[
        {"tenant": "A", "subject": MAC, "predicate": "hostname", "value": "a-host",
         "valid_from": T0, "valid_to": None, "confidence": 0.9, "source_type": "dhcp",
         "observation_id": "oa", "updated_at": T0},
        {"tenant": "B", "subject": MAC, "predicate": "hostname", "value": "b-host",
         "valid_from": T0, "valid_to": None, "confidence": 0.9, "source_type": "dhcp",
         "observation_id": "ob", "updated_at": T1}])
    res = r.fetch_timeline(ch, ["A", "B"], MAC)
    assert set(res["tenants"]) == {"A", "B"}
    assert res["tenants"]["A"]["facts"]["hostname"][0]["value"] == "a-host"
    assert res["tenants"]["B"]["facts"]["hostname"][0]["value"] == "b-host"   # not collapsed


# ── IP-ownership: arrival-order independence through observe -> flush -> read ──

AA = "aa:aa:aa:aa:aa:aa"
BB = "bb:bb:bb:bb:bb:bb"


def _dhcp_ip(mac, ip="10.0.0.9", lease=None, host=None):
    d = {"assigned_ip": ip, "client_mac": mac}
    if host:
        d["hostname"] = host
    if lease:
        d["lease_time"] = lease
    return {"event_type": "dhcp", "dhcp": d}


class _RoundTripCH:
    """insert() accumulates asset-service rows; query() serves fetch_timeline's
    per-tenant fact + observation reads from them — an end-to-end observe -> flush ->
    read check. Stamps a monotonically increasing updated_at (as ClickHouse now64
    would on insert) so a later tombstone/closed re-emit wins over an earlier open one
    in resolution._authoritative()."""

    def __init__(self):
        self.facts: list = []
        self.obs: list = []
        self._seq = 0

    def insert(self, table, rows, column_names):
        for row in rows:
            self._seq += 1
            d = dict(zip(column_names, row))
            d.setdefault("updated_at", "2000-01-01T00:00:%02d.000Z" % (self._seq % 60))
            (self.facts if table == "ndr.asset_fact" else
             self.obs if table == "ndr.identity_observation" else []).append(d)

    def query(self, sql, parameters):
        tenant = parameters["tenant"]
        if "FROM ndr.asset FINAL" in sql or "FROM ndr.entity_relationship FINAL" in sql:
            return _Result([], [])  # this fake exercises only facts/evidence replay
        if "identity_observation" in sql:                 # restore_state evidence replay
            cols = ["tenant_id", "obs_id", "normalized_time", "observation"]
            rows = [[o["tenant_id"], o["obs_id"], o["normalized_time"], o["observation"]]
                    for o in self.obs if o["tenant_id"] == tenant]
            return _Result(cols, rows)
        if "asset_fact" in sql:
            # Two callers: fetch_timeline (per-subject read) and _load_emitted (every
            # subject, no entity param). We return ALL versions incl tombstones — the fake
            # does NOT collapse like ClickHouse FINAL, so resolution._authoritative does
            # the version collapse + is_deleted removal both callers rely on.
            entity = parameters.get("entity")
            cols = ["tenant_id", "subject", "predicate", "value", "valid_from", "valid_to",
                    "confidence", "source_type", "observation_id", "is_deleted", "updated_at"]
            rows = [[f["tenant_id"], f["subject"], f["predicate"], f["value"], f["valid_from"],
                     f["valid_to"], f["confidence"], f["source_type"], f["observation_id"],
                     f["is_deleted"], f["updated_at"]]
                    for f in self.facts
                    if f["tenant_id"] == tenant and (entity is None or f["subject"] == entity)]
            return _Result(cols, rows)
        ips = set(parameters["ips"])
        cols = ["obs_id", "normalized_time", "type", "entity_values"]
        rows = [[o["obs_id"], o["normalized_time"],
                 json.loads(o["observation"]).get("type", ""), list(o["entity_values"])]
                for o in self.obs
                if o["tenant_id"] == tenant and set(o["entity_values"]) & ips]
        return _Result(cols, rows)


def _ip_intervals(ch, subject, tenant="default"):
    return r.fetch_timeline(ch, [tenant], subject)["tenants"][tenant]["facts"].get("ip", [])


class _FaultCH(_RoundTripCH):
    """A _RoundTripCH whose NEXT ndr.asset_fact insert fails once (then heals) — an
    INTERRUPTED persist: identity evidence written earlier in the same flush is already
    durable, but the derived interval rows are lost. flush() must leave _emitted and
    _pending_facts intact on that failure, and the next start must repair from raw evidence."""

    def __init__(self):
        super().__init__()
        self.fail_facts = False

    def insert(self, table, rows, column_names):
        if table == "ndr.asset_fact" and self.fail_facts:
            self.fail_facts = False
            raise RuntimeError("injected asset_fact insert failure")
        super().insert(table, rows, column_names)


def test_ip_ownership_reversed_arrival_caps_prior_holder_defect1():
    # MAC-A leases .9 at 12:00 (1h lease -> 13:00); MAC-B takes .9 at 12:05. A's
    # ownership MUST end at B's arrival (12:05), NOT run to the lease end — and that
    # must hold whether B's record arrives before or after A's (order independence).
    for order in ([(BB, T1, None), (AA, T0, 3600)],     # reversed (B first)
                  [(AA, T0, 3600), (BB, T1, None)]):     # chronological
        app = _load_app()
        ch = _RoundTripCH()
        for i, (mac, ts, lease) in enumerate(order):
            app.observe(_dhcp_ip(mac, lease=lease), "suricata.raw.v1", 0, i + 1, ts)
        app.flush(ch)
        a_ivs = _ip_intervals(ch, "mac:" + AA)
        b_ivs = _ip_intervals(ch, "mac:" + BB)
        assert [(i["value"], i["valid_to"]) for i in a_ivs] == [("10.0.0.9", r._iso(T1))]
        assert [(i["value"], i["valid_from"], i["valid_to"]) for i in b_ivs] == \
            [("10.0.0.9", r._iso(T1), None)]              # B holds it from 12:05, open


def test_ip_ownership_equal_time_conflict_single_owner_defect1():
    # Two MACs claim .9 at the SAME instant (a genuine conflict). Exactly ONE owns it
    # (deterministic tie-break by lease id in owner_at) — never both, so no overlapping
    # intervals — and the PERSISTED owner is exactly whom resolve_mac attributes: both
    # paths share owner_at, so they cannot disagree, whatever arrival order fixed the ids.
    for order in ([AA, BB], [BB, AA]):
        app = _load_app()
        ch = _RoundTripCH()
        for i, mac in enumerate(order):
            app.observe(_dhcp_ip(mac), "suricata.raw.v1", 0, i + 1, T0)
        app.flush(ch)
        winner = r.resolve_mac(app._bindings, "10.0.0.9", T0)      # point attribution
        loser = BB if winner == AA else AA
        assert [(i["value"], i["valid_to"]) for i in _ip_intervals(ch, "mac:" + winner)] \
            == [("10.0.0.9", None)]                                # winner owns it, open
        assert _ip_intervals(ch, "mac:" + loser) == []             # loser owns nothing (no overlap)


def test_ip_ownership_rebuild_removes_prior_holder_stale_row_via_tombstone_defect1():
    # After reassignment, the prior holder's row that was persisted OPEN before B
    # arrived is rewritten CLOSED (a rebuild that changes its bound), and any dropped
    # boundary is tombstoned — a read never surfaces a stale open interval for A.
    app = _load_app()
    app.observe(_dhcp_ip(AA, lease=3600), "suricata.raw.v1", 0, 1, T0)
    ch = _RoundTripCH()
    app.flush(ch)                                         # A persisted (open, lease end 13:00)
    assert _ip_intervals(ch, "mac:" + AA)[0]["valid_to"] == r._iso(r.lease_expiry(T0, 3600))
    app.observe(_dhcp_ip(BB), "suricata.raw.v1", 0, 2, T1)   # B takes it at 12:05
    app.flush(ch)
    a_ivs = _ip_intervals(ch, "mac:" + AA)
    assert [(i["value"], i["valid_to"]) for i in a_ivs] == [("10.0.0.9", r._iso(T1))]  # capped


def test_ip_ownership_shortened_replacement_lease_bounds_at_new_expiry_defect1():
    # A shorter REPLACEMENT lease must cap ownership at the NEW expiry — not linger to
    # the original lease end. AA leases .9 at 12:00 for 1h (-> 13:00) then re-leases it
    # at 12:05 for 60s (-> 12:06). Ownership must end at 12:06, and attribution must
    # agree (resolve_mac None past 12:06), so persisted facts and attribution never
    # diverge (reviewer defect: rebuild retained ownership until 13:00).
    app = _load_app()
    ch = _RoundTripCH()
    app.observe(_dhcp_ip(AA, lease=3600), "suricata.raw.v1", 0, 1, T0)   # 12:00 -> 13:00
    app.observe(_dhcp_ip(AA, lease=60), "suricata.raw.v1", 0, 2, T1)     # 12:05 -> 12:06
    app.flush(ch)
    ivs = _ip_intervals(ch, "mac:" + AA)
    assert r._instant(ivs[-1]["valid_to"]) == r._instant(r.lease_expiry(T1, 60))   # 12:06, not 13:00
    assert r.resolve_mac(app._bindings, "10.0.0.9", "2026-09-28T12:05:30Z") == AA  # inside new lease
    assert r.resolve_mac(app._bindings, "10.0.0.9", T2) is None                    # 12:10 > 12:06
    # a timeline observation after the shortened lease expires is excluded (§13.5).
    ch.obs.append({"tenant_id": "default", "obs_id": "late", "normalized_time": T2,
                   "observation": json.dumps({"type": "flow"}), "entity_values": ["10.0.0.9"]})
    ev = r.fetch_timeline(ch, ["default"], "mac:" + AA)["tenants"]["default"]["events"]
    assert "late" not in [e["obs_id"] for e in ev if e["kind"] == "observation"]


def test_ip_ownership_equal_time_unequal_lease_both_permutations_defect1():
    # Two MACs claim .9 at the SAME instant with UNEQUAL leases (AA 60s, BB 3600s). One
    # deterministic winner (by lease id) owns only its OWN lease window; the shadowed
    # claim never resurfaces after the winner's lease expires — and rebuild vs resolve_mac
    # agree. (reviewer defect: rebuild gave one MAC to its expiry, resolve_mac attributed
    # the other after it.)
    leases = {AA: 60, BB: 3600}
    for order in ([AA, BB], [BB, AA]):                                # both permutations
        app = _load_app()
        ch = _RoundTripCH()
        for i, mac in enumerate(order):
            app.observe(_dhcp_ip(mac, lease=leases[mac]), "suricata.raw.v1", 0, i + 1, T0)
        app.flush(ch)
        winner = r.resolve_mac(app._bindings, "10.0.0.9", T0)
        loser = BB if winner == AA else AA
        w_ivs = _ip_intervals(ch, "mac:" + winner)
        assert [(i["value"], r._instant(i["valid_to"])) for i in w_ivs] == \
            [("10.0.0.9", r._instant(r.lease_expiry(T0, leases[winner])))]  # winner's OWN lease
        assert _ip_intervals(ch, "mac:" + loser) == []               # shadowed -> no interval
        # once the winner's lease expires the loser is NOT resurrected (§13.5).
        gone = r.lease_expiry(T0, leases[winner])
        assert r.resolve_mac(app._bindings, "10.0.0.9", gone) is None


def test_restart_ip_ownership_matches_uninterrupted_defect3():
    # AA leases .9 at 12:00 and RENEWS at 12:10; a late BB reassignment at 12:05 must
    # split AA's ownership identically whether or not the service restarted. This only
    # holds if the coalesced renewal ts survives the reload (reviewer defect: restart
    # kept only the interval summary, losing AA's ownership from 12:10 onward).
    def final_ip(restart):
        app = _load_app()
        ch = _RoundTripCH()
        app.observe(_dhcp_ip(AA, lease=3600), "suricata.raw.v1", 0, 1, T0)   # 12:00
        app.observe(_dhcp_ip(AA, lease=3600), "suricata.raw.v1", 0, 2, T2)   # renew 12:10
        app.flush(ch)
        if restart:
            app = _load_app()
            app.restore_state(ch)                                            # replay persisted evidence
        app.observe(_dhcp_ip(BB), "suricata.raw.v1", 0, 3, T1)               # late reassignment 12:05
        ch2 = _RoundTripCH()
        app.flush(ch2)
        return [(i["value"], r._iso(i["valid_from"]), r._iso(i["valid_to"]))
                for i in _ip_intervals(ch2, "mac:" + AA)]
    rebuilt, uninterrupted = final_ip(restart=True), final_ip(restart=False)
    assert rebuilt == uninterrupted                                          # no divergence
    assert rebuilt[0] == ("10.0.0.9", r._iso(T0), r._iso(T1))                # 12:00–12:05 (capped by BB)
    assert rebuilt[-1][1] == r._iso(T2)                                      # AA re-owns from 12:10 on


def test_same_start_lease_tiebreak_attributes_identically_after_reload_u7():
    # Two leases for the SAME ip share an IDENTICAL start (a genuine equal-start
    # conflict). The tie-break (by lease id — the source obs_id) must pick the SAME owner
    # for point-attribution (resolve_mac) and persisted ownership, and that agreement must
    # survive a persist + reload — the two can never disagree.
    app = _load_app()
    ch = _RoundTripCH()
    app.observe(_dhcp_ip(AA, lease=3600), "suricata.raw.v1", 0, 1, T0)   # AA @ 12:00
    app.observe(_dhcp_ip(BB, lease=3600), "suricata.raw.v1", 0, 2, T0)   # BB @ 12:00 (tie)
    in_mem = r.resolve_mac(app._bindings, "10.0.0.9", T0)                # point attribution
    app.flush(ch)
    loser = BB if in_mem == AA else AA
    assert [i["value"] for i in _ip_intervals(ch, "mac:" + in_mem)] == ["10.0.0.9"]
    assert _ip_intervals(ch, "mac:" + loser) == []                      # loser owns nothing
    # restart: a fresh process rebuilds bindings + intervals from the persisted facts.
    app2 = _load_app()
    app2.restore_state(ch)
    assert r.resolve_mac(app2._bindings, "10.0.0.9", T0) == in_mem       # same owner after reload


def test_same_mac_two_ips_same_start_both_persisted_across_restart_u7():
    # Reviewer defect: one MAC owns TWO addresses at the SAME lease start. Both attribute
    # to it live, but the persisted interval identity was (subject, predicate, valid_from)
    # — so the two IPs shared a key and only the last-written survived. value is now part
    # of the identity (storage ORDER BY, _authoritative, _emitted, tombstones), so both
    # addresses persist as distinct intervals and BOTH survive a restart-rebuild.
    app = _load_app()
    ch = _RoundTripCH()
    app.observe(_dhcp_ip(AA, ip="10.0.0.9", lease=3600), "suricata.raw.v1", 0, 1, T0)
    app.observe(_dhcp_ip(AA, ip="10.0.0.10", lease=3600), "suricata.raw.v1", 0, 2, T0)
    assert r.resolve_mac(app._bindings, "10.0.0.9", T0) == AA        # both attribute live
    assert r.resolve_mac(app._bindings, "10.0.0.10", T0) == AA
    app.flush(ch)
    before = sorted(i["value"] for i in _ip_intervals(ch, "mac:" + AA))
    assert before == ["10.0.0.10", "10.0.0.9"]                       # BOTH retained (not collapsed)
    assert _vv(app._emitted[("mac:" + AA, "ip")]) == \
        {(r._iso(T0), "10.0.0.9"), (r._iso(T0), "10.0.0.10")}
    app2 = _load_app()                                               # restart -> rebuild from evidence
    app2.restore_state(ch)
    after = sorted(i["value"] for i in _ip_intervals(ch, "mac:" + AA))
    assert after == before                                          # both survive the rebuild


def test_restart_rebuild_reproduces_byte_identical_intervals_u7():
    # A restart must rebuild to the EXACT same intervals as an uninterrupted run — no
    # lost evidence (each renewal's obs_id + lease survives as its own persisted claim),
    # no order dependence. A late reassignment inserted between AA's two renewals splits
    # ownership identically whether or not the service restarted midway (§13.4).
    def run(restart):
        app = _load_app()
        ch = _RoundTripCH()
        app.observe(_dhcp_ip(AA, lease=3600, host="a"), "suricata.raw.v1", 0, 1, T0)  # AA @ 12:00
        app.observe(_dhcp_ip(AA, lease=3600, host="a"), "suricata.raw.v1", 0, 2, T2)  # renew 12:10
        app.flush(ch)
        if restart:
            app = _load_app()
            app.restore_state(ch)                                                     # replay evidence
        app.observe(_dhcp_ip(BB, host="b"), "suricata.raw.v1", 0, 3, T1)              # late 12:05
        ch2 = _RoundTripCH()
        app.flush(ch2)
        drop = lambda f: tuple(sorted((k, str(v)) for k, v in f.items() if k != "updated_at"))
        return sorted(drop(f) for f in ch2.facts)
    assert run(restart=True) == run(restart=False)                       # byte-identical


def test_interrupted_persist_repaired_on_restart_u7():
    # (c) An interrupted persist is repaired on next start. AA owns .9 over two windows
    # split by a lease gap (12:00–12:05 and 12:10–12:15), persisted as TWO intervals. A
    # renewal at 12:05 later FILLS the gap so the rebuild coalesces to ONE interval
    # (valid_from 12:00), dropping the 12:10 boundary — but that persist is INTERRUPTED
    # after the identity evidence commits. On failure the clean index does NOT advance.
    # A restart rebuilds from raw evidence AND reconciles against the obsolete persisted
    # key, tombstoning the stale 12:10 interval; a read then shows exactly ONE interval,
    # and _emitted reflects the repair ONLY because the repair persist succeeded (§13.4).
    ch = _FaultCH()
    app = _load_app()
    app.observe(_dhcp_ip(AA, lease=300), "suricata.raw.v1", 0, 1, T0)   # 12:00 -> 12:05
    app.observe(_dhcp_ip(AA, lease=300), "suricata.raw.v1", 0, 2, T2)   # 12:10 -> 12:15
    app.flush(ch)
    assert len(_ip_intervals(ch, "mac:" + AA)) == 2                     # gap-split into two
    assert _vv(app._emitted[("mac:" + AA, "ip")]) == {(r._iso(T0), "10.0.0.9"), (r._iso(T2), "10.0.0.9")}

    app.observe(_dhcp_ip(AA, lease=300), "suricata.raw.v1", 0, 3, T1)   # 12:05 -> 12:10 fills gap
    ch.fail_facts = True
    try:
        app.flush(ch)
        raise AssertionError("expected injected asset_fact failure")
    except RuntimeError:
        pass
    # persist failed: clean index NOT advanced, obsolete rows still active in CH.
    assert _vv(app._emitted[("mac:" + AA, "ip")]) == {(r._iso(T0), "10.0.0.9"), (r._iso(T2), "10.0.0.9")}
    assert len(_ip_intervals(ch, "mac:" + AA)) == 2

    app2 = _load_app()                                                 # restart
    app2.restore_state(ch)                                             # repair from raw evidence
    ivs = _ip_intervals(ch, "mac:" + AA)
    assert [(i["value"], r._iso(i["valid_from"])) for i in ivs] == \
        [("10.0.0.9", r._iso(T0))]                                     # ONE coalesced interval
    assert r._instant(ivs[0]["valid_to"]) == r._instant(r.lease_expiry(T2, 300))   # runs to 12:15
    assert _vv(app2._emitted[("mac:" + AA, "ip")]) == {(r._iso(T0), "10.0.0.9")}   # clean index shrank after repair
    assert r.resolve_mac(app2._bindings, "10.0.0.9", "2026-09-28T12:12:00Z") == AA  # attribution agrees


def test_evidence_sql_orders_identity_table_and_migrates_is_deleted_defect2():
    # deploy/clickhouse/init/05-evidence.sql must (a) create identity_observation
    # BEFORE the view that UNIONs it (fresh init has no forward reference), and
    # (b) carry an explicit upgrade migration adding is_deleted to pre-U7 asset_fact
    # tables, before the entity_timeline view that reads it. (A live fresh-DB apply is
    # an operational gate — no ClickHouse in the unit env — so this guards the script.)
    # Guards a repo file; skip when the repo layout isn't present (e.g. the flat /app
    # container build-gate, where deploy/ isn't copied and parents[2] doesn't exist).
    try:
        sql = Path(__file__).resolve().parents[2].joinpath(
            "deploy", "clickhouse", "init", "05-evidence.sql").read_text()
    except (IndexError, FileNotFoundError, OSError):
        return
    # Order against actual declarations, not comments: the file's header comment names
    # the evidence_observations view before it is declared, so .index() on raw text would
    # match the comment. Strip -- line comments (the only comment style here) for ordering.
    decl = "\n".join(line.split("--", 1)[0] for line in sql.splitlines())
    assert (decl.index("CREATE TABLE IF NOT EXISTS ndr.identity_observation")
            < decl.index("CREATE OR REPLACE VIEW ndr.evidence_observations"))
    alter = "ALTER TABLE ndr.asset_fact ADD COLUMN IF NOT EXISTS is_deleted"
    assert alter in sql
    assert decl.index(alter) < decl.index("CREATE OR REPLACE VIEW ndr.entity_timeline")
    # value AND observation_id (the lease id) are in asset_fact's dedup key: value keeps a
    # MAC's two IPs distinct, observation_id keeps two same-start intervals for ONE ip
    # (distinct leases) from collapsing under ReplacingMergeTree.
    assert "ORDER BY (tenant_id, subject, predicate, value, valid_from, observation_id)" in sql
    assert "MIGRATION" in sql        # reload note for existing data (ops step, out of scope)


def test_two_same_start_intervals_one_ip_both_survive_u7():
    # DEDUP KEY: two intervals for the SAME ip that share subject + value + valid_from but
    # come from DISTINCT leases (different observation_id) must BOTH survive — they do not
    # collapse under ReplacingMergeTree because the lease id is part of the dedup key.
    # (value + valid_from alone keyed them identically and dropped one.)
    rows = [
        {"tenant_id": "A", "subject": MAC, "predicate": "ip", "value": "10.0.0.9",
         "valid_from": T0, "valid_to": None, "observation_id": "obs:lease-1",
         "is_deleted": 0, "updated_at": T0},
        {"tenant_id": "A", "subject": MAC, "predicate": "ip", "value": "10.0.0.9",
         "valid_from": T0, "valid_to": None, "observation_id": "obs:lease-2",
         "is_deleted": 0, "updated_at": T0}]
    kept = r._authoritative(rows)
    assert {row["observation_id"] for row in kept} == {"obs:lease-1", "obs:lease-2"}   # BOTH
    # a same-LEASE re-emit (identical observation_id) still collapses to its newest version —
    # the key change distinguishes distinct leases without breaking version dedup.
    dup = rows + [{**rows[0], "valid_to": T2, "updated_at": T2}]
    kept2 = r._authoritative(dup)
    assert len(kept2) == 2                                             # not three
    lease1 = next(row for row in kept2 if row["observation_id"] == "obs:lease-1")
    assert lease1["valid_to"] == T2                                    # newest version of lease-1 won


class _FakeConsumer:
    """Minimal at-least-once Kafka consumer: drain() serves records from the last committed
    offset; commit() advances the committed offset to the consumed position. A crash before
    commit() means restart() rewinds to the last committed offset — the uncommitted records
    are re-served. records: (value, topic, partition, offset, normalized_ts) tuples."""

    def __init__(self, records):
        self.records = records
        self.committed = 0          # offset up to which work is durably acknowledged
        self.pos = 0
        self.commits = []           # commit call log (ordering / advance proof)

    def drain(self):
        batch = self.records[self.pos:]
        self.pos = len(self.records)
        return batch

    def commit(self):
        self.committed = self.pos
        self.commits.append(self.committed)

    def restart(self):              # crash + restart: resume from the last committed offset
        self.pos = self.committed


def test_persist_precedes_commit_offset_after_persist_u7():
    # OFFSET-AFTER-PERSIST: persist_and_commit must flush (durable write) BEFORE committing
    # the Kafka offset — never the reverse. Proven by call order: the last event is the
    # commit, and at least one durable insert precedes it.
    app = _load_app()
    events = []

    class _CH(_RoundTripCH):
        def insert(self, table, rows, column_names):
            events.append(("insert", table))
            super().insert(table, rows, column_names)

    class _Con:
        def commit(self):
            events.append(("commit", None))

    app.observe(_dhcp_ip(AA, lease=3600), "suricata.raw.v1", 0, 0, T0)
    app.persist_and_commit(_CH(), _Con())
    assert events[-1] == ("commit", None)                    # commit is LAST
    assert any(e[0] == "insert" for e in events[:-1])        # a durable write ran first


def test_crash_between_write_and_commit_recovers_identically_u7():
    # A crash AFTER the ClickHouse flush but BEFORE the Kafka offset commit must lose no
    # evidence and rebuild IDENTICALLY: the offset never advanced, so the uncommitted records
    # are re-consumed on restart; folding is idempotent (canonical obs_id) and restore_state
    # repairs, so the authoritative state matches an uninterrupted run.
    recs = [
        (_dhcp_ip(AA, lease=3600), "suricata.raw.v1", 0, 0, T0),
        (_dhcp_ip(AA, lease=3600), "suricata.raw.v1", 0, 1, T2),   # renewal
        (_dhcp_ip(BB), "suricata.raw.v1", 0, 2, T1)]               # late reassignment

    def logical(ch):
        facts = {}
        for subj in ("mac:" + AA, "mac:" + BB):
            f = r.fetch_timeline(ch, ["default"], subj)["tenants"]["default"]["facts"]
            facts[subj] = {pred: [(i["value"], r._iso(i["valid_from"]), r._iso(i["valid_to"]))
                                  for i in ivs] for pred, ivs in f.items()}
        return facts, sorted({o["obs_id"] for o in ch.obs})

    # ── uninterrupted: consume all, persist, commit ──
    app = _load_app()
    ch = _RoundTripCH()
    con = _FakeConsumer(recs)
    for value, topic, part, off, ts in con.drain():
        app.observe(value, topic, part, off, ts)
    app.persist_and_commit(ch, con)
    assert con.committed == 3 and con.commits == [3]           # offset advanced only via commit
    want = logical(ch)

    # ── crashed: flush succeeds (durable), commit NEVER runs ──
    app2 = _load_app()
    ch2 = _RoundTripCH()
    con2 = _FakeConsumer(recs)
    for value, topic, part, off, ts in con2.drain():
        app2.observe(value, topic, part, off, ts)
    app2.flush(ch2)                                            # write commits to CH...
    #  ...crash here — no consumer.commit(): offset stays at 0
    assert con2.committed == 0                                 # offset did NOT advance past the write
    assert len({o["obs_id"] for o in ch2.obs}) == 3           # yet the raw evidence IS durable

    # ── restart: repair from evidence, re-consume the uncommitted records, then commit ──
    con2.restart()                                            # resume from last committed offset (0)
    app3 = _load_app()
    app3.restore_state(ch2)                                   # repair interval cache from raw evidence
    for value, topic, part, off, ts in con2.drain():         # re-serves offsets 0..2 (same obs_ids)
        app3.observe(value, topic, part, off, ts)
    app3.persist_and_commit(ch2, con2)
    assert con2.committed == 3                                # now durably acknowledged

    assert logical(ch2) == want                              # identical rebuild, no lost evidence


class _Rec:
    """A Kafka record as poll_and_observe reads it: value/topic/partition/offset plus the
    LogAppendTime pair. timestamp_type=1 == LogAppendTime (valid); 0 == CreateTime (rejected)."""
    def __init__(self, value, topic, partition, offset, timestamp=1_759_000_000_000,
                 timestamp_type=1):
        self.value, self.topic, self.partition, self.offset = value, topic, partition, offset
        self.timestamp, self.timestamp_type = timestamp, timestamp_type


class _TP:
    """A (topic, partition) key; hashable so it keys poll()'s result and seek()/commit() state."""
    def __init__(self, topic, partition):
        self.topic, self.partition = topic, partition
    def __hash__(self):
        return hash((self.topic, self.partition))
    def __eq__(self, other):
        return (self.topic, self.partition) == (other.topic, other.partition)


class _PollConsumer:
    """Real-shape KafkaConsumer stand-in for main()'s loop. poll() serves each partition's
    records from its current position and advances position over the whole batch (as the real
    client does); seek() rewinds a partition; a bare commit() acks each partition's CURRENT
    position — so after a seek only contiguous successfully-observed offsets are committed."""
    def __init__(self, records):                 # records: {(_TP): [_Rec,...]} in offset order
        self.records = records
        self.pos = {tp: 0 for tp in records}
        self.committed = {tp: 0 for tp in records}
        self.commits = []

    def poll(self, timeout_ms=0, max_records=0):
        out = {}
        for tp, recs in self.records.items():
            batch = recs[self.pos[tp]:]
            if batch:
                out[tp] = batch
                self.pos[tp] = len(recs)         # poll advances over the whole fetched batch
        return out

    def seek(self, tp, offset):
        self.pos[tp] = offset                    # offsets are 0-based list indices in the fake

    def commit(self):
        self.committed = dict(self.pos)
        self.commits.append(dict(self.pos))


def test_main_loop_failed_record_not_committed_and_replayable_u7():
    # BLOCKING (codex): a validation/observe failure must NOT let the offset advance past
    # unpersisted evidence. Offset 0 is a good DHCP; offset 1 has a spoofable CreateTime ts
    # (rejected); offset 2 is good. poll_and_observe must observe 0, reject 1, seek the
    # partition back to 1 and stop — so offset 2 is not consumed ahead of the failed 1, and
    # the committed offset stays at 1 (only offset 0's evidence is acknowledged).
    app = _load_app()
    ch = _RoundTripCH()
    tp = _TP("suricata.raw.v1", 0)
    con = _PollConsumer({tp: [
        _Rec(_dhcp_ip(AA, lease=3600), tp.topic, tp.partition, 0),
        _Rec(_dhcp_ip(BB), tp.topic, tp.partition, 1, timestamp_type=0),   # CreateTime: rejected
        _Rec(_dhcp_ip(AA, lease=3600), tp.topic, tp.partition, 2)]})

    app.poll_and_observe(con)
    app.persist_and_commit(ch, con)
    assert con.committed[tp] == 1                       # advanced only past the persisted offset 0
    assert con.pos[tp] == 1                             # rewound: the failed record replays next
    assert {o["obs_id"] for o in ch.obs} and len(ch.obs) == 1   # only offset 0 persisted
    ip_bb = _ip_intervals(ch, "mac:" + BB)
    assert ip_bb == []                                 # offset 1 (and the skipped 2) not folded

    # Replay: offset 1 now arrives with a valid LogAppendTime ts; 1 and 2 are re-served from
    # the committed position and processed, so NO evidence was lost by the earlier failure.
    con.records[tp][1] = _Rec(_dhcp_ip(BB), tp.topic, tp.partition, 1)
    app.poll_and_observe(con)
    app.persist_and_commit(ch, con)
    assert con.committed[tp] == 3                       # all three now durably acknowledged
    assert len(ch.obs) == 3


def test_main_loop_crash_before_first_commit_replays_from_earliest_u7():
    # BLOCKING (codex): a NEW group/partition that crashes before its FIRST commit has no
    # committed offset. auto_offset_reset must be "earliest" so restart re-reads the oldest
    # record instead of jumping to the tail and dropping the uncommitted initial batch.
    src = Path(_load_app().__file__).read_text()
    assert 'auto_offset_reset="earliest"' in src

    # Model it: committed starts at 0 (no prior commit). poll+flush write durably, then the
    # process crashes before commit() — committed stays 0. A restart re-serves from 0 and the
    # canonical-obs_id fold is idempotent, so the rebuild is identical with no lost evidence.
    app = _load_app()
    ch = _RoundTripCH()
    tp = _TP("suricata.raw.v1", 0)
    recs = [_Rec(_dhcp_ip(AA, lease=3600), tp.topic, tp.partition, 0),
            _Rec(_dhcp_ip(AA, lease=3600), tp.topic, tp.partition, 1)]
    con = _PollConsumer({tp: list(recs)})

    app.poll_and_observe(con)
    app.flush(ch)                                       # durable write...
    #  ...crash before commit(): the offset never advanced from 0
    assert con.committed[tp] == 0
    ip_before = _ip_intervals(ch, "mac:" + AA)

    con.pos[tp] = con.committed[tp]                     # restart: resume from last committed (0)
    app2 = _load_app()
    app2.restore_state(ch)                              # repair interval cache from raw evidence
    app2.poll_and_observe(con)                          # re-serves offsets 0..1 (same obs_ids)
    app2.persist_and_commit(ch, con)
    assert con.committed[tp] == 2                       # now acknowledged
    assert _ip_intervals(ch, "mac:" + AA) == ip_before  # identical rebuild, no lost evidence


# ── U3a: additive entity attributes on the merged record (model only) ─────────
# resolve()==merge() here: the function that resolves an observation into the entity
# record. These pin (2) unchanged shape when no new attrs, (3) carried-only-when-observed
# never fabricated, (4) signature unchanged.

_SHIPPED_KEYS = {"ip_set", "mac_set", "hostname_set", "evidence_sources",
                 "first_seen", "last_seen", "confidence", "role_if_known"}
_U3A_KEYS = {"username", "role", "os_hint", "criticality", "owner",
             "applications", "listening_services", "certificates", "ja4",
             "attribute_provenance"}


def test_merge_without_new_attrs_yields_shipped_shape_no_new_keys():
    # (2) An obs with none of the new attributes returns exactly the pre-U3a record:
    # no new keys, no provenance — existing callers see no change.
    a = r.merge(None, r.extract_evidence(ARP)[0], T0)
    assert set(a) == _SHIPPED_KEYS                       # only shipped keys present
    assert not (_U3A_KEYS & set(a))                      # no additive key fabricated
    a = r.merge(a, r.extract_evidence(DHCP)[0], T1)      # a second fold still adds none
    assert not (_U3A_KEYS & set(a))


def test_merge_carries_attribute_only_when_observed():
    # (3) A new attribute is set ONLY when the observation provides it, with provenance;
    # an attribute the obs omits is ABSENT (never null-defaulted, never inferred).
    obs = {"ip": "10.0.0.5", "mac": "AA:BB:CC:00:11:22", "hostname": None,
           "src": "dhcp", "username": "bob", "os_hint": "Win11"}
    a = r.merge(None, obs, T0)
    assert a["username"] == "bob" and a["os_hint"] == "Win11"
    assert "role" not in a and "criticality" not in a and "owner" not in a   # unobserved -> absent
    assert set(a["attribute_provenance"]) == {"username", "os_hint"}         # only observed ones
    assert a["attribute_provenance"]["username"] == {"source": "dhcp", "observed_at": T0}


def test_merge_does_not_fabricate_role_or_listening_service_when_unobserved():
    # CRITICAL (codex finding): role / listening-service / os recorded only from observed
    # evidence — an identity-only obs asserts none of them.
    a = r.merge(None, r.extract_evidence(DHCP)[0], T0)
    for attr in ("role", "os_hint", "listening_services"):
        assert attr not in a                             # never asserted unobserved
    assert "attribute_provenance" not in a               # nothing observed -> no provenance


def test_merge_accumulates_list_attrs_and_records_provenance():
    obs1 = {"ip": "10.0.0.5", "src": "http", "applications": ["nginx"]}
    obs2 = {"ip": "10.0.0.5", "src": "http", "applications": ["nginx", "openssh"]}
    a = r.merge(None, obs1, T0)
    a = r.merge(a, obs2, T1)
    assert a["applications"] == ["nginx", "openssh"]     # accumulated, deduped, order-stable
    assert a["attribute_provenance"]["applications"]["observed_at"] == T1   # last observation


def test_merge_empty_list_attr_is_not_recorded():
    # An observation carrying an EMPTY list is not evidence of a value -> nothing recorded.
    a = r.merge(None, {"ip": "10.0.0.5", "src": "http", "applications": []}, T0)
    assert "applications" not in a and "attribute_provenance" not in a


def test_merge_into_record_with_null_provenance_scalar_and_list():
    # Regression (codex): the schema permits attribute_provenance: null. Merging an observed
    # scalar OR list attribute into such a record must initialize the null mapping, not raise
    # (setdefault would preserve None -> TypeError at _note_provenance).
    base = {"ip_set": [], "mac_set": [], "hostname_set": [], "evidence_sources": [],
            "first_seen": T0, "last_seen": T0, "confidence": 0.5, "role_if_known": "",
            "attribute_provenance": None}
    a = r.merge(dict(base), {"ip": "10.0.0.5", "src": "dhcp", "role": "dc"}, T1)  # scalar
    assert a["role"] == "dc"
    assert a["attribute_provenance"] == {"role": {"source": "dhcp", "observed_at": T1}}
    b = r.merge(dict(base), {"ip": "10.0.0.5", "src": "http", "applications": ["nginx"]}, T1)
    assert b["applications"] == ["nginx"]                                        # list
    assert b["attribute_provenance"]["applications"] == {"source": "http", "observed_at": T1}


def test_merge_signature_unchanged_positional_and_keyword():
    # (4) Existing positional and keyword call forms still work (additive, no new params).
    obs = r.extract_evidence(ARP)[0]
    pos = r.merge(None, obs, T0)
    kw = r.merge(asset=None, obs=obs, ts=T0)
    assert pos == kw
    import inspect
    assert list(inspect.signature(r.merge).parameters) == ["asset", "obs", "ts"]


def test_merge_scalar_attr_none_value_not_recorded():
    # An explicit None scalar is "unobserved", not "observed as null" -> not recorded.
    a = r.merge(None, {"ip": "10.0.0.5", "src": "arp", "role": None}, T0)
    assert "role" not in a and "attribute_provenance" not in a


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} resolution tests passed")
