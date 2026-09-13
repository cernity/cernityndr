"""Build gate for extract (run: `python test_extract.py`)."""
import json

import extract as x
import episodes as ep


def test_flagged_from_alerts_host():
    docs = [{"event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "93.184.216.34"},
            {"event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "8.8.8.8"}]
    assert x.flagged_from_alerts(docs) == {"10.0.0.5", "93.184.216.34", "8.8.8.8"}


def test_flagged_from_alerts_flow():
    docs = [{"event_type": "alert", "community_id": "1:aaa"},
            {"event_type": "alert", "community_id": "1:bbb"},
            {"event_type": "alert", "src_ip": "10.0.0.1"}]
    assert x.flagged_from_alerts(docs, "flow") == {"1:aaa", "1:bbb"}


def test_flagged_from_alerts_excludes_flow_telemetry():
    # The flow-endpoint bug (§4): flow/nsm records are stored but are NOT analyst
    # detections, so their endpoints must not be scored as Arm A positives.
    docs = [{"event_type": "flow", "src_ip": "10.0.0.9", "dest_ip": "8.8.8.8"},
            {"event_type": "netflow", "src_ip": "10.0.0.10"},
            {"event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "203.0.113.66"}]
    assert x.flagged_from_alerts(docs) == {"10.0.0.5", "203.0.113.66"}


def test_flagged_from_notices_parses_zeek_notices():
    # Zeek notices have no event_type=alert; the shipper normalizes src/dst -> src_ip/dest_ip.
    docs = [{"src_ip": "10.0.0.5", "dest_ip": "203.0.113.66"}, {"src_ip": "10.0.0.7"}]
    assert x.flagged_from_notices(docs) == {"10.0.0.5", "203.0.113.66", "10.0.0.7"}
    assert x.flagged_from_notices([{"community_id": "1:z"}], "flow") == {"1:z"}


def test_flagged_from_findings_host_parses_entities_string():
    docs = [{"entities": json.dumps([{"type": "ip", "role": "src", "value": "10.0.0.5"},
                                     {"type": "ip", "role": "dst", "value": "93.184.216.34"},
                                     {"type": "spray", "distinct_accounts": 10}])}]
    assert x.flagged_from_findings(docs) == {"10.0.0.5", "93.184.216.34"}


def test_flagged_from_findings_tolerates_bad_entities():
    assert x.flagged_from_findings([{"entities": "not-json"}, {}]) == set()


def test_detections_from_alerts_filters_flow_and_maps_behavior():
    docs = [{"event_type": "flow", "src_ip": "1.1.1.1"},
            {"event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "203.0.113.66",
             "alert": {"category": "A Network Trojan was detected"}}]
    d = x.detections_from_alerts(docs)
    assert len(d) == 1 and d[0]["behavior"] == "c2"
    assert {e["value"] for e in d[0]["entities"]} == {"10.0.0.5", "203.0.113.66"}


def test_detections_from_findings_parses_roles_and_id():
    docs = [{"finding_id": "f1", "category": "c2",
             "entities": json.dumps([{"type": "ip", "role": "src", "value": "10.0.0.5"},
                                     {"type": "spray", "value": "ignore"}])}]
    d = x.detections_from_findings(docs)
    assert d[0]["finding_id"] == "f1" and d[0]["behavior"] == "c2"
    assert d[0]["entities"] == [{"value": "10.0.0.5", "role": "src"}]


def test_detections_from_findings_includes_domain_entities():
    # an FQDN-beacon finding implicates a DOMAIN, not just an ip — both must be matchable.
    docs = [{"category": "c2", "entities": json.dumps([
        {"type": "ip", "role": "src", "value": "10.0.0.5"},
        {"type": "domain", "role": "c2", "value": "evil.example"},
        {"type": "rotating_ips", "value": 4}])}]
    vals = {e["value"] for e in x.detections_from_findings(docs)[0]["entities"]}
    assert vals == {"10.0.0.5", "evil.example"}


# §26 Major-2: tenant identity must come from the record's ACTUAL schema (findings key by
# `tenant_id`). Reading only `tenant` collapsed every real finding to "default".
def test_detections_read_contract_tenant_id():
    # a real delivered finding carries tenant_id and NO bare `tenant` field
    d = x.detections_from_findings([{"finding_id": "f1", "category": "c2", "tenant_id": "customer-7",
                                     "entities": json.dumps([{"type": "ip", "role": "src", "value": "10.0.0.5"}])}])
    assert d[0]["tenant"] == "customer-7", "finding tenant_id lost at extraction -> tenant isolation defeated"
    # bare-tenant legacy fallback still honoured; absent -> default
    assert x.detections_from_alerts([{"event_type": "alert", "src_ip": "10.0.0.5", "tenant": "t2"}])[0]["tenant"] == "t2"
    assert x.detections_from_alerts([{"event_type": "alert", "src_ip": "10.0.0.5"}])[0]["tenant"] == "default"


def test_two_tenants_stay_separate_through_extract_to_score():
    # identical IP + finding_id in two tenants must remain two incidents after extract -> match -> dedup.
    ents = json.dumps([{"type": "ip", "role": "src", "value": "10.0.0.5"},
                       {"type": "ip", "role": "dst", "value": "203.0.113.66"}])
    docs = [{"finding_id": "f1", "category": "c2", "tenant_id": "A", "entities": ents},
            {"finding_id": "f1", "category": "c2", "tenant_id": "B", "entities": ents}]
    dets = x.detections_from_findings(docs)
    eps = [{"id": "epA", "label": "malicious", "behavior": "c2", "tenant": "A",
            "entities": [{"value": "10.0.0.5", "role": "initiator"}, {"value": "203.0.113.66", "role": "target"}]},
           {"id": "epB", "label": "malicious", "behavior": "c2", "tenant": "B",
            "entities": [{"value": "10.0.0.5", "role": "initiator"}, {"value": "203.0.113.66", "role": "target"}]}]
    r = ep.score(dets, eps)
    assert r["episode_recall"] == 1.0 and sorted(r["surfaced_ids"]) == ["epA", "epB"]
    assert r["analyst_items"] == 2, "same (tenant, finding_id) across tenants must not dedup to one"


# §25.3: extract must PROPAGATE observation intervals from each arm's actual time fields, so the
# temporal scorer has something to compare (previously every detection was untimed -> soft-credited).
def test_detections_carry_intervals_from_real_time_fields():
    f = x.detections_from_findings([{"finding_id": "f1", "category": "c2", "tenant_id": "t",
                                     "first_seen": "2026-01-01T00:00:00Z", "last_seen": "2026-01-01T00:05:00Z",
                                     "entities": json.dumps([{"type": "ip", "role": "src", "value": "10.0.0.5"}])}])
    iv = f[0]["interval"]
    assert iv and iv["end"] - iv["start"] == 300.0                 # 5 minutes, RFC3339 'Z' parsed
    a = x.detections_from_alerts([{"event_type": "alert", "src_ip": "10.0.0.5",
                                   "flow": {"start": "2026-01-01T00:00:00+00:00", "end": "2026-01-01T00:00:10+00:00"}}])
    assert a[0]["interval"]["end"] - a[0]["interval"]["start"] == 10.0
    # a finding with no time fields -> no interval (stays ambiguous under the scorer, not in-window)
    assert x.detections_from_findings([{"finding_id": "f2", "category": "c2",
                                        "entities": json.dumps([])}])[0]["interval"] is None
    # malformed timestamp -> None, not a crash
    assert x.detections_from_notices([{"src_ip": "10.0.0.5", "ts": "not-a-time"}])[0]["interval"] is None


def test_extract_to_score_disjoint_windows_do_not_cross_credit():
    # §25.3 acceptance: real-shaped exported findings in two disjoint windows must credit only their
    # own episode through the ACTUAL extractor -> scorer (not hand-built scorer dicts).
    ents = json.dumps([{"type": "ip", "role": "src", "value": "10.0.0.5"},
                       {"type": "ip", "role": "dst", "value": "203.0.113.66"}])
    docs = [{"finding_id": "fa", "category": "c2", "tenant_id": "default", "entities": ents,
             "first_seen": "2026-01-01T00:00:02Z", "last_seen": "2026-01-01T00:00:03Z"},   # window A
            {"finding_id": "fb", "category": "c2", "tenant_id": "default", "entities": ents,
             "first_seen": "2026-01-01T01:00:02Z", "last_seen": "2026-01-01T01:00:03Z"}]    # window B (1h later)
    a0 = ep_epoch("2026-01-01T00:00:00Z")
    eps = [{"id": "A", "label": "malicious", "behavior": "c2",
            "interval": {"start": a0, "end": a0 + 10},
            "entities": [{"value": "10.0.0.5", "role": "initiator"}, {"value": "203.0.113.66", "role": "target"}]},
           {"id": "B", "label": "malicious", "behavior": "c2",
            "interval": {"start": a0 + 3600, "end": a0 + 3610},
            "entities": [{"value": "10.0.0.5", "role": "initiator"}, {"value": "203.0.113.66", "role": "target"}]}]
    r = ep.score(x.detections_from_findings(docs), eps)
    assert sorted(r["surfaced_ids"]) == ["A", "B"] and r["episode_recall"] == 1.0
    # a single window-A finding must NOT credit window B (shared entities, disjoint time)
    r2 = ep.score(x.detections_from_findings(docs[:1]), eps)
    assert r2["surfaced_ids"] == ["A"] and r2["episodes_missed"] == 1


def test_replay_offset_maps_truth_onto_delivered_clock():
    # detection delivered at replay time; truth authored at original BASE -> offset reconciles them.
    ents = json.dumps([{"type": "ip", "role": "src", "value": "10.0.0.5"}])
    det = x.detections_from_findings([{"finding_id": "f", "category": "c2", "tenant_id": "default",
                                       "entities": ents, "first_seen": "2030-01-01T00:00:05Z",
                                       "last_seen": "2030-01-01T00:00:06Z"}])
    base = ep_epoch("2026-01-01T00:00:00Z")
    e = {"id": "x", "label": "malicious", "behavior": "c2", "interval": {"start": base, "end": base + 10},
         "entities": [{"value": "10.0.0.5", "role": "initiator"}]}
    off = ep_epoch("2030-01-01T00:00:00Z") - base
    assert ep.score(det, [e])["episode_recall"] == 0.0                        # no offset -> disjoint (ambiguous)
    assert ep.score(det, [e], replay_offset=off)["episode_recall"] == 1.0     # mapped -> in window


def ep_epoch(s):
    from datetime import datetime
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def test_build_results_composes_accuracy_and_noise():
    meta = {"scenario": "t", "granularity": "per-host"}
    arms = {
        "suricata_siem": {"flagged": {"10.0.0.5"}, "raw_events": 50000, "alerts": 300, "delivered": 300},
        "cernity_siem": {"flagged": {"10.0.0.5", "10.0.0.9"}, "raw_events": 50000, "alerts": 8, "delivered": 4},
    }
    truth = {"10.0.0.5", "10.0.0.9"}
    res = x.build_results(meta, arms, truth, honesty=["h"], caveats=["c"])
    assert res["arms"]["suricata_siem"]["accuracy"]["recall"] == 0.5     # caught 1 of 2
    assert res["arms"]["cernity_siem"]["accuracy"]["recall"] == 1.0      # caught both
    assert res["arms"]["cernity_siem"]["noise"]["suppression_ratio"] == 0.5
    assert res["honesty"] == ["h"] and res["caveats"] == ["c"]


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"ok {name}")
    print("all ok")
