"""Build gate for extract (run: `python test_extract.py`)."""
import json

import extract as x


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
