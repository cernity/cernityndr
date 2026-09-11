"""Build gate for slips_map (run directly: `python test_slips_map.py`)."""
import json

from slips_map import alert_to_candidate


def test_maps_source_target_threat_level_and_technique():
    alert = {"ID": "abc-1", "Category": ["Intrusion.Botnet"],
             "Source": [{"IP4": ["10.0.0.5"]}], "Target": [{"IP4": ["93.184.216.34"]}],
             "threat_level": "high", "Confidence": 0.8,
             "Description": "periodic C2 behavior", "DetectTime": "2026-09-10T12:00:00Z"}
    c = alert_to_candidate(alert, "acme")
    assert c["detector_id"] == "slips_ml"
    assert c["tenant_id"] == "acme"
    assert c["finding_id"] == "slips-abc-1"
    assert c["category"] == "c2"
    assert c["mitre"] == ["T1071"]
    assert c["severity"] == 8
    assert c["confidence"] == 0.8
    assert c["state"] == "CANDIDATE"
    assert c["first_seen"] == "2026-09-10T12:00:00Z"       # RFC3339 UTC
    ents = json.loads(c["entities"])   # emitted as a json string, matching detectors
    assert {"type": "ip", "role": "attacker", "value": "10.0.0.5"} in ents
    assert any(e.get("role") == "victim" and e["value"] == "93.184.216.34" for e in ents)


def test_unknown_category_is_honest_anomaly_no_fabricated_mitre():
    alert = {"Category": ["Anomaly.Traffic"], "Source": [{"IP4": ["10.0.0.9"]}],
             "threat_level": "medium"}
    c = alert_to_candidate(alert, "t")
    assert c["category"] == "anomaly"
    assert "mitre" not in c          # no defensible technique -> no ATT&CK invented
    assert c["severity"] == 6


def test_absent_threat_level_defaults_critical():
    c = alert_to_candidate({"Source": [{"IP4": ["10.0.0.1"]}]}, "t")
    assert c["severity"] == 9        # _THREAT_SEV["critical"]
    assert c["confidence"] == 0.7    # default when SLIPS omits Confidence


def test_ipv6_and_stable_id_when_no_alert_id():
    a = {"Category": ["Recon.Scanning"], "Source": [{"IP6": ["fe80::1"]}],
         "threat_level": "low", "DetectTime": "2026-09-10T01:02:03Z", "Description": "scan"}
    c1 = alert_to_candidate(a, "t")
    c2 = alert_to_candidate(a, "t")
    assert c1["category"] == "recon" and c1["mitre"] == ["T1046"]
    assert c1["severity"] == 4
    assert c1["finding_id"] == c2["finding_id"]   # deterministic without an ID


def test_no_attacker_ip_is_dropped():
    assert alert_to_candidate({"Category": ["Anomaly"], "Source": []}, "t") is None
    assert alert_to_candidate({"Category": ["Anomaly"]}, "t") is None


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok {name}")
    print("all ok")
