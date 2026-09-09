"""Tests for IDS-alert promotion (gap G1). Real-shaped Suricata alert records."""
import json
import promote as p

# A real threat: Spamhaus DROP-listed inbound (from the sensor's live alert log).
SPAMHAUS = {
    "event_type": "alert", "src_ip": "168.80.32.59", "dest_ip": "192.168.222.245",
    "alert": {"signature": "ET DROP Spamhaus DROP Listed Traffic Inbound group 29",
              "category": "Misc Attack", "severity": 2, "signature_id": 2400028,
              "metadata": {"signature_severity": ["Minor"]}},
}
TROJAN = {
    "event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "45.9.148.2",
    "alert": {"signature": "ET MALWARE Cobalt Strike Beacon", "category": "A Network Trojan was detected",
              "severity": 1, "signature_id": 2028000},
}
# Noise that must NOT promote:
ETHERTYPE = {"event_type": "alert", "src_ip": "a", "dest_ip": "b",
             "alert": {"signature": "SURICATA Ethertype unknown", "category": "Generic Protocol Command Decode",
                       "severity": 3, "signature_id": 2200076}}
STUN = {"event_type": "alert", "src_ip": "a", "dest_ip": "b",
        "alert": {"signature": "ET INFO Session Traversal Utilities NAT (STUN Binding Request)",
                  "category": "Misc activity", "severity": 3, "signature_id": 2016149}}
FLOW = {"event_type": "flow", "src_ip": "a", "dest_ip": "b"}


def test_promotes_known_bad_ip_hit():
    c = p.to_candidate(SPAMHAUS)
    assert c is not None
    assert c["detector_id"] == "ids_signature" and c["category"] == "c2"
    assert c["severity"] == 8 and c["confidence"] == 0.9
    assert "168.80.32.59" in c["entities"] and "Spamhaus" in c["entities"]


def test_promotes_malware_c2_as_sev9():
    c = p.to_candidate(TROJAN)
    assert c is not None and c["category"] == "c2" and c["severity"] == 9


def test_finding_carries_community_id_join_key():
    # join back to the exact connection's telemetry (metadata enrichment).
    c = p.to_candidate(dict(SPAMHAUS, community_id="1:xyz", flow_id=99))
    assert '"community_id"' in c["entities"] and '"1:xyz"' in c["entities"]
    assert '"flow_id"' in c["entities"]


def test_no_join_key_when_source_event_lacks_it():
    c = p.to_candidate(SPAMHAUS)            # no community_id/flow_id on the alert
    assert "community_id" not in c["entities"] and "flow_id" not in c["entities"]


def test_suppresses_decoder_noise():
    assert p.to_candidate(ETHERTYPE) is None
    assert p.is_threat_alert(ETHERTYPE["alert"]) is False


def test_suppresses_et_info_stun():
    assert p.to_candidate(STUN) is None


def test_ignores_non_alert_events():
    assert p.to_candidate(FLOW) is None


def test_major_signature_severity_promotes_even_if_numeric_soft():
    a = {"signature": "ET EXPLOIT Something", "category": "Web Application Attack",
         "severity": 3, "signature_id": 2099999, "metadata": {"signature_severity": ["Major"]}}
    assert p.is_threat_alert(a) is True
    assert p.category_for(a) == "malware"


if __name__ == "__main__":
    for n, f in sorted(globals().items()):
        if n.startswith("test_") and callable(f):
            f(); print("ok:", n)
    print("all passed")
