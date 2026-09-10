"""U9 finding state-machine tests — pure logic.

  python3 test_state_machine.py
  pytest test_state_machine.py
"""
import state_machine as sm

SCAN = {
    "finding_id": "hscan-10.9.9.9-202608181941", "tenant_id": "homelab",
    "detector_id": "horizontal_scan", "detector_version": "1.0",
    "category": "recon", "severity": 5, "confidence": 0.7,
    "first_seen": "2026-08-18 19:40:00", "last_seen": "2026-08-18 19:41:00",
    "entities": '[{"type":"ip","role":"scanner","value":"10.9.9.9"}]',
    "state": "CANDIDATE",
}
LOW_CONF_EXFIL = dict(SCAN, finding_id="exfil-1", category="exfil", confidence=0.6)


def test_recon_low_severity_is_delivery_suppressed():
    # A low-severity recon scan (sev 5, no threat anchoring) finalizes on metadata
    # but is delivery-suppressed (B2): still emitted to final.v1 for correlation
    # and persisted, but not delivered to the analyst plane.
    f, route = sm.build_finding(SCAN)
    assert route == "final"                       # still on the bus for correlation
    assert f["state"] == "SUPPRESSED"
    assert f["enrichment_state"] == "NOT_REQUIRED"
    assert f["devo_delivery_state"] == "SUPPRESSED"
    assert f["suppression_reason"]
    assert f["mitre"] == ["T1046"]


def test_new_categories_map_to_mitre():
    # U1: coverage-gap detectors emit new categories that must resolve to techniques.
    for cat, tech in (("discovery", "T1046"), ("impact", "T1486"),
                      ("defense_evasion", "T1571"), ("credential_access", "T1110")):
        f, _ = sm.build_finding(dict(SCAN, category=cat, severity=8, confidence=1.0))
        assert tech in f["mitre"], f"{cat} -> {f['mitre']}"


def test_candidate_mitre_overrides_category_map():
    # U1: a detector may emit its own precise technique (e.g. AS-REP roasting).
    f, _ = sm.build_finding(dict(SCAN, category="credential_access", severity=8,
                                 confidence=1.0, mitre=["T1558.004"]))
    assert f["mitre"] == ["T1558.004"]             # candidate wins over the coarse map


def test_finding_above_suppression_ceiling_is_delivered():
    # The same detector raised above the ceiling (threat gate saw a hostile dst)
    # is delivered normally.
    f, route = sm.build_finding(dict(SCAN, severity=7))
    assert route == "final" and f["state"] == "FINAL"
    assert f["devo_delivery_state"] == "QUEUED" and f["suppression_reason"] == ""


def test_suppress_delivery_predicate():
    assert sm.suppress_delivery({"detector_id": "beacon", "severity": 5}) is True
    assert sm.suppress_delivery({"detector_id": "beacon", "severity": 6}) is False
    assert sm.suppress_delivery({"detector_id": "ids_signature", "severity": 2}) is False  # confirmed threat


def test_low_confidence_content_needs_packets():
    f, route = sm.build_finding(LOW_CONF_EXFIL)
    assert route == "capture"
    assert f["state"] == "CAPTURE_REQUESTED"
    assert f["enrichment_state"] == "REQUIRED"


def test_high_confidence_is_metadata_sufficient():
    f, route = sm.build_finding(dict(LOW_CONF_EXFIL, confidence=0.95))
    assert route == "final"


def test_failed_enrichment_still_finalizes():
    f, _ = sm.build_finding(LOW_CONF_EXFIL)          # CAPTURE_REQUESTED
    done = sm.apply_enrichment_result(f, {"status": "failed"})
    assert done["state"] == "FINAL"                   # not dropped
    assert done["enrichment_state"] == "ENRICHMENT_FAILED"
    assert done["devo_delivery_state"] == "QUEUED"


def test_ok_enrichment_attaches_evidence():
    f, _ = sm.build_finding(LOW_CONF_EXFIL)
    done = sm.apply_enrichment_result(f, {"status": "ok", "evidence_refs": ["minio://ndr-pcap/x"]})
    assert done["enrichment_state"] == "ENRICHED"
    assert "minio://ndr-pcap/x" in done["evidence_refs"]


def test_finding_id_deterministic_for_dedup():
    # Same window/scanner -> same id -> ClickHouse ReplacingMergeTree dedups.
    a, _ = sm.build_finding(SCAN)
    b, _ = sm.build_finding(dict(SCAN))
    assert a["finding_id"] == b["finding_id"]


def test_mitre_absent_category_is_empty():
    f, _ = sm.build_finding(dict(SCAN, category="unknown"))
    assert f["mitre"] == []


def test_g3_confirmed_threat_source_captures_evidence_regardless_of_confidence():
    # IDS-signature / threat-intel / nDPI-malicious findings capture packets for
    # EVIDENCE even at high confidence (G3), while behavioral high-conf still
    # finalizes on metadata (unchanged).
    f, route = sm.build_finding({"detector_id": "ids_signature", "category": "c2",
                                 "confidence": 0.9, "severity": 8, "entities": "[]"})
    assert route == "capture" and f["enrichment_state"] == "REQUIRED"
    assert sm.decide_enrichment({"detector_id": "threat_intel", "category": "c2", "confidence": 0.95}) == "packets_needed"
    # nDPI risk alone is a low-confidence feature: it does NOT spend capture budget
    # (corroboration by another detector escalates it), so it finalizes on metadata.
    assert sm.decide_enrichment({"detector_id": "ndpi_risk", "category": "malware", "confidence": 0.6}) == "metadata_sufficient"
    assert sm.decide_enrichment({"detector_id": "beacon", "category": "c2", "confidence": 0.95}) == "metadata_sufficient"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} finding state-machine tests passed")
