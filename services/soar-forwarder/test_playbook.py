"""U13 SOAR playbook tests (pure)."""
import playbook as p

SCAN = {"finding_id": "hscan-1", "category": "recon", "detector_id": "horizontal_scan",
        "severity": 5, "confidence": 0.7, "state": "FINAL",
        "enrichment_state": "NOT_REQUIRED", "mitre": ["T1046"],
        "entities": '[{"type":"ip","role":"scanner","value":"10.9.9.9"}]'}
HIGH = dict(SCAN, finding_id="c2-1", category="c2", severity=8, mitre=["T1071"])
FAILED = dict(HIGH, enrichment_state="ENRICHMENT_FAILED")


def test_recon_notifies_and_watchlists():
    a = p.actions_for(SCAN)
    assert "notify" in a and "watchlist_source" in a and "contain_sim" not in a


def test_high_severity_triggers_simulated_containment():
    assert "contain_sim" in p.actions_for(HIGH)


def test_failed_enrichment_flags_review():
    assert "flag_review" in p.actions_for(FAILED)


def test_notification_extracts_entities_and_priority():
    n = p.notification(HIGH)
    assert "10.9.9.9" in n["message"]
    assert n["priority"] == 4          # sev 8 -> priority 4
    assert "T1071" in n["tags"]


def test_notification_survives_bad_entities():
    n = p.notification(dict(SCAN, entities="not json"))
    assert n["message"]                # no crash


def test_playbook_bundles_actions_and_notification():
    r = p.playbook(SCAN)
    assert r["finding_id"] == "hscan-1"
    assert "notify" in r["actions"] and r["notification"]["title"]


def test_correlation_incident_escalates():
    inc = dict(HIGH, finding_id="incident-1", detector_id="correlation_incident",
               category="incident", severity=9)
    a = p.actions_for(inc)
    assert "escalate_incident" in a and "contain_sim" in a


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} playbook tests passed")
