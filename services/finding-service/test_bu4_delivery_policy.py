"""B-U4 (plan 010 Track B, review R06): delivery policy is applied at every terminal revision,
independent of the enrichment outcome — losing (or gaining) evidence never changes whether a
low-severity non-threat finding reaches the analyst plane, and an already-delivered finding is
never retracted."""
import os

os.environ.setdefault("LOG_FORMAT", "text")

import state_machine as sm  # noqa: E402


def _cap(sev, det="beacon"):
    """An undelivered, capture-bound finding."""
    return {"finding_id": "f", "tenant_id": "t", "detector_id": det, "category": "c2", "severity": sev,
            "confidence": 0.5, "state": "CAPTURE_REQUESTED", "enrichment_state": "REQUIRED",
            "revision": 1, "evidence_refs": [], "suppression_reason": ""}


def test_low_sev_capture_timeout_is_suppressed_not_delivered():
    done = sm.finalize_timeout(_cap(2))
    assert done["state"] == "SUPPRESSED", "losing evidence must not promote a low-sev finding to the analyst"
    assert done["enrichment_state"] == "TIMEOUT"


def test_low_sev_capture_enriched_is_suppressed_but_keeps_evidence():
    done = sm.apply_enrichment_result(_cap(2), {"status": "ok", "evidence_refs": ["minio://x"]})
    assert done["state"] == "SUPPRESSED"
    assert "minio://x" in done["evidence_refs"]          # retained for correlation/audit, just not delivered


def test_high_sev_capture_timeout_is_delivered():
    assert sm.finalize_timeout(_cap(7))["state"] == "FINAL"


def test_delivered_confirmed_threat_stays_final_on_timeout():
    f = dict(_cap(2, det="ids_signature"))
    f["state"], f["enrichment_state"] = "FINAL", "PENDING"   # already delivered (deliver-now)
    assert sm.finalize_timeout(f)["state"] == "FINAL", "an already-delivered finding is never retracted"


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok  " + _n)
    print("\nall B-U4 delivery-policy tests passed")
