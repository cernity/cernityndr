"""Managed file hashes retain their evidence through finalization."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("hash_state", Path(__file__).with_name("state_machine.py"))
state = importlib.util.module_from_spec(spec)
spec.loader.exec_module(state)


def test_hash_intel_survives_finalization_and_timeout():
    match = {"type": "hash", "indicator": "a" * 64, "feed": "malwarebazaar",
             "source": "abuse.ch", "score": 90, "tlp": "green",
             "first_seen": "2026-09-01T00:00:00Z", "expiry": "2026-10-01T00:00:00Z"}
    candidate = {"finding_id": "ti-hash", "tenant_id": "a", "detector_id": "threat_intel",
                 "category": "malware", "severity": 9, "confidence": .81,
                 "entities": "[]", "intel_match": match}
    finding, route = state.build_finding(candidate)
    assert route == "final_and_capture" and finding["state"] == "FINAL"
    assert finding["intel_match"] == match
    assert state.finalize_timeout(finding)["intel_match"] == match
