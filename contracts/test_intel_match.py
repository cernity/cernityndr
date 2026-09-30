"""Validate real U2 candidates and reject incomplete or malformed match metadata."""
import copy
import importlib.util
import json
from pathlib import Path
import sys

import pytest
from jsonschema import Draft202012Validator, ValidationError

HERE = Path(__file__).resolve().parent
SERVICE = HERE.parent / "services" / "threat-intel"
SCHEMA = json.loads((HERE / "finding.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA)


def candidate(hash_match=False):
    # Load under a unique name: multiple services own an app.py in this repository.
    sys.path.insert(0, str(SERVICE))
    try:
        spec = importlib.util.spec_from_file_location("u2_contract_app", SERVICE / "app.py")
        app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(app)
        from test_lifecycle import IntelStore, rec, NOW
        import lifecycle
        store = IntelStore()
        app._intel["store"], app.TENANT = store, "contract-tenant"
        indicator, kind = ("a" * 64, "hash") if hash_match else ("bad.example", "domain")
        lifecycle.ingest(store, [rec(indicator, kind, 80, 0.9, "feed",
                                     tenant=app.TENANT)], NOW)
        sent = []
        class Producer:
            def send(self, topic, value):
                sent.append(value)
        if hash_match:
            lifecycle.ingest(store, [rec(indicator, kind, 70, 0.8, "second", tenant=app.TENANT)], NOW)
        event = {"type": "file", "fields": {"file": {"state": "hashes_only", "sha256": indicator}}} if hash_match else {"tls": {"sni": "bad.example"}}
        app.process_observation(event, Producer(), NOW)
        assert len(sent) == 1
        return sent[0]
    finally:
        sys.path.pop(0)


def test_live_candidate_contract():
    Draft202012Validator.check_schema(SCHEMA)
    doc = candidate()
    VALIDATOR.validate(doc)
    assert doc["intel_match"]["indicator"] == "bad.example"
    assert doc["intel_match"]["provenance"][0]["feed"] == "feed"


@pytest.mark.parametrize("field", SCHEMA["properties"]["intel_match"]["required"])
def test_match_requires_evidence_metadata(field):
    doc = candidate()
    del doc["intel_match"][field]
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize("patch", [
    {"type": "invented"}, {"indicator": ""},
    {"score": 101}, {"score": -1}, {"source_trust": 2}, {"source_trust": -1},
    {"tlp": "unknown"}, {"provenance": []}, {"suppressed": "false"},
    {"observed_field": ""}, {"observed_value": ""}, {"extra": True},
])
def test_match_rejects_invalid_metadata(patch):
    doc = candidate()
    doc["intel_match"].update(patch)
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


def test_match_provenance_requires_source_trust():
    doc = copy.deepcopy(candidate())
    del doc["intel_match"]["provenance"][0]["source_trust"]
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


def test_legacy_candidate_still_valid():
    doc = candidate()
    del doc["intel_match"]
    VALIDATOR.validate(doc)


def test_hash_candidate_dedup_and_finding_lifecycle():
    doc = candidate(hash_match=True)
    VALIDATOR.validate(doc)
    assert len(doc["intel_match"]["provenance"]) == 2
    spec = importlib.util.spec_from_file_location("u5_finding_state", SERVICE.parent / "finding-service/state_machine.py")
    state = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(state)
    finding, route = state.build_finding(doc)
    assert route == "final_and_capture"
    assert finding["intel_match"] == doc["intel_match"]
    VALIDATOR.validate(finding)
