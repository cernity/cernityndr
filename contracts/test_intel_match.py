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


def candidate():
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
        lifecycle.ingest(store, [rec("bad.example", "domain", 80, 0.9, "feed",
                                     tenant=app.TENANT)], NOW)
        sent = []
        class Producer:
            def send(self, topic, value):
                sent.append(value)
        app.process_observation({"tls": {"sni": "bad.example"}}, Producer(), NOW)
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
    {"type": "hash"}, {"type": "invented"}, {"indicator": ""},
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
