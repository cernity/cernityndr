"""sensor-quality.v1 fixtures and the finding-service wire result."""
import copy
import importlib.util
import json
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
from test_sensor_health import CHECKER

HERE = Path(__file__).parent
SCHEMA = json.loads((HERE / "sensor-quality.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=CHECKER)
MINIMAL = {"schema_version": "sensor-quality.v1", "tenant_id": "acme", "sensor_id": "s1",
           "observed_at": "2026-10-14T00:00:00Z", "quality": "unknown",
           "signals": {"capture_drop_ratio": None, "applayer_flows_per_pkt": None}, "reasons": []}
FULL = dict(MINIMAL, quality="degraded", reasons=["CAPTURE_LOSS"],
            signals={"capture_drop_ratio": 0.3, "applayer_flows_per_pkt": 0.1})


def rejects(doc):
    try:
        VALIDATOR.validate(doc)
    except ValidationError:
        return True
    return False


def test_valid_schema_and_documents():
    Draft202012Validator.check_schema(SCHEMA)
    VALIDATOR.validate(MINIMAL)
    for quality in ("good", "degraded", "blind", "unknown"):
        VALIDATOR.validate(dict(FULL, quality=quality))


def test_invalid_documents():
    for key in SCHEMA["required"]:
        doc = copy.deepcopy(FULL)
        del doc[key]
        assert rejects(doc), key
    for patch in ({"schema_version": "v2"}, {"sensor_id": ""}, {"tenant_id": ""},
                  {"quality": "healthy"}, {"observed_at": "yesterday"}, {"extra": 1},
                  {"reasons": [""]}, {"reasons": ["CAPTURE_LOSS", "CAPTURE_LOSS"]}):
        assert rejects(dict(FULL, **patch)), patch
    for key in FULL["signals"]:
        for value in (-1, "0", True):
            doc = copy.deepcopy(FULL)
            doc["signals"][key] = value
            assert rejects(doc)
        doc = copy.deepcopy(FULL)
        del doc["signals"][key]
        assert rejects(doc)
    assert rejects(dict(FULL, signals=dict(FULL["signals"], capture_drop_ratio=1.1)))
    assert rejects(dict(FULL, signals=dict(FULL["signals"], extra=0)))


def test_adjusted_finding_contract():
    spec = importlib.util.spec_from_file_location("quality_state_machine", HERE.parent / "services/finding-service/state_machine.py")
    sm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sm)
    schema = json.loads((HERE / "finding.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=CHECKER)
    cand = {"finding_id": "f1", "tenant_id": "acme", "detector_id": "scan",
            "detector_version": "1", "category": "recon", "severity": 7, "confidence": 0.8,
            "first_seen": FULL["observed_at"], "last_seen": FULL["observed_at"],
            "source_events": [{"record": {"host": "s1"}}], "state": "CANDIDATE"}
    finding, _ = sm.build_finding(cand, lambda tenant, sensor: FULL)
    validator.validate(finding)
    unknown, _ = sm.build_finding(dict(cand, source_events=[]), lambda *args: None)
    validator.validate(unknown)
    for patch in ({"factor": 1.1}, {"original_confidence": -1}, {"quality": "bad"}, {"extra": True}):
        doc = copy.deepcopy(finding)
        doc["observation_quality"].update(patch)
        assert list(validator.iter_errors(doc)), patch


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok ", name)
