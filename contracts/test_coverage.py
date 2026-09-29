"""Contract test for coverage.v1: the coverage-service /coverage response shape,
validated by building a real report from coverage.py and checking it against the
schema, plus a few malformed reports that must be rejected.
"""
import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

SCHEMA = json.loads(Path(__file__).with_name("coverage.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA)


def _coverage_module():
    path = Path(__file__).resolve().parents[1] / "services/coverage-service/coverage.py"
    spec = importlib.util.spec_from_file_location("coverage_logic", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_schema_is_valid():
    Draft202012Validator.check_schema(SCHEMA)


def test_built_report_matches_schema():
    coverage = _coverage_module()
    dmap = coverage.load_detector_map([
        {"detector_id": "east-west", "techniques": ["T1046", "T1021.002"]},
    ])
    report = coverage.build_coverage(dmap, observed=["T1046", "T1486"])
    VALIDATOR.validate(report)  # real service output conforms to the contract


@pytest.mark.parametrize("field", SCHEMA["required"])
def test_missing_top_level_field_rejected(field):
    coverage = _coverage_module()
    report = coverage.build_coverage(coverage.load_detector_map([]), observed=[])
    del report[field]
    with pytest.raises(ValidationError):
        VALIDATOR.validate(report)


@pytest.mark.parametrize("bad_technique", ["T104", "1046", "T1046.1", "not-a-technique"])
def test_malformed_technique_id_rejected(bad_technique):
    report = {
        "techniques": [{"technique": bad_technique, "covered": True, "detectors": [], "observed": False}],
        "gaps": [],
        "summary": {"total": 1, "covered": 1, "gaps": 0, "observed": 0},
    }
    with pytest.raises(ValidationError):
        VALIDATOR.validate(report)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
