"""Validate hunt.v1 requests independently of the worker and evidence backend."""
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError


SCHEMA = json.loads(Path(__file__).with_name("hunt.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())


def job():
    return {
        "schema": "hunt.v1", "hunt_id": "hunt-1", "tenant": "tenant-a",
        "from": "2026-09-01T00:00:00Z", "to": "2026-09-02T00:00:00Z",
        "indicators": [{"type": "ip", "indicator": "192.0.2.1",
                        "intel_known_at": "2026-09-03T00:00:00Z"}],
    }


def test_schema_is_valid():
    Draft202012Validator.check_schema(SCHEMA)


@pytest.mark.parametrize("kind,value", [
    ("ip", "192.0.2.1"), ("domain", "example.test"),
    ("ja3", "a" * 32), ("ja4", "tls-fingerprint"), ("cert", "ab:cd"),
    ("hash", "a" * 64), ("url", "https://example.test/path"),
])
def test_indicator_dimensions_including_deferred(kind, value):
    # Deferred dimensions must reach the worker's explicit unsupported result.
    doc = job()
    doc["indicators"][0].update(type=kind, indicator=value)
    VALIDATOR.validate(doc)


def test_saved_intel_set():
    doc = job()
    del doc["indicators"]
    doc["intel_set"] = "feed.snapshot-1"
    VALIDATOR.validate(doc)


@pytest.mark.parametrize("field", ["schema", "hunt_id", "tenant", "from", "to"])
def test_required_job_fields(field):
    doc = job()
    del doc[field]
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize("both", [False, True])
def test_exactly_one_indicator_source(both):
    doc = job()
    if both:
        doc["intel_set"] = "feed"
    else:
        del doc["indicators"]
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize("patch", [
    {"schema": "hunt.v2"}, {"hunt_id": ""}, {"tenant": ""},
    {"tenant": ["tenant-a", "tenant-b"]}, {"tenant": "tenant/a"},
    {"from": "not-a-date"}, {"to": "2026-09-02T00:00:00"},
    {"page_size": 0}, {"page_size": 1001}, {"page_size": 1.5},
    {"indicators": []}, {"unexpected": True},
])
def test_invalid_job_fields(patch):
    doc = job()
    doc.update(patch)
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize("field", ["type", "indicator", "intel_known_at"])
def test_required_indicator_fields(field):
    doc = job()
    del doc["indicators"][0][field]
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize("patch", [
    {"type": "unknown"}, {"indicator": ""}, {"indicator": "   "},
    {"indicator": "x" * 2049}, {"intel_known_at": "not-a-date"},
    {"intel_known_at": "2026-09-03T00:00:00"}, {"unexpected": True},
])
def test_invalid_indicator_fields(patch):
    doc = job()
    doc["indicators"][0].update(patch)
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize("size", [1, 1000])
def test_page_size_boundaries(size):
    doc = job()
    doc["page_size"] = size
    VALIDATOR.validate(doc)


def test_indicator_count_bound():
    doc = job()
    doc["indicators"] *= 100
    VALIDATOR.validate(doc)
    doc["indicators"].append(doc["indicators"][0].copy())
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)
