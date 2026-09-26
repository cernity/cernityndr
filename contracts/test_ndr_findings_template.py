"""B-U7/R11: the checked-in ndr-findings ES index template pins queryable core fields to explicit
types (deterministic aggregation/sort) and flattens intel/geo (no field explosion)."""
import json
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TMPL = json.load(open(os.path.join(_ROOT, "deploy", "central", "es", "ndr-findings-index-template.json")))
_PROPS = _TMPL["template"]["mappings"]["properties"]


def test_targets_ndr_findings():
    assert _TMPL["index_patterns"] == ["ndr-findings-*"]


def test_intel_and_geo_are_flattened():
    assert _PROPS["intel"]["type"] == "flattened" and _PROPS["geo"]["type"] == "flattened"


def test_core_fields_are_explicitly_typed():
    for f in ("finding_id", "tenant_id", "detector_id", "detector_version", "category", "state"):
        assert _PROPS[f]["type"] == "keyword", f
    for f in ("severity", "revision"):
        assert _PROPS[f]["type"] in ("integer", "long"), f
    for f in ("@timestamp", "first_seen", "last_seen", "emitted_at"):
        assert _PROPS[f]["type"] == "date", f


def test_field_limit_raised():
    assert int(_TMPL["template"]["settings"]["index.mapping.total_fields.limit"]) >= 2000


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok  " + _n)
    print("\nall ndr-findings template tests passed")
