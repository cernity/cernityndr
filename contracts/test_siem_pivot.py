"""Contract test for the §18.4 stable pivot field set and its CIM/ECS mappings.

Guards that siem_pivot.schema.json and services/findings-forwarder/mappings.py stay in lockstep: the
extractor output conforms to the schema, and every schema field is covered by both the CIM and ECS
maps (no pivot silently unmapped)."""
import importlib.util
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

HERE = Path(__file__).resolve().parent
FORWARDER = HERE.parent / "services" / "findings-forwarder"
SCHEMA = json.loads((HERE / "siem_pivot.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA)


def _mappings():
    # The forwarder dir is not a package; load mappings.py by path (multiple services own same-named
    # modules in this repo — the test_intel_match.py pattern).
    sys.path.insert(0, str(FORWARDER))
    try:
        spec = importlib.util.spec_from_file_location("u7_mappings", FORWARDER / "mappings.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    finally:
        sys.path.remove(str(FORWARDER))


mappings = _mappings()

REPRESENTATIVE = {
    "finding_id": "beacon-1", "revision": 2, "detector_version": "2.0",
    "model_version": "slips-2026.09", "sensor_ids": ["sensor-a"],
    "entities": [{"type": "entity", "value": "default|asset:h7"},
                 {"type": "asset", "value": "asset:h7"}],
    "evidence_refs": ["minio://ndr-pcap/x.pcap"],
    "source_events": [{"community_id": "1:abc=", "obs_id": "obs:" + "a" * 64}],
    "incident_id": "incident-1",
}


def test_schema_is_valid():
    Draft202012Validator.check_schema(SCHEMA)


def test_pivot_output_conforms_to_schema():
    # Scenario 1 (contract side): the extractor's canonical output validates against the pivot schema,
    # for both a rich finding and a sparse one (all-null but finding_id).
    VALIDATOR.validate(mappings.pivot(REPRESENTATIVE))
    VALIDATOR.validate(mappings.pivot({"finding_id": "x"}))


def test_every_schema_field_is_mapped_to_cim_and_ecs():
    # No pivot field may be defined in the schema without a CIM and an ECS home.
    props = set(SCHEMA["properties"])
    assert props == set(mappings.CIM_MAP), "CIM_MAP drifted from schema"
    assert props == set(mappings.ECS_MAP), "ECS_MAP drifted from schema"


def test_maps_are_injective():
    # A canonical field must not collapse onto another's target name (would clobber a pivot on export).
    assert len(set(mappings.CIM_MAP.values())) == len(mappings.CIM_MAP)
    assert len(set(mappings.ECS_MAP.values())) == len(mappings.ECS_MAP)


def test_file_artifact_and_investigation_are_nullable():
    # Track A / U9 fields: null must validate (they don't exist yet).
    p = mappings.pivot(REPRESENTATIVE)
    assert p["file_artifact_id"] is None and p["investigation_id"] is None
    VALIDATOR.validate(p)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"all {len(fns)} siem_pivot contract tests passed")
