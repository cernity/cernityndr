"""nDPI risk-set normalization: Suricata emits `flow_risk` (dict or list); the
detector must read it (not just fall back to breed)."""
import os
import json
from pathlib import Path

os.environ["NDR_TENANT"] = "default"

import app
import detectors as det
import ndpi_policy as ndpi_pol


def test_flow_risk_dict_id_to_name():
    risks = app._ndpi_risks({"flow_risk": {"7": "Self-signed Certificate", "0": "Malicious JA3"}})
    assert "Self-signed Certificate" in risks and "Malicious JA3" in risks


def test_flow_risk_dict_name_to_bool():
    risks = app._ndpi_risks({"flow_risk": {"Malicious JA3 Fingerprint": True}})
    assert "Malicious JA3 Fingerprint" in risks


def test_flow_risk_list_passthrough():
    assert app._ndpi_risks({"flow_risk": ["Suspicious DGA Domain"]}) == ["Suspicious DGA Domain"]


def test_legacy_risk_field_still_works():
    assert app._ndpi_risks({"risk": ["Cleartext Credentials"]}) == ["Cleartext Credentials"]


def test_empty_when_no_ndpi():
    assert app._ndpi_risks({}) == []


def test_risk_feeds_the_detector():
    # a real Suricata flow_risk name must trip the ndpi risk detector
    risks = app._ndpi_risks({"flow_risk": {"1": "Malicious JA3 Fingerprint"}})
    hit, matched = det.ndpi_risk_hit([str(r) for r in risks])
    assert hit and matched


# --- U3/R15: emitted candidates must conform to the strict finding schema ---
def _load_schema():
    # locate the finding schema across layouts: repo (a parent has contracts/), a flat image
    # (/app), or not bundled -> None (schema tests then skip; R15 is also covered by
    # contracts/test_contracts.py and the behavioral image does not validate at runtime).
    here = Path(__file__).resolve()
    for base in list(here.parents) + [Path("/app")]:
        for rel in ("contracts/finding.schema.json", "finding.schema.json"):
            p = base / rel
            if p.exists():
                return json.loads(p.read_text())
    return None


_SCHEMA = _load_schema()
_PROPS = set(_SCHEMA["properties"]) if _SCHEMA else set()
_REQ = set(_SCHEMA["required"]) if _SCHEMA else set()


def _conforms(cand):
    # finding.schema.json is additionalProperties:false -> every key must be declared, required present
    assert cand is not None, "candidate was dedup-suppressed; use a unique identity/entities per test"
    extra = set(cand) - _PROPS
    assert not extra, f"undeclared fields (schema additionalProperties:false): {extra}"
    assert _REQ <= set(cand), f"missing required: {_REQ - set(cand)}"


def test_legacy_candidate_conforms_to_schema():
    if _SCHEMA is None:
        return       # schema not bundled in this image
    ent = json.dumps([{"type": "ip", "role": "src", "value": "10.0.0.9"}])
    _conforms(app._candidate("ndpi_risk", "malware", 6, 0.6, ent, "schema-legacy"))


def test_structured_candidate_conforms_to_schema():
    if _SCHEMA is None:
        return       # schema not bundled in this image
    fnds = ndpi_pol.ndpi_findings({"flow_risk": {"35": {"risk": "Susp Entropy", "severity": "Low"}}},
                                  "10.0.0.1", "10.0.0.2", "schema-structured")
    assert len(fnds) == 1
    fnd = fnds[0]
    c = app._candidate("ndpi_risk", fnd["category"], fnd["severity"], fnd["confidence"],
                       json.dumps(fnd["entities"]), "schema-structured",
                       detector_version=ndpi_pol.DETECTOR_VERSION, identity=fnd["identity"])
    _conforms(c)
    assert c["detector_version"] == "2.0" and c["category"] == "observation" and c["severity"] == 2


def test_r15_fields_are_declared_in_schema():
    if _SCHEMA is None:
        return       # schema not bundled in this image
    # the fields the emitter actually sets, previously rejected by additionalProperties:false
    assert {"observed", "emitted_at", "revision"} <= _PROPS


def test_structured_mode_default_is_legacy():
    assert app.NDPI_MODE == "legacy"       # inert until explicitly enabled (plan 008 KTD6)


if __name__ == "__main__":
    import inspect
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    ran = 0
    for fn in fns:
        if inspect.getfullargspec(fn).args:
            continue
        fn(); print(f"ok  {fn.__name__}"); ran += 1
    print(f"\nall {ran} nDPI tests passed")
