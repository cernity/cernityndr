"""B-U8/R12: the capability manifest declares the producer->topic->consumer matrix + the capture-control
credential and carve-scope contracts. Validates the manifest is coherent (and that Modbus is wired to
ot-detectors, and the capture credential is least-privilege — read arm, write status/result)."""
import json
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MAN = json.load(open(os.path.join(_ROOT, "deploy", "central", "capability-manifest.json")))
_ROUTE = open(os.path.join(_ROOT, "deploy", "fluent-bit", "route.lua"), encoding="utf-8").read()
_BY_TOPIC = {t["topic"]: t for t in _MAN["topics"]}


def test_modbus_wired_to_ot_detectors():
    assert "ot-detectors" in _BY_TOPIC["suricata.modbus.v1"]["consumers"]
    assert 'topic = "suricata.modbus.v1"' in _ROUTE, "route.lua must route modbus explicitly"


def test_finding_flow_is_declared():
    assert "finding-service" in _BY_TOPIC["ndr.finding.candidate.v1"]["consumers"]
    assert set(_BY_TOPIC["ndr.finding.final.v1"]["consumers"]) >= {"correlation-service", "findings-forwarder"}


def test_capture_credential_is_least_privilege():
    cc = _MAN["capture_control_credential"]
    assert cc["read"] == ["ndr.capture.arm.v1"]                       # consume the arm directive
    assert set(cc["write"]) == {"ndr.capture.status.v1", "ndr.enrichment.request.v1"}
    # it must not just reuse the write-only telemetry shipper credential
    assert "not" in cc["requirement"].lower() and "telemetry" in cc["requirement"].lower()


def test_carve_scope_disclosure_documented():
    assert "broad-window" in _MAN["carve_scope_disclosure"]["requirement"]


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok  " + _n)
    print("\nall capability-manifest tests passed")
