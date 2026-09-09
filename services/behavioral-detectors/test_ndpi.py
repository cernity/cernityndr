"""nDPI risk-set normalization: Suricata emits `flow_risk` (dict or list); the
detector must read it (not just fall back to breed)."""
import os

os.environ["NDR_TENANT"] = "default"

import app
import detectors as det


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


if __name__ == "__main__":
    test_flow_risk_dict_id_to_name()
    test_flow_risk_dict_name_to_bool()
    test_flow_risk_list_passthrough()
    test_legacy_risk_field_still_works()
    test_empty_when_no_ndpi()
    test_risk_feeds_the_detector()
    print("all nDPI tests passed")
