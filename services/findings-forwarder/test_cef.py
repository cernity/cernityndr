import cef

FINDING = {
    "finding_id": "beacon-1", "detector_id": "beacon", "category": "c2",
    "severity": 8, "tenant_id": "default", "mitre": ["T1071"],
    "entities": [{"type": "ip", "role": "src", "value": "10.0.0.5"},
                 {"type": "ip", "role": "dst", "value": "203.0.113.10"}],
}


def test_cef_header_and_fields():
    line = cef.to_cef(FINDING)
    assert line.startswith("CEF:0|Cernity|NDR|1.0|beacon|c2|8|")
    assert "src=10.0.0.5" in line
    assert "dst=203.0.113.10" in line
    assert "cs1=beacon-1" in line
    assert "cs2=T1071" in line


def test_cef_entities_from_json_string():
    f = dict(FINDING, entities='[{"role":"src","value":"1.1.1.1"},{"role":"dst","value":"2.2.2.2"}]')
    line = cef.to_cef(f)
    assert "src=1.1.1.1" in line and "dst=2.2.2.2" in line


def test_cef_escapes_pipe_in_header():
    line = cef.to_cef(dict(FINDING, detector_id="a|b"))
    assert "a\\|b" in line


if __name__ == "__main__":
    test_cef_header_and_fields()
    test_cef_entities_from_json_string()
    test_cef_escapes_pipe_in_header()
    print("ok test_cef")
