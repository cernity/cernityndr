"""Finding-contract conformance (plan U8). Asserts every emitted candidate
matches the CONTRACT.md envelope, so a schema drift fails the build."""
import json
import os

os.environ.setdefault("NDR_STATE_BACKEND", "memory")
import app

_ENVELOPE = {"finding_id", "tenant_id", "detector_id", "detector_version",
             "category", "severity", "confidence", "first_seen", "last_seen",
             "entities", "state"}
_CATEGORIES = {"c2", "exfil", "dns_tunnel", "malware", "anomaly"}
_DETECTORS = {"beacon", "beacon_fqdn", "strobe", "long_connection",
              "long_connection_cumulative", "exfil", "dns_tunnel", "dns_exploded",
              "ndpi_risk", "rare_destination"}


_nonce = [0]


def _sample(detector_id, category, sev):
    _nonce[0] += 1                        # unique per call so shared dedup never suppresses a sample
    ents = json.dumps([{"type": "ip", "role": "src", "value": "10.0.0.1"},
                       {"type": "ip", "role": "dst", "value": f"203.0.113.{_nonce[0] % 250}"},
                       {"type": "nonce", "value": _nonce[0]}])
    return app._candidate(detector_id, category, sev, 0.9, ents, "acme")


def test_envelope_shape_and_types():
    c = _sample("beacon", "c2", 7)
    assert c is not None
    assert set(c.keys()) == _ENVELOPE, f"envelope keys drifted: {set(c.keys()) ^ _ENVELOPE}"
    assert isinstance(c["severity"], int) and 1 <= c["severity"] <= 10
    assert isinstance(c["confidence"], float) and 0 <= c["confidence"] <= 1
    assert c["state"] == "CANDIDATE"
    assert c["detector_version"] == "1.0"
    assert c["tenant_id"] == "acme"
    json.loads(c["entities"])            # entities is JSON-encoded


def test_all_documented_detectors_conform():
    for det_id in _DETECTORS:
        c = _sample(det_id, "c2", 5)
        assert c is not None and set(c.keys()) == _ENVELOPE, f"{det_id} envelope"
        assert c["detector_id"] == det_id


def test_category_values_are_in_contract():
    for cat in _CATEGORIES:
        c = _sample("beacon", cat, 5)
        assert c["category"] in _CATEGORIES


if __name__ == "__main__":
    import inspect
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        if inspect.getfullargspec(fn).args:
            continue
        fn(); print(f"ok  {fn.__name__}")
    print("all contract conformance tests passed")
