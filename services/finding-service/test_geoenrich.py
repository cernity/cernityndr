"""geoenrich tests (pure; fake readers, no MaxMind DB or geoip2 needed)."""
import json

import geoenrich


class _City:
    def __init__(self, iso):
        self.country = type("C", (), {"country": type("X", (), {"iso_code": iso})})()

    def city(self, ip):
        return self.country  # our fake returns the same object shape .country.iso_code


class _FakeGeo:
    def city(self, ip):
        return type("R", (), {"country": type("C", (), {"iso_code": "NL"})})()


class _FakeAsn:
    def asn(self, ip):
        return type("R", (), {"autonomous_system_number": 14061,
                              "autonomous_system_organization": "DigitalOcean"})()


def _finding(entities):
    return {"finding_id": "beacon-1", "entities": json.dumps(entities)}


def test_no_readers_is_noop():
    f = _finding([{"type": "ip", "role": "dst", "value": "8.8.8.8"}])
    out = geoenrich.enrich_finding(f, {})
    assert "geo" not in out


def test_external_ip_enriched():
    f = _finding([{"type": "ip", "role": "src", "value": "192.168.1.5"},
                  {"type": "ip", "role": "dst", "value": "8.8.8.8"}])
    out = geoenrich.enrich_finding(f, {"geo": _FakeGeo(), "asn": _FakeAsn()})
    assert "192.168.1.5" not in out["geo"]                 # internal skipped
    assert out["geo"]["8.8.8.8"] == {"country": "NL", "asn": 14061, "as_org": "DigitalOcean"}


def test_community_id_passthrough():
    f = _finding([{"type": "community_id", "value": "1:abc="},
                  {"type": "ip", "role": "dst", "value": "8.8.8.8"}])
    out = geoenrich.enrich_finding(f, {})
    assert out["community_id"] == "1:abc="


def test_is_external():
    assert geoenrich._is_external("1.1.1.1") is True
    assert geoenrich._is_external("10.0.0.1") is False
    assert geoenrich._is_external("192.168.0.1") is False
    assert geoenrich._is_external("127.0.0.1") is False
    assert geoenrich._is_external("not-an-ip") is False


def test_entities_as_list():
    f = {"finding_id": "x", "entities": [{"type": "ip", "value": "8.8.8.8"}]}
    out = geoenrich.enrich_finding(f, {"asn": _FakeAsn()})
    assert out["geo"]["8.8.8.8"]["asn"] == 14061


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print("ok ", fn.__name__)
    print("all %d geoenrich tests passed" % len(fns))
