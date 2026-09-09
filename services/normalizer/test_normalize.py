"""U6 normalizer tests — pure transforms, no Kafka/ClickHouse.

  python3 test_normalize.py     # zero-dep self-check
  pytest test_normalize.py
"""
import models as m

FLOW = {
    "event_type": "flow", "timestamp": "2026-08-18T18:20:00.0Z",
    "flow_id": 42, "community_id": "1:abc",
    "src_ip": "10.0.0.5", "src_port": 51000,
    "dest_ip": "1.1.1.1", "dest_port": 443, "proto": "TCP",
    "app_proto": "tls",
    "flow": {"pkts_toserver": 10, "pkts_toclient": 8,
             "bytes_toserver": 1200, "bytes_toclient": 3400, "state": "established"},
    "ndpi": {"proto": "TLS.Google", "app_protocol": "Google",
             "risk": ["Known Proto on Non Std Port"]},
}
TLS = {
    "event_type": "tls", "timestamp": "2026-08-18T18:20:01.0Z",
    "community_id": "1:abc", "src_ip": "10.0.0.5", "dest_ip": "1.1.1.1",
    "dest_port": 443,
    "tls": {"sni": "example.com", "version": "TLS 1.3",
            "ja3": {"hash": "aaa"}, "ja3s": {"hash": "bbb"}, "ja4": "t13d1516h2_x_y"},
}
DNS_V3 = {
    "event_type": "dns", "timestamp": "2026-08-18T18:20:02.0Z",
    "community_id": "1:abc", "src_ip": "10.0.0.5", "dest_ip": "192.168.222.19",
    "dns": {"version": 3, "queries": [{"rrname": "example.com", "rrtype": "A"}],
            "rcode": "NOERROR"},
}


def test_flow_maps_core_fields():
    tbl, row = m.normalize(FLOW, "homelab", "ol9-suri")
    assert tbl == "network_flow"
    assert row["community_id"] == "1:abc"
    assert row["dst_ip"] == "1.1.1.1" and row["dst_port"] == 443
    assert row["app_proto"] == "tls"
    assert row["ndpi_protocol"] == "TLS.Google"
    assert row["ndpi_risk_set"] == ["Known Proto on Non Std Port"]
    assert row["pkts_to_server"] == 10 and row["bytes_to_client"] == 3400


def test_identity_injected_from_config():
    # EVE has no tenant/sensor; both come from the trusted ingress config.
    _, row = m.normalize(FLOW, "homelab", "ol9-suri")
    assert row["tenant_id"] == "homelab" and row["sensor_id"] == "ol9-suri"


def test_identity_prefers_edge_stamped_sensor():
    ev = dict(FLOW, host="sensor-004287")
    _, row = m.normalize(ev, "homelab", "cfg-default")
    assert row["sensor_id"] == "sensor-004287"   # fleet case
    assert row["tenant_id"] == "homelab"         # tenant never trusted from wire


def test_tls_maps_ja4_and_hashes():
    tbl, row = m.normalize(TLS, "homelab", "ol9-suri")
    assert tbl == "tls_observation"
    assert row["ja4"] == "t13d1516h2_x_y"
    assert row["ja3"] == "aaa" and row["ja3s"] == "bbb"
    assert row["sni"] == "example.com"


def test_dns_v3_normalizes():
    tbl, row = m.normalize(DNS_V3, "homelab", "ol9-suri")
    assert tbl == "dns_transaction"
    assert row["dns_version"] == 3
    assert row["query_name"] == "example.com" and row["query_type"] == "A"


def test_dns_wrong_version_quarantined():
    bad = {"event_type": "dns", "timestamp": "t", "src_ip": "x", "dest_ip": "y",
           "dns": {"version": 2, "rrname": "old.example"}}
    try:
        m.normalize(bad, "homelab", "ol9-suri", dns_version=3)
        assert False, "v2 record on a v3 stream must quarantine"
    except m.QuarantineError:
        pass


def test_ndpi_opaque_no_hardcoded_keys():
    # An nDPI object with unexpected 3rd-party keys must not crash normalization.
    ev = dict(FLOW, ndpi={"some_future_field": 1, "risk": {"R1": "x"}})
    _, row = m.normalize(ev, "homelab", "ol9-suri")
    assert row["ndpi_risk_set"] == ["R1"]
    assert row["ndpi_protocol"] == ""   # unknown shape -> empty, not an error


def test_unsupported_event_type_skipped():
    assert m.normalize({"event_type": "arp"}, "homelab", "ol9-suri") is None


def test_netflow_dropped_no_double_count():
    # netflow (unidirectional) is no longer persisted; only the canonical
    # bidirectional flow record writes network_flow, so counts are not doubled.
    nf = dict(FLOW, event_type="netflow")
    assert m.normalize(nf, "homelab", "ol9-suri") is None


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} normalizer tests passed")
