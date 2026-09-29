"""Threat-intel parse + match tests (pure)."""
import ti

FEODO = """# Feodo Tracker
# comment
185.100.87.202
1.2.3.4,443,online
not-an-ip
"""
SSLBL_CERT = """# Listingdate,SHA1,Reason
2026-01-01 00:00:00,aabbccddeeff00112233445566778899aabbccdd,MalwareX C2
"""
SSLBL_JA3 = """# firstseen,ja3_md5,reason
2026-01-01,e7d705a3286e19ea42f587b344ee6865,Malware C2
"""


def test_parse_feodo():
    s = ti.parse_feodo(FEODO)
    assert s == {"185.100.87.202", "1.2.3.4"}


def test_parse_hash_csv_cert_and_ja3():
    assert "aabbccddeeff00112233445566778899aabbccdd" in ti.parse_hash_csv(SSLBL_CERT)
    assert "e7d705a3286e19ea42f587b344ee6865" in ti.parse_hash_csv(SSLBL_JA3)


def test_match_ip():
    hit, feed, ioc = ti.match_static("185.100.87.202", "", "", {"185.100.87.202"}, set(), set())
    assert hit and feed == "feodo_c2" and ioc == "185.100.87.202"


def test_match_ja3_case_insensitive():
    hit, feed, _ = ti.match_static("9.9.9.9", "E7D705A3286E19EA42F587B344EE6865", "",
                            set(), {"e7d705a3286e19ea42f587b344ee6865"}, set())
    assert hit and feed == "sslbl_ja3"


def test_match_cert():
    hit, feed, _ = ti.match_static("9.9.9.9", "", "AABBCCDDEEFF00112233445566778899AABBCCDD",
                            set(), set(), {"aabbccddeeff00112233445566778899aabbccdd"})
    assert hit and feed == "sslbl_cert"


def test_no_match():
    assert ti.match_static("8.8.8.8", "abc", "def", {"1.1.1.1"}, set(), set())[0] is False


def test_parse_fp_list():
    txt = "# known C2 server fps\nT13d1516h2_8daaf6152771_b186095e22b6,CobaltStrike\n\n1a2b3c4d\n"
    s = ti.parse_fp_list(txt)
    assert "t13d1516h2_8daaf6152771_b186095e22b6" in s and "1a2b3c4d" in s   # lowercased


def test_match_server_fp_ja4s():
    bl = {"t13d1516h2_8daaf6152771_b186095e22b6"}
    hit, typ, ioc = ti.match_server_fp("", "T13d1516h2_8daaf6152771_b186095e22b6", "", bl)
    assert hit and typ == "c2fp_ja4s" and ioc == "t13d1516h2_8daaf6152771_b186095e22b6"


def test_match_server_fp_empty_blocklist_is_noop():
    assert ti.match_server_fp("x", "y", "z", set())[0] is False


def test_match_server_fp_no_match():
    assert ti.match_server_fp("aaa", "bbb", "ccc", {"ddd"})[0] is False


def test_join_key_entities():
    # community_id/flow_id join the finding back to the exact connection's telemetry.
    import app
    assert app.join_key_entities({"community_id": "1:x", "flow_id": 7}) == [
        {"type": "community_id", "value": "1:x"}, {"type": "flow_id", "value": 7}]
    assert app.join_key_entities({}) == []



# Shared fixtures also run in the service image without pytest.
from test_lifecycle import IntelStore, rec, NOW, FUTURE, PAST
import lifecycle


CASES = [
    ("ip", "2001:db8::1", {"src_ip": "2001:0db8:0:0:0:0:0:1"}, "src_ip"),
    ("ip", "1.2.3.4", {"dest_ip": "1.2.3.4"}, "dest_ip"),
    ("domain", "bad.example", {"tls": {"sni": "BAD.EXAMPLE"}}, "tls.sni"),
    ("domain", "bad.example", {"dns": {"rrname": "bad.example"}}, "dns.rrname"),
    ("domain", "bad.example", {"dns": {"queries": [{"rrname": "bad.example"}]}}, "dns.queries.0.rrname"),
    ("domain", "bad.example", {"http": {"hostname": "bad.example"}}, "http.hostname"),
    ("url", "https://bad.example/Secret?Token=ABC", {"http": {"url": "HTTPS://BAD.EXAMPLE/Secret?Token=ABC"}}, "http.url"),
    ("ja3", "abcd", {"tls": {"ja3": {"hash": "ABCD"}}}, "tls.ja3"),
    ("ja3", "abcd", {"tls": {"ja3s": "ABCD"}}, "tls.ja3s"),
    ("ja4", "t13_x_y", {"tls": {"ja4": "T13_X_Y"}}, "tls.ja4"),
    ("ja4", "t13_x_y", {"tls": {"ja4s": "T13_X_Y"}}, "tls.ja4s"),
    ("cert", "abcdef", {"tls": {"fingerprint": "ABCDEF"}}, "tls.fingerprint"),
]


def test_live_dimensions_and_provenance():
    for kind, indicator, observation, field in CASES:
        store = IntelStore()
        record = rec(indicator, kind, 80, 0.9, "trusted")
        lifecycle.ingest(store, [record], NOW)
        hits = ti.match(observation, store, "t1", NOW)
        assert len(hits) == 1, (kind, hits)
        hit = hits[0]
        assert hit["indicator"] == indicator and hit["type"] == kind
        assert hit["observed_field"] == field
        assert hit["score"] == 80 and hit["source_trust"] == 0.9
        assert hit["source"] == "src" and hit["tlp"] == "amber"
        assert hit["provenance"] == record["provenance"]
        assert not hit["suppressed"]


def test_no_fabricated_dimensions_or_url_case_folding():
    store = IntelStore()
    lifecycle.ingest(store, [rec("https://bad.example/Secret", "url", 80, 1, "f"),
                             rec("abc", "hash", 80, 1, "f")], NOW)
    for observation in ({}, {"tls": None}, {"tls": "bad", "dns": {"queries": None}},
                        {"http": {"hostname": "bad.example", "url": "/Secret"}},
                        {"http": {"url": "https://bad.example/secret"}},
                        {"fileinfo": {"sha256": "abc"}}, {"http": {"url": "https://[bad"}}):
        assert ti.match(observation, store, "t1", NOW) == []


def test_live_cidr_and_tenant_isolation():
    store = IntelStore()
    lifecycle.ingest(store, [rec("10.0.0.0/24", "ip", 80, 1, "f"),
                             rec("2001:db8::/32", "ip", 80, 1, "f"),
                             rec("10.0.0.1", "ip", 99, 1, "secret", tenant="t2")], NOW)
    assert ti.match({"src_ip": "10.0.0.1"}, store, "t1", NOW)[0]["indicator"] == "10.0.0.0/24"
    assert ti.match({"src_ip": "2001:db8::1"}, store, "t1", NOW)[0]["indicator"] == "2001:db8::/32"
    assert ti.match({"src_ip": "10.0.1.1"}, store, "t1", NOW) == []
    assert ti.match({"src_ip": "10.0.0.1", "tenant_id": "t2"}, store, "t1", NOW) == []
    assert ti.match({"src_ip": "10.0.0.1"}, store, "t3", NOW) == []


def test_live_expiry_trust_and_suppression():
    store = IntelStore()
    observation = {"dest_ip": "1.2.3.4"}
    lifecycle.ingest(store, [rec("1.2.3.4", "ip", 30, 1, "trusted", expiry=lifecycle.iso(NOW + 10)),
                             rec("1.2.3.4", "ip", 100, 0.1, "untrusted")], NOW)
    assert ti.match(observation, store, "t1", NOW)[0]["score"] == 30
    hit = ti.match(observation, store, "t1", NOW + 10)[0]
    assert hit["score"] == 100 and hit["source_trust"] == 0.1
    store.suppress("t1", "ip", "1.2.3.4", "operator", "known test", NOW + 30, NOW)
    assert ti.match(observation, store, "t1", NOW)[0]["suppressed"]
    assert not ti.match(observation, store, "t1", NOW + 30)[0]["suppressed"]
    assert ti.match(observation, store, "t1", lifecycle.epoch(FUTURE)) == []


class Producer:
    def __init__(self):
        self.sent = []

    def send(self, topic, candidate):
        self.sent.append((topic, candidate))


def test_managed_candidate_and_local_audit():
    import app
    import json
    store = IntelStore()
    old_store, old_tenant = app._intel["store"], app.TENANT
    app._intel["store"], app.TENANT = store, "t1"
    app._seen.clear()
    try:
        lifecycle.ingest(store, [rec("1.2.3.4", "ip", 80, 0.5, "f")], NOW)
        event = {"dest_ip": "1.2.3.4", "src_ip": "10.0.0.1", "community_id": "1:abc"}
        producer = Producer()
        app.process_observation(event, producer, NOW)
        topic, candidate = producer.sent[0]
        assert topic == "ndr.finding.candidate.v1"
        assert candidate["intel_match"] == ti.match(event, store, "t1", NOW)[0]
        assert candidate["tenant_id"] == "t1" and candidate["confidence"] == 0.4
        assert {"type": "community_id", "value": "1:abc"} in json.loads(candidate["entities"])
        app.process_observation(event, producer, NOW)
        assert len(producer.sent) == 1
        app.process_observation(dict(event, src_ip="10.0.0.2"), producer, NOW)
        assert len(producer.sent) == 2
        assert producer.sent[0][1]["finding_id"] != producer.sent[1][1]["finding_id"]
        store.suppress("t1", "ip", "1.2.3.4", "owner", "test", NOW + 10, NOW)
        app.process_observation(event, producer, NOW)
        assert len(producer.sent) == 2
        audits = [a for a in store.audit_log(["t1"]) if a["action"] == "intel.match"]
        assert len(audits) == 1 and audits[0]["intel_match"]["suppressed"]
        assert audits[0]["observation"]["community_id"] == "1:abc"
        assert store.audit_log(["t2"]) == []
        # Suppression expiry must resume even after an active hit in the same window.
        app.process_observation(event, producer, NOW)
        app.process_observation(event, producer, NOW + 10)
        assert len(producer.sent) == 3
        app.process_observation(dict(event, tenant_id="t2"), producer, NOW + 10)
        assert len(producer.sent) == 3
        lifecycle.ingest(store, [rec("1.2.3.4", "ip", 100, 1, "red", tlp="red")], NOW)
        app.process_observation(event, producer, NOW + 10)
        assert len(producer.sent) == 3
        assert any(a.get("intel_match", {}).get("tlp") == "red" for a in store.audit_log(["t1"]))
    finally:
        app._intel["store"], app.TENANT = old_store, old_tenant
        app._seen.clear()


def test_managed_store_does_not_fall_back_to_static():
    import app
    old_store, old_feodo = app._intel["store"], app._feeds["feodo"]
    app._intel["store"], app._feeds["feodo"] = IntelStore(), {"1.2.3.4"}
    try:
        producer = Producer()
        app.process_observation({"dest_ip": "1.2.3.4"}, producer, NOW)
        assert producer.sent == []
    finally:
        app._intel["store"], app._feeds["feodo"] = old_store, old_feodo


def test_live_consumer_topics_and_candidate_emission():
    import app
    from types import SimpleNamespace
    from unittest.mock import patch

    store = IntelStore()
    lifecycle.ingest(store, [rec(indicator, kind, 80, 0.9, "f")
                             for kind, indicator, _, _ in CASES], NOW)
    events = [observation for _, _, observation, _ in CASES]
    producer = Producer()
    producer.flush = lambda: None
    producer.close = lambda: None
    def poll(**kwargs):
        app._running = False
        return {"partition": [SimpleNamespace(value=e) for e in events]}
    consumer = SimpleNamespace(poll=poll, close=lambda: None)
    old_store = app._intel["store"]
    app._seen.clear()
    try:
        app._intel["store"] = store
        with patch.object(app, "TENANT", "t1"), patch.object(app, "_running", True), \
             patch.object(app, "_init_intel"), patch.object(app, "refresh"), \
             patch.object(app.signal, "signal"), patch.object(app.threading, "Thread"), \
             patch.object(app.time, "time", return_value=NOW), \
             patch.object(app.ndr_runtime, "make_producer", return_value=producer), \
             patch.object(app.ndr_runtime, "make_consumer", return_value=consumer) as make_consumer:
            app.main()
        assert set(make_consumer.call_args.args) == {
            "suricata.flow.v1", "suricata.tls.v1", "suricata.dns.v1", "suricata.http.v1"}
        assert len(producer.sent) == len(CASES)
        assert {c["intel_match"]["type"] for _, c in producer.sent} == {
            "ip", "domain", "url", "ja3", "ja4", "cert"}
        assert all(c["intel_match"]["provenance"] for _, c in producer.sent)
    finally:
        app._intel["store"] = old_store
        app._seen.clear()


def test_multiple_dimensions_are_not_reduced_to_first_hit():
    store = IntelStore()
    lifecycle.ingest(store, [rec("1.2.3.4", "ip", 80, 1, "f"),
                             rec("bad.example", "domain", 70, 1, "f"),
                             rec("abc", "ja3", 60, 1, "f")], NOW)
    hits = ti.match({"dest_ip": "1.2.3.4", "tls": {"sni": "bad.example", "ja3": "abc"}},
                    store, "t1", NOW)
    assert {h["type"] for h in hits} == {"ip", "domain", "ja3"}

if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} threat-intel tests passed")
