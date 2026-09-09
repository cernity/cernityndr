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
    hit, feed, ioc = ti.match("185.100.87.202", "", "", {"185.100.87.202"}, set(), set())
    assert hit and feed == "feodo_c2" and ioc == "185.100.87.202"


def test_match_ja3_case_insensitive():
    hit, feed, _ = ti.match("9.9.9.9", "E7D705A3286E19EA42F587B344EE6865", "",
                            set(), {"e7d705a3286e19ea42f587b344ee6865"}, set())
    assert hit and feed == "sslbl_ja3"


def test_match_cert():
    hit, feed, _ = ti.match("9.9.9.9", "", "AABBCCDDEEFF00112233445566778899AABBCCDD",
                            set(), set(), {"aabbccddeeff00112233445566778899aabbccdd"})
    assert hit and feed == "sslbl_cert"


def test_no_match():
    assert ti.match("8.8.8.8", "abc", "def", {"1.1.1.1"}, set(), set())[0] is False


def test_join_key_entities():
    # community_id/flow_id join the finding back to the exact connection's telemetry.
    import app
    assert app.join_key_entities({"community_id": "1:x", "flow_id": 7}) == [
        {"type": "community_id", "value": "1:x"}, {"type": "flow_id", "value": 7}]
    assert app.join_key_entities({}) == []


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} threat-intel tests passed")
