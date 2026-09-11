"""protocol-detectors externalized state + fleet JA4 rarity + shared dedup (plan 006)."""
import json

import app
import store


class _P:
    def __init__(self):
        self.sent = []

    def send(self, topic, msg):
        self.sent.append(msg)

    def flush(self):
        pass


def _fresh():
    app._store = store.make_store("memory")


def test_ssh_bruteforce_from_shared_counter():
    _fresh()
    p = _P()
    for _ in range(15):                                  # ssh_brute_hit min_sessions=15
        app._handle({"event_type": "ssh", "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2"}, p)
    assert any(m["detector_id"] == "ssh_bruteforce" for m in p.sent)


def test_ja4_rarity_uses_fleet_wide_set():
    _fresh()
    p = _P()
    for i in range(5):                                   # warmup: 5 distinct JA4s (not rare yet)
        app._handle({"event_type": "tls", "src_ip": f"10.0.0.{i}",
                     "tls": {"ja4": f"ja4_{i}", "sni": "x"}}, p)
    assert not any(m["detector_id"] == "ja4_rarity" for m in p.sent)
    app._handle({"event_type": "tls", "src_ip": "10.0.0.9",
                 "tls": {"ja4": "ja4_new", "sni": "evil"}}, p)   # new after warmup -> rare
    assert any(m["detector_id"] == "ja4_rarity" for m in p.sent)


def test_dedup_no_double_emit():
    _fresh()
    p = _P()
    ev = {"event_type": "tls", "src_ip": "10.0.0.1", "tls": {"sni": "pastebin.com", "ja4": "j"}}
    app._handle(dict(ev), p)
    app._handle(dict(ev), p)                             # same bucket -> shared dedup
    assert sum(1 for m in p.sent if m["detector_id"] == "cloud_staging") == 1


def test_stable_hash_deterministic():
    assert app._stable("x") == app._stable("x")


def test_ja3_object_fingerprint_does_not_crash_and_uses_the_hash():
    # F06: newer Suricata emits tls.ja3 / ja3s as {"hash","string"} OBJECTS, not strings.
    # The old code used the object directly as a rarity-set member -> unhashable-dict
    # TypeError (the audit's crash). Normalize to the hash string.
    _fresh()
    p = _P()
    for i in range(6):                                    # warm up with distinct object fps
        app._handle({"event_type": "tls", "src_ip": f"10.0.0.{i}",
                     "tls": {"ja3": {"hash": f"h{i}", "string": "771,4-5"}, "sni": "x"}}, p)
    app._handle({"event_type": "tls", "src_ip": "10.0.0.99",
                 "tls": {"ja3": {"hash": "hnew", "string": "771,4-5"}, "sni": "evil"}}, p)
    hits = [m for m in p.sent if m["detector_id"] == "ja4_rarity"]
    assert hits, "ja3-object client after warmup was not flagged rare"
    ents = json.loads(hits[-1]["entities"])
    fp = next(e["value"] for e in ents if e.get("type") in ("ja3", "ja4"))
    assert fp == "hnew", f"fingerprint should be the hash string, got {fp!r}"


def test_ja3s_object_server_fingerprint_does_not_crash():
    _fresh()
    p = _P()
    for i in range(6):
        app._handle({"event_type": "tls", "dest_ip": f"1.1.1.{i}",
                     "tls": {"ja3s": {"hash": f"s{i}", "string": "a,b"}, "sni": "x"}}, p)
    app._handle({"event_type": "tls", "dest_ip": "2.2.2.2",
                 "tls": {"ja3s": {"hash": "snew", "string": "a,b"}, "sni": "evil"}}, p)
    assert any(m["detector_id"] == "server_fp_rarity" for m in p.sent)


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f()
            print("ok", _n)
    print("all proto-state tests passed")
