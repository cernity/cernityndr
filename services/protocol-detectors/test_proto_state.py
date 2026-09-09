"""protocol-detectors externalized state + fleet JA4 rarity + shared dedup (plan 006)."""
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


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f()
            print("ok", _n)
    print("all proto-state tests passed")
