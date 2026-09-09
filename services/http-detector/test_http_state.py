"""http-detector shared-Redis dedup + stable-hash (plan 006 scale-safety).
Single-process, in-memory; no broker."""
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


_WEBSHELL_EVE = {"event_type": "http", "src_ip": "10.0.0.1", "dest_ip": "1.2.3.4",
                 "http": {"http_method": "GET", "url": "/uploads/shell.php?cmd=whoami",
                          "hostname": "evil.example"}}


def test_http_finding_emits():
    _fresh()
    p = _P()
    app._handle(dict(_WEBSHELL_EVE), p)
    assert p.sent, "expected a finding on a webshell/cmdi URL"


def test_dedup_no_double_emit_across_replicas_simulated():
    _fresh()
    p = _P()
    app._handle(dict(_WEBSHELL_EVE), p)
    app._handle(dict(_WEBSHELL_EVE), p)          # same bucket -> shared dedup suppresses
    dets = [m["detector_id"] for m in p.sent]
    # every detector fired once, none twice
    assert len(dets) == len(set(dets)), f"double-emit: {dets}"


def test_stable_hash_deterministic():
    assert app._stable("a:b:c") == app._stable("a:b:c")


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f()
            print("ok", _n)
    print("all http-state tests passed")
