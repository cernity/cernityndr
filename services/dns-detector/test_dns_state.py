"""Externalized NXDOMAIN state + HA dedup + partition scoping (plan 005).
Single-process, in-memory backend; no broker."""
import json
import time

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
    return app._store


def _plant_nx(part, client, n):
    for _ in range(n):
        app._nx_add(part, client)


def _srcs(sent, detector="nxdomain_burst"):
    return [e["value"] for m in sent if m["detector_id"] == detector
            for e in json.loads(m["entities"]) if e.get("role") == "src"]


def test_nxdomain_burst_fires_from_store():
    _fresh()
    _plant_nx(3, "10.0.0.9", app.NXDOMAIN_THRESHOLD + 1)     # over threshold
    p = _P()
    app.evaluate(p, parts={3})
    assert "10.0.0.9" in _srcs(p.sent)


def test_below_threshold_no_fire():
    _fresh()
    _plant_nx(0, "10.0.0.5", 3)                              # under threshold
    p = _P()
    app.evaluate(p, parts={0})
    assert p.sent == []


def test_dedup_no_double_emit_across_evaluate():
    _fresh()
    _plant_nx(1, "10.0.0.7", app.NXDOMAIN_THRESHOLD + 5)
    p = _P()
    app.evaluate(p, parts={1})
    app.evaluate(p, parts={1})                              # same bucket -> shared dedup suppresses
    n = sum(1 for m in p.sent if m["detector_id"] == "nxdomain_burst")
    assert n == 1, f"expected 1 emit, got {n}"


def test_partition_scoped():
    _fresh()
    _plant_nx(0, "10.0.0.1", app.NXDOMAIN_THRESHOLD + 1)
    _plant_nx(5, "10.0.0.2", app.NXDOMAIN_THRESHOLD + 1)
    p = _P()
    app.evaluate(p, parts={0})                              # only partition 0
    srcs = _srcs(p.sent)
    assert "10.0.0.1" in srcs and "10.0.0.2" not in srcs


def test_ipv6_client_key_roundtrips():
    _fresh()
    _plant_nx(4, "2001:db8::1", app.NXDOMAIN_THRESHOLD + 1)
    p = _P()
    app.evaluate(p, parts={4})
    assert "2001:db8::1" in _srcs(p.sent)                    # colons preserved through key parse


def test_stable_hash_deterministic():
    assert app._stable("10.0.0.1") == app._stable("10.0.0.1")


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f()
            print("ok", _n)
    print("all dns-state tests passed")
