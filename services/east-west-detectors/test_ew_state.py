"""Externalized east-west state + HA dedup + partition scoping (plan 005).
Single-process, in-memory backend; no broker."""
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
    return app._store


def _dets(sent):
    return [m["detector_id"] for m in sent]


def test_lateral_fanout_fires_from_store():
    _fresh()
    for i in range(6):                                   # 6 distinct dsts on admin port (>= 5)
        app._ew_add("lat:", 2, "10.0.0.5", f"10.0.0.{100 + i}|445")
    p = _P()
    app.evaluate(p, flow_parts={2}, raw_parts=set())
    assert "lateral_movement" in _dets(p.sent)


def test_rdp_fanout_fires():
    _fresh()
    for i in range(4):                                   # 4 distinct 3389 dsts (>= 3)
        app._ew_add("rdp:", 1, "10.0.0.6", f"10.0.0.{50 + i}")
    p = _P()
    app.evaluate(p, flow_parts={1}, raw_parts=set())
    assert "rdp_fanout" in _dets(p.sent)


def test_kerberoast_fires():
    _fresh()
    for i in range(9):                                   # 9 distinct SPNs (>= 8)
        app._ew_add("krb:", 3, "10.0.0.7", json.dumps({"sname": f"svc{i}/host", "encryption": "aes"}))
    p = _P()
    app.evaluate(p, flow_parts=set(), raw_parts={3})     # krb scoped by raw.v1 partitions
    assert "kerberoasting" in _dets(p.sent)


def test_below_threshold_no_fire():
    _fresh()
    for i in range(3):                                   # only 3 lateral dsts (< 5)
        app._ew_add("lat:", 0, "10.0.0.8", f"10.0.0.{i}|445")
    p = _P()
    app.evaluate(p, flow_parts={0}, raw_parts=set())
    assert p.sent == []


def test_dedup_no_double_emit():
    _fresh()
    for i in range(6):
        app._ew_add("lat:", 1, "10.0.0.9", f"10.0.0.{i}|445")
    p = _P()
    app.evaluate(p, flow_parts={1}, raw_parts=set())
    app.evaluate(p, flow_parts={1}, raw_parts=set())     # same bucket -> shared dedup
    assert sum(1 for m in p.sent if m["detector_id"] == "lateral_movement") == 1


def test_partition_scoped():
    _fresh()
    for i in range(6):
        app._ew_add("lat:", 0, "10.0.0.1", f"10.0.0.{i}|445")
    for i in range(6):
        app._ew_add("lat:", 5, "10.0.0.2", f"10.0.1.{i}|445")
    p = _P()
    app.evaluate(p, flow_parts={0}, raw_parts=set())     # only partition 0
    srcs = [e["value"] for m in p.sent for e in json.loads(m["entities"]) if e.get("role") == "src"]
    assert "10.0.0.1" in srcs and "10.0.0.2" not in srcs


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f()
            print("ok", _n)
    print("all ew-state tests passed")
