"""B-U3 (plan 010 Track B, review R04): IDS finding identity carries occurrence window + sensor, so
two SEPARATE observations don't collide, while the same alert stays idempotent across restarts."""
import os

os.environ.setdefault("LOG_FORMAT", "text")

import promote as p  # noqa: E402

BASE = {"event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "203.0.113.9", "host": "sensor-a",
        "timestamp": "2026-09-25T00:00:00Z",
        "alert": {"signature_id": 2001, "signature": "ET MALWARE Win32/x CnC", "severity": 1,
                  "category": "malware"}}


def _id(eve):
    c = p.to_candidate(eve)
    assert c is not None, "fixture must be a threat alert"
    return c["finding_id"]


def test_same_alert_is_idempotent():
    assert _id(BASE) == _id(dict(BASE))


def test_within_window_same_id():
    assert _id(BASE) == _id(dict(BASE, timestamp="2026-09-25T00:02:00Z"))   # <5m window


def test_distinct_occurrence_time_distinct_id():
    assert _id(BASE) != _id(dict(BASE, timestamp="2026-09-25T01:00:00Z"))   # a later window


def test_distinct_sensor_distinct_id():
    assert _id(BASE) != _id(dict(BASE, host="sensor-b"))


if __name__ == "__main__":
    for n, f in sorted(globals().items()):
        if n.startswith("test_") and callable(f):
            f(); print("ok:", n)
    print("all passed")
