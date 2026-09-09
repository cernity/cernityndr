"""Tests for the shared logging setup (JSON formatter + log_event fields)."""
import json
import logging

import ndr_runtime


def test_json_formatter_standard_fields():
    f = ndr_runtime._JsonFormatter("behavioral-detectors")
    rec = logging.LogRecord("x", logging.WARNING, "f.py", 1, "something happened", None, None)
    d = json.loads(f.format(rec))
    assert d["svc"] == "behavioral-detectors"
    assert d["level"] == "WARNING"
    assert d["msg"] == "something happened"
    assert "ts" in d and "tenant" in d


def test_json_formatter_carries_event_and_fields():
    f = ndr_runtime._JsonFormatter("svc")
    rec = logging.LogRecord("x", logging.INFO, "f.py", 1, "beacon src=10.0.0.5", None, None)
    rec.cernity_event = "beacon"
    rec.cernity_fields = {"src": "10.0.0.5", "dst": "203.0.113.10", "score": 1.0}
    d = json.loads(f.format(rec))
    assert d["event"] == "beacon"
    assert d["src"] == "10.0.0.5" and d["dst"] == "203.0.113.10" and d["score"] == 1.0


def test_log_event_sets_message_and_extra(capture=None):
    seen = {}

    class Cap(logging.Handler):
        def emit(self, record):
            seen["msg"] = record.getMessage()
            seen["event"] = getattr(record, "cernity_event", None)
            seen["fields"] = getattr(record, "cernity_fields", None)

    lg = logging.getLogger("test-log-event")
    lg.handlers[:] = [Cap()]
    lg.setLevel(logging.INFO)
    ndr_runtime.log_event(lg, "beacon", src="10.0.0.5", score=1.0)
    assert seen["event"] == "beacon"
    assert seen["fields"] == {"src": "10.0.0.5", "score": 1.0}
    assert "src=10.0.0.5" in seen["msg"]


if __name__ == "__main__":
    test_json_formatter_standard_fields()
    test_json_formatter_carries_event_and_fields()
    test_log_event_sets_message_and_extra()
    print("all logging tests passed")
