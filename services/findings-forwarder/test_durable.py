"""U6/F07 durable-delivery tests for DurableSink: retry -> dead-letter, idempotent
admission (no re-send of an already-delivered finding), and no silent drops. No SIEM,
no Kafka, no real sleep.

  /opt/homebrew/bin/python3 test_durable.py
"""
import json
import os
import tempfile

from adapters import DurableSink


class FlakySink:
    """Fails its first `fail_times` emit_batch calls, then succeeds. Records deliveries."""
    def __init__(self, fail_times=0):
        self.fail_times = fail_times
        self.calls = 0
        self.delivered = []

    def emit_batch(self, findings):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RuntimeError("sink down")
        self.delivered.extend(f["finding_id"] for f in findings)


def _sink(inner, **kw):
    kw.setdefault("sleep", lambda _s: None)      # no real backoff sleep in tests
    kw.setdefault("backoff", 0)
    return DurableSink(inner, "test", **kw)


def test_retries_then_succeeds():
    inner = FlakySink(fail_times=2)
    s = _sink(inner, retries=4)
    s.emit_batch([{"finding_id": "a"}])
    assert inner.delivered == ["a"] and inner.calls == 3   # 2 failures + 1 success


def test_dead_letters_after_exhausting_retries():
    with tempfile.TemporaryDirectory() as d:
        inner = FlakySink(fail_times=99)                    # never recovers
        s = _sink(inner, retries=2, dlq_dir=d)
        s.emit_batch([{"finding_id": "b"}])                 # returns (never raises) -> caller can ack
        assert inner.delivered == []                        # never delivered
        dlq = os.path.join(d, "dlq-test.jsonl")
        rows = [json.loads(l) for l in open(dlq)]
        assert rows and rows[0]["finding"]["finding_id"] == "b"   # not lost — dead-lettered


def test_idempotent_admission_skips_already_delivered():
    inner = FlakySink()
    s = _sink(inner)
    s.emit_batch([{"finding_id": "c"}])
    s.emit_batch([{"finding_id": "c"}, {"finding_id": "d"}])   # c is a replay/duplicate
    assert inner.delivered == ["c", "d"]                    # c delivered once, not twice


def test_dead_lettered_is_not_retried_forever():
    with tempfile.TemporaryDirectory() as d:
        inner = FlakySink(fail_times=99)
        s = _sink(inner, retries=1, dlq_dir=d)
        s.emit_batch([{"finding_id": "e"}])
        before = inner.calls
        s.emit_batch([{"finding_id": "e"}])                 # already handled (dead-lettered) -> skipped
        assert inner.calls == before


def test_health_callback_reflects_delivery_then_backend_loss():
    # F15: readiness must track real backend state — a delivery reports healthy, an
    # exhausted dead-letter reports unhealthy.
    health = []
    _sink(FlakySink(fail_times=0), on_health=health.append).emit_batch([{"finding_id": "h1"}])
    assert health[-1] is True
    with tempfile.TemporaryDirectory() as d:
        _sink(FlakySink(fail_times=99), retries=1, dlq_dir=d,
              on_health=health.append).emit_batch([{"finding_id": "h2"}])
    assert health[-1] is False


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} durable-delivery tests passed")
