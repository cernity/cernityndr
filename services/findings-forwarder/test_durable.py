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


class PartialSink:
    """Per-item contract: returns the findings whose id is in `reject` as failed (not delivered),
    delivers the rest. `heal_after` lets a rejected id start succeeding after N calls (recovery)."""
    def __init__(self, reject=(), heal_after=None):
        self.reject, self.heal_after, self.calls, self.delivered = set(reject), heal_after, 0, []

    def emit_batch(self, findings):
        self.calls += 1
        rejecting = self.reject if (self.heal_after is None or self.calls <= self.heal_after) else set()
        ok = [f for f in findings if f["finding_id"] not in rejecting]
        self.delivered.extend(f["finding_id"] for f in ok)
        return [f for f in findings if f["finding_id"] in rejecting]


def _sink(inner, **kw):
    kw.setdefault("sleep", lambda _s: None)      # no real backoff sleep in tests
    kw.setdefault("backoff", 0)
    kw.setdefault("dlq_dir", tempfile.mkdtemp())  # ledger + DLQ live in a temp dir, never /var/lib
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


def test_receipt_counts_delivered_and_dead_lettered():
    # Rec-D: the per-sink receipt accounts for what was delivered vs durably dead-lettered.
    inner = FlakySink(fail_times=0)
    s = _sink(inner)
    s.emit_batch([{"finding_id": "a"}, {"finding_id": "b"}])
    assert s.receipt() == {"name": "test", "delivered": 2, "dead_lettered": 0}
    with tempfile.TemporaryDirectory() as d:
        s2 = _sink(FlakySink(fail_times=99), retries=1, dlq_dir=d)
        s2.emit_batch([{"finding_id": "c"}])
        assert s2.receipt()["dead_lettered"] == 1 and s2.receipt()["delivered"] == 0


def test_partial_rejection_counts_only_accepted_and_dead_letters_the_rest():
    # §stage2: a partial-failure response must not count the failed item as delivered.
    with tempfile.TemporaryDirectory() as d:
        inner = PartialSink(reject=["b"])                   # b never accepted
        s = _sink(inner, retries=1, dlq_dir=d)
        s.emit_batch([{"finding_id": "a"}, {"finding_id": "b"}])
        assert inner.delivered == ["a"]                     # only a landed
        assert s.receipt() == {"name": "test", "delivered": 1, "dead_lettered": 1}
        rows = [json.loads(l) for l in open(os.path.join(d, "dlq-test.jsonl"))]
        assert [r["finding"]["finding_id"] for r in rows] == ["b"]   # b dead-lettered, not lost


def test_recoverable_partial_failure_eventually_delivers_all():
    inner = PartialSink(reject=["b"], heal_after=1)         # b rejected once, then accepted
    s = _sink(inner, retries=3)
    s.emit_batch([{"finding_id": "a"}, {"finding_id": "b"}])
    assert sorted(inner.delivered) == ["a", "b"]
    assert s.receipt() == {"name": "test", "delivered": 2, "dead_lettered": 0}   # each counted once


def test_receipt_does_not_double_count_replays():
    inner = FlakySink()
    s = _sink(inner)
    s.emit_batch([{"finding_id": "a"}])
    s.emit_batch([{"finding_id": "a"}])                     # replay -> idempotent, not re-counted
    assert s.receipt()["delivered"] == 1


def test_ledger_survives_restart_and_does_not_resend():
    # §stage2: a fresh DurableSink over the same ledger dir must NOT re-send an already-delivered
    # obligation (restart-safe dedup + audit), even though its per-worker counters start at 0.
    with tempfile.TemporaryDirectory() as d:
        DurableSink(FlakySink(), "test", dlq_dir=d, sleep=lambda _s: None).emit_batch([{"finding_id": "a"}])
        inner2 = FlakySink()
        s2 = DurableSink(inner2, "test", dlq_dir=d, sleep=lambda _s: None)   # "restart": fresh process
        s2.emit_batch([{"finding_id": "a"}, {"finding_id": "b"}])
        assert inner2.delivered == ["b"]                    # a already delivered pre-restart, not resent
        assert s2.delivered == 1 and s2.dead_lettered == 0  # only the new obligation counted this worker
        obl = os.path.join(d, "obligations-test.jsonl")
        rows = [json.loads(l) for l in open(obl)]
        assert {r["finding_id"] for r in rows} == {"a", "b"} and all(r["outcome"] == "delivered" for r in rows)


def test_new_revision_is_delivered_even_if_finding_id_seen():
    # §stage2 revision-at-sink: same finding_id, a NEW revision is a new obligation -> delivered.
    with tempfile.TemporaryDirectory() as d:
        inner = FlakySink()
        s = DurableSink(inner, "test", dlq_dir=d, sleep=lambda _s: None)
        s.emit_batch([{"finding_id": "f", "revision": 1}])
        s.emit_batch([{"finding_id": "f", "revision": 1}])   # replay same revision -> skipped
        s.emit_batch([{"finding_id": "f", "revision": 2}])   # new revision -> delivered
        assert inner.delivered == ["f", "f"] and s.delivered == 2   # rev1 once, rev2 once


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


def test_record_suppressed_writes_withheld_obligation_by_identity():
    # §59.1: a delivery-suppressed finding is recorded in the obligation ledger by (finding_id, revision)
    # identity with dest '(withheld)', so suppression is reconciled per revision, not as an aggregate count.
    with tempfile.TemporaryDirectory() as d:
        s = DurableSink(FlakySink(), "test", dlq_dir=d, sleep=lambda _s: None)
        s.record_suppressed([{"finding_id": "lo", "revision": 1, "tenant_id": "t"}], worker="w")
        s.record_suppressed([{"finding_id": "lo", "revision": 1, "tenant_id": "t"}], worker="w")  # replay
        rows = [json.loads(l) for l in open(os.path.join(d, "obligations-test.jsonl"))]
        assert len(rows) == 1                                          # idempotent by identity
        assert rows[0]["outcome"] == "suppressed" and rows[0]["dest"] == "(withheld)"
        assert rows[0]["finding_id"] == "lo" and rows[0]["revision"] == 1
