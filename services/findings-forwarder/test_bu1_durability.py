"""B-U1 (plan 010 Track B): fanout durability — a sink's ledger/DLQ write failure must NOT let the
offset commit (MultiAdapter raises SinkDurabilityError), the DLQ payload is durable before the ledger
records dead_lettered, and an unwritable DLQ dir is caught at startup. No SIEM, no Kafka.

  python3 test_bu1_durability.py
"""
import json
import os
import tempfile

from adapters import DurableSink, MultiAdapter, SinkDurabilityError, dlq_writable


class OkSink:
    def __init__(self):
        self.got = []

    def emit_batch(self, findings):
        self.got.extend(f["finding_id"] for f in findings)
        return []                                    # all accepted


class DownSink:
    def emit_batch(self, findings):
        raise RuntimeError("sink down")              # delivery failure -> DurableSink dead-letters (no raise out)


def test_dead_letter_writes_payload_then_ledger():
    # A delivery failure dead-letters: the DLQ payload file exists with the finding AND the ledger
    # records dead_lettered — durability write happened, nothing dropped.
    with tempfile.TemporaryDirectory() as d:
        s = DurableSink(DownSink(), "es", dlq_dir=d, retries=1, sleep=lambda _s: None)
        s.emit_batch([{"finding_id": "f1", "revision": 1}])
        dlq = [json.loads(x) for x in open(os.path.join(d, "dlq-es.jsonl"))]
        ledg = [json.loads(x) for x in open(os.path.join(d, "obligations-es.jsonl"))]
        assert dlq and dlq[0]["finding"]["finding_id"] == "f1"
        assert any(r["outcome"] == "dead_lettered" for r in ledg)


class LedgerBrokenSink:
    """Simulates a sink whose durability store is broken: emit_batch raises (as DurableSink would when
    its own ledger/DLQ write fails)."""
    def emit_batch(self, findings):
        raise OSError("ledger write failed")


def test_multiadapter_raises_on_durability_failure_but_runs_all_sinks():
    ok = OkSink()
    m = MultiAdapter([ok, LedgerBrokenSink()])
    try:
        m.emit_batch([{"finding_id": "f1"}])
        assert False, "MultiAdapter must raise when a sink's durability write fails"
    except SinkDurabilityError as e:
        assert "LedgerBrokenSink" in e.sinks
    assert ok.got == ["f1"], "healthy sinks still receive the batch"


def test_dlq_writable_check():
    with tempfile.TemporaryDirectory() as d:
        okv, err = dlq_writable(os.path.join(d, "dlq"))
        assert okv and err is None
    bad, err = dlq_writable("/proc/cernity-cannot-write-here/dlq")   # unwritable path
    assert bad is False and err


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok  " + fn.__name__)
    print("\nall %d B-U1 durability tests passed" % len(fns))
