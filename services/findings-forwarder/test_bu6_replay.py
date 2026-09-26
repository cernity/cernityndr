"""B-U6 (plan 010 Track B, review R10): explicit dead-letter replay preserving obligation identity +
attempt history, and bounded ledger compaction/retention (was unbounded append-only growth)."""
import json
import os
import tempfile
from datetime import datetime, timezone

from adapters import DurableLedger, DurableSink


class Down:
    def emit_batch(self, fs):
        raise RuntimeError("down")


class Ok:
    def __init__(self):
        self.got = []

    def emit_batch(self, fs):
        self.got += [f["finding_id"] for f in fs]
        return []


def test_replay_redelivers_dead_lettered_and_transitions_ledger():
    with tempfile.TemporaryDirectory() as d:
        s = DurableSink(Down(), "es", dlq_dir=d, retries=0, sleep=lambda _s: None)
        f = {"finding_id": "f1", "revision": 1, "tenant_id": "t"}
        s.emit_batch([f])                                        # dead-letters
        assert s._ledger.terminal(f, "es") == "dead_lettered"
        ok = Ok()
        s.inner = ok                                            # sink repaired
        replayed, failing = s.replay()
        assert (replayed, failing) == (1, 0) and ok.got == ["f1"]
        assert s._ledger.terminal(f, "es") == "delivered"       # audited transition, history preserved
        dlq = os.path.join(d, "dlq-es.jsonl")
        remaining = [x for x in open(dlq) if x.strip()] if os.path.isfile(dlq) else []
        assert remaining == [], "a replayed obligation is removed from the DLQ"


def test_compact_keeps_latest_per_key_and_bounds_file():
    with tempfile.TemporaryDirectory() as d:
        led = DurableLedger(os.path.join(d, "obl.jsonl"))
        f = {"finding_id": "f1", "revision": 1, "tenant_id": "t"}
        led.record([f], "es", "dead_lettered", "w")
        led.transition([f], "es", "delivered", "w", note="replay")
        led.transition([f], "es", "delivered", "w", note="replay2")
        before = sum(1 for x in open(led.path) if x.strip())
        kept = led.compact()
        after = sum(1 for x in open(led.path) if x.strip())
        assert before >= 3 and kept == 1 and after == 1          # collapsed to one record per key
        assert led.terminal(f, "es") == "delivered"              # current outcome preserved


def test_compact_retention_drops_old_records():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "obl.jsonl")
        with open(path, "w") as fh:
            fh.write(json.dumps({"tenant_id": "t", "finding_id": "old", "revision": 1, "dest": "es",
                                 "outcome": "delivered", "ts": "2000-01-01T00:00:00+00:00"}) + "\n")
            fh.write(json.dumps({"tenant_id": "t", "finding_id": "new", "revision": 1, "dest": "es",
                                 "outcome": "delivered", "ts": datetime.now(timezone.utc).isoformat()}) + "\n")
        led = DurableLedger(path)
        assert led.compact(retain_secs=3600) == 1                # only the fresh record retained


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok  " + _n)
    print("\nall B-U6 replay/retention tests passed")
