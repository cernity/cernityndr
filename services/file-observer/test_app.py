"""file-observer (U1b) consumer-loop tests: a poison record (malformed JSON or
invalid UTF-8) is logged and SKIPPED without crashing the loop, and following
valid records still produce rows. Regression for the reviewer's poison-record
crash: the JSON decode used to live in the value_deserializer, so it ran inside
consumer.poll() OUTSIDE per-record handling — one bad record raised before any
commit and replayed forever on restart. Now bytes are consumed raw and decoded
per-record; an all-poison batch still commits so its offsets advance.

app.py is path-loaded with fake clickhouse_connect + ndr_runtime + observe injected
first: clickhouse_connect is not a test dependency, and 'app' is a name shared by
several services. The fakes are removed from sys.modules afterwards so the real
ndr_runtime is intact for the rest of the suite.
"""
import importlib.util
import json
import logging
import os
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent

STAMP = "2026-09-29T12:00:00Z"
CLOSED = dict(state="CLOSED", gaps=False, start=0, sha256="a" * 64)


def _fileinfo_bytes():
    eve = {"event_type": "fileinfo", "timestamp": STAMP, "flow_id": 42,
           "src_ip": "10.0.0.5", "dest_ip": "45.9.1.2",
           "fileinfo": {"filename": "invoice.exe", "size": 4096, "tx_id": 7, **CLOSED}}
    return json.dumps(eve).encode()


class _Rec:
    def __init__(self, value, offset, *, timestamp_type=1, timestamp=1_700_000_000_000):
        self.value = value                 # raw bytes, as the consumer now yields
        self.offset = offset
        self.timestamp_type = timestamp_type
        self.timestamp = timestamp
        self.topic = "suricata.file.v1"
        self.partition = 0


class _Consumer:
    """Yields one batch, then empty batches; the empty poll stops the loop."""
    def __init__(self, records):
        self._batches = [{("suricata.file.v1", 0): records}]
        self.on_drained = lambda: None
        self.commits = 0
        self.closed = False

    def poll(self, timeout_ms=0, max_records=0):
        if self._batches:
            return self._batches.pop(0)
        self.on_drained()                  # no more input -> let the loop exit
        return {}

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


class _Client:
    def __init__(self):
        self.inserted = []

    def insert(self, table, data, column_names=None):
        self.inserted.extend(data)


def _load_app(consumer, client):
    """Load app.py with its I/O boundaries faked. Fakes must be in sys.modules
    BEFORE app.py's top-level imports run; they are restored afterwards."""
    fake_ch = types.ModuleType("clickhouse_connect")
    fake_ch.get_client = lambda **kw: client
    fake_rt = types.ModuleType("ndr_runtime")
    fake_rt.setup_logging = lambda name: logging.getLogger(name)
    fake_rt.make_consumer = lambda *a, **k: consumer
    fake_rt.start_health = lambda *a, **k: None
    obs_spec = importlib.util.spec_from_file_location("observe", HERE / "observe.py")
    obs = importlib.util.module_from_spec(obs_spec)
    obs_spec.loader.exec_module(obs)

    saved = {k: sys.modules.get(k) for k in ("clickhouse_connect", "ndr_runtime", "observe")}
    sys.modules.update(clickhouse_connect=fake_ch, ndr_runtime=fake_rt, observe=obs)
    os.environ.setdefault("CLICKHOUSE_PASSWORD", "test")
    os.environ["NDR_FLUSH_SECS"] = "0"     # timer always elapsed -> commit each pass with input
    try:
        spec = importlib.util.spec_from_file_location("file_observer_app", HERE / "app.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
    return module


def _run(records):
    client, consumer = _Client(), _Consumer(records)
    module = _load_app(consumer, client)
    consumer.on_drained = lambda: setattr(module, "_running", False)
    module.main()
    return consumer, client


def test_malformed_json_then_valid_record_is_skipped_not_crashed():
    consumer, client = _run([_Rec(b"{broken-json", 0), _Rec(_fileinfo_bytes(), 1)])
    assert len(client.inserted) == 1          # the valid record survived the poison one
    assert consumer.commits >= 1              # offsets advanced past the skipped record
    assert consumer.closed


def test_invalid_utf8_then_valid_record_is_skipped_not_crashed():
    consumer, client = _run([_Rec(b"\xff\xfe\x00bad", 0), _Rec(_fileinfo_bytes(), 1)])
    assert len(client.inserted) == 1
    assert consumer.commits >= 1
    assert consumer.closed


def test_all_poison_batch_still_commits_offsets():
    # No valid rows to insert, but the offsets MUST still advance or a restart replays
    # the poison forever (the exact failure the reviewer reproduced).
    consumer, client = _run([_Rec(b"{bad", 0), _Rec(b"\xff\xfe", 1)])
    assert client.inserted == []
    assert consumer.commits >= 1


def test_tombstone_value_is_skipped():
    consumer, client = _run([_Rec(None, 0), _Rec(_fileinfo_bytes(), 1)])
    assert len(client.inserted) == 1
    assert consumer.commits >= 1


def test_contract_rejected_record_then_valid_record_is_skipped():
    # Well-formed JSON bytes that observe quarantines (completed capture, non-string
    # sha256) must skip via the QuarantineError arm, not stall a later valid record.
    poison = json.dumps({"event_type": "fileinfo", "timestamp": STAMP,
                         "fileinfo": {"state": "CLOSED", "gaps": False,
                                      "start": 0, "sha256": 123}}).encode()
    consumer, client = _run([_Rec(poison, 0), _Rec(_fileinfo_bytes(), 1)])
    assert len(client.inserted) == 1
    assert consumer.commits >= 1


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f()
            print("ok  " + _n)
    print("\nall file-observer app tests passed")
