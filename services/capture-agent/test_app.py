"""U4/F11 wiring tests for the capture agent's I/O shell, without Kafka/MinIO/socket.
Proves the active-job counter is freed on ANY capture failure (including an arming
failure) — the old structure decremented only in the ship block, so an arming
exception leaked a budget slot until the sensor refused every future capture.

  PYTHONPATH=../../shared /opt/homebrew/bin/python3 test_app.py
"""
import os

os.environ.setdefault("LOG_FORMAT", "text")

import agent                                   # noqa: E402
import app                                     # noqa: E402  (boto3/kafka are lazy in main())
import suricata_socket as ss                   # noqa: E402


class FakeProducer:
    def __init__(self):
        self.sent = []

    def send(self, topic, value):
        self.sent.append((topic, value))

    def flush(self):
        pass


def _run_capture_with(dataset_add):
    """Run one _capture with a stubbed socket + fake producer; return the producer."""
    p = FakeProducer()
    orig = ss.dataset_add
    ss.dataset_add = dataset_add
    app._active = 1                            # main() incremented the slot before dispatch
    try:
        # ttl_secs=1 bounds the wait loop so the empty-window path returns promptly.
        app._capture({"capture_profile": "ip", "value": "203.0.113.9", "finding_id": "f1",
                      "ttl_secs": 1}, p, s3=None)   # s3 unused: no pcaps in the (empty) window
    finally:
        ss.dataset_add = orig
    return p


def test_arming_exception_still_frees_the_budget_slot():
    # Arming raises before any pcap work — the counter must still return to 0.
    def boom(*_a, **_k):
        raise RuntimeError("suricata socket down")
    p = _run_capture_with(boom)
    assert app._active == 0, "arming failure leaked an active-job slot"
    # and the orchestrator is told, so it frees its budget too
    states = [v.get("state") for t, v in p.sent if t == app.STATUS_TOPIC]
    assert "failed" in states


def test_empty_window_still_frees_the_budget_slot():
    # Arming succeeds, disarm is a no-op stub, but no packets were captured -> the
    # ship block fails cleanly and the slot is still freed.
    def noop(*_a, **_k):
        return None
    orig_rm = ss.dataset_remove
    ss.dataset_remove = noop
    try:
        p = _run_capture_with(noop)
    finally:
        ss.dataset_remove = orig_rm
    assert app._active == 0
    states = [v.get("state") for t, v in p.sent if t == app.STATUS_TOPIC]
    assert "failed" in states                  # "no packets captured in window"


def test_uploader_readiness_tracks_health():
    # The measured-health predicate the main loop feeds to metrics.set_ready.
    assert agent.uploader_healthy(0, 10_000)                       # idle
    assert not agent.uploader_healthy(1, 10_000, stale_secs=300)   # stalled uploader


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} capture-agent app tests passed")
