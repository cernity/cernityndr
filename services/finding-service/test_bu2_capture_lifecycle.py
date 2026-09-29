"""B-U2 (plan 010 Track B, review R02): a completed capture (armed=False) must NOT be finalized as a
timeout — its enrichment result still follows; a late result after a timeout re-opens as a NEW revision
rather than being dropped; a bare armed=False refusal still finalizes. Drives the handlers directly.

  PYTHONPATH=../../shared python3 test_bu2_capture_lifecycle.py
"""
import os

os.environ.setdefault("LOG_FORMAT", "text")

import app  # noqa: E402

SIG = {"finding_id": "sig-1", "tenant_id": "homelab", "detector_id": "ids_signature",
       "detector_version": "1", "category": "c2", "severity": 8, "confidence": 0.9,
       "entities": '[{"type":"ip","role":"dst","value":"203.0.113.9"}]',
       "sensor_ids": ["sensor-7"], "state": "CANDIDATE"}


class FakeProducer:
    def __init__(self):
        self.sent = []

    def send(self, topic, value, key=None):
        self.sent.append((topic, value, key))


def _finals(p):
    return [v for t, v, _k in p.sent if t == app.FINAL_TOPIC]


def test_completed_with_armed_false_does_not_finalize():
    # The REAL agent completion message carries armed=False (capture-agent sets it on completion);
    # treating armed=False as a refusal dropped the enrichment result (R02).
    app._finalized_capture.clear()
    p, pending = FakeProducer(), {}
    app._handle_candidate(SIG, p, {}, pending, 120, now=0.0, ch=None)
    n = len(_finals(p))
    app._handle_status({"finding_id": "sig-1", "tenant_id": "homelab", "state": "completed",
                        "armed": False, "bytes": 10}, p, {}, pending, ch=None)
    assert len(_finals(p)) == n, "a completed capture must not finalize (await the result)"
    assert ("homelab", "sig-1") in pending
    app._handle_result({"finding_id": "sig-1", "tenant_id": "homelab", "status": "ok",
                        "evidence_refs": ["minio://x"]}, p, {}, pending, ch=None)
    f = _finals(p)[-1]
    assert f["enrichment_state"] == "ENRICHED" and "minio://x" in f["evidence_refs"]


def test_bare_armed_false_refusal_still_finalizes():
    app._finalized_capture.clear()
    p, pending = FakeProducer(), {}
    app._handle_candidate(SIG, p, {}, pending, 120, now=0.0, ch=None)
    app._handle_status({"finding_id": "sig-1", "tenant_id": "homelab", "armed": False, "reason": "budget"},
                       p, {}, pending, ch=None)
    assert _finals(p)[-1]["enrichment_state"] == "TIMEOUT"
    assert ("homelab", "sig-1") not in pending


def test_late_result_after_timeout_reopens_as_new_revision():
    app._finalized_capture.clear()
    p, pending = FakeProducer(), {}
    app._handle_candidate(SIG, p, {}, pending, 1.0, now=0.0, ch=None)
    app._sweep_timeouts(p, {}, pending, now=2.0, ch=None)                 # timeout-finalize
    to = _finals(p)[-1]
    assert to["enrichment_state"] == "TIMEOUT"
    to_rev = to["revision"]
    app._handle_result({"finding_id": "sig-1", "tenant_id": "homelab", "status": "ok",
                        "evidence_refs": ["minio://late"]}, p, {}, pending, ch=None)
    late = _finals(p)[-1]
    assert late["enrichment_state"] == "ENRICHED" and "minio://late" in late["evidence_refs"]
    assert late["revision"] > to_rev, "a late result must land as a NEW revision after the timeout"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok  " + fn.__name__)
    print("\nall %d B-U2 capture-lifecycle tests passed" % len(fns))


def test_u6_preserved_reference_attaches_via_existing_result_handler():
    """Local consumer unit test only; store/bus delivery is deferred to U1b."""
    app._finalized_capture.clear()
    p, pending = FakeProducer(), {}
    app._handle_candidate(SIG, p, {}, pending, 120, now=0, ch=None)
    ref = 'ndr-pcap/homelab-tenant-hash/request-preserve.pcap'
    app._handle_status({'finding_id': 'sig-1', 'tenant_id': 'homelab',
                        'state': 'completed', 'kind': 'preserve', 'armed': False,
                        'pcap_ref': ref}, p, {}, pending, ch=None)
    assert ('homelab', 'sig-1') in pending
    # The capture agent emits this existing result shape after a successful upload.
    app._handle_result({'finding_id': 'sig-1', 'tenant_id': 'homelab', 'status': 'ok',
                        'evidence_refs': [ref]}, p, {}, pending, ch=None)
    assert ref in _finals(p)[-1]['evidence_refs']
    assert _finals(p)[-1]['tenant_id'] == 'homelab'
