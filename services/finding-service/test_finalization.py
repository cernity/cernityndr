"""U1 finalization-loop tests (F01) — the finding-service consumer wiring that
closes the capture lifecycle, without Kafka or Docker. The audit's blocker was a
dangling loop: the service emitted CAPTURE_REQUESTED and nothing ever finalized it.
These drive the handlers directly with a fake producer:

  * a confirmed threat reaches the sink IMMEDIATELY and requests capture,
  * it gains evidence when the enrichment result arrives,
  * a failed/refused/timed-out capture still finalizes it (never a drop),
  * a low-confidence capture-only finding is delivered on timeout, not lost.

  PYTHONPATH=../../shared /opt/homebrew/bin/python3 test_finalization.py
"""
import os

os.environ.setdefault("LOG_FORMAT", "text")

import app                                    # noqa: E402  (env set before import)

SIG = {"finding_id": "sig-1", "tenant_id": "homelab", "detector_id": "ids_signature",
       "detector_version": "1", "category": "c2", "severity": 8, "confidence": 0.9,
       "entities": '[{"type":"ip","role":"dst","value":"203.0.113.9"}]',
       "sensor_ids": ["sensor-7"], "state": "CANDIDATE"}
# beacon/exfil, low confidence -> packets_needed for adjudication (not a confirmed threat).
LOW = {"finding_id": "exfil-1", "tenant_id": "homelab", "detector_id": "beacon",
       "detector_version": "1", "category": "exfil", "severity": 7, "confidence": 0.6,
       "entities": '[{"type":"ip","role":"dst","value":"203.0.113.9"}]', "state": "CANDIDATE"}


class FakeProducer:
    def __init__(self):
        self.sent = []

    def send(self, topic, value, key=None):
        self.sent.append((topic, value, key))


def _by_topic(p, topic):
    return [v for t, v, _k in p.sent if t == topic]


def _keys(p, topic):
    return [k for t, _v, k in p.sent if t == topic]


def test_confirmed_threat_reaches_sink_immediately_and_requests_capture():
    p, pending = FakeProducer(), {}
    app._handle_candidate(SIG, p, {}, pending, 120, now=0.0, ch=None)
    finals = _by_topic(p, app.FINAL_TOPIC)
    caps = _by_topic(p, app.CAPTURE_TOPIC)
    assert len(finals) == 1 and finals[0]["state"] == "FINAL"          # SIEM now
    assert finals[0]["enrichment_state"] == "PENDING"
    assert len(caps) == 1 and caps[0]["sensor_id"] == "sensor-7"       # sensor-specific
    assert caps[0]["value"] == "203.0.113.9"
    assert "sig-1" in pending                                          # tracked to finalize


def test_pending_finding_gains_evidence_on_result():
    p, pending = FakeProducer(), {}
    app._handle_candidate(SIG, p, {}, pending, 120, now=0.0, ch=None)
    app._handle_result({"finding_id": "sig-1", "status": "ok",
                        "evidence_refs": ["minio://ndr-pcap/x"]}, p, {}, pending, ch=None)
    finals = _by_topic(p, app.FINAL_TOPIC)
    assert len(finals) == 2                                            # deliver-now + enriched update
    assert finals[1]["enrichment_state"] == "ENRICHED"
    assert "minio://ndr-pcap/x" in finals[1]["evidence_refs"]
    assert "sig-1" not in pending                                      # loop closed


def test_failed_enrichment_still_finalizes_never_drops():
    p, pending = FakeProducer(), {}
    app._handle_candidate(SIG, p, {}, pending, 120, now=0.0, ch=None)
    app._handle_result({"finding_id": "sig-1", "status": "failed"}, p, {}, pending, ch=None)
    upd = _by_topic(p, app.FINAL_TOPIC)[-1]
    assert upd["state"] == "FINAL" and upd["enrichment_state"] == "ENRICHMENT_FAILED"


def test_refused_capture_finalizes_on_status():
    p, pending = FakeProducer(), {}
    app._handle_candidate(SIG, p, {}, pending, 120, now=0.0, ch=None)
    app._handle_status({"finding_id": "sig-1", "armed": False, "reason": "budget"},
                       p, {}, pending, ch=None)
    upd = _by_topic(p, app.FINAL_TOPIC)[-1]
    assert upd["state"] == "FINAL" and upd["enrichment_state"] == "TIMEOUT"
    assert "sig-1" not in pending


def test_agent_completed_status_waits_for_result():
    # A 'completed' capture status is not the enrichment outcome — the evidence comes
    # on ndr.enrichment.result.v1. Finalizing on 'completed' would drop the evidence.
    p, pending = FakeProducer(), {}
    app._handle_candidate(SIG, p, {}, pending, 120, now=0.0, ch=None)
    before = len(_by_topic(p, app.FINAL_TOPIC))
    app._handle_status({"finding_id": "sig-1", "state": "completed", "bytes": 10},
                       p, {}, pending, ch=None)
    assert len(_by_topic(p, app.FINAL_TOPIC)) == before               # no premature finalize
    assert "sig-1" in pending


def test_no_overlay_low_conf_finalizes_on_timeout():
    # No orchestrator/agent/zeek: a low-conf capture-only finding would dangle forever
    # in CAPTURE_REQUESTED. The timeout sweep delivers it rather than losing it.
    p, pending = FakeProducer(), {}
    app._handle_candidate(LOW, p, {}, pending, 1.0, now=0.0, ch=None)
    assert _by_topic(p, app.FINAL_TOPIC) == []                        # adjudicating, not delivered yet
    assert "exfil-1" in pending
    app._sweep_timeouts(p, {}, pending, now=2.0, ch=None)            # past the deadline
    dl = _by_topic(p, app.FINAL_TOPIC)
    assert len(dl) == 1 and dl[0]["state"] == "FINAL"                # delivered, not lost
    assert dl[0]["enrichment_state"] == "TIMEOUT"
    assert "exfil-1" not in pending


def test_unknown_result_is_idempotent_noop():
    p, pending = FakeProducer(), {}
    app._handle_result({"finding_id": "ghost", "status": "ok"}, p, {}, pending, ch=None)
    assert p.sent == [] and pending == {}


def test_final_delivery_is_partition_keyed_by_entity():
    # F08: final.v1 is keyed by tenant|entity so one host's whole history lands on one
    # partition — correlation replicas never split it. Deliver-now + the enriched update
    # must carry the SAME key.
    p, pending = FakeProducer(), {}
    app._handle_candidate(SIG, p, {}, pending, 120, now=0.0, ch=None)
    app._handle_result({"finding_id": "sig-1", "status": "ok", "evidence_refs": ["x"]},
                       p, {}, pending, ch=None)
    keys = _keys(p, app.FINAL_TOPIC)
    assert keys == [b"homelab|ip:203.0.113.9", b"homelab|ip:203.0.113.9"]  # stable, tenant-scoped


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} finalization-loop tests passed")
