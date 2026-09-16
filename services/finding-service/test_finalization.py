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
    assert ("homelab", "sig-1") in pending                                          # tracked to finalize


def test_pending_finding_gains_evidence_on_result():
    p, pending = FakeProducer(), {}
    app._handle_candidate(SIG, p, {}, pending, 120, now=0.0, ch=None)
    app._handle_result({"finding_id": "sig-1", "status": "ok",
                        "evidence_refs": ["minio://ndr-pcap/x"]}, p, {}, pending, ch=None)
    finals = _by_topic(p, app.FINAL_TOPIC)
    assert len(finals) == 2                                            # deliver-now + enriched update
    assert finals[1]["enrichment_state"] == "ENRICHED"
    assert "minio://ndr-pcap/x" in finals[1]["evidence_refs"]
    assert ("homelab", "sig-1") not in pending                                      # loop closed


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
    assert ("homelab", "sig-1") not in pending


def test_agent_completed_status_waits_for_result():
    # A 'completed' capture status is not the enrichment outcome — the evidence comes
    # on ndr.enrichment.result.v1. Finalizing on 'completed' would drop the evidence.
    p, pending = FakeProducer(), {}
    app._handle_candidate(SIG, p, {}, pending, 120, now=0.0, ch=None)
    before = len(_by_topic(p, app.FINAL_TOPIC))
    app._handle_status({"finding_id": "sig-1", "state": "completed", "bytes": 10},
                       p, {}, pending, ch=None)
    assert len(_by_topic(p, app.FINAL_TOPIC)) == before               # no premature finalize
    assert ("homelab", "sig-1") in pending


def test_no_overlay_low_conf_finalizes_on_timeout():
    # No orchestrator/agent/zeek: a low-conf capture-only finding would dangle forever
    # in CAPTURE_REQUESTED. The timeout sweep delivers it rather than losing it.
    p, pending = FakeProducer(), {}
    app._handle_candidate(LOW, p, {}, pending, 1.0, now=0.0, ch=None)
    assert _by_topic(p, app.FINAL_TOPIC) == []                        # adjudicating, not delivered yet
    assert ("homelab", "exfil-1") in pending
    app._sweep_timeouts(p, {}, pending, now=2.0, ch=None)            # past the deadline
    dl = _by_topic(p, app.FINAL_TOPIC)
    assert len(dl) == 1 and dl[0]["state"] == "FINAL"                # delivered, not lost
    assert dl[0]["enrichment_state"] == "TIMEOUT"
    assert ("homelab", "exfil-1") not in pending


class FakeCH:
    """Captures ClickHouse inserts so we can assert what was durably persisted."""
    def __init__(self):
        self.rows = []

    def insert(self, table, rows, column_names=None):
        self.rows += [dict(zip(column_names, r)) for r in rows]


def test_each_revision_persists_as_a_distinct_durable_row():
    # R03 durable persistence: the initial FINAL (revision 1) and the enriched update
    # (revision 2) must land as TWO distinct rows carrying distinct revision values — not
    # one row collapsing the history. The table's sort key is revision-scoped so both
    # survive; ingested_at is the ReplacingMergeTree version for idempotent re-persist.
    p, pending, ch = FakeProducer(), {}, FakeCH()
    app._handle_candidate(SIG, p, {}, pending, 120, now=0.0, ch=ch)          # persists rev 1
    app._handle_result({"finding_id": "sig-1", "status": "ok",
                        "evidence_refs": ["minio://x"]}, p, {}, pending, ch=ch)  # persists rev 2
    persisted = [r for r in ch.rows if r["finding_id"] == "sig-1"]
    revs = sorted(r["revision"] for r in persisted)
    assert revs == [1, 2], f"expected distinct revisions 1 and 2, got {revs}"
    assert all("ingested_at" in r for r in persisted)                        # version column present
    rev2 = next(r for r in persisted if r["revision"] == 2)
    assert rev2["enrichment_state"] == "ENRICHED"                            # the update, retained separately


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


def test_pending_recovery_reloads_only_unfinalized(tmp_path=None):
    # F14: on restart, reload capture-bound findings still awaiting finalization; a FINAL deliver-now
    # threat -> delivered=True, a CAPTURE_REQUESTED low-conf finding -> delivered=False; an already
    # finalized (ENRICHED/TIMEOUT) finding is NOT reloaded. Keys are (tenant_id, finding_id).
    rows = [
        {"finding_id": "cap-1", "tenant_id": "t", "state": "CAPTURE_REQUESTED", "enrichment_state": "REQUIRED", "revision": 1},
        {"finding_id": "thr-1", "tenant_id": "t", "state": "FINAL", "enrichment_state": "PENDING", "revision": 1},
        {"finding_id": "done-1", "tenant_id": "t", "state": "FINAL", "enrichment_state": "ENRICHED", "revision": 2},
        {"finding_id": "to-1", "tenant_id": "t", "state": "FINAL", "enrichment_state": "TIMEOUT", "revision": 2},
    ]
    pend = app._pending_from_rows(rows, deadline_secs=120, now=0.0)
    assert set(pend) == {("t", "cap-1"), ("t", "thr-1")}          # only un-finalized reloaded
    assert pend[("t", "thr-1")]["delivered"] is True             # deliver-now threat, already on SIEM
    assert pend[("t", "cap-1")]["delivered"] is False            # capture-only, not yet delivered
    assert pend[("t", "cap-1")]["deadline"] == 0.0               # §62.6 immediate deadline, not a fresh window
    # a reloaded capture-only finding is then finalized on the next sweep -> delivered, never dangling
    p = FakeProducer()
    app._sweep_timeouts(p, {}, pend, now=1.0, ch=None)
    dl = _by_topic(p, app.FINAL_TOPIC)
    assert any(f["finding_id"] == "cap-1" and f["state"] == "FINAL" for f in dl)


def test_pending_recovery_is_tenant_safe():
    # §62.6: two tenants sharing a finding_id must NOT collide — the recovered map keys them separately.
    rows = [
        {"finding_id": "shared", "tenant_id": "acme", "state": "CAPTURE_REQUESTED", "enrichment_state": "REQUIRED", "revision": 1},
        {"finding_id": "shared", "tenant_id": "globex", "state": "FINAL", "enrichment_state": "PENDING", "revision": 1},
    ]
    pend = app._pending_from_rows(rows, 120, 0.0)
    assert set(pend) == {("acme", "shared"), ("globex", "shared")}      # distinct entries, no collision
    # a result for acme's copy finalizes ONLY acme's; globex's stays pending
    p = FakeProducer()
    app._handle_result({"finding_id": "shared", "tenant_id": "acme", "status": "ok"}, p, {}, pend, ch=None)
    assert ("acme", "shared") not in pend and ("globex", "shared") in pend


def test_load_pending_from_ch_disabled_is_ok_empty():
    assert app._load_pending_from_ch(None, 120, 0.0) == ({}, True)


def test_pending_recovery_failure_is_observable():
    # §62.6: a query FAILURE returns recovery_ok=False (observable), not a silent empty-success.
    class BoomCH:
        def query(self, *a, **k):
            raise RuntimeError("clickhouse down")
    pend, ok = app._load_pending_from_ch(BoomCH(), 120, 0.0)
    assert pend == {} and ok is False


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} finalization-loop tests passed")
