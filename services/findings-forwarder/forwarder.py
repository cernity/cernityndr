"""Pure forward logic: hand findings to the sink adapter. Uses the adapter's
emit_batch when available (efficient bulk delivery), else per-finding emit."""
from datetime import datetime, timezone


def handle_batch(findings, adapter):
    if not findings:
        return
    if hasattr(adapter, "emit_batch"):
        adapter.emit_batch(findings)
    else:
        for f in findings:
            adapter.emit(f)


def sink_receipts(adapter):
    """Normalise one adapter or a MultiAdapter to a list of per-sink receipts."""
    r = adapter.receipt() if hasattr(adapter, "receipt") else None
    return r if isinstance(r, list) else ([r] if r else [])


def build_receipt(adapter, consumed, suppressed, worker=None, seq=0):
    """The accountable completion receipt (Rec-D): every consumed finding is either delivered,
    intentionally suppressed, or dead-lettered — so a reader can prove the forwarder accounted for
    all its input, not merely that the bus drained. The per-sink invariant target is
    delivered + dead_lettered == consumed - suppressed. `worker` (a stable per-process id) + `seq`
    (monotonic) make receipts attributable so a reader aggregates the latest PER worker across a
    partitioned/restarted fleet instead of trusting one recent message (§handoff stage 3)."""
    sinks = sink_receipts(adapter)
    return {
        "schema_version": "1.0", "svc": "findings-forwarder",
        "worker": worker, "seq": seq,
        "consumed": consumed, "suppressed": suppressed, "sinks": sinks,
        "delivered_live": consumed - suppressed,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
