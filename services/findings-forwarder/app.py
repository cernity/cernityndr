"""findings-forwarder: consume ndr.finding.final.v1 and forward each finding
through the configured sink adapter (CERNITY_SINK). Emit-only boundary: this is
the one service that leaves Cernity for the operator's SIEM."""
import logging
import os
import signal
import time
import uuid

import ndr_runtime

from adapters import get_adapter
from forwarder import handle_batch, build_receipt

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                    format="%(asctime)s %(levelname)s %(message)s")
log = ndr_runtime.setup_logging("findings-forwarder")

FINAL_TOPIC = "ndr.finding.final.v1"
RECEIPT_TOPIC = "ndr.sink.receipt.v1"                # Rec-D: accountable per-sink delivery disposition
HEARTBEAT_SECS = int(os.environ.get("LOG_HEARTBEAT_SECS", "60"))
RECEIPTS_ON = os.environ.get("CERNITY_SINK_RECEIPTS", "1").strip().lower() not in ("", "0", "false", "no")
_running = True


def _stop(*_):
    global _running
    _running = False


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    import metrics                                    # lazy: /healthz /readyz /metrics
    # Sink health drives readiness (F15): a wedged/dead-lettering sink flips /readyz false.
    adapter = get_adapter(on_health=lambda name, ok: metrics.set_ready(f"sink:{name}", ok))
    ndr_runtime.start_health(ready=("consumer",))    # start the health server (F15)
    # enable_auto_commit=False: offsets are committed only AFTER durable delivery (F07),
    # so a crash/redeploy before a finding is delivered replays it instead of losing it.
    consumer = ndr_runtime.make_consumer(FINAL_TOPIC, group_id="cernity-findings-forwarder",
                                         auto_offset_reset="earliest", enable_auto_commit=False)
    producer = ndr_runtime.make_producer() if RECEIPTS_ON else None
    worker = uuid.uuid4().hex                          # stable per-process id: receipts are attributable
    log.info("findings-forwarder up: consuming %s -> sink=%s (worker %s)",
             FINAL_TOPIC, type(adapter).__name__, worker[:8])
    total = suppressed = seq = 0
    last_beat = time.monotonic()

    def emit_receipt():
        # Rec-D: publish the accountable disposition (consumed = suppressed + delivered + dead-lettered
        # per sink) so a reader can confirm every consumed finding was accounted for, not just drained.
        nonlocal seq
        if producer is None:
            return
        try:
            seq += 1
            producer.send(RECEIPT_TOPIC, value=build_receipt(adapter, total, suppressed, worker, seq))
            producer.flush()
        except Exception as e:                       # noqa: BLE001 (a receipt failure must not drop findings)
            log.warning("could not emit sink receipt: %s", e)

    while _running:
        batch = consumer.poll(timeout_ms=1000)
        for _tp, records in batch.items():
            findings = [r.value for r in records]
            # Suppressed findings stay on the bus for correlation but are withheld from the analyst
            # plane; count them here so the receipt accounts for consumed = suppressed + delivered.
            live = [f for f in findings if f.get("state") != "SUPPRESSED"]
            suppressed += len(findings) - len(live)
            handle_batch(live, adapter)              # DurableSink: retries + dead-letters, never drops
            total += len(findings)
            for f in findings:                       # per-finding detail: DEBUG only, off by default
                log.debug("forwarded finding %s (%s)", f.get("finding_id", "?"), f.get("category", "?"))
        if batch:
            consumer.commit()                        # explicit ack AFTER durable delivery (F07)
            emit_receipt()                           # refresh the receipt after each committed batch
        now = time.monotonic()
        if now - last_beat >= HEARTBEAT_SECS:
            log.info("alive: %d finding(s) forwarded so far", total)
            last_beat = now
    emit_receipt()                                   # final disposition on shutdown


if __name__ == "__main__":
    main()
