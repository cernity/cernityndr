"""findings-forwarder: consume ndr.finding.final.v1 and forward each finding
through the configured sink adapter (CERNITY_SINK). Emit-only boundary: this is
the one service that leaves Cernity for the operator's SIEM."""
import logging
import os
import signal
import time

import ndr_runtime

from adapters import get_adapter
from forwarder import handle_batch

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                    format="%(asctime)s %(levelname)s %(message)s")
log = ndr_runtime.setup_logging("findings-forwarder")

FINAL_TOPIC = "ndr.finding.final.v1"
HEARTBEAT_SECS = int(os.environ.get("LOG_HEARTBEAT_SECS", "60"))
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
    log.info("findings-forwarder up: consuming %s -> sink=%s", FINAL_TOPIC, type(adapter).__name__)
    total = 0
    last_beat = time.monotonic()
    while _running:
        batch = consumer.poll(timeout_ms=1000)
        for _tp, records in batch.items():
            findings = [r.value for r in records]
            handle_batch(findings, adapter)          # DurableSink: retries + dead-letters, never drops
            total += len(findings)
            for f in findings:                       # per-finding detail: DEBUG only, off by default
                log.debug("forwarded finding %s (%s)", f.get("finding_id", "?"), f.get("category", "?"))
        if batch:
            consumer.commit()                        # explicit ack AFTER durable delivery (F07)
        # Periodic heartbeat at INFO: enough to confirm the service is alive and
        # how much it has forwarded, without a line per finding filling the disk.
        now = time.monotonic()
        if now - last_beat >= HEARTBEAT_SECS:
            log.info("alive: %d finding(s) forwarded so far", total)
            last_beat = now


if __name__ == "__main__":
    main()
