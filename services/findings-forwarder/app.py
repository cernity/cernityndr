"""findings-forwarder: consume ndr.finding.final.v1 and forward each finding
through the configured sink adapter (CERNITY_SINK). Emit-only boundary: this is
the one service that leaves Cernity for the operator's SIEM."""
import logging
import signal

import ndr_runtime

from adapters import get_adapter
from forwarder import handle_batch

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("findings-forwarder")

FINAL_TOPIC = "ndr.finding.final.v1"
_running = True


def _stop(*_):
    global _running
    _running = False


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    adapter = get_adapter()
    consumer = ndr_runtime.make_consumer(FINAL_TOPIC, group_id="cernity-findings-forwarder",
                                         auto_offset_reset="earliest")
    log.info("findings-forwarder up: %s -> %s", FINAL_TOPIC, type(adapter).__name__)
    while _running:
        batch = consumer.poll(timeout_ms=1000)
        for _tp, records in batch.items():
            handle_batch([r.value for r in records], adapter)


if __name__ == "__main__":
    main()
