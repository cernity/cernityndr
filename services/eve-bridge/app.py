"""EVE bridge: consume the sensor's Suricata EVE off the bus and append it to a
growing eve.json that a SLIPS container ingests. Central-only; the sensor is
untouched. Which EVE event-types to forward is a tuning choice, so the input
topics are configurable (EVE_BRIDGE_TOPICS).
"""
import os
import signal

import ndr_runtime
import bridge

log = ndr_runtime.setup_logging("eve-bridge")

TOPICS = [t.strip() for t in os.environ.get(
    "EVE_BRIDGE_TOPICS", "suricata.flow.v1,suricata.raw.v1").split(",") if t.strip()]
GROUP_ID = os.environ.get("NDR_GROUP_ID", "ndr-eve-bridge")
OUT_FILE = os.environ.get("EVE_BRIDGE_OUT", "/slips-input/eve.json")
MAX_BYTES = int(os.environ.get("EVE_BRIDGE_MAX_BYTES", str(512 * 1024 * 1024)))

_running = True


def _stop(*_):
    global _running
    _running = False


def _open(path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    return open(path, "a")


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    consumer = ndr_runtime.make_consumer(*TOPICS, group_id=GROUP_ID, auto_offset_reset="latest")
    m = ndr_runtime.metrics
    m.start(int(os.environ.get("NDR_METRICS_PORT", "9108")))
    m.set_ready("consumer")
    f = _open(OUT_FILE)
    written = f.tell()
    log.info("eve-bridge up (topics=%s -> %s)", TOPICS, OUT_FILE)
    while _running:
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=1000).items():
            for rec in records:
                try:
                    line = bridge.eve_line(rec.value)
                except Exception as ex:
                    m.dropped("encode")
                    log.debug("skip record: %s", ex)
                    continue
                f.write(line)
                written += len(line)
            f.flush()
        if bridge.should_rotate(written, MAX_BYTES):
            # ponytail: single .1 backup; SLIPS reads the live file. If SLIPS ever
            # needs gap-free rotation, hand it the interface instead of a file.
            f.close()
            os.replace(OUT_FILE, OUT_FILE + ".1")
            f = _open(OUT_FILE)
            written = 0
            log.info("eve-bridge rotated %s", OUT_FILE)
    f.close()
    consumer.close()


if __name__ == "__main__":
    main()
