"""Zeek-notice promotion service. Consumes zeek.notice.v1 (Zeek notice.log
records, shipped as JSON by the sensor/central Vector) and promotes each notice
into ndr.finding.candidate.v1 via promote_notice.py, so Zeek's own detections
reach the SIEM through the findings-first path. Dedups per (finding_id, window)
so a chatty notice does not flood. Promotion logic is covered by
test_promote_notice.py; this is the Kafka I/O shell.
"""
import json
import logging
import os
import signal
import time

import ndr_runtime                      # shared tuned consumer/producer (plan 003 U6 rollout)
import promote_notice

log = logging.getLogger("zeek-notice")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
TENANT = os.environ.get("NDR_TENANT", "default")
WINDOW = float(os.environ.get("WINDOW_SECS", "600"))     # dedup bucket, 10 min
IN_TOPIC = "zeek.notice.v1"
CANDIDATE_TOPIC = "ndr.finding.candidate.v1"

_emitted: set = set()
_running = True


def _stop(*_):
    global _running
    _running = False


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    producer = ndr_runtime.make_producer()
    consumer = ndr_runtime.make_consumer(IN_TOPIC, group_id="ndr-zeek-notice", auto_offset_reset="latest")
    log.info("zeek-notice up: promoting Zeek notices -> findings (findings-first to SIEM)")
    ndr_runtime.start_health()          # /healthz /readyz /metrics (plan 003 obs)
    while _running:
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=1000).items():
            for rec in records:
                cand = promote_notice.to_candidate(rec.value, TENANT)
                if cand is None:
                    continue
                bucket = int(time.time() // WINDOW)
                key = f"{cand['finding_id']}-{bucket}"
                if key in _emitted:
                    continue
                _emitted.add(key)
                producer.send(CANDIDATE_TOPIC, cand)
                log.info("ZEEK_NOTICE sev=%s cat=%s %s",
                         cand["severity"], cand["category"], cand["entities"][:140])
        producer.flush()
    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
