"""Protocol-anomaly promotion service (re-eval gap G4). Consumes
suricata.anomaly.v1, promotes threat-relevant anomalies (anomaly.py) to
ndr.finding.candidate.v1. Dedups per (finding_id, window)."""
import logging
import os
import signal
import time

import ndr_runtime                      # shared tuned consumer/producer (plan 003 U5/U6)
import anomaly

log = logging.getLogger("anomaly-detector")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
TENANT = os.environ.get("NDR_TENANT", "default")
WINDOW = float(os.environ.get("WINDOW_SECS", "600"))
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
    consumer = ndr_runtime.make_consumer("suricata.anomaly.v1", group_id="ndr-anomaly-detector", auto_offset_reset="latest")
    ndr_runtime.start_health()          # /healthz /readyz /metrics (plan 003 obs)
    log.info("anomaly-detector up: promoting protocol anomalies -> findings")
    while _running:
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=1000).items():
            for rec in records:
                cand = anomaly.to_candidate(rec.value, TENANT)
                if cand is None:
                    continue
                key = f"{cand['finding_id']}-{int(time.time() // WINDOW)}"
                if key in _emitted:
                    continue
                _emitted.add(key)
                producer.send(CANDIDATE_TOPIC, cand)
                log.info("PROTOCOL_ANOMALY %s", cand["entities"][:140])
        producer.flush()
    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
