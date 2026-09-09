"""IDS-alert promotion service (re-eval gap G1). Consumes suricata.raw.v1 and
promotes the THREAT-relevant Suricata signature alerts (promote.py) into
ndr.finding.candidate.v1 — so the IDS's own "known attack" verdicts finally
become first-class findings. Dedups per (finding_id, window) so a chatty rule
does not flood. Promotion logic is covered by test_promote.py; this is the
Kafka I/O shell.
"""
import json
import logging
import os
import signal
import time

import ndr_runtime                      # shared tuned consumer/producer (plan 003 U6 rollout)
import promote

log = logging.getLogger("ids-alerts")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
TENANT = os.environ.get("NDR_TENANT", "default")
WINDOW = float(os.environ.get("WINDOW_SECS", "600"))     # dedup bucket, 10 min
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
    consumer = ndr_runtime.make_consumer("suricata.raw.v1", group_id="ndr-ids-alerts", auto_offset_reset="latest")
    ndr_runtime.start_health()          # /healthz /readyz /metrics (plan 003 obs)
    log.info("ids-alerts up: promoting threat-relevant Suricata signatures -> findings")
    while _running:
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=1000).items():
            for rec in records:
                cand = promote.to_candidate(rec.value, TENANT)
                if cand is None:
                    continue
                bucket = int(time.time() // WINDOW)
                key = f"{cand['finding_id']}-{bucket}"
                if key in _emitted:
                    continue
                _emitted.add(key)
                producer.send(CANDIDATE_TOPIC, cand)
                log.info("IDS_SIGNATURE sev=%s cat=%s %s",
                         cand["severity"], cand["category"], cand["entities"][:140])
        producer.flush()
    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
