"""Executable-delivery detector. Hash feeds and matching live in threat-intel."""
import os
import signal
import time

import ndr_runtime                      # shared tuned consumer/producer (plan 003 U6 rollout)
import filematch

log = ndr_runtime.setup_logging("file-threat")
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
    consumer = ndr_runtime.make_consumer("suricata.file.v1", group_id="ndr-file-threat", auto_offset_reset="latest")
    ndr_runtime.start_health()          # /healthz /readyz /metrics (plan 003 obs)
    log.info("file-threat up: risky-delivery on suricata.file.v1")
    while _running:
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=1000).items():
            for rec in records:
                cand = filematch.to_candidate(rec.value, tenant=TENANT)
                if cand is None:
                    continue
                key = f"{cand['finding_id']}-{int(time.time() // WINDOW)}"
                if key in _emitted:
                    continue
                _emitted.add(key)
                producer.send(CANDIDATE_TOPIC, cand)
                log.info("FILE_THREAT %s sev=%s %s", cand["detector_id"], cand["severity"], cand["entities"][:140])
        producer.flush()
    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
