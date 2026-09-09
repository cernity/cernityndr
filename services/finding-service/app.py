"""NDR finding service (plan U9): candidates -> lifecycle -> findings.

Consumes ndr.finding.candidate.v1, runs the state machine (state_machine.py),
persists to ClickHouse ndr.finding (ReplacingMergeTree dedups by finding_id),
and emits ndr.finding.final.v1 (FINAL) or ndr.capture.request.v1 (packets needed).
Lifecycle correctness is covered by test_state_machine.py; this is the I/O shell.
"""
import json
import logging
import os
import signal
from datetime import datetime, timezone

import ndr_runtime                      # shared tuned consumer/producer (plan 003 U6 rollout)

import state_machine as sm

log = logging.getLogger("finding-service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
CH_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse")
CH_USER = os.environ.get("CLICKHOUSE_USER", "ndr")
CH_PASS = os.environ.get("CLICKHOUSE_PASSWORD")
# ClickHouse persistence is optional: findings still flow to the bus without it.
# Treat an empty value as unset (compose passes an empty string when it is left
# blank), so persistence is off unless a real password is provided.
CH_ENABLED = bool(CH_PASS)

CANDIDATE_TOPIC = "ndr.finding.candidate.v1"
FINAL_TOPIC = "ndr.finding.final.v1"
CAPTURE_TOPIC = "ndr.capture.request.v1"

COLS = ["finding_id", "tenant_id", "sensor_ids", "detector_id", "detector_version",
        "category", "severity", "confidence", "first_seen", "last_seen", "entities",
        "evidence_refs", "mitre", "state", "enrichment_state", "capture_job_ids",
        "suppression_reason", "devo_delivery_state"]

_running = True


def _stop(*_):
    global _running
    _running = False


def _dt(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _row(f: dict) -> list:
    r = dict(f)
    r["first_seen"] = _dt(r.get("first_seen"))
    r["last_seen"] = _dt(r.get("last_seen"))
    r["severity"] = int(r.get("severity", 0) or 0)
    r["confidence"] = float(r.get("confidence", 0) or 0)
    for k in ("sensor_ids", "evidence_refs", "mitre", "capture_job_ids"):
        r[k] = r.get(k) or []
    for k in ("entities", "suppression_reason", "enrichment_state", "devo_delivery_state"):
        r[k] = r.get(k) or ""
    return [r.get(c) for c in COLS]


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    ch = None
    if CH_ENABLED:
        import clickhouse_connect
        ch = clickhouse_connect.get_client(host=CH_HOST, username=CH_USER, password=CH_PASS)
    producer = ndr_runtime.make_producer()
    consumer = ndr_runtime.make_consumer(CANDIDATE_TOPIC, group_id="ndr-finding-service", auto_offset_reset="earliest")
    ndr_runtime.start_health()          # /healthz /readyz /metrics (plan 003 obs)
    log.info("finding-service up: %s -> ClickHouse %s", CANDIDATE_TOPIC, CH_HOST if CH_ENABLED else "(disabled)")

    while _running:
        batch = consumer.poll(timeout_ms=1000, max_records=200)
        for _tp, records in batch.items():
            for rec in records:
                finding, route = sm.build_finding(rec.value)
                if CH_ENABLED:
                    ch.insert("ndr.finding", [_row(finding)], column_names=COLS)
                if route == "final":
                    producer.send(FINAL_TOPIC, finding)
                    log.info("FINAL %s (%s)", finding["finding_id"], finding["category"])
                else:
                    producer.send(CAPTURE_TOPIC, {"finding_id": finding["finding_id"],
                                                  "entities": finding.get("entities")})
                    log.info("CAPTURE_REQUESTED %s", finding["finding_id"])
        producer.flush()

    consumer.close()
    producer.close()
    log.info("finding-service stopped")


if __name__ == "__main__":
    main()
