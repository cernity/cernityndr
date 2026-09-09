"""Coverage-detector service: consumes suricata.stats.v1, raises a coverage
finding when a sensor's visibility is degraded (capture loss or app-layer
blindness). Dedups per (sensor, kind, window) so a persistent condition does not
spam. See coverage.py for the pure detection logic.
"""
import logging
import os
import signal
import time

import ndr_runtime                      # shared tuned consumer/producer (plan 003 U5/U6)

import coverage as cov

log = ndr_runtime.setup_logging("coverage-detector")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
TENANT = os.environ.get("NDR_TENANT", "default")
WINDOW = float(os.environ.get("WINDOW_SECS", "600"))         # dedup bucket
SENSOR_ID = os.environ.get("NDR_SENSOR_ID", "sensor")        # each sensor self-identifies
DROP_THRESHOLD = float(os.environ.get("NDR_COVERAGE_DROP_RATIO", "0.02"))
APPLAYER_MIN_PKTS = int(os.environ.get("NDR_COVERAGE_MIN_PKTS", "5000"))
APPLAYER_RATIO = float(os.environ.get("NDR_COVERAGE_APPLAYER_RATIO", "0.001"))
CANDIDATE_TOPIC = os.environ.get("NDR_CANDIDATE_TOPIC", "ndr.finding.candidate.v1")
GROUP_ID = os.environ.get("NDR_GROUP_ID", "ndr-coverage-detector")

_emitted: set = set()          # (sensor, kind, window_bucket) dedup
_running = True


def _stop(*_):
    global _running
    _running = False


def _sensor_of(eve: dict) -> str:
    """Prefer a sensor/host id stamped on the record (multi-sensor deploys);
    fall back to this container's NDR_SENSOR_ID."""
    for k in ("sensor", "host", "hostname"):
        v = eve.get(k)
        if v:
            return str(v)
    return SENSOR_ID


def _emit_once(producer, kind: str, sensor: str, value):
    bucket = int(time.time() // WINDOW)
    key = (sensor, kind, bucket)
    if key in _emitted:
        return
    cand = cov.to_candidate(kind, sensor, value, TENANT)
    if not cand:
        return
    producer.send(CANDIDATE_TOPIC, cand)
    _emitted.add(key)
    log.info("COVERAGE_DEGRADED sensor=%s kind=%s value=%s sev=%s", sensor, kind, value, cand["severity"])


def evaluate(producer, eve: dict):
    if eve.get("event_type") != "stats":
        return
    stats = eve.get("stats") or {}
    sensor = _sensor_of(eve)
    loss, ratio = cov.capture_loss(stats, DROP_THRESHOLD)
    if loss:
        _emit_once(producer, "capture_loss", sensor, ratio)
    blind, al_ratio = cov.applayer_blind(stats, APPLAYER_MIN_PKTS, APPLAYER_RATIO)
    if blind:
        _emit_once(producer, "applayer_blind", sensor, al_ratio)


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    producer = ndr_runtime.make_producer()
    consumer = ndr_runtime.make_consumer("suricata.stats.v1", group_id=GROUP_ID, auto_offset_reset="latest")
    ndr_runtime.start_health()          # /healthz /readyz /metrics (plan 003 obs)
    log.info("coverage-detector up (suricata.stats.v1 -> %s)", CANDIDATE_TOPIC)
    while _running:
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=200).items():
            for rec in records:
                try:
                    evaluate(producer, rec.value)
                except Exception as e:            # never let one bad record kill the loop
                    log.debug("skip stats record: %s", e)
        producer.flush()
    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
