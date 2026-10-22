"""Protocol promotion plus U8 observation-based outbound-volume detection.

External history supports replica-shared, idempotent learning when
OUTBOUND_HISTORY_STORE=1; the default local path resets on restart. Event-time
windows close at wall clock minus allowed lateness after an empty poll.
Replicas must receive complete entity windows (upstream entity partitioning);
shared history does not merge partial feature aggregates.

The decode-layer anomalies the threat path filters out are tallied per sensor
per window and assessed for checksum rejection, which emits a sensor-health
candidate rather than a threat finding. Each replica tallies only the partitions
it is assigned, so the share is per-replica; it is a dominance indicator, not a
fleet-wide rate.
"""
import os
import signal
import time
from datetime import datetime

import ndr_runtime                      # shared tuned consumer/producer (plan 003 U5/U6)
import anomaly
from features import FeatureExtractor

log = ndr_runtime.setup_logging("anomaly-detector")
BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
TENANT = os.environ.get("NDR_TENANT", "default")
WINDOW = float(os.environ.get("WINDOW_SECS", "600"))
CANDIDATE_TOPIC = "ndr.finding.candidate.v1"
SENSOR_ID = os.environ.get("NDR_SENSOR_ID", "sensor")        # fallback when records are unstamped
# Sensor-health window, on the wall clock like the dedup bucket above: the signal
# is a property of the engine over an interval of reporting, not of event time.
CHECKSUM_WINDOW = float(os.environ.get("CHECKSUM_HEALTH_WINDOW_SECS", "600"))
CHECKSUM_SHARE = float(os.environ.get("CHECKSUM_HEALTH_SHARE", anomaly.CHECKSUM_SHARE_THRESHOLD))
CHECKSUM_MIN_SAMPLE = int(os.environ.get("CHECKSUM_HEALTH_MIN_SAMPLE", anomaly.CHECKSUM_MIN_SAMPLE))
_emitted: set = set()
_checksum: dict = {}            # (sensor, window bucket) -> checksum tally
_running = True


def _stop(*_):
    global _running
    _running = False


def _sensor_of(eve: dict) -> str:
    """Prefer a sensor/host id stamped on the record (multi-sensor deploys);
    fall back to this container's NDR_SENSOR_ID."""
    for key in ("sensor_id", "host", "sensor", "hostname"):
        value = eve.get(key)
        if value:
            return str(value)
    return SENSOR_ID


def tally_health(eve: dict, bucket: int) -> None:
    """Accumulate one record into its sensor's current health window. Counts
    every anomaly event, including the threat-relevant ones: they are the
    denominator the checksum share is measured against."""
    key = (_sensor_of(eve), bucket)
    anomaly.tally_checksum_anomalies(
        [eve], _checksum.setdefault(key, {"checksum": 0, "other_decode": 0, "anomalies": 0}))


def flush_health(producer, bucket: int) -> list:
    """Assess and drop every window older than `bucket`. Separate from the
    threat path on purpose: a sensor rejecting traffic is a health problem, and
    a window below threshold emits nothing at all.

    The service owns the clock: the bucket index is turned back into the
    window's wall-clock bounds here and passed in, so the assessment itself
    stays a pure function of the counts and the window."""
    emitted = []
    for key in [k for k in _checksum if k[1] != bucket]:
        sensor, wid = key
        tally = _checksum.pop(key)
        cand = anomaly.to_sensor_health(
            tally["checksum"], tally["anomalies"], sensor, TENANT,
            other_decode_count=tally["other_decode"], share_threshold=CHECKSUM_SHARE,
            min_sample=CHECKSUM_MIN_SAMPLE,
            window_start=wid * CHECKSUM_WINDOW, window_end=(wid + 1) * CHECKSUM_WINDOW)
        if cand is None:
            continue
        producer.send(CANDIDATE_TOPIC, cand)
        health = cand["summary"]["sensor_health"]
        log.warning("SENSOR_CHECKSUM_REJECTION sensor=%s share=%s sample=%s verdict=%s",
                    sensor, health["checksum_anomaly_share"], health["sample_size"],
                    health["verdict"])
        emitted.append(cand)
    return emitted


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    producer = ndr_runtime.make_producer()
    consumer = ndr_runtime.make_consumer(
        "suricata.anomaly.v1", "ndr.observation.normalized.v1",
        group_id="ndr-anomaly-detector", auto_offset_reset="latest")
    extractor = FeatureExtractor(int(os.environ.get("FEATURE_WINDOW_SECS", "300")))
    history_store = None
    # Flip only after enabled-path parity, restart and retention gates plus the
    # persistent Redis rollout in ADR 016; never silently fall back on store errors.
    if os.environ.get("OUTBOUND_HISTORY_STORE", "0") == "1":
        from store import RedisStore
        history_store = RedisStore(os.environ["OUTBOUND_HISTORY_REDIS_URL"])
        history_store._r.ping()
    model = anomaly.OutboundBytesModel(store=history_store)
    lateness = int(os.environ.get("FEATURE_LATENESS_SECS", "60"))
    if lateness < 0:
        raise ValueError("FEATURE_LATENESS_SECS must be nonnegative")
    ndr_runtime.start_health()          # /healthz /readyz /metrics (plan 003 obs)
    log.info("anomaly-detector up: promoting protocol anomalies -> findings")
    event_watermark = float("-inf")
    while _running:
        consumer_records = consumer.poll(timeout_ms=1000, max_records=1000)
        for _tp, records in consumer_records.items():
            for rec in records:
                if rec.topic == "ndr.observation.normalized.v1":
                    extractor.add(rec.value)
                    try:
                        stamp = datetime.fromisoformat(rec.value['ts']['normalized'].replace('Z', '+00:00'))
                        if stamp.tzinfo is not None:
                            event_watermark = max(event_watermark, min(stamp.timestamp(), time.time()))
                    except (KeyError, TypeError, ValueError):
                        pass
                    continue
                tally_health(rec.value, int(time.time() // CHECKSUM_WINDOW))
                cand = anomaly.to_candidate(rec.value, TENANT)
                if cand is None:
                    continue
                key = f"{cand['finding_id']}-{int(time.time() // WINDOW)}"
                if key in _emitted:
                    continue
                _emitted.add(key)
                producer.send(CANDIDATE_TOPIC, cand)
                log.info("PROTOCOL_ANOMALY %s", cand["entities"][:140])
        flush_health(producer, int(time.time() // CHECKSUM_WINDOW))
        # Event-time progress closes windows even under continuous traffic. An idle
        # poll advances to wall time; lateness bounds cross-partition reordering.
        watermark = event_watermark if any(consumer_records.values()) else time.time()
        if watermark != float("-inf"):
            for cand in model.evaluate(extractor.close(watermark - lateness)):
                producer.send(CANDIDATE_TOPIC, cand).get(timeout=30)
        if extractor.late_observations:
            log.warning("late observations excluded: %s", extractor.late_observations)
        producer.flush()
    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
