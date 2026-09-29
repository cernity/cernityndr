"""Protocol promotion plus U8 observation-based outbound-volume detection.

Run one replica: cohort history is local and resets on restart. Event-time
windows close at wall clock minus allowed lateness after an empty poll.
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
_emitted: set = set()
_running = True


def _stop(*_):
    global _running
    _running = False


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    producer = ndr_runtime.make_producer()
    consumer = ndr_runtime.make_consumer(
        "suricata.anomaly.v1", "ndr.observation.normalized.v1",
        group_id="ndr-anomaly-detector", auto_offset_reset="latest")
    extractor = FeatureExtractor(int(os.environ.get("FEATURE_WINDOW_SECS", "300")))
    model = anomaly.OutboundBytesModel()
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
                cand = anomaly.to_candidate(rec.value, TENANT)
                if cand is None:
                    continue
                key = f"{cand['finding_id']}-{int(time.time() // WINDOW)}"
                if key in _emitted:
                    continue
                _emitted.add(key)
                producer.send(CANDIDATE_TOPIC, cand)
                log.info("PROTOCOL_ANOMALY %s", cand["entities"][:140])
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
