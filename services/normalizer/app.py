"""NDR normalizer service (plan U6): Redpanda -> typed rows -> ClickHouse.

Consumes the suricata.{flow,tls,dns,http}.v1 topics, runs the pure transforms
in models.py at the trusted-ingress boundary, and batch-inserts into ClickHouse.
Transform correctness is covered by test_normalize.py; this file is the I/O shell.
"""
import json
import os
import signal
import time
from datetime import datetime, timezone

import ndr_runtime                      # shared tuned consumer/producer (plan 003 U6 rollout)
import clickhouse_connect

import models

log = ndr_runtime.setup_logging("normalizer")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
CH_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse")
CH_USER = os.environ.get("CLICKHOUSE_USER", "ndr")
CH_PASS = os.environ["CLICKHOUSE_PASSWORD"]
TENANT = os.environ.get("NDR_TENANT", "default")
SENSOR = os.environ.get("NDR_SENSOR", "sensor-1")
DNS_VERSION = int(os.environ.get("NDR_DNS_VERSION", "3"))
FLUSH_ROWS = int(os.environ.get("NDR_FLUSH_ROWS", "500"))
FLUSH_SECS = float(os.environ.get("NDR_FLUSH_SECS", "5"))
TOPICS = ["suricata.flow.v1", "suricata.tls.v1", "suricata.dns.v1", "suricata.http.v1"]   # netflow no longer produced

_running = True


def _stop(*_):
    global _running
    _running = False


def _ts(row: dict) -> dict:
    """Coerce the EVE ISO timestamp to a datetime ClickHouse accepts."""
    raw = row.get("event_time") or ""
    try:
        row["event_time"] = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        row["event_time"] = datetime.now(timezone.utc)
    return row


def flush(ch, buffers: dict, producer):
    for table, rows in buffers.items():
        if not rows:
            continue
        cols = list(rows[0].keys())
        data = [[r[c] for c in cols] for r in rows]
        ch.insert(f"ndr.{table}", data, column_names=cols)
        # Publish only after durable row insertion. Any failure leaves offsets
        # uncommitted: retries may duplicate, but retain the same obs_id.
        for row in rows:
            doc = json.loads(row["observation"])
            entity = doc["entities"][0]["value"] if doc["entities"] else doc["sensor_id"]
            producer.send(models.OBSERVATION_TOPIC,
                          key=json.dumps([doc["tenant"], entity]).encode(),
                          value=doc).get(timeout=30)
        log.info("inserted and published %d -> ndr.%s", len(rows), table)
    buffers.clear()


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    ch = clickhouse_connect.get_client(host=CH_HOST, username=CH_USER, password=CH_PASS)
    consumer = ndr_runtime.make_consumer(*TOPICS, group_id="ndr-normalizer", auto_offset_reset="latest", enable_auto_commit=False, value_deserializer=lambda b: json.loads(b.decode("utf-8")))
    producer = ndr_runtime.make_producer(acks="all")
    ndr_runtime.start_health()          # /healthz /readyz /metrics (plan 003 obs)
    log.info("normalizer up: %s -> %s (tenant=%s sensor=%s)", BOOTSTRAP, CH_HOST, TENANT, SENSOR)

    buffers: dict[str, list] = {}
    pending = 0
    last = time.monotonic()
    while _running:
        batch = consumer.poll(timeout_ms=1000, max_records=FLUSH_ROWS)
        for _tp, records in batch.items():
            for rec in records:
                try:
                    if rec.timestamp_type != 1 or rec.timestamp is None or rec.timestamp < 0:
                        raise RuntimeError("normalizer requires input topics with LogAppendTime")
                    result = models.observation(
                        rec.value, TENANT, SENSOR, dns_version=DNS_VERSION,
                        topic=rec.topic, partition=rec.partition, offset=rec.offset,
                        ingested_at=datetime.fromtimestamp(
                            rec.timestamp / 1000, timezone.utc).isoformat())
                except models.QuarantineError as e:
                    log.warning("quarantined: %s", e)
                    continue
                if result is None:
                    continue
                table, row, _observation = result
                buffers.setdefault(table, []).append(_ts(row))
                pending += 1
        now = time.monotonic()
        if pending >= FLUSH_ROWS or (pending and now - last >= FLUSH_SECS):
            flush(ch, buffers, producer)
            consumer.commit()
            pending, last = 0, now

    flush(ch, buffers, producer)
    consumer.commit()
    producer.close()
    consumer.close()
    log.info("normalizer stopped")


if __name__ == "__main__":
    main()
