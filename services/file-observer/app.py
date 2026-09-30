"""file-observer (U1b): suricata.file.v1 -> ndr.file_observation.

Consumes fileinfo events, runs the pure transform in observe.py at the
trusted-ingress boundary, and batch-inserts canonical file observations into
ClickHouse. Transform correctness and contract validation live in observe.py — a
row that fails the pinned contract raises QuarantineError and is dropped here, never
inserted (fail closed); this file is the Kafka + ClickHouse I/O shell.
"""
import json
import os
import signal
import time
from datetime import datetime, timezone

import ndr_runtime
import clickhouse_connect

import observe

log = ndr_runtime.setup_logging("file-observer")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
CH_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse")
CH_USER = os.environ.get("CLICKHOUSE_USER", "ndr")
CH_PASS = os.environ["CLICKHOUSE_PASSWORD"]
TENANT = os.environ.get("NDR_TENANT", "default")
SENSOR = os.environ.get("NDR_SENSOR", "sensor-1")
FLUSH_ROWS = int(os.environ.get("NDR_FLUSH_ROWS", "500"))
FLUSH_SECS = float(os.environ.get("NDR_FLUSH_SECS", "5"))

_running = True


def _stop(*_):
    global _running
    _running = False


def flush(ch, rows):
    if not rows:
        return
    cols = ["observation", "raw_record"]           # every other column is MATERIALIZED
    data = [[r[c] for c in cols] for r in rows]
    ch.insert(observe.TABLE, data, column_names=cols)
    log.info("inserted %d -> %s", len(rows), observe.TABLE)
    rows.clear()


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    ch = clickhouse_connect.get_client(host=CH_HOST, username=CH_USER, password=CH_PASS)
    consumer = ndr_runtime.make_consumer(
        observe.FILE_TOPIC, group_id="ndr-file-observer",
        auto_offset_reset="latest", enable_auto_commit=False,
        # Consume RAW bytes. Decoding/JSON-parsing inside the deserializer would run
        # under consumer.poll(), OUTSIDE the per-record try below — one poison record
        # (malformed JSON / bad UTF-8) would then crash poll() before any commit and
        # replay forever on restart. Decode per-record instead so poison is skippable.
        value_deserializer=lambda b: b)
    ndr_runtime.start_health()          # /healthz /readyz /metrics (plan 003 obs)
    log.info("file-observer up: %s -> %s (tenant=%s sensor=%s)", BOOTSTRAP, CH_HOST, TENANT, SENSOR)

    rows: list[dict] = []
    pending = False                                 # records consumed (valid OR skipped) not yet committed
    last = time.monotonic()
    while _running:
        batch = consumer.poll(timeout_ms=1000, max_records=FLUSH_ROWS)
        for _tp, records in batch.items():
            for rec in records:
                pending = True
                try:
                    if rec.timestamp_type != 1 or rec.timestamp is None or rec.timestamp < 0:
                        raise RuntimeError("file-observer requires input topics with LogAppendTime")
                    if rec.value is None:           # tombstone / empty payload -> nothing to parse
                        raise observe.QuarantineError("empty record value")
                    eve = json.loads(rec.value.decode("utf-8"))
                    result = observe.file_observation(
                        eve, TENANT, SENSOR,
                        topic=rec.topic, partition=rec.partition, offset=rec.offset,
                        ingested_at=datetime.fromtimestamp(
                            rec.timestamp / 1000, timezone.utc).isoformat())
                except (observe.QuarantineError, json.JSONDecodeError, UnicodeDecodeError) as e:
                    # Poison record (malformed JSON, bad UTF-8, or a payload the pinned
                    # contract rejects): log and SKIP. Its offset advances with the next
                    # commit below, so a restart never re-encounters it forever. A
                    # LogAppendTime misconfiguration is NOT caught here — it crashes loudly.
                    log.warning("skipped %s[%d]@%d: %s", rec.topic, rec.partition, rec.offset, e)
                    continue
                if result is None:                  # non-fileinfo telemetry on the topic
                    continue
                _table, row, _doc = result
                rows.append(row)
        now = time.monotonic()
        if len(rows) >= FLUSH_ROWS or (pending and now - last >= FLUSH_SECS):
            # Insert pending valid rows, THEN commit: a failure leaves offsets uncommitted,
            # so a replay re-inserts the same replay-stable obs_id (DISTINCT view dedups it).
            # Committing here also advances past skipped poison records — even an all-poison
            # batch (rows empty) commits, so a restart does not replay it forever.
            flush(ch, rows)
            consumer.commit()
            last = now
            pending = False

    flush(ch, rows)
    consumer.commit()
    consumer.close()
    log.info("file-observer stopped")


if __name__ == "__main__":
    main()
