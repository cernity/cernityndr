-- NDR analytics plane — findings store + retention (plan U7).
-- Extends the U6 minimal schema. The findings table is written by the finding
-- service (U9) and is the pivot surface for reconstruct-by-source (U19).

-- Retention: metadata is cheap but not kept forever (v2 §14.4). 30d default;
-- PCAP/raw (MinIO) has its own shorter lifecycle.
ALTER TABLE ndr.network_flow    MODIFY TTL event_time + INTERVAL 30 DAY;
ALTER TABLE ndr.tls_observation MODIFY TTL event_time + INTERVAL 30 DAY;
ALTER TABLE ndr.dns_transaction MODIFY TTL event_time + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS ndr.finding
(
    finding_id          String,
    tenant_id           LowCardinality(String),
    sensor_ids          Array(String),
    detector_id         LowCardinality(String),
    detector_version    LowCardinality(String),
    category            LowCardinality(String),
    severity            UInt8,
    confidence          Float32,
    first_seen          DateTime64(3),
    last_seen           DateTime64(3),
    entities            String,               -- JSON array of entity objects
    evidence_refs       Array(String),
    mitre               Array(String),
    state               LowCardinality(String),
    enrichment_state    LowCardinality(String),
    capture_job_ids     Array(String),
    suppression_reason  String,
    devo_delivery_state LowCardinality(String),
    revision            UInt16 DEFAULT 1,         -- R03: monotonic lifecycle revision (state_machine.py)
    ingested_at         DateTime64(3) DEFAULT now64(3)  -- ReplacingMergeTree version: idempotent re-persist of the SAME revision
)
-- R03 durable revision persistence: revision is part of the sort key, so each lifecycle
-- revision (initial FINAL, enriched update, timeout-finalization) is a DISTINCT, retained,
-- searchable row — not collapsed into one. ReplacingMergeTree(ingested_at) still dedups a
-- re-persist of the SAME (finding_id, revision) to the latest insert (Kafka replay is
-- idempotent), while advancing state produces a new revision = a new row. Query the current
-- view with `argMax(...) ... GROUP BY finding_id` or `LIMIT 1 BY finding_id ORDER BY revision DESC`;
-- the full lifecycle is `WHERE finding_id = ? ORDER BY revision`.
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMMDD(first_seen)
ORDER BY (tenant_id, category, finding_id, revision)
TTL first_seen + INTERVAL 180 DAY;             -- findings kept longer than raw
-- Migration on an EXISTING deployment (fresh installs get the above): the ORDER BY of a
-- ReplacingMergeTree cannot be altered in place, so add the columns and rebuild the table to
-- pick up the revision-scoped sort key.
--   ALTER TABLE ndr.finding ADD COLUMN IF NOT EXISTS revision UInt16 DEFAULT 1;
--   ALTER TABLE ndr.finding ADD COLUMN IF NOT EXISTS ingested_at DateTime64(3) DEFAULT now64(3);
--   -- then: CREATE ndr.finding_v2 (... ORDER BY (tenant_id, category, finding_id, revision)),
--   --       INSERT INTO ndr.finding_v2 SELECT * FROM ndr.finding, EXCHANGE TABLES.
