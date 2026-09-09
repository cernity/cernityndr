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
    devo_delivery_state LowCardinality(String)
)
ENGINE = ReplacingMergeTree                    -- last write per finding_id wins (state advances)
PARTITION BY toYYYYMMDD(first_seen)
ORDER BY (tenant_id, category, finding_id)
TTL first_seen + INTERVAL 180 DAY;             -- findings kept longer than raw
