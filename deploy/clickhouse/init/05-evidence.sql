-- U4: apply before deploying the new normalizer; safe to re-run.
-- Existing rows cannot recover absent raw fields/capabilities. Leave observation
-- empty and exclude them from the canonical view instead of fabricating evidence.
CREATE TABLE IF NOT EXISTS ndr.http_observation
(
    tenant_id LowCardinality(String),
    sensor_id LowCardinality(String),
    event_time DateTime64(3)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(event_time)
ORDER BY (tenant_id, sensor_id, event_time)
TTL event_time + INTERVAL 30 DAY;

ALTER TABLE ndr.network_flow
    ADD COLUMN IF NOT EXISTS observation String DEFAULT '' CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS raw_record String DEFAULT '' CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS obs_id String MATERIALIZED JSONExtractString(observation, 'obs_id'),
    ADD COLUMN IF NOT EXISTS normalized_time DateTime64(3, 'UTC') MATERIALIZED
        coalesce(parseDateTime64BestEffortOrNull(JSONExtractString(observation, 'ts', 'normalized'), 3, 'UTC'), toDateTime64(0, 3, 'UTC')),
    ADD COLUMN IF NOT EXISTS entity_values Array(String) MATERIALIZED
        arrayMap(e -> JSONExtractString(e, 'value'), JSONExtractArrayRaw(observation, 'entities'));
ALTER TABLE ndr.network_flow
    ADD INDEX IF NOT EXISTS evidence_entity entity_values TYPE bloom_filter(0.01) GRANULARITY 1,
    ADD INDEX IF NOT EXISTS evidence_time normalized_time TYPE minmax GRANULARITY 1,
    ADD INDEX IF NOT EXISTS evidence_id obs_id TYPE bloom_filter(0.01) GRANULARITY 1;

ALTER TABLE ndr.dns_transaction
    ADD COLUMN IF NOT EXISTS observation String DEFAULT '' CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS raw_record String DEFAULT '' CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS obs_id String MATERIALIZED JSONExtractString(observation, 'obs_id'),
    ADD COLUMN IF NOT EXISTS normalized_time DateTime64(3, 'UTC') MATERIALIZED
        coalesce(parseDateTime64BestEffortOrNull(JSONExtractString(observation, 'ts', 'normalized'), 3, 'UTC'), toDateTime64(0, 3, 'UTC')),
    ADD COLUMN IF NOT EXISTS entity_values Array(String) MATERIALIZED
        arrayMap(e -> JSONExtractString(e, 'value'), JSONExtractArrayRaw(observation, 'entities'));
ALTER TABLE ndr.dns_transaction
    ADD INDEX IF NOT EXISTS evidence_entity entity_values TYPE bloom_filter(0.01) GRANULARITY 1,
    ADD INDEX IF NOT EXISTS evidence_time normalized_time TYPE minmax GRANULARITY 1,
    ADD INDEX IF NOT EXISTS evidence_id obs_id TYPE bloom_filter(0.01) GRANULARITY 1;

ALTER TABLE ndr.tls_observation
    ADD COLUMN IF NOT EXISTS observation String DEFAULT '' CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS raw_record String DEFAULT '' CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS obs_id String MATERIALIZED JSONExtractString(observation, 'obs_id'),
    ADD COLUMN IF NOT EXISTS normalized_time DateTime64(3, 'UTC') MATERIALIZED
        coalesce(parseDateTime64BestEffortOrNull(JSONExtractString(observation, 'ts', 'normalized'), 3, 'UTC'), toDateTime64(0, 3, 'UTC')),
    ADD COLUMN IF NOT EXISTS entity_values Array(String) MATERIALIZED
        arrayMap(e -> JSONExtractString(e, 'value'), JSONExtractArrayRaw(observation, 'entities'));
ALTER TABLE ndr.tls_observation
    ADD INDEX IF NOT EXISTS evidence_entity entity_values TYPE bloom_filter(0.01) GRANULARITY 1,
    ADD INDEX IF NOT EXISTS evidence_time normalized_time TYPE minmax GRANULARITY 1,
    ADD INDEX IF NOT EXISTS evidence_id obs_id TYPE bloom_filter(0.01) GRANULARITY 1;

ALTER TABLE ndr.http_observation
    ADD COLUMN IF NOT EXISTS observation String DEFAULT '' CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS raw_record String DEFAULT '' CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS obs_id String MATERIALIZED JSONExtractString(observation, 'obs_id'),
    ADD COLUMN IF NOT EXISTS normalized_time DateTime64(3, 'UTC') MATERIALIZED
        coalesce(parseDateTime64BestEffortOrNull(JSONExtractString(observation, 'ts', 'normalized'), 3, 'UTC'), toDateTime64(0, 3, 'UTC')),
    ADD COLUMN IF NOT EXISTS entity_values Array(String) MATERIALIZED
        arrayMap(e -> JSONExtractString(e, 'value'), JSONExtractArrayRaw(observation, 'entities'));
ALTER TABLE ndr.http_observation
    ADD INDEX IF NOT EXISTS evidence_entity entity_values TYPE bloom_filter(0.01) GRANULARITY 1,
    ADD INDEX IF NOT EXISTS evidence_time normalized_time TYPE minmax GRANULARITY 1,
    ADD INDEX IF NOT EXISTS evidence_id obs_id TYPE bloom_filter(0.01) GRANULARITY 1;

-- DISTINCT collapses byte-identical at-least-once replay rows at read time.
-- Filter tenant_id plus has(entity_values, entity) and normalized_time >= from
-- AND normalized_time < until. Index effectiveness requires live measurement.
CREATE OR REPLACE VIEW ndr.evidence_observations AS
SELECT DISTINCT tenant_id, obs_id, normalized_time, entity_values,
    JSONExtractString(observation, 'type') AS type,
    JSONExtractRaw(observation, 'ts') AS ts,
    JSONExtractRaw(observation, 'entities') AS entities,
    JSONExtractRaw(observation, 'fields') AS fields,
    JSONExtract(observation, 'capabilities', 'Array(String)') AS capabilities,
    JSONExtractRaw(observation, 'source_ref') AS source_ref,
    observation
FROM (
    SELECT tenant_id, obs_id, normalized_time, entity_values, observation FROM ndr.network_flow WHERE observation != ''
UNION ALL
    SELECT tenant_id, obs_id, normalized_time, entity_values, observation FROM ndr.dns_transaction WHERE observation != ''
UNION ALL
    SELECT tenant_id, obs_id, normalized_time, entity_values, observation FROM ndr.tls_observation WHERE observation != ''
UNION ALL
    SELECT tenant_id, obs_id, normalized_time, entity_values, observation FROM ndr.http_observation WHERE observation != ''
);
