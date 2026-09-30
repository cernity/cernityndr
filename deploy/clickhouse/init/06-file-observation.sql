-- U1a data model only. Apply after 05-evidence.sql; safe to re-run.
-- Existing volumes require explicit migration; init scripts run on fresh DBs only.
-- Writers must validate against file_observation.schema.json before insertion.
-- As with the other typed rows, observation contains the complete canonical
-- envelope and raw_record preserves canonical JSON of the decoded source record.
-- File hashes describe file bytes; source_ref.sha256 describes raw_record.
CREATE TABLE IF NOT EXISTS ndr.file_observation
(
    observation String CODEC(ZSTD(3)),
    raw_record String CODEC(ZSTD(3)),
    tenant_id LowCardinality(String) MATERIALIZED JSONExtractString(observation, 'tenant'),
    sensor_id LowCardinality(String) MATERIALIZED JSONExtractString(observation, 'sensor_id'),
    event_time DateTime64(3, 'UTC') MATERIALIZED
        parseDateTime64BestEffort(JSONExtractString(observation, 'ts', 'sensor'), 3, 'UTC'),
    obs_id String MATERIALIZED JSONExtractString(observation, 'obs_id'),
    normalized_time DateTime64(3, 'UTC') MATERIALIZED
        coalesce(parseDateTime64BestEffortOrNull(JSONExtractString(observation, 'ts', 'normalized'), 3, 'UTC'), toDateTime64(0, 3, 'UTC')),
    entity_values Array(String) MATERIALIZED
        arrayMap(e -> JSONExtractString(e, 'value'), JSONExtractArrayRaw(observation, 'entities')),
    state LowCardinality(String) MATERIALIZED JSONExtractString(observation, 'fields', 'file', 'state'),
    first_seen DateTime64(3, 'UTC') MATERIALIZED
        parseDateTime64BestEffort(JSONExtractString(observation, 'fields', 'file', 'first_seen'), 3, 'UTC'),
    last_seen DateTime64(3, 'UTC') MATERIALIZED
        parseDateTime64BestEffort(JSONExtractString(observation, 'fields', 'file', 'last_seen'), 3, 'UTC'),
    sha256 Nullable(String) MATERIALIZED JSONExtract(observation, 'fields', 'file', 'sha256', 'Nullable(String)'),
    sha1 Nullable(String) MATERIALIZED JSONExtract(observation, 'fields', 'file', 'sha1', 'Nullable(String)'),
    md5 Nullable(String) MATERIALIZED JSONExtract(observation, 'fields', 'file', 'md5', 'Nullable(String)'),
    mime Nullable(String) MATERIALIZED JSONExtract(observation, 'fields', 'file', 'mime', 'Nullable(String)'),
    size Nullable(UInt64) MATERIALIZED JSONExtract(observation, 'fields', 'file', 'size', 'Nullable(UInt64)'),
    filename Nullable(String) MATERIALIZED JSONExtract(observation, 'fields', 'file', 'filename', 'Nullable(String)'),
    transfer_ref Nullable(String) MATERIALIZED JSONExtract(observation, 'fields', 'file', 'transfer_ref', 'Nullable(String)'),
    session_ref Nullable(String) MATERIALIZED JSONExtract(observation, 'fields', 'file', 'session_ref', 'Nullable(String)'),
    source_obs_ref Nullable(String) MATERIALIZED JSONExtract(observation, 'fields', 'file', 'source_obs_ref', 'Nullable(String)'),
    file_artifact_id Nullable(String) MATERIALIZED JSONExtract(observation, 'fields', 'file', 'file_artifact_id', 'Nullable(String)'),
    INDEX evidence_entity entity_values TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX evidence_time normalized_time TYPE minmax GRANULARITY 1,
    INDEX evidence_id obs_id TYPE bloom_filter(0.01) GRANULARITY 1,
    CONSTRAINT canonical_type CHECK JSONExtractString(observation, 'type') = 'file',
    CONSTRAINT canonical_table CHECK JSONExtractString(observation, 'source_ref', 'table') = 'ndr.file_observation',
    CONSTRAINT canonical_id CHECK match(obs_id, '^obs:[a-f0-9]{64}$'),
    CONSTRAINT source_id CHECK JSONExtractString(observation, 'source_ref', 'obs_id') = obs_id,
    CONSTRAINT source_tenant CHECK JSONExtractString(observation, 'source_ref', 'tenant') = tenant_id
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(event_time)
ORDER BY (tenant_id, sensor_id, event_time)
TTL event_time + INTERVAL 30 DAY;

-- Retain every existing member, projection and replay-deduplication rule from
-- 05-evidence.sql. Read the supplied canonical source_ref; do not fabricate one.
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
UNION ALL
    SELECT tenant_id, obs_id, normalized_time, entity_values, observation FROM ndr.identity_observation WHERE observation != ''
UNION ALL
    SELECT tenant_id, obs_id, normalized_time, entity_values, observation FROM ndr.file_observation WHERE observation != ''
);
