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

-- U7: identity (arp/dhcp) evidence the normalizer does NOT type. asset-service
-- persists one row per identity event, keyed by the SAME canonical obs_id its facts
-- reference, so asset_fact.observation_id resolves to a real, retrievable row (§13.4)
-- and the MAC's IP/hostname surface as joinable entity values. Same evidence-column
-- shape as the typed tables so it unions cleanly into ndr.evidence_observations.
-- Created BEFORE that view because the view UNIONs this table — a fresh init must not
-- reference a table that does not yet exist.
CREATE TABLE IF NOT EXISTS ndr.identity_observation
(
    tenant_id       LowCardinality(String),
    obs_id          String,
    normalized_time DateTime64(3, 'UTC'),
    entity_values   Array(String),
    observation     String CODEC(ZSTD(3))
)
ENGINE = ReplacingMergeTree
PARTITION BY tenant_id
ORDER BY (tenant_id, obs_id);

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
UNION ALL
    SELECT tenant_id, obs_id, normalized_time, entity_values, observation FROM ndr.identity_observation WHERE observation != ''
);

-- U7: temporal, evidence-backed asset facts (design §13.4). Each row is ONE
-- validity interval of ONE fact. A changed value opens a NEW interval (a new
-- valid_from) and closes the prior (its valid_to); asset-service never overwrites.
-- ReplacingMergeTree(updated_at) collapses re-emits of the same interval (same
-- open time) so closing an interval — re-inserting it with valid_to set and a
-- newer updated_at — replaces the open row at merge time. valid_to NULL == open.
CREATE TABLE IF NOT EXISTS ndr.asset_fact
(
    tenant_id          LowCardinality(String),
    subject            String,                            -- asset_key / entity id
    predicate          LowCardinality(String),            -- hostname | mac | ...
    value              String,
    confidence         Float32,
    valid_from         DateTime64(3, 'UTC'),
    valid_to           Nullable(DateTime64(3, 'UTC')),    -- NULL == still valid
    source_type        LowCardinality(String),            -- §13.4 source.type (dhcp/arp/flow)
    observation_id     String,                            -- §13.4 source.observation_id (evidence-backed)
    method             String,
    classifier_version LowCardinality(String),
    is_deleted         UInt8 DEFAULT 0,                    -- 1 == tombstone: interval a rebuild dropped
    updated_at         DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
-- (updated_at, is_deleted): the newest version of an interval wins; when it is a
-- tombstone the row is dropped on merge, so an obsolete interval a rebuild removed
-- does not linger. Read with FINAL and filter is_deleted = 0 (§13.4 idempotence).
ENGINE = ReplacingMergeTree(updated_at, is_deleted)
PARTITION BY tenant_id
-- Dedup key components beyond (tenant, subject, predicate):
--   * value       — a subject can hold several VALUES of one predicate at one valid_from
--                    (a MAC owning two IPs at the same lease start); without it they collapse.
--   * valid_from  — each distinct interval start.
--   * observation_id — the lease/interval identity (the source obs_id). Without it, two
--                    SAME-START intervals for ONE ip (distinct leases observed at the same
--                    instant, same value + same valid_from) share the ORDER BY key and
--                    collapse under ReplacingMergeTree, losing one lease's evidence. It makes
--                    each interval's identity total. A tombstone carries the SAME value AND
--                    observation_id (asset-service flush) so it lands on the exact row it retires.
--
-- MIGRATION (existing data): ClickHouse cannot ALTER an existing table's ORDER BY in place.
-- An asset_fact created before this key change (ordered on (…, value, valid_from)) must be
-- reloaded to adopt the new key: rename the old table aside, run this CREATE, INSERT ... SELECT
-- the old rows (observation_id is already a stored column, so no data is fabricated), then drop
-- the old table. This data move is an OPS step and is out of scope for this DDL.
ORDER BY (tenant_id, subject, predicate, value, valid_from, observation_id);

-- Upgrade migration: asset_fact installations created BEFORE U7 tombstones have no
-- is_deleted column (their engine was ReplacingMergeTree(updated_at)), so the CREATE
-- TABLE IF NOT EXISTS above is a no-op on them and would leave restore_state(),
-- inserts, the timeline queries, and entity_timeline referencing a missing column.
-- Add it in place, preserving existing facts. The read path treats a newer
-- is_deleted=1 version as a dropped interval via FINAL + `WHERE is_deleted = 0`
-- (and resolution._authoritative), which needs only the column and a higher
-- updated_at on the tombstone — the engine's deleted-column optimization
-- (ReplacingMergeTree's 2nd arg) is not required for correct reads, so an in-place
-- ADD COLUMN fully enables tombstone reads/writes on pre-U7 tables. Fresh DBs already
-- have the column from the CREATE above, where this ALTER is a no-op.
ALTER TABLE ndr.asset_fact ADD COLUMN IF NOT EXISTS is_deleted UInt8 DEFAULT 0;

-- Entity timeline: observations UNION fact changes, one row per event, keyed by the
-- NORMALIZED ts (kind='observation' -> normalized_time; kind='fact_change' ->
-- valid_from). Filter tenant_id plus entity (=subject / has(entity_values,entity))
-- and ORDER BY ts at read time. asset_fact is read with FINAL so an interval that
-- was closed (re-inserted with valid_to set + newer updated_at) supersedes its open
-- version at read time even before background merges — no open+closed duplicate.
-- The live query is verified in the real env; asset-service also merges the two
-- streams in Python with equivalent version selection (resolution._authoritative).
CREATE OR REPLACE VIEW ndr.entity_timeline AS
SELECT tenant_id, arrayJoin(entity_values) AS entity, normalized_time AS ts,
    'observation' AS kind, obs_id, type AS obs_type,
    '' AS predicate, '' AS value, toFloat32(0) AS confidence,
    CAST(NULL AS Nullable(DateTime64(3, 'UTC'))) AS valid_to, '' AS source_type
FROM ndr.evidence_observations
UNION ALL
SELECT tenant_id, subject AS entity, valid_from AS ts,
    'fact_change' AS kind, observation_id AS obs_id,
    '' AS obs_type, predicate, value, confidence, valid_to, source_type
FROM ndr.asset_fact FINAL WHERE is_deleted = 0;   -- tombstoned intervals excluded
