-- Correlation-service window-state persistence (plan U9, Track B).
-- The service holds per-entity rolling windows in memory and snapshots them
-- here so a restart reloads the window (Python + ClickHouse durability, KTD1).
-- ReplacingMergeTree(updated) keeps only the latest snapshot per entity.

CREATE TABLE IF NOT EXISTS ndr.entity_risk_state
(
    tenant_id     LowCardinality(String),
    entity        String,
    findings_json String,               -- JSON array of the entity's in-window findings
    updated       DateTime64(3)
)
ENGINE = ReplacingMergeTree(updated)
PARTITION BY tenant_id
ORDER BY (tenant_id, entity)
TTL toDateTime(updated) + INTERVAL 2 DAY;   -- state older than the window is dead
