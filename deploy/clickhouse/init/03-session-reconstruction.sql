-- NDR session reconstruction storage (plan U17/U18/U19; v2 §15.5, §16).
-- asset = the entity spine (reconstruct-by-source keys on it); session = stitched
-- flows. Both ReplacingMergeTree so the owning service upserts by key.

CREATE TABLE IF NOT EXISTS ndr.asset
(
    tenant_id        LowCardinality(String),
    asset_key        String,
    first_seen       DateTime64(3),
    last_seen        DateTime64(3),
    ip_set           Array(String),
    mac_set          Array(String),
    hostname_set     Array(String),
    role_if_known    LowCardinality(String),
    evidence_sources Array(String),
    confidence       Float32
)
ENGINE = ReplacingMergeTree(last_seen)
PARTITION BY tenant_id
ORDER BY (tenant_id, asset_key);

CREATE TABLE IF NOT EXISTS ndr.session
(
    session_id     String,
    tenant_id      LowCardinality(String),
    session_type   LowCardinality(String),   -- transport | host_pair | identity
    src_ip         String,
    dst_ip         String,
    app_proto      LowCardinality(String),
    started        DateTime64(3),
    ended          DateTime64(3),
    community_ids  Array(String),
    flows          UInt32,
    bytes_total    UInt64
)
ENGINE = ReplacingMergeTree(ended)
PARTITION BY toYYYYMMDD(started)
ORDER BY (tenant_id, session_id);
