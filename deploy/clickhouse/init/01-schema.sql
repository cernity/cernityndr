-- NDR analytics plane — minimal schema for the normalizer (plan U6).
-- Full table set, retention/TTL, and materialized views are U7. These three
-- are what U6 writes today. Ordered by (tenant_id, ...entity..., event_time)
-- so reconstruct-by-source (U19) and per-entity detectors (U8) scan efficiently.
CREATE DATABASE IF NOT EXISTS ndr;

CREATE TABLE IF NOT EXISTS ndr.network_flow
(
    tenant_id           LowCardinality(String),
    sensor_id           LowCardinality(String),
    event_time          DateTime64(3),
    flow_id             UInt64,
    community_id        String,
    src_ip              String,
    src_port            UInt16,
    dst_ip              String,
    dst_port            UInt16,
    transport           LowCardinality(String),
    app_proto           LowCardinality(String),
    ndpi_protocol       LowCardinality(String),
    ndpi_application    LowCardinality(String),
    ndpi_risk_set       Array(String),
    pkts_to_server      UInt64,
    pkts_to_client      UInt64,
    bytes_to_server     UInt64,
    bytes_to_client     UInt64,
    state               LowCardinality(String),
    alerted             UInt8
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(event_time)
ORDER BY (tenant_id, src_ip, event_time);

CREATE TABLE IF NOT EXISTS ndr.tls_observation
(
    tenant_id       LowCardinality(String),
    sensor_id       LowCardinality(String),
    event_time      DateTime64(3),
    community_id    String,
    src_ip          String,
    dst_ip          String,
    dst_port        UInt16,
    sni             String,
    tls_version     LowCardinality(String),
    ja3             String,
    ja3s            String,
    ja4             String,
    ndpi_application LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(event_time)
ORDER BY (tenant_id, ja4, event_time);

CREATE TABLE IF NOT EXISTS ndr.dns_transaction
(
    tenant_id       LowCardinality(String),
    sensor_id       LowCardinality(String),
    event_time      DateTime64(3),
    dns_version     UInt8,
    community_id    String,
    client_ip       String,
    resolver_ip     String,
    query_name      String,
    query_type      LowCardinality(String),
    rcode           LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(event_time)
ORDER BY (tenant_id, client_ip, event_time);
