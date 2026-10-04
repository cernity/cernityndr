-- U3c: observed entity-to-entity relationship edges (design §13.5 entity graph).
-- ADDITIVE, forward-only: a NEW table only — no shipped table is touched. Apply after
-- 07; safe to re-run. asset-service writes one row per (src_entity, dst_entity, kind),
-- advancing [first_seen, last_seen] as the edge is re-observed; `evidence` is the JSON
-- provenance {event_type, observed_at, detail}. Endpoints are entity UIDs (mac:… / ip:…)
-- resolved through the same asset_key spine as asset_fact.subject — never raw IPs.
CREATE TABLE IF NOT EXISTS ndr.entity_relationship
(
    tenant_id   LowCardinality(String),
    src_entity  String,                              -- entity UID (mac:… / ip:…)
    dst_entity  String,                              -- entity UID (mac:… / ip:…)
    kind        LowCardinality(String),              -- resolves | communicates-with
    first_seen  DateTime64(3, 'UTC'),
    last_seen   DateTime64(3, 'UTC'),
    evidence    String CODEC(ZSTD(3)),               -- JSON {event_type, observed_at, detail}
    updated_at  DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
-- ReplacingMergeTree(updated_at): the newest re-emit of an edge (widened last_seen /
-- latest evidence) supersedes the prior version at merge/read. Read with FINAL.
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY tenant_id
-- One logical edge per (tenant, src, dst, kind); re-observations collapse onto it.
ORDER BY (tenant_id, src_entity, dst_entity, kind);
