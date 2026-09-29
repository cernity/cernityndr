# U9: deterministic investigation read boundary

Status: implemented, pending independent review.

The engine reduces a materialized, bounded snapshot. Only queries.py accesses
backends: it reuses evidence-service's typed observation query and reads current
finding revisions from ndr.finding (the shipped finding service has no finding
HTTP reader). The intel step reuses persisted threat_intel match findings. It does
not refresh intel or claim that historical matches are currently active. Beacon
steps reuse beacon/beacon_fqdn detector findings, never detect periodicity anew.

POST /investigations accepts entity_id, finding_ids, reason, window {from,to},
and optional case_id. The optional case is read with the shipped GET /cases/{id}
API using server-provisioned per-tenant reader credentials and checked for tenant,
entity and trigger membership. Its linked findings restrict the history step.
Without a case, history is all entity findings in the requested window. The other
steps always use the entity window. Result refs name actual observations/findings;
case IDs are context, not fabricated evidence refs.

INVESTIGATION_SESSIONS maps bearer tokens to {tenant, expires_at,
investigation_read: true}. One server-selected tenant per session avoids merged
investigations. CASE_API_URL and INVESTIGATION_CASE_TOKENS (tenant to case reader
token) enable optional case reads. No credentials or tenant claims are accepted
in the body. Reads and rejected requests emit credential-free audit records.
Deploy behind the same TLS gateway as the case API, with read-only DB privileges.

The query registry and playbook are version 1. Full context is classified as
suspicious with fixed rule confidence 0.75, not a calibrated likelihood or proof
of C2: entity co-occurrence does not prove shared destination. Missing evidence
is inconclusive, never benign. Empty result refs remain empty rather than borrowing
trigger IDs to make an unsupported step look supported. No response is executed.

Requests are bounded to one day and 10000 observations/findings, with evidence
keyset pagination. Overflow fails rather than producing a complete-looking partial
result. Identity hashes the deterministic document and snapshot contents, including
finding revisions. Live reads are not a cross-service transactional snapshot;
identical snapshots reproduce identical output, changing backends may change it.
The 256-result tenant-keyed cache is process-local: restart or eviction returns
404 and callers can rerun the read. Durable investigation storage is outside U9.

Local tests use backend doubles. They do not establish live ClickHouse query
execution, gateway configuration, deployed service integration, or image build.
