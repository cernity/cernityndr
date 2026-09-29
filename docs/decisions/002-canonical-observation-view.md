# U4: canonical observations over existing typed evidence

Status: implemented, pending independent review.

Use the architecture's `ndr.observation.normalized.v1` topic; no existing binding
collides. Support conn (EVE flow), DNS, TLS and HTTP in this increment. Further
protocols require contract and transform extensions. Retain the existing typed
normalization interface for existing callers.

Extend each typed row with compressed `observation` JSON and `raw_record` JSON.
Add an HTTP typed table for the newly consumed HTTP stream. Expose one ordinary
`ndr.evidence_observations` UNION view, not a parallel canonical MergeTree or
materialized table. Materialized ID, entity-value and normalized-time columns
and skipping indexes support tenant plus entity/time or exact-ID predicates on
all four tables, including destination entities. This adds storage for canonical
metadata (including some typed-field duplication) and one preserved decoded EVE
object per row, plus small index columns. It avoids another full table copy and
cross-table dual-write consistency. Benchmark compression, index selectivity and
view predicate pushdown live before sizing production. Existing 30-day typed
retention also applies to raw evidence here; separate raw retention is deferred.

A source reference names the typed table, trusted tenant and observation ID.
Retrieve `raw_record` using both tenant and ID, verifying its SHA-256 over UTF-8
canonical JSON. This preserves the decoded bus object, not original sensor bytes
or proof of MinIO archival. Existing rows have no preserved record: their empty
observation column excludes them from the view. No backfill fabricates fidelity.

Observation IDs hash tenant, sensor and Kafka topic/partition/offset, preserving
occurrence identity and deterministic replay. The bus must not recreate input
topics with reused offsets inside the evidence-retention period. Reingesting the
same event at a new offset creates a new occurrence. Findings may use `obs_id`
strings as exact evidence_refs; existing community/flow refs are unchanged and
are not upgraded to exact lineage. Finding producers are outside U4.

Insert the typed row before publishing, await the publication acknowledgment,
then commit consumer offsets. Failures stop processing without committing;
replay may duplicate both typed rows and bus emissions. The view uses DISTINCT
to collapse identical canonical observations; consumers deduplicate by tenant
and obs_id. Underlying typed tables retain replay duplicates until TTL expiry,
as before; DISTINCT has query cost and is not physical exactly-once storage.
A pending insert is not visible on the bus until publication succeeds; there is
no distributed transaction. Source references share their row's retention.

A7 retains sensor time and supplies normalized time plus the normalization
method. The pure transform accepts a trusted measured sensor-minus-reference
offset and subtracts it. The live service has no health lookup in U4, so it uses
a labeled ingest fallback with null offset. It requires Kafka LogAppendTime:
CreateTime is producer controlled and cannot attest to ingest correction. The
service stops without committing if the requirement is unmet. Operators must
configure LogAppendTime for the four input topics before cutover and handle
historical CreateTime records explicitly (they cannot silently be relabeled).
This is arrival time, not recovered event time; clock-sensitive consumers must
account for transport delay. Joining measured health offsets is future work.

Capabilities describe the actual included evidence. Conn is conservatively
flow-only; no packet, payload, pretrigger-PCAP, or file-byte flags are invented.
DNS/TLS/HTTP flags require their source objects, fingerprints require supplied
values, and canonical fields omit absent EVE keys instead of defaulting them.
The preserved raw record can contain additional source fields without claiming
that canonical consumers support them.

Deployment applies `05-evidence.sql` before the normalizer and grants the
normalizer principal production rights to the canonical topic. Existing
ClickHouse volumes need the migration run explicitly; init scripts only run on
fresh databases. The local gate tests schema/transforms and mocked service I/O.
Live ClickHouse migration, index behavior and bus delivery remain real-environment
gates; U4 does not implement the U5 evidence API.
