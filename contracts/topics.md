# NDR Kafka / Redpanda topic families

Origin: `suricata-ndr` v2 §14.1. These names are the contract between the shipper
(Vector, U5), normalizer (U6), detectors (U8), finding service (U9), capture
orchestrator (U10), and central enrichment (U11). `test_contracts.py` asserts this
list matches the canonical set — edit both together or the test fails.

Partition key convention (fleet-scale, see plan Enterprise Scale-Out Blueprint):
every keyed topic is keyed by `(tenant_id, entity)` so all events about an entity
reach the same stateful worker. `tenant_id` is always the leading key component —
tenant isolation is a partition invariant, never a downstream filter.

## Ingest (raw telemetry — analytics input, never SIEM input)

```text
suricata.raw.v1
suricata.flow.v1
suricata.dns.v1
suricata.tls.v1
suricata.http.v1
suricata.ssh.v1
suricata.windows.v1
suricata.file.v1
suricata.anomaly.v1
suricata.stats.v1
suricata.modbus.v1
```

`suricata.modbus.v1` carries Suricata's native Modbus app-layer EVE (consumed by
`ot-detectors`); enabled per-deployment via the opt-in OT sensor profile.

## Findings (the only thing that reaches the SIEM plane)

```text
ndr.finding.candidate.v1
ndr.finding.final.v1
```

## Capture / enrichment control plane

```text
ndr.capture.request.v1
ndr.capture.arm.v1        # orchestrator -> sensor capture-agent (gated arm directive)
ndr.capture.status.v1
ndr.enrichment.request.v1
ndr.enrichment.result.v1
```

## File artifact plane (U2)

```text
ndr.file.extracted.v1     # capture-agent -> file-yara / file-artifact (carved-file announce)
ndr.file.artifact.v1      # file-artifact -> file-observer (bytes_available linkage)
```

`ndr.file.extracted.v1` announces a carved file the capture-agent shipped to MinIO under
a tenant-scoped STAGING key (`ndr-files/<tenant-segment>/incoming/<sha256>`). `file-artifact`
validates those bytes (size, archive depth/member size, zip-slip) and, only on success,
promotes them to the ACCEPTED key (`.../artifacts/<sha256>`), then publishes
`ndr.file.artifact.v1` — the `bytes_available` linkage carrying `file_artifact_id`, the
accepted `object_ref`, `sha256` and the server-derived `tenant_segment`. `file-observer`
consumes it and emits the `bytes_available` file observation into `ndr.file_observation`,
applying the linkage ONLY when its `tenant_segment` matches the observer's configured tenant
(no cross-tenant linkage). Like the observer's other inputs, `ndr.file.artifact.v1` MUST be a
broker `LogAppendTime` topic: the observer stops without committing on `CreateTime` records,
which cannot establish ingest time.

## Sensor health telemetry

```text
ndr.sensor.health.v1
```

Carries `sensor-health.v1` (`sensor-health.schema.json`) from the mandatory
`sensor-agent`, independently of optional packet capture. No existing topic uses
this binding. Key is UTF-8 JSON `[tenant, sensor_uuid]`; consumers must verify the
asserted tenant/sensor against enrollment and authenticated ingress identity.
This is health telemetry, not a finding or SIEM input. The secure bus grants the
sensor principal write/describe/create on this exact topic only.

## Canonical evidence

```text
ndr.observation.normalized.v1
```

Carries `cernity.observation.v1` (`observation.schema.json`) from the normalizer
following insertion into the typed evidence row. Key is UTF-8 JSON
`[tenant, first_entity_value]`, or `[tenant, sensor_id]` if no entity is present.
At-least-once delivery: consumers deduplicate by `(tenant, obs_id)`.
This is evidence telemetry, not a SIEM finding. `source_ref` resolves the named
ClickHouse table by `tenant_id = tenant AND obs_id = source_ref.obs_id`; its
`raw_record` contains the preserved decoded bus object. No raw sensor-byte or
MinIO-delivery claim is made. Findings can reference the exact `obs_id` string
in `evidence_refs`; existing flow/community references are not exact event IDs.

`ts.sensor` retains the sensor timestamp. `ts.normalized` uses a trusted measured
sensor-minus-reference offset if supplied to the transform; otherwise the live
service uses the Kafka record timestamp with `method = ingest-fallback` and a
null offset. The service requires broker `LogAppendTime` on these input topics and stops
without committing on `CreateTime` records, which cannot establish ingest time.
Health-to-normalizer offset lookup and correlation skew tolerance are not
implemented by U4. Consumers must inspect `ts.method` before clock-sensitive use.

## U6 capture v2 coexistence

`ndr.capture.request.v2` carries `capture-request.v2` (see
`capture-request.schema.json`). It is the orchestrator's **signed preserve
output** to upgraded capture agents. Epoch UTC seconds describe a half-open,
fully elapsed packet window. U6 supports the existing IP host selector;
community-ID/5-tuple selectors and future-window scheduling are not implemented.

The existing finding-service continues producing `ndr.capture.request.v1`.
With no local preserve policy, the orchestrator continues producing
`ndr.capture.arm.v1` unchanged. With an enabled sensor policy, it gates that
intent and produces v2 instead. A denied preserve never silently falls back to
forward capture. Deploy upgraded agents before enabling policies. Do not publish
the same intent on both request topics; v2 is output, not another orchestrator
input in this increment. No producer-controlled `authorized` boolean is trusted.

Agents consume both the existing arm topic and v2, and reject v2 payloads on the
arm topic. A preserve does not also arm a forward capture. Terminal preserve
messages retain `ndr.capture.status.v1`, adding `kind: preserve`, `request_id`,
`tenant_id`, `coverage` and `pcap_ref`. Their budget accounting is separate from
v1 arms. Successful preservation also emits `ndr.enrichment.result.v1` with
`status: ok`, tenant/finding IDs, and `evidence_refs: [pcap_ref]`. The existing
finding-service result handler attaches that reference, including its existing
late-result behavior. This reports preserved evidence, not Zeek analysis.

U1b must provision ACLs: only the orchestrator may produce v2; enrolled agents
may consume scoped directives and produce completion/results for their tenant.
Signed sensor-specific directives add defense in depth, but neither payload
fields nor a MAC establish the original finding producer's transport identity.
The signed command key is sensor-specific local administration configuration.
All new runtime bus clients use the shared authenticated-client factories.

## U9 analyst feedback

`ndr.disposition.v1` is reserved for `disposition.v1`
(`disposition.schema.json`); no existing topic binding collides. This is advisory
feedback, never a finding or a detector suppression command.

U9 consumes this contract at `POST /dispositions` in feedback-service (port
8094), through authenticated HTTP sessions. Vantage is outside the bus trust
boundary: it must not publish directly to the sensor/central bus. This skeleton
has no Kafka consumer and does not treat Kafka headers/keys as authenticated
analyst identity. A future bus adapter must preserve the authenticated ingress
identity; reserving the topic does not claim a deployed bus pipeline.

Server-owned `FEEDBACK_SESSIONS` maps opaque bearer session tokens to
`emitter`, `analyst`, `tenant`, epoch `expires_at`, and `disposition_write: true`.
Use a separate expiring session per analyst and tenant, provisioned by the trusted
authentication system, never one shared Vantage token with caller-selected analyst
headers. An empty map denies all writes. TLS termination and credential
provisioning are deployment requirements. Body analyst/tenant/scope are claims,
not grants: scope is reduced to finding (verdict) or exact entity (allowlist).
All references are tenant-qualified; this skeleton does not resolve findings.

Verdicts `true_positive` and `benign` route to `anomaly_ground_truth`,
`false_positive` to `detector_fp_candidate`, and `allowlist` to `ignore_list`.
Allowlist can have a null finding_id; all forms require an entity and reason.
The durable SQLite feedback table is the skeleton's routed sink/outbox, with
separate tenant/sink columns; downstream model/detector integrations are deferred.
Each accepted record and its audit event commit atomically before HTTP 202.
Mount a private persistent volume at `/data` (`FEEDBACK_DB` overrides the path).
No read or approval API is exposed. Retries can create additional audited
suggestions; delivery is not exactly-once. Do not feed these records directly
into active suppression lists or train models automatically.

Every suggestion has server-bound owner, justification, audit_id, capabilities,
creation and expiration. `FEEDBACK_TTL_SECONDS` defaults to 86400 and is bounded
to 30 days. Payload timestamps are provenance only and cannot extend expiration.
All entries are `suggested`; there is no activation path. The isolated ignore-list
evaluation seam additionally requires separate approval provenance, exact tenant
and entity match, and an unexpired lifetime on every evaluation. Expiration is
logical, not physical deletion of audit history. Live TLS/session provisioning,
bus transport, downstream delivery and Vantage emission are not proven by U9.

## U1 threat-intel lifecycle

The intel topic name `ndr.intel.v1` is reserved for the `intel.v1` contract
(`intel.schema.json`); no existing topic binding collides. U1 ships the managed
lifecycle only — normalize (STIX/TAXII 2.1, MISP, HTTP(S), abuse.ch feed
connectors) → dedup (merge provenance, keep the best TRUSTED score) → score →
expire — behind a per-tenant SQLite store (`services/threat-intel/store.py`), plus
an auditable, EXPIRING suppression decision (owner + justification + expiry,
re-checked live at match time like the U9 ignore-list). It is NOT a bus producer
in this increment: live matching (U2) still emits on the existing
`ndr.finding.candidate.v1`, and retrospective hunting (U3) reads the observation
history — so no new Kafka topic is provisioned here, only the contract + store.

Every indicator is tenant-scoped by primary key `(tenant, type, indicator)` and
carries source/feed/score/tlp/source_trust/first_seen/last_seen/expiry/provenance.
Feed trust controls (§12.1): per-feed auth + TLS certificate pinning (fail-closed);
a low-`source_trust` feed cannot override a high-trust indicator's effective score;
TLP:red is never exportable. OpenCTI + Git/GitHub/GitLab connectors (§12.2) are a
deferred later increment — the `Connector` interface leaves room without change.

The `threat-intel` service wires this in via `INTEL_DB` (per-tenant SQLite path;
unset ⇒ lifecycle off, legacy static-set matching unchanged) and `INTEL_FEEDS` (JSON
feed-spec list, or a path to one). Each configured feed is fetched and ingested on
the periodic refresh; a per-feed fetch/parse failure is logged and skipped so it
never corrupts the store. Effective TLP is the MOST RESTRICTIVE marking across merged
provenance, and effective score comes only from currently-valid (unexpired) per-source
assertions, so an expired trusted source cedes to a still-valid lower-trust one.

## U3 retrospective IOC hunts

`ndr.hunt.v1` is reserved for `hunt.v1` (`hunt.schema.json`), with no Kafka
producer or consumer in U3. This worker exposes authenticated HTTP on port 8096.
`HUNT_TOKENS` is a server-owned JSON map of opaque bearer token to **one tenant**;
empty configuration denies access. A multi-tenant operator uses separate scoped
credentials. The request tenant is a checked claim, never a grant. TLS termination
and token provisioning are deployment requirements.

`POST /hunts` accepts `{schema:"hunt.v1", hunt_id, tenant, from, to, indicators}`
with each indicator carrying `type`, `indicator`, and `intel_known_at`. Alternatively,
`intel_set` names a server-configured U1 snapshot: `HUNT_INTEL_SETS` points to a JSON
file shaped `{tenant: {set_name: [intel.v1 records]}}`. No cross-service SQLite
sharing or invented U1 API is required. Saved records use the earliest retained
`provenance.observed_at` acquisition timestamp, never feed `first_seen`; missing
acquisition provenance is an error. U1 refresh can replace older provenance, so
this is not a guarantee of the earliest-ever acquisition. Supply an explicit known
timestamp when that independently retained history is available.

Each POST advances at most one evidence page (default 500, maximum 1000 records)
within the evidence layer's one-day query bound. Jobs allow at most 100 indicators
and a 31-day window. Repeat the identical POST until `status` is `complete`;
completed requests return persisted results without querying again. Request changes
under an existing tenant/hunt_id are rejected; use a new ID for a fresh scan.
`GET /hunts/{hunt_id}?after=&limit=` pages persisted hits (maximum 1000); the
response `next_after` is a result cursor, distinct from the internal evidence
checkpoint. A pending job's result pages are provisional; enumerate after completion
for a stable full result. Empty hits are successful. Unsupported hash/URL dimensions
are reported explicitly in `unsupported`, including in mixed jobs.

The worker reuses the evidence query layer's tenant binding, UNION view, one-day
cap and `(normalized_time, obs_id)` keyset paging through an internal tenant scan.
The public evidence endpoint still requires an entity. Domain/JA/cert values are
not in the current entity index, so the scan matches actual canonical fields:
source/destination IP (including CIDR), DNS queries/answers, TLS SNI, HTTP hostname,
JA3/JA3S, JA4/JA4S and TLS fingerprint. Full URL and file hash hunting are deferred.
No finding or SIEM export is emitted. Explicit hunts are historical investigation
requests, not live prioritization: saved snapshots may include expired/suppressed
intel and remain local to the tenant, including restricted TLP content.

Windows are half-open over **normalized evidence time**, as in the evidence API.
`observed_at` preserves `ts.sensor` (traffic time), with full `observation_ts`
retained so clock correction and ingest fallback stay visible. `intel_known_at`
is compared to that sensor time for `learned_after_observation`; clock accuracy
limits that comparison. Hits retain exact obs_id and source_ref. SQLite commits
hits and progress atomically, deduplicating retries. Mount a private persistent
volume at `/data` (`HUNT_DB` override), and run one worker process per database.
No background scheduler is included; the submitter drives continuation. Live
ClickHouse execution, scan performance, container builds and deployment are
real-environment checks, not claims established by mocked tests.
