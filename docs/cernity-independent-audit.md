# Cernity independent implementation audit

## 1. Verdict: Partially

Cernity implements useful central behavioral analytics, and I verified a replayed beacon reaching its file sink through the actual broker, detector, finding service, and forwarder. It does **not** substantiate the executive summary's claim of a complete, reliably delivered, horizontally scalable NDR: confirmed threat findings stall in an unfinished capture lifecycle, sensor credentials can bypass the analytics tier and forge final findings, and documented deployment paths contain operational defects. Passing unit tests establish meaningful component behavior but miss these system failures. Confidence is high in the reproduced defects and narrow working path; production detection accuracy, fleet capacity, live sensor capture, and the optional ML ensemble remain unverified.

**Audited subject:** local working tree at commit `1cffad4cfa1def18eaf8212a9b2e9289dffc0a4e`, including the existing README modification and untracked executive summary. The audit brief was read from `/Users/carterfields/Documents/git/carterscode/homelabai/docs/cernity-audit-brief.md`. This is an audit of that checkout, not certification of every published image or the v0.3.3 tag. Existing implementation and documentation changes were preserved.

**Evidence labels:** **Claimed** means stated in the summary/docs; **Implemented** means inspected in code; **Verified** means executed in this audit. Verification is scoped to the stated test, not every deployment or input.

### Execution record

| Check | Result and scope |
|---|---|
| `PYBIN=python3 bash run-tests.sh` | **Verified: passes.** Shared, contract, and top-level service test scripts. This is not a measured line/branch coverage percentage. |
| Additional benchmark, feeder, nested behavioral validation scripts | **Verified: pass.** Executed separately because the aggregate script does not traverse those directories. |
| Redis contract tests | **Verified: pass** against an isolated Redis container, in addition to memory tests. |
| README quickstart with defaults | **Verified: fails.** Broker reports `CERNITY_BUS_PASSWORD required in secure mode`. Copying the example alone does not generate credentials/certificates. |
| Documented insecure fallback | **Verified: fails.** Broker reports `unrecognised option '--check=false'`. |
| Secure quickstart with generated audit certificates and credential injected through a temporary Compose override | **Verified: starts and emits a real `beacon`, `category:c2`, `state:FINAL` finding.** Service source was unchanged. |
| External Kafka listener | **Verified:** unauthenticated client could not establish a usable Kafka connection; SASL/SCRAM over TLS connected. That sensor credential also successfully published an audit marker directly to the final-findings topic, which reached the sink. |
| Findings lifecycle | **Verified:** two identical control candidates produced two sink records. Signature and threat-intel candidates produced capture requests and no final sink record. Publishing a successful enrichment result did not complete the signature finding. |
| Deterministic defect probes | **Verified:** refreshed TTL retains old state; CDN flow enters neither beacon window; documented RPC/pipe input produces no candidate; JA3 object raises a type error; actual outputs violate the finding schema. |
| Benchmark smoke | **Verified:** generates a report from supplied synthetic documents. This does not run Suricata, Zeek, RITA, or measure production accuracy. |

Docker execution used ARM64 Docker Desktop and Redpanda `v26.2.1`, image digest recorded in [evidence](audit-evidence/redpanda-image.json). The quickstart builds succeeded before broker startup failed. Some image build layers were cached; this was not a cache-free build of all 25 services.

**Not run:** a physical sensor and Fluent Bit tailing real EVE, a live SIEM API, the complete packet capture/Zeek/MinIO overlay, the SLIPS runtime, Kubernetes deployment, Redis Cluster failover, a full labeled-PCAP comparative benchmark, or a 1,000-sensor workload. No comprehensive dependency vulnerability scan, legal compliance certification, or GitHub branch-protection audit was performed.

Reproductions and captured output are in [audit-evidence](audit-evidence/README.md).

## 2. What is genuinely strong

* **The basic analytics path is real.** The feeder sends EVE events, not prebuilt findings. The behavioral worker computes the beacon candidate; the finding service and forwarder deliver it. See `tools/eve-feeder/feeder.py`, `services/behavioral-detectors/app.py:259`, and [captured beacon](audit-evidence/quickstart-findings.jsonl).
* **Statistical methods are implemented.** `detectors.py` contains Bowley skew, median absolute deviation, timing/size regularity, count weighting, domain aggregation, and DNS grouping. Tests exercise positive and negative cases. This establishes real heuristic logic, not externally validated detection fidelity or exact RITA equivalence.
* **The functional separation improves auditability.** Pure modules make individual decisions easy to inspect and reproduce. Dockerfiles execute real assertion scripts and fail on nonzero exits; the behavioral image also runs its nested validation smoke.
* **Several distributed-state primitives are useful.** The Redis store has sorted event windows, partition indexes, and atomic `SET NX EX` dedup admission. Memory and Redis contract tests pass. These primitives do not by themselves establish correct rolling semantics, atomic publication, or systemwide idempotence.
* **Central Compose hardening and external TLS are substantive.** The core Python services drop capabilities, use read-only roots and non-root users, and set no-new-privileges. The external listener demonstrably requires authentication. Coverage of other deployment paths is weaker.
* **Core reputation enrichment has a defensible privacy filter.** `services/finding-service/intel.py:35` uses `ipaddress.ip_address(...).is_global` before calling reputation providers. Existing tests verify private-address exclusion. This establishes globally routable filtering, not knowledge of operator-owned public address space.

## 3. Per-dimension findings

### A. Detection legitimacy and correctness

**Claimed:** broad behavioral and AD coverage, robust RITA methods, CDN/fronted beacon coverage, precise ATT&CK labeling.

**Implemented:** actual statistical beaconing plus threshold, rarity, string-match, and count heuristics. These are valid categories of detection methods, but much of the product is explicitly threshold based. “Not thresholds in a trenchcoat” obscures that distinction rather than proving quality.

**Verified gaps:**

* JA3/JA3S are treated as scalar fingerprints in `services/protocol-detectors/app.py:101`. A JA3 object containing `hash` and `string` raises `TypeError: unhashable type: 'dict'` against memory; the handler catches and drops the record. JA3S can interrupt processing even when a JA4 value exists. Suricata documents the compound fingerprint representation. [Suricata source documentation](https://github.com/OISF/suricata/blob/main/doc/userguide/output/eve/eve-json-format.rst).
* `services/east-west-detectors/app.py:287` reads `interface_uuid`/`interface`, not `interfaces[].uuid`; SMB handling does not inspect nested `smb.dcerpc`. Its pipe test misses `share_type:PIPE, filename:svcctl`. Document-shaped test inputs produced zero findings. Suricata documents interface arrays and SMB fields. [Suricata EVE format](https://docs.suricata.io/en/suricata-8.0.1/output/eve/eve-json-format.html).
* AS-REP detection is explicitly dormant with ordinary Suricata telemetry, as `docs/suricata-config.md` acknowledges. Its existence as a pure function is not working sensor coverage.
* The LLMNR handler checks port 5355 only. Calling it mDNS coverage is unsupported: no 5353 path exists. Counting answered names also does not establish that a host does not own those names.
* CDN exclusion is applied before both IP and domain beacon accumulation (`behavioral-detectors/app.py:458`). A configured CDN address generated neither window. The domain comes from a passive DNS IP mapping to a registered parent, not a general TLS-SNI consumer. Aggregating many subdomains under a parent is not exact-FQDN matching.
* IPv6 internal classification is inconsistent. East-west only recognizes listed IPv4 private prefixes; behavioral/protocol classification also uses string prefixes and omits ULA by default. IPv6-safe key parsing is not IPv6 detection parity.

The RITA comparison helper exists but compares destination sets, not full source/destination verdict identity or scoring calibration. I did not run a RITA oracle. A high regularity score measures regularity; it is not a calibrated probability of compromise.

### B. Architecture and scalability

**Implemented:** Kafka consumer groups, partition-scoped evaluation in important workers, Redis backend and optional manually sharded Redis stores, worker Compose and Helm replicas/HPA.

**Verified/inspected limitations:**

* Central Compose defaults to memory and contains no Redis service or `NDR_REDIS_URL` forwarding. Fixed container names prevent simply scaling its named services in place. The separate scale path is the intended alternative, but “same stateless model everywhere” is inaccurate.
* Counters and sets refresh the expiry of the whole key on every observation. Old bytes, destinations, principals, and fingerprints remain while activity continues. I reproduced retention beyond the alleged window in memory and live Redis. This can turn normal long-lived activity into apparent bursts and invalidate rarity/prevalence baselines. Sorted beacon windows do perform score pruning; the defect is not universal to every state type.
* `RedisStore` constructs `redis.Redis`, not `RedisCluster`. `ShardedRedisStore` is client-selected independent shards, not Redis Cluster discovery, redirection, or failover support. The guides' “swap in Redis Cluster” instruction is unsupported by this implementation.
* Correlation keeps process-local entity lists and periodically writes ClickHouse snapshots (`services/correlation-service/app.py:49`). Final messages are sent without an entity partition key. Replicas can receive incomplete pieces of one host's history; shared snapshot storage does not make this an atomic shared state machine.
* Kafka auto-commit, buffered state writes, asynchronous publication, and dedup admission before confirmed delivery are not a transaction. Restarts and failures can lose or repeat work. This was inspected, not a comprehensive fault-injection exercise.
* Multi-site identity is not established at ingress. `route.lua` supplies a topic/key but no authenticated tenant/sensor stamp. Behavioral code trusts `tenant`/`site`, while other workers use deployment-wide identity. Overlapping addresses and malicious sensor input are unresolved fleet boundaries.

The scale guide correctly distinguishes edge packet bandwidth from central metadata throughput. Nonetheless, no audited evidence establishes capacity at 1,000 sensors. A single-process synthetic load harness is not a distributed fleet test.

### C. Telemetry and contract integrity

**Implemented:** JSON schemas, example validation tests, basic normalizer field checks, routing by event type.

**Verified:** `ids-alerts/promote.py` generates candidates missing required `first_seen` and `last_seen`. `build_finding` emits `devo_delivery_state:SUPPRESSED`, which its schema enum forbids. The schema tests pass because they do not validate all actual producer outputs.

The normalizer is a separate consumer writing ClickHouse, not a mandatory gateway in front of detectors. Its checks cannot protect direct detector ingestion. The envelope schema promises identity that raw shipper messages do not carry. `findings-forwarder/adapters.py:23` rejects only `SUPPRESSED`, rather than admitting only validated final states. Direct publishing with a sensor credential bypassed the lifecycle entirely in the live test.

### D. Findings quality and noise reduction

**Implemented/verified:** severity suppression and metadata finalization work on their tested paths; the beacon contains interval, jitter and connection-count evidence.

**Blocker:** confirmed threat sources always route to capture, regardless of confidence. `finding-service/app.py:76` subscribes only to candidates. `apply_enrichment_result` is only called in tests; no runtime service consumes the resulting enrichment topic to finish the original finding. The capture request contains only finding ID and entities, while the orchestrator expects a scalar value and sensor ID. Thus enabling optional forensics does not repair the full path.

**Verified:** duplicate control candidates produce duplicate file deliveries. There is no admission/delivery dedup in the finding service. ClickHouse `ReplacingMergeTree` cannot prevent already-emitted duplicates in a file, webhook, or Splunk sink. Several producers still use process-seeded `hash()`; the same IDS event generated different IDs under different Python hash seeds. Behavioral dedup includes changing evidence in its key, so changing connection counts can create fresh findings for the same behavior.

Noise reduction cannot be inferred from missing output: stalled true threat findings also reduce volume. No production false-positive/false-negative estimates were established. Some outputs lack detection math or ATT&CK tags; `malware` and `anomaly` have no category fallback, and kerberoasting uses the generic credential-access fallback rather than its specific technique.

### E. Security of Cernity

**Verified:** central external SASL/TLS authentication works with supplied credentials. **Verified Major:** the entrypoint grants the sensor principal superuser status (`deploy/central/redpanda/entrypoint.sh:50`); it can write final findings. I used a harmless audit marker, not a real response action. Sensor compromise therefore crosses the analytics trust boundary. Use separate service principals and topic/group ACLs, not a shared superuser distributed to sensors.

**Implemented gaps:** `deploy/scale/infra.yml` exposes plaintext Kafka and unauthenticated Redis on host interfaces. It does not inherit the central secure entrypoint. `deploy/scale/workers.yml` defines hardening anchors but does not apply them to its services; Helm templates have no corresponding security contexts. The summary's blanket “closed and validated” claim does not hold across supported paths.

The sensor capture agent creates Kafka clients directly without SASL/TLS configuration (`services/capture-agent/app.py:220`), and its Compose definition lacks the CA and SASL variables. It cannot use the documented secure external listener as configured.

Object-key sanitization is useful, but accepts arbitrary syntactically safe bucket/key strings; bucket authorization is not established by path sanitization. Capture uses shared files and uploads the largest file rather than an isolated per-finding slice. An exception during initial dataset arming bypasses the later active-job decrement. Orchestrator health is a constant healthy stub, not measured packet loss or CPU.

A limited tracked-file scan found no high-confidence private-key, AWS-access-key, or GitHub-token patterns. History for `.env` and the secrets directory showed no entries. This is **not** a complete history/image secret audit. The sensor Compose does contain a demo MinIO password default, contrary to an absolute claim that no credentials are committed. Most image references and many dependencies are mutable/unpinned; one behavioral requirements file is pinned. Zeek package installation uses `|| true`, allowing fingerprint capability to be absent in a successful build.

### F. NDR completeness

A public vendor definition describes NDR using non-signature analytical detection and investigation/response capabilities. This is a comparison framework, not a certification checklist. The full Gartner research was not available for review. [Cisco NDR overview](https://www.cisco.com/site/us/en/learn/topics/security/what-is-network-detection-response.html).

| Capability | Assessed status |
|---|---|
| Central behavioral detection | **Partial, implemented; narrow replay verified.** |
| Known-threat integration | **Implemented but blocked at finalization.** |
| Prioritization and explanation | **Partial; suppression works, fidelity and complete evidence do not follow.** |
| Cross-event incident correlation | **Implemented; full runtime/replica correctness unverified and architecture has gaps.** |
| Historical hunting and forensics | **Optional code/storage schemas exist; complete capture lifecycle broken.** |
| Automated response | **External integration hooks; built-in containment is simulated.** `soar-forwarder/playbook.py` explicitly returns `contain_sim`. |
| Analyst console/case management | **Delegated to SIEM, openly disclosed; intentional boundary.** |
| Vulnerability scanning | **Absent, openly disclosed; intentional boundary.** |
| ML | **Optional adapter/overlay exists; runtime not verified and provenance labeling is unsound.** |

Every mapped SLIPS alert becomes `slips_ml`, regardless of its originating detector. Upstream SLIPS includes heuristic, threat-intelligence, scan and ML modules. Therefore “SLIPS plus heuristic” does not prove “ML plus heuristic” or independent corroboration. Preserve originating module/model identity and only boost confidence for qualifying independent evidence. [SLIPS detection modules](https://stratospherelinuxips.readthedocs.io/en/develop/detection_modules.html).

### G. Testing and quality gates

The component tests and Docker build gates are real. However, tests of pure enrichment merging do not prove a result consumer exists; tests using invented simplified telemetry do not prove Suricata compatibility. Redis contracts omit active-refresh aging expectations and permit optional Redis execution to be skipped.

CI invokes the aggregate suite on pushes/PRs. Docker e2e runs only through manual workflow dispatch and has the same missing default credentials as the quickstart. It tests one beacon path and stops at the first nonempty sink result. No inspected workflow runs full labeled-PCAP/RITA comparison or fleet failover tests. Repository settings were not inspected, so CI presence must not be described as enforced merge protection.

Publishing lists 25 services and requests amd64/arm64 builds, but only tags outputs `latest`; it does not publish the triggering version tag in this workflow. Local Git tags include v0.3.3; that alone does not establish that every registry image matches it. I did not verify all remote image manifests or their provenance.

### H. Deployment and operability

**Verified defects:** the default quickstart and insecure fallback fail as recorded. Secure startup works after real credentials/certs are supplied. The README sink-read command addresses the central Compose project, whereas quickstart is a different project; the e2e script itself documents why it uses `docker exec` instead.

Central forwarder environment includes only bus, sink name, file path and log level. Setting Splunk, Elasticsearch, webhook, syslog or Devo credentials in `.env` does not pass them through. The setup guide also omits `--env-file .env` in its later forwarder re-create command after explaining its necessity. Several advertised enrichment and tuning variables are likewise not wired into the central services.

Helm defaults the file sink but does not set `CERNITY_SINK_FILE` or mount a writable output volume. Its default adapter path is `/var/lib/cernity/findings.jsonl`; the non-root image only prepares `/out`. This is an inspected default-path failure, not a launched Kubernetes test.

Central Redpanda relies on the image's anonymous data volume rather than an explicitly named volume. Inspection confirmed that data is volume-backed, but the Compose definition does not provide a stable named reattachment for a down/up deployment. Scale Redis disables snapshots and does not enable AOF, so its named volume alone does not make state durable. File output is append-only without rotation. ClickHouse raw/finding TTLs and Docker log rotation do exist, so “everything grows forever” would be inaccurate.

Health endpoints exist in multiple services, but readiness often marks the consumer ready immediately and does not track later backend failure. Forwarder does not start the shared health server, and Helm does not wire readiness/liveness probes. Heartbeats are not proof of successful processing or delivery.

### I. Documentation accuracy and benchmark credibility

Five central claims tested against evidence:

| Claim | Assessment |
|---|---|
| Beacon replay yields a final finding | **Verified after supplying missing secure configuration.** |
| Finding service deduplicates | **Contradicted by duplicate live sink deliveries.** |
| Confirmed findings survive enrichment failure | **Pure helper implemented; runtime completion absent.** |
| Security fixes cover the solution | **Contradicted by scale listener exposure and sensor superuser.** |
| High fidelity and comparative superiority are proven | **Not established by the shipped benchmark.** |

`benchmarks/run.py:95` queries immediately after waiting only for the Suricata container; its own comment says count-stabilization polling is omitted. `_eve_paths()` returns an empty list, so the full-path determinism hash hashes no engine outputs. Search retrieves at most 10,000 documents and treats query failures as empty datasets. The Zeek container exists but its results are not incorporated into a scored reference arm. The Arm B SIEM setup also inherits the missing forwarder environment mapping. These defects can produce incomplete, misleading comparisons. The successful synthetic smoke uses provided counts/documents, not captured detector performance.

The executive summary and README also call Suricata stateless or say it “has no memory.” That premise is false: Suricata supports flow state, flowbits and cross-flow tracking facilities. Its scope differs from this central analytic tier, but it is not a stateless packet matcher. [Suricata rule types](https://docs.suricata.io/en/suricata-8.0.6/rules/rule-types.html), [flow keywords](https://docs.suricata.io/en/latest/rules/flow-keywords.html?highlight=noalert).

“No ML” and “ML is a future track” are stale alongside the existing SLIPS overlay. “MITRE on every finding,” “every finding carries its detection math,” “all detectors are stateless,” and “CDN-fronted beacon coverage” exceed implementation evidence. “No phone-home” should distinguish absence of vendor telemetry from outbound threat-feed downloads and optional enrichment; those external requests exist.

### J. Licensing

The checked-in license makes original Cernity code source-available and restricts competing products. Its competition language includes free products, so the restriction is broader than “cannot resell.” The official Perimeter version listing identifies 1.0.1; direct full-text retrieval failed during this audit, so no byte-for-byte upstream license equivalence is asserted. [PolyForm Perimeter versions](https://polyformproject.org/licenses/perimeter/).

Third-party notices correctly distinguish JA4 from JA4+ and disclose FoxIO's monetization restriction. FoxIO permits internal business use; “noncommercial” should not be read as banning a business from protecting its own network. [FoxIO license FAQ](https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md).

Redis notices are stale: Redis 8 offers AGPLv3 alongside RSALv2/SSPLv1. Mutable image tags also prevent a fixed bill of materials from being inferred from the repo. [Redis licenses](https://redis.io/legal/licenses/).

I found no evidence sufficient to declare the entire distribution legally compliant or incompatible. Separate-process composition alone is not a completed redistribution compliance analysis. Most Python Dockerfiles do not copy Cernity's LICENSE/NOTICE into their filesystem; verify notice delivery, bundled dependencies, and corresponding-source obligations per actual released image before claiming distribution compliance.

## 4. Prioritized gap list

Severity is based on operator impact. **Blocker** prevents a core promised outcome; **Major** materially affects security, correctness, delivery, or scale; **Minor** reduces operability or documentary reliability. Multiple related defects are grouped under one item.

| ID | Severity | Gap, location and impact | Concrete fix and acceptance condition |
|---|---|---|---|
| F01 | **Blocker** | Incomplete capture/finalization, `finding-service/app.py:76–98`, `state_machine.py:51`, `capture-orchestrator/app.py:58`. Confirmed threats never reach the sink; requests lack capture identity/value. | Deliver confirmed threats immediately with pending evidence; persist lifecycle, consume result/status topics, implement timeout/refusal/failure finalization, emit valid sensor-specific jobs. E2e signature/TI tests must pass with overlay absent, enabled, failed and unavailable. |
| F02 | **Major** | Sensor superuser and direct-final injection, `deploy/central/redpanda/entrypoint.sh:50`. A sensor can forge trusted output. | Per-sensor produce-only telemetry ACLs, separate analytics/forwarder principals and group permissions; negative test final/capture/config writes and cross-tenant reads. |
| F03 | **Major** | Insecure scale path; unused hardening anchors and absent Helm security contexts, `deploy/scale/{infra,workers}.yml`, Helm templates. | Reuse hardened security profiles, secure listeners and state transport, apply actual security contexts; test every supported deployment path. |
| F04 | **Major** | SIEM and enrichment config not passed to containers, `deploy/central/docker-compose.yml:158–191`, scale/Helm pipeline. Operator configuration does not select a working real sink. | Explicit env/secret mapping and writable file storage; compose/render tests plus authenticated sink integration tests. |
| F05 | **Major** | Whole-key TTL mistaken for rolling windows, `shared/store.py:155`, `:323`, behavioral and east-west callers. Old observations distort detections and active cardinality may grow. | Event-scored members or rotating buckets; expire individual observations; tests with continuous activity beyond multiple windows and bounded cardinality. |
| F06 | **Major** | JA3/RPC/SMB compatibility and CDN blind spots, protocol `app.py:101`, east-west `app.py:250–292`, behavioral `app.py:458`. Advertised coverage misses real input. | Normalize actual versioned EVE fields before detection; replay real PCAP-derived positive/negative fixtures; document dormant capabilities and CDN exclusions. |
| F07 | **Major** | Duplicate/lost deliveries, finding app and `findings-forwarder/adapters.py:237`, `shared/ndr_runtime.py:60`. Failed fan-out sinks are logged then abandoned; bulk item errors only warn. | Durable per-sink outbox/retry/DLQ, explicit acknowledgement after durable processing, stable idempotency keys, duplicate/restart/outage/partial-bulk tests. |
| F08 | **Major** | Incomplete fleet identity and replica state, Fluent Bit route, correlation app, Redis client. Correlation can mix/split identities and Cluster is not drop-in. | Trusted ingress identities, tenant-aware keys throughout, entity-keyed durable correlation, explicit supported Redis topology and failover tests. |
| F09 | **Major** | Broken default/demo startup, README and Redpanda entrypoint. | One verified bootstrap path that generates/loads secrets; use the correct CLI; pin/test broker version; run fresh-install e2e in CI. |
| F10 | **Major** | Benchmark cannot establish claimed accuracy/noise reduction, `benchmarks/run.py:95–139`. | Wait for complete ingestion/delivery, fail on query/engine errors, paginate, hash real inputs/outputs, pin versions/rules and score the actual reference arm; include false negatives introduced by gating. |
| F11 | **Major** | Optional capture agent cannot authenticate to secure bus; resource/health gates incomplete, capture app and sensor Compose. | Use shared secured clients and least-privilege storage credentials; outer `finally` cleanup, measured health, per-job packet selection and failure/restart tests. |
| F12 | **Major** | ML provenance conflation, `slips-adapter/slips_map.py:96`, `correlation-service/correlate.py:181`. Ordinary SLIPS evidence becomes asserted ML agreement. | Carry detector/model provenance and independence conditions; only qualify verified ML evidence for ML corroboration. |
| F13 | **Major** | Contract drift and unchecked final admission, finding schema, IDS producer, forwarder. | Validate real outputs and ingress, version adapters, quarantine malformed records; test all producer variants including suppression. |
| F14 | **Major** | Persistence mismatch: central broker relies on an anonymous volume without named reattachment; scale Redis has no persistence enabled. | Explicit durable volumes/AOF or documented recovery model, restore procedures, restart/recreate tests. |
| F15 | **Minor** | Incomplete readiness, file rotation and mutable release artifacts. | Wire probes to actual consumer/backend state, rotate sink files, publish versioned digest-linked images and test required Zeek packages. |
| F16 | **Minor** | Stale scope, blanket MITRE/math claims and incomplete license inventory. | Revise summary/coverage docs to match tested behavior; correct mappings and version-specific notices; include release SBOM and notice delivery. |

## 5. Overclaims and honesty check

The project's explicit boundaries around SIEM ownership, vulnerability scanning and optional central forensics are reasonable and disclosed. The defect is not that it lacks a commercial console or CVE scanner. The defect is that several capabilities represented as closed, complete or validated are disconnected, incompatible with normal input, or only demonstrated with synthetic helpers.

The supplied executive summary should not serve as evidence of its own accuracy. Statements that a previous independent audit closed every issue were not accompanied by evidence that supersedes the current reproducible failures. The proper distinction is a working narrow analytics demonstration versus an operationally validated NDR system.

## 6. Does it solve the stated problem?

**It partially solves central behavioral analysis over Suricata EVE.** An operator who supplies the missing deployment configuration can obtain useful findings without running the behavioral worker on the sensor. The successful beacon demonstrates that contribution.

**It does not yet deliver the complete promised operational outcome.** A sensor operator following the quickstart first hits startup/configuration problems; real threat alerts then encounter the missing finalization loop, real protocol telemetry encounters parser assumptions, and a fleet encounters identity/state/security boundaries the architectural description treats as solved. The smaller output stream cannot yet be claimed to preserve threats while removing noise.

The strongest supporting case is the working core, inspectable math, component tests and useful state primitives. The strongest opposing case is the live loss of confirmed-threat output and ability of an authenticated sensor to forge final findings. Both are observable; neither should be replaced by a general impression of code quality.

## 7. Recommendations

1. **Complete threat delivery before adding detector breadth.** Fix F01 and establish durable per-sink delivery/idempotence. Require signature, TI, benign suppression and failure-path e2e checks.
2. **Enforce the sensor trust boundary across every deployment.** Remove superuser sensors, secure the scale stack, authenticate the capture client and bind tenant/sensor identity at ingress.
3. **Make the data/state semantics correct.** Normalize real Suricata outputs, repair rolling windows and identifier scoping, and prove restart/rebalance behavior against real Redis and Kafka.
4. **Make deployment and evidence reproducible.** Wire supported configuration, storage and probes; pin release artifacts and make integration checks routine. Repair the benchmark before using it to claim fidelity or scale.
5. **Rewrite the executive summary around verified scope.** Describe central heuristic analytics, mark dormant/optional components, state measured limits, and remove universal claims about statelessness, MITRE coverage, ML agreement and completed hardening.
