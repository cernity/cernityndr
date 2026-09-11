# Response to the independent implementation audit

> Companion to [`cernity-independent-audit.md`](cernity-independent-audit.md). This is the
> project's engineering response. It is an **acknowledgment, not a rebuttal** — the audit is
> credible, its reproductions are sound, and its central conclusions are accepted.

## 1. Position

The audit is **substantially correct**. It ran real reproductions against a live broker and
verified concrete defects — a stalled confirmed-threat finalization path, a sensor credential
that can forge final findings, broken default/insecure startup, whole-key TTL retention, and
several contract and deployment gaps. We accept the **Partial** verdict and the distinction it
draws: *a working, inspectable, narrow central-analytics demonstration* is not the same as *an
operationally validated NDR*. The executive summary and README claimed the latter; the code
supports the former today.

Two things are corrected immediately (see §3): the **documentation overclaims** the audit
identified, and the framing that "a previous audit closed every issue." The prior audit ran
against `v0.2.0`; the `v0.3.x` changes closed some of its findings but **introduced or left
open** several this deeper audit caught (notably the sensor-superuser grant and the
insecure-fallback CLI defect). That is on us, and the record is now straight.

## 2. Disposition of every finding

Legend: **Accept** — valid, will fix. **Accept (context)** — valid, with a scoping note that
does not dispute the defect. No finding is rejected.

| ID | Sev | Disposition | Note |
|---|---|---|---|
| F01 | Blocker | **Accept** | Confirmed threats route to capture and never finalize — no service consumes the enrichment-result topic; `apply_enrichment_result` is test-only. Top priority. This session's routing fix addressed *structural* categories only; the confirmed-threat loop is genuinely incomplete. |
| F02 | Major | **Accept** | The bus entrypoint grants the *sensor's* SCRAM user cluster **superuser** (`entrypoint.sh:48`), so a compromised sensor can write final findings. Introduced in the v0.3.0 bus work — a real trust-boundary break. |
| F03 | Major | **Accept** | Scale (`infra.yml`/`workers.yml`) and Helm do not inherit the secure listener/hardening; the "secure by default" claim holds for **central Compose only**. |
| F04 | Major | **Accept** | Central `finding-service`/`findings-forwarder` env passes only bus/sink-name/file/log — SIEM and enrichment vars set in `.env` never reach the containers. |
| F05 | Major | **Accept** | `SET NX EX`/counter keys refresh whole-key TTL on every write, so old observations persist past the "window." Sorted beacon windows prune; the other state types do not. |
| F06 | Major | **Accept** | Real EVE-shape gaps: JA3/JA3S compound objects raise `TypeError` (dropped), east-west reads `interface_uuid`/`interfaces` and misses nested `smb.dcerpc` + `filename:svcctl` pipes, CDN exclusion suppresses the very beacons it should catch, IPv6 classification is inconsistent. Advertised coverage exceeds parser reality. |
| F07 | Major | **Accept** | No delivery-side dedup; failed fan-out sinks are logged then dropped; some producers (`ids-alerts/promote.py:104`) use process-seeded `hash()` → unstable IDs across replicas/restarts. |
| F08 | Major | **Accept** | No authenticated tenant/sensor identity at ingress; correlation keeps process-local entity lists and emits without an entity partition key. Multi-site correctness is not established. |
| F09 | Major | **Accept** | `CERNITY_INSECURE_BUS=1` runs the raw `redpanda start … --check=false` (an `rpk`-only flag) → crash. The default quickstart also needs generated creds the README doesn't create. Both startup paths are broken as documented. |
| F10 | Major | **Accept** | The benchmark queries before ingestion settles, `_eve_paths()` hashes nothing, and the Zeek arm is never scored. It cannot support accuracy/noise claims — it is a **smoke harness**, and was over-described. |
| F11 | Major | **Accept** | The `capture-agent` builds Kafka clients without SASL/TLS and its Compose lacks the CA/creds — it cannot use the secure listener. Capture also uploads the largest file, not a per-finding slice. |
| F12 | Major | **Accept** | Every SLIPS alert is stamped `slips_ml` regardless of which upstream SLIPS module produced it (SLIPS has threat-intel/scan/ML modules). "ML × heuristic corroboration" therefore overclaims provenance. |
| F13 | Major | **Accept** | `build_finding` emits `devo_delivery_state:"SUPPRESSED"`, which the schema enum forbids; `ids-alerts` candidates omit required `first_seen`/`last_seen`. Schema tests don't validate real producer output. |
| F14 | Major | **Accept** | Central Redpanda uses the image's anonymous volume (no named reattachment); scale Redis has neither RDB nor AOF. Durability across down/up is not guaranteed. |
| F15 | Minor | **Accept** | Readiness marks ready immediately, no sink-file rotation, mutable image tags, Zeek install `|| true`. |
| F16 | Minor | **Accept** | Doc overclaims (see §3). |

The audit's own concessions are noted and correct: SIEM-ownership, no-vuln-scan, and
optional-forensics are **disclosed, intentional boundaries** — not defects.

## 3. Corrected immediately (docs)

The audit's honesty section is right, and these are being fixed now (the summary it reviewed was
an untracked draft — it is revised to verified scope before it ships):

- **"Suricata has no memory / stateless matcher"** — **false as written.** Suricata has flow
  state, flowbits, and cross-flow tracking. Corrected to: Suricata's stateful facilities are
  *edge- and rule-scoped*; what it doesn't do is central, cross-host, long-window behavioral
  analytics — which is Cernity's role.
- **"MITRE on every finding" / "every finding carries its detection math"** — softened to "where
  defensible" (some categories have no technique/fallback, matching the schema's own wording).
- **"stateless detectors" / "all detectors stateless"** — corrected to "stateless *workers*
  sharing state in Redis" (accurate; correlation is explicitly stateful).
- **"CDN-fronted beacon coverage"** — removed as a headline claim pending the F06 fix; the CDN
  exclusion currently suppresses it.
- **"secure by default … closed and validated"** — scoped to the **central Compose** path;
  scale/Helm hardening is marked in-progress.
- **"no phone-home"** — clarified to *no vendor telemetry*, while acknowledging opt-in outbound
  threat-feed and enrichment requests.
- The "previous audit closed everything" framing is retracted; version claims are separated from
  per-checkout verification.

## 4. Remediation roadmap (toward a *verified* NDR — the v0.4 line)

Ordered by the audit's own priority — deliver correctly and securely before adding breadth.

**Phase 1 — make the promise true (Blocker + trust boundary).**
1. **F01** — finalize confirmed threats. Deliver them immediately with a `pending-evidence`
   marker; add a runtime consumer for the enrichment-result/capture-status topics that completes
   or fails the original finding on timeout/refusal; emit capture jobs with the identity the
   orchestrator expects. Acceptance: signature/TI e2e passes with the overlay absent, enabled,
   failed, and unavailable.
2. **F02 + F08 + F11** — the sensor trust boundary. Per-sensor **produce-only** telemetry ACLs,
   separate analytics/forwarder principals, authenticated tenant/sensor identity stamped at
   ingress, and a secured capture-agent client. Negative tests: a sensor credential must fail to
   write final/capture/config topics or read cross-tenant.

**Phase 2 — correct data & delivery semantics.**
3. **F05** — real rolling windows (per-observation expiry / rotating buckets), bounded
   cardinality under continuous activity.
4. **F07 + F13** — durable per-sink outbox with idempotency keys and DLQ; stable cross-process
   IDs everywhere; validate real producer output against the schema; **fix the
   `devo_delivery_state` enum and the missing `first_seen`/`last_seen`.**
5. **F06** — normalize real versioned EVE fields (compound JA3/JA3S, `interfaces[].uuid`, nested
   `smb.dcerpc`, `filename` pipes) and validate against **real PCAP-derived** fixtures, not
   document-shaped inputs.

**Phase 3 — deployment, durability, evidence.**
6. **F03 + F04 + F09 + F14** — one verified bootstrap path (fresh-install e2e in CI), secure
   scale/Helm, wired SIEM/enrichment config, durable named volumes / AOF.
7. **F10 + F12** — repair the benchmark (settle ingestion, hash real I/O, score the Zeek arm,
   account for gated false-negatives) before any accuracy claim; carry SLIPS module provenance
   and only corroborate genuine ML.
8. **F15 + F16** — real readiness, file rotation, pinned digest-linked images, SBOM + notice
   delivery; finish the doc pass.

## 5. What remains true

The audit affirms the parts worth affirming: the analytics path is real (the feeder replays EVE,
not findings; the behavioral worker computes the beacon; it reaches the sink), the statistical
methods (Bowley skew, MAD, count weighting, DNS grouping) are genuinely implemented, the
pure-function + build-gate structure makes the engine auditable, the Redis primitives and central
hardening are substantive, and the reputation privacy filter is defensible. That is a real
foundation — it is just **narrower and less finished than the summary claimed**, and this
response and the roadmap exist to close exactly that gap honestly.

## 6. Already corrected in this change

- **Documentation overclaims (§3)** — the executive summary and README are revised to verified
  scope (statelessness, MITRE "every", detection-math "every", CDN beacon, secure-by-default
  scope, no-phone-home, ML provenance, benchmark accuracy).
- **F13 (part)** — `build_finding` no longer emits the schema-invalid `devo_delivery_state:
  "SUPPRESSED"`; a suppressed finding now correctly reports delivery-state `NONE` (the state
  stays `SUPPRESSED`). Guarded by the existing state-machine test.

Everything else in §2/§4 is a tracked remediation item, not yet fixed. The Blocker (F01) and the
sensor trust boundary (F02) are the first code work, planned as the **v0.4** line.

*Prepared in response to the audit at commit `1cffad4`. Fixes land per the work-hours change
process; this response, the corrected summary/README, and the F13 enum fix are the first
deliverables.*
