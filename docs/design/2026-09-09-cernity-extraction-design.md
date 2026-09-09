# Cernity — Extraction & Architecture Design

**Date:** 2026-09-09
**Status:** approved design; extraction not yet started
**Repo:** https://github.com/cernity/cernityndr

Cernity is the central-analytics ("middle tier") of a tiered NDR architecture,
extracted from a proven private homelab build into a standalone, source-available
project. This document is the design of record for that extraction.

---

## 1. Purpose & principle

Build a turnkey, deployable central NDR analytics engine (goal A) that anyone
with a Suricata sensor can point at with a small config change. Keep the internal
seams clean enough that two secondary uses fall out for free: an importable
detector library (C) and a reference implementation (B). The shipped artifact is
the engine; the library and teaching value are consequences of good boundaries,
not separate products.

Governing principle (do not violate):

> **Raw network telemetry is analytics input. Security findings are SIEM input.**

The public contract is the **bus topics + JSON schemas** in `contracts/`.

## 2. Boundaries

- **Ingestion:** Suricata stays stock plus a documented `eve.json` config snippet.
  Everything downstream of the sensor is Cernity.
- **Output:** emit-only. Cernity's terminal output is `ndr.finding.final.v1`,
  delivered through a pluggable **findings-forwarder** with adapters (OpenSearch as
  the documented reference; plus Splunk HEC, webhook, syslog/CEF, file). Cernity
  does **not** ship a SIEM — it forwards findings to the operator's SIEM. Any SIEM
  is a config or adapter swap.

## 3. Deployment tiers (everything runs as a container)

**Tier 1 — Sensor bundle** (per Suricata box):
- `cernity-suricata` — containerized reference sensor for evaluators. Operators with
  a tuned bare-metal Suricata skip this and bind-mount their existing
  `/var/log/suricata` + command socket instead.
- `cernity-fluent-bit` — log shipper. Tails `eve-*.json`, routes each event type to
  its bus topic, keys by source IP. Replaces the earlier Vector shipper. (Filebeat
  and Vector are documented drop-in alternatives.)
- `cernity-capture-agent` — optional, on-demand packet forensics. Self-arms over the
  bus (no inbound access), actuates Suricata's own conditional PCAP, ships bounded
  pcap to object storage, requests central Zeek enrichment. Does **no** packet
  inspection itself; the look-back ring buffer is off by default.

No detection runs on the sensor. The sensor produces and forwards logs, and
optionally grabs packets when told.

**Tier 2 — Central core** (always on): `normalizer`, `ids-alerts`, the detectors
(`behavioral-detectors`, `protocol-detectors`, `dns-detector`, `http-detector`,
`east-west-detectors`, `anomaly-detector`, `coverage-detector`), `asset-service`,
`correlation-service`, `finding-service`, `findings-forwarder`.

**Tier 3 — Central overlays** (shipped, toggleable via compose overlay files):
- Zeek loop: `capture-orchestrator`, `zeek-central`, `zeek-notice`, `reconstruction`
- File inspection: `file-threat`, `file-yara`
- Advanced streaming: `flink` (scan + session stitching)
- Response: `soar-forwarder`

**Tier 4 — Backends** (stateful): Redpanda (bus), Redis (detector window state),
ClickHouse (raw-telemetry store), MinIO (pcap/file object store).

**Tier 5 — Docs only** (not shipped): Suricata `eve.json` config guide; OpenSearch
dashboard reference.

### On effectiveness vs. the Zeek loop

The homelab bake-off (2026-08-21, real Lumma Stealer pcap) showed Zeek added **zero
unique detections** over Suricata; its unique value was forensics and asset
intelligence (software inventory, cert/OCSP, protocol anomalies). Therefore the
capture-agent + Zeek loop is documented as a **forensics/enrichment** capability,
not a detection multiplier. Every metadata detector works without it.

## 4. Distribution & packaging

- **Docker Hub image per service** under the `cernity` org: image `cernity/<svc>`,
  container name `cernity-<svc>` (self-identifying in an operator's `docker ps`).
- **Compose files:** `deploy/sensor`, `deploy/central`, `deploy/overlays/*`, and a
  `deploy/quickstart` all-in-one (central stack + a replay feeder) so an evaluator
  sees findings end-to-end without a live sensor.
- **PyPI package** `cernity-ndr` (detectors + shared libs + contracts) for the
  library use case (C).
- **`:latest`** is the default image tag convention.

## 5. Source of truth (model A)

`cernityndr` is **canonical** for all generic engine code. The private homelab keeps
only site-specific configuration and consumes the published `cernity/*` images via a
thin homelab overlay (its IPs, secrets, and internal service wiring). Migrating the
live homelab to run from the published images is part of the extraction work — the
homelab becomes one Cernity deployment among others, and is the continuous
proof-of-function.

## 6. The Vector → Fluent Bit migration

The homelab migrates from Vector to Fluent Bit at the same time, so the personal
build and the public repo stay identical. The migration is **validated by the proof
rig** (`replay-diff` + the bake-off): Fluent Bit must ingest EVE and produce the same
findings Vector did, with no detection parity regression, before the switch is
accepted in either repo.

## 7. Net-new build work

1. **findings-forwarder** — generalize the ES-coupled `findings-sink` into a
   pluggable sink with adapters (OpenSearch, Splunk HEC, webhook, syslog/CEF, file);
   absorb the old `wazuh-forwarder` as one adapter.
2. **Fluent Bit config** — replace the Vector shipper (sensor bundle).
3. **Strip homelab coupling** — remove hardcoded IPs, Vault references, `orion-*`
   dependencies, and homelab hostnames from all services; make everything
   environment/config-topic driven.
4. **`cernity-` rename** across services and images.
5. **Repo scaffolding** — LICENSE, README, TRADEMARK, NOTICE, THIRD-PARTY-NOTICES,
   CONTRIBUTING, `pyproject.toml`, CI (build+push images, run tests + proof rig).
6. **Homelab overlay** — reduce `homelabai/docker/ndr/` to a thin overlay consuming
   `cernity/*` images.

## 8. Proof & test tooling (repo, not shipped as images)

`bakeoff-*`, `replay-diff`, `harness`, `validation` live under `tools/` and `tests/`
and run in CI. They validate detection parity (including the Fluent Bit switch) and
provide the Suricata-vs-Zeek evidence that substantiates the architecture.

## 9. Deferred (not v1)

Enterprise multi-tenant / HA hardening (Redis-backed multi-tenant window state, N-way
HA dedup at fleet scale). Consistent with the 2026-08-25 decision and the fact that
the proven build is single-tenant. Revisit once the core is public.

## 10. Licensing & ownership

- **License:** PolyForm Perimeter 1.0.1 — source-available (Fair Source), not
  OSI open source, non-expiring. Permits any use (run, modify, self-host,
  redistribute) **except providing to others a product that competes with Cernity.**
  Chosen deliberately: keep Cernity free for every operator while preventing a vendor
  from reselling it as their own product.
- **Scope:** the license covers **only the Cernity Project's own original code.**
  Third-party software Cernity uses, bundles, or depends on (Suricata, Zeek, Fluent
  Bit, Redpanda, Redis, ClickHouse, MinIO, OpenSearch, Python libraries) is governed
  by its own license — see `THIRD-PARTY-NOTICES.md`. Techniques from RITA and
  abuse.ch feeds are modeled, not redistributed.
- **Ownership:** attributed to **the Cernity Project** (organization), not an
  individual. Contributors grant the project relicensing rights (see
  `CONTRIBUTING.md`) so ownership of the combined work stays with the project and
  dual/commercial licensing remains possible.
- **Trademark:** "Cernity" is a trademark of the Cernity Project (`TRADEMARK.md`);
  the code license does not grant rights to the name.

## 11. Proposed repo layout

```
LICENSE  NOTICE  TRADEMARK.md  THIRD-PARTY-NOTICES.md  CONTRIBUTING.md  README.md
pyproject.toml
contracts/                 # public API: JSON schemas + topics
services/<svc>/            # one dir + Dockerfile per shipped service
shared/                    # store, runtime, metrics library
deploy/
  sensor/docker-compose.yml
  central/docker-compose.yml
  overlays/{zeek,files,clickhouse,soar,flink}.yml
  quickstart/docker-compose.yml
  fluent-bit/              # reference shipper config
docs/
  design/                  # this document
  suricata-config.md
  opensearch-example.md
  architecture.md
tools/{bakeoff,replay-diff,harness,validation}/
tests/
.github/workflows/         # CI: test + build/push images + run proof
```

## 12. Open follow-ups

- Whether central overlays are on-by-default in the quickstart or behind flags
  (leaning: quickstart brings the full experience up; a documented `lite` profile
  runs core only).
- CLA automation (CLA-assistant bot) before the first outside PR.
- Trademark registration timing (common-law use now; register later).
