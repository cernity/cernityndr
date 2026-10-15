# Third-Party Components

Cernity is an **orchestration of Cernity's own original software together with
independent third-party software.** The Cernity license (PolyForm Perimeter 1.0.1,
see [LICENSE](LICENSE)) covers **only** the original work of the Cernity Project.
It does **not** cover, relicense, or sublicense any of the third-party components
below. Each of those is an independent work governed by its own license and terms.

This matters in two situations:

1. **When you run Cernity**, you are also running these third-party components under
   their own licenses.
2. **When you redistribute Cernity** — including pulling and re-pushing Cernity
   container images that bundle third-party software — the obligations of each
   bundled component's license apply to that component, in addition to the Cernity
   license applying to Cernity's own code.

## What Cernity itself is

Covered by the Cernity license (PolyForm Perimeter 1.0.1): the Cernity services and
detectors (`normalizer`, `behavioral-detectors`, `protocol-detectors`,
`dns-detector`, `http-detector`, `east-west-detectors`, `anomaly-detector`,
`coverage-detector`, `threat-intel`, `correlation-service`, `finding-service`,
`asset-service`, `findings-forwarder`, `capture-orchestrator`, `zeek-notice`,
`file-threat`, `file-yara`, `soar-forwarder`, `reconstruction`,
`cernity-capture-agent`), the shared libraries, the `contracts/` schemas, and the
Cernity configuration and documentation.

## Third-party software Cernity uses, bundles, or depends on

These are **not** Cernity's work and are **not** under the Cernity license. The
license shown is the upstream project's; always confirm against the upstream
project, as licenses change by version.

| Component | Role in Cernity | Upstream license (verify upstream) |
|---|---|---|
| Suricata | edge IDS / telemetry source (not shipped; operator-provided or reference image) | GPL-2.0 |
| Zeek | central on-demand deep analysis (optional overlay) | BSD-3-Clause |
| JA4 (TLS client fingerprint), `FoxIO-LLC/ja4` Zeek package | base client-fingerprint rarity; bundled in the `cernity/zeek-central` image | BSD-3-Clause (base JA4 is open source, no patent claims) |
| JA4+ suite (JA4S / JA4H / JA4X / JA4SSH …), `FoxIO-LLC/ja4` Zeek package | on-demand forensic fingerprints via `zeek-central` enrichment; bundled in the image | **FoxIO License 1.1** (patent-pending; free for internal & academic use, **not** for monetization) — see note below |
| JA3, `salesforce/ja3` Zeek package | legacy TLS fingerprint + abuse.ch SSLBL matching; bundled in the image | BSD-3-Clause |
| nDPI (ntop) | optional Suricata plugin; the `ndpi` risk/breed verdict feeds `behavioral-detectors` (operator-built into Suricata, **not shipped** — no Cernity image links or distributes it) | **≤ 5.x:** LGPL-3.0 (library) / GPL-3.0 (some tools) — verify by component. **6.0+:** core library stays LGPL-3.0, but ntop added *dual-licensed components on top* whose terms depend on whether the project generates direct or indirect revenue — see note below |
| Fluent Bit | sensor-side log shipper | Apache-2.0 |
| Redpanda | message bus | Redpanda Community License / BSL (source-available) |
| Redis | detector window state | AGPL-3.0 (Redis 8+) or RSALv2 / SSPL (7.4–7.8); pre-7.4 is BSD — verify by version |
| ClickHouse | raw-telemetry analytics store (optional) | Apache-2.0 |
| MinIO | pcap/file object store (optional) | AGPL-3.0 |
| OpenSearch / OpenSearch Dashboards | documented reference SIEM (not shipped) | Apache-2.0 |
| SLIPS (Stratosphere IPS) | opt-in ML behavioral-detection overlay (`deploy/overlays/slips.yml`); pulled as the upstream `stratosphereips/slips` image, **not** part of Cernity's code | **GPL-2.0** — see note below |
| Apache Flink | optional streaming-SQL detector overlay (`deploy/overlays/flink.yml`); pulled as the upstream image, not shipped in Cernity's code | Apache-2.0 |
| Python + libraries (e.g. kafka client, boto3, prometheus-client, jsonschema) | service runtime | PSF / Apache-2.0 / MIT / BSD (per package) |

## Techniques modeled, not redistributed

Cernity reimplements published behavioral-analysis methods over Suricata telemetry.
The following are referenced and modeled — their code is **not** included or
redistributed here, and their own licenses govern their own works:

- **RITA** (Real Intelligence Threat Analytics), Active Countermeasures — GPL-3.0 —
  the reference method for beaconing, long-connection, and DNS-tunnel scoring.
- **abuse.ch** feeds (Feodo Tracker, SSLBL, JA3) — used under abuse.ch's own terms;
  operators are responsible for complying with the feed terms.

## Note on JA4+ (FoxIO License 1.1)

FoxIO splits its fingerprinting suite: the base **JA4** (TLS client) method is
BSD-3-Clause and free for any use, but the rest of the suite — **JA4+** (JA4S, JA4H,
JA4X, JA4SSH, and the others) — is licensed under the **FoxIO License 1.1**. That
license permits internal, academic, and non-commercial use, but **prohibits
monetization**: selling JA4+ fingerprinting as part of a commercial product or service
requires a separate OEM license from FoxIO (john@foxio.io).

Cernity's own code does **not** implement the JA4+ methods — `zeek-central` merely reads
the fingerprint values emitted by the bundled FoxIO Zeek package. The `cernity/zeek-central`
image, however, does bundle that package. If you redistribute Cernity images commercially,
or offer JA4+ output as part of a paid product, review the FoxIO License 1.1 and contact
FoxIO. Running Cernity for your own organization's security is squarely within the
permitted non-commercial/internal use.

## Note on nDPI 6.0+ (LGPL-3.0 core + dual-licensed components)

**Cernity does not ship, link, or distribute nDPI.** No Cernity image contains it. The
sensor deployment (`deploy/sensor/docker-compose.yml`) does not run Suricata at all — it
mounts the operator's `/var/log/suricata` read-only and ships EVE. Cernity's services only
*read* the `ndpi` object out of EVE when the operator's own Suricata build emits one. The
library's licensing obligations therefore sit with whoever built that Suricata, not with
Cernity. (`deploy/benchmark/` is the one place Cernity runs Suricata itself, for PCAP
replay; see the note at the end.)

From **nDPI 6.0 (Aug 2026)** ntop moved to a dual-license model. The core library remains
**LGPL-3.0**. On top of it sit additional ntop components whose terms depend on the
project's classification, which the host application now declares in code via the
`ndpi_init_detection_module()` call:

- **Not-for-profit** — "all projects where nDPI does not create *direct* revenue (e.g. a
  product that includes nDPI) or *indirect* revenue (e.g. providing a service using
  nDPI)". The dual-licensed components may be used freely.
- **For-profit** — any project where nDPI is used to generate direct or indirect revenue.
  Such a project may either use **only** the core LGPL-3.0 components, or sign a
  commercial agreement with ntop (`license@ntop.org`).

The test is **revenue**, not license shape. Cernity is free to use and is not sold, and no
paid service is offered on top of it, so a Cernity deployment creates neither direct nor
indirect nDPI revenue. PolyForm Perimeter is orthogonal to ntop's test — it restricts
building a competing product; it does not make a project revenue-generating. An operator
who *does* monetize a deployment makes their own classification, and that declaration
happens in their sensor build, not in Cernity.

Benchmark caveat: `deploy/benchmark/suricata/suricata.yaml` lists
`/usr/lib/suricata/ndpi.so`, but the `jasonish/suricata:latest` image it runs is built with
`nDPI: no`. The replay harness therefore cannot exercise the nDPI path; production sensors
built with `--enable-ndpi` can and do.

## Note on SLIPS (GPL-2.0)

The opt-in ML detection overlay runs **SLIPS** (Stratosphere IPS), which is **GPL-2.0**.
Cernity does **not** vendor or link SLIPS' code: the overlay pulls the upstream
`stratosphereips/slips` image and talks to it over files and the message bus, so the
GPL obligation stays contained to that separately-distributed upstream image. Cernity's
own adapters (`eve-bridge`, `slips-adapter`) are Cernity-licensed and contain no SLIPS
code. The overlay is off by default; a future native ML detector would remove the GPL
dependency entirely (see [docs/roadmap.md](docs/roadmap.md)).

## Note for redistributors

If you build and distribute Cernity images, you are distributing third-party
software inside them (for example Suricata under GPL-2.0, MinIO under AGPL-3.0).
Those licenses impose their own obligations (such as offering corresponding source)
on you as the distributor of those components. The Cernity license does not remove
or alter those obligations. Consult each upstream license before redistributing.
