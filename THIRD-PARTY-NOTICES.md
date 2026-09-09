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
| Fluent Bit | sensor-side log shipper | Apache-2.0 |
| Redpanda | message bus | Redpanda Community License / BSL (source-available) |
| Redis | detector window state | RSALv2 / SSPL (recent versions) — verify by version |
| ClickHouse | raw-telemetry analytics store (optional) | Apache-2.0 |
| MinIO | pcap/file object store (optional) | AGPL-3.0 |
| OpenSearch / OpenSearch Dashboards | documented reference SIEM (not shipped) | Apache-2.0 |
| Python + libraries (e.g. kafka client, boto3, prometheus-client, jsonschema) | service runtime | PSF / Apache-2.0 / MIT / BSD (per package) |

## Techniques modeled, not redistributed

Cernity reimplements published behavioral-analysis methods over Suricata telemetry.
The following are referenced and modeled — their code is **not** included or
redistributed here, and their own licenses govern their own works:

- **RITA** (Real Intelligence Threat Analytics), Active Countermeasures — GPL-3.0 —
  the reference method for beaconing, long-connection, and DNS-tunnel scoring.
- **abuse.ch** feeds (Feodo Tracker, SSLBL, JA3) — used under abuse.ch's own terms;
  operators are responsible for complying with the feed terms.

## Note for redistributors

If you build and distribute Cernity images, you are distributing third-party
software inside them (for example Suricata under GPL-2.0, MinIO under AGPL-3.0).
Those licenses impose their own obligations (such as offering corresponding source)
on you as the distributor of those components. The Cernity license does not remove
or alter those obligations. Consult each upstream license before redistributing.
