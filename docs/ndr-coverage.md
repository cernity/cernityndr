# How Cernity completes Suricata into a full NDR

Suricata is a world-class **IDS and edge sensor**: it inspects packets at line rate,
matches known-bad signatures, and emits rich protocol/flow telemetry (EVE JSON). What it
is *not* — on its own — is a full **Network Detection and Response (NDR)** platform. An
IDS has no memory of what a host did over the last ten minutes, no central analytics, no
findings lifecycle, no enrichment, and no response path.

**Cernity is the add-on that supplies exactly those missing NDR capabilities.** Suricata
inspects; Cernity remembers, analyzes, correlates, enriches, prioritizes, and hands
finished findings to your SIEM. Together they are a complete, self-hosted NDR.

This page maps the recognized NDR capability areas (aligned with the Gartner NDR
definition and common vendor requirement lists) to **what Suricata provides**, **what
Cernity adds**, and **how**. It is deliberately honest about the boundaries — where a
capability is delegated to your SIEM by design, and where Cernity does not play.

---

## Detection breadth — known *and* unknown threats

**NDR needs multiple detection methods, not just signatures.**

| Method | Suricata alone | How Cernity covers it |
|---|---|---|
| **Signature / known-bad** | ✅ native | `ids-alerts` promotes Suricata signature hits into the same finding pipeline, so they correlate with everything else |
| **Behavioral (unknown threats)** | ❌ (no state) | `behavioral-detectors` — stateful, per-host rolling windows in Redis: **beaconing** (RITA-style timing regularity + jitter), **data exfiltration** (volume + sustained low-and-slow), **DNS tunneling / DGA** (query volume + entropy), **long connections**, **rare-destination / first-seen**, **fleet-prevalence** |
| **Protocol / fingerprint anomalies** | logs the metadata | `protocol-detectors` — JA3/JA4 client + server fingerprint rarity, DoH to unapproved resolvers, cloud-staging, TLS cert anomalies, SSH brute force, port/protocol mismatch |
| **Encrypted-traffic analysis** | emits JA3/JA4 | Cernity turns those fingerprints into detections (rarity, known-bad matching) and extracts the **full JA4+ suite** (JA4S/JA4H/JA4X/JA4SSH) on captured flows via `zeek-central` — visibility *without* decryption |
| **Lateral movement (east-west)** | logs SMB/RDP/Kerberos | `east-west-detectors` — SMB/RDP/DCE-RPC fan-out, Kerberoasting, internal scanning |
| **Application-risk (nDPI)** | optional plugin | `behavioral-detectors` consumes Suricata's nDPI `flow_risk` verdict (malicious JA3/JA4, DGA, cleartext creds, bad TLS) as a detection input |
| **IoC / threat-intel matching** | ❌ | `threat-intel` matches live traffic against abuse.ch blocklists (C2 IPs, malicious certs, bad JA3) |

Both **east-west (internal)** and **north-south (routed)** traffic are covered — the
behavioral and protocol detectors watch north-south; the east-west detectors watch
lateral movement.

> **Honest boundary — detection is heuristic/statistical, not ML.** Cernity's methods are
> threshold-, rarity-, and entropy-based (the proven RITA/Zeek approach), which makes them
> **explainable by construction**. Cernity does *not* currently ship machine-learning
> baseline models. ML-based behavioral detection is a deliberate future track, not a
> shipped capability.

---

## Explainable findings with evidence

**NDR findings must be transparent — an analyst has to see *why*.**

Suricata gives you an alert. Cernity gives you an **explained finding**: `finding-service`
attaches **MITRE ATT&CK** technique tags, the involved **entities**, the **detection math**
that fired it (e.g. a beacon's exact interval, jitter, and connection count), and an
**enrichment block** — GeoIP/ASN, reverse DNS, domain age / newly-registered-domain flag,
JA3/JA4 fingerprint names, and optional IP reputation (VirusTotal / GreyNoise). When a
finding is worth proving, Cernity fetches the **actual packets** on demand (the
`capture-agent` → `zeek-central` loop) and carves files — evidence, not just an assertion.

---

## High-fidelity response triggers (noise reduction)

**NDR must send the SIEM *findings*, not a firehose of raw events.**

This is Cernity's core thesis:

> **Raw network telemetry is analytics input. Security findings are SIEM input.**

`finding-service` de-duplicates candidates (a beacon seen 500 times becomes *one*
finding), gates severity by how hostile the destination looks (`gated_severity` +
fleet-prevalence), and applies a **delivery-suppression ceiling** so low-severity,
un-anchored findings are kept for correlation but never delivered to the analyst plane.
The result is a small stream of high-fidelity, ready-to-act findings — the opposite of
alert fatigue.

---

## Network forensics & retention (historical investigation)

**NDR must let you investigate the past.**

Suricata's telemetry is ephemeral. Cernity retains it: `normalizer` writes typed rows to
**ClickHouse** for hunting and pivoting ("show me everything this host did"), captured
**pcaps and carved files** live in **MinIO**, `correlation-service` links related findings
into a kill-chain, and `reconstruction` builds a per-host timeline and entity graph.

---

## Automated response & integration

**NDR must be able to act, and fit your stack.**

`soar-forwarder` runs response playbooks on final findings and can notify or drive a SOAR
(TheHive, Shuffle, n8n). `findings-forwarder` delivers findings to **your SIEM** through a
pluggable adapter — Elasticsearch/OpenSearch, Splunk, Devo, syslog/CEF, or webhook — and
can **fan out to several at once**.

---

## Openness & extensibility

**NDR should be open, not a black box.**

Cernity is **broker-agnostic** (anything speaking the Kafka API), its `contracts/` JSON
schemas are the public interface for writing your own producers/consumers, its SIEM
adapters and threat-intel/fingerprint sources are pluggable, and it is **source-available**
(PolyForm Perimeter) — you can read, audit, and extend every detector.

---

## Complete data sovereignty

**NDR should keep your data yours.**

Cernity is **100% self-hosted** — no SaaS, no cloud dependency, no phone-home. Enrichment
runs offline where possible (GeoIP from mounted MaxMind DBs), and the online reputation
lookups are **opt-in and external-IP-only** (internal addresses are never sent to a third
party). You own the ClickHouse store, the MinIO pcaps, and every finding.

---

## What Cernity deliberately leaves to your stack

Being honest about the seams keeps the architecture clean:

- **The analyst console & guided threat-hunting UI** — Cernity is a *findings engine*, not
  a UI platform. It provides the **hunting substrate** (queryable ClickHouse telemetry,
  correlation, reconstruction) and delivers findings **into your SIEM**, which is where the
  dashboards, hunting queries, and case management live.
- **Deep packet inspection is tiered, by design** — DPI happens at the **edge** (Suricata +
  nDPI) and **on demand** (`zeek-central` over captured pcaps), never continuously in the
  center. That is the whole point of the tiered model: inspect once at line rate, ship
  lightweight telemetry, analyze centrally on hardware that has room for it.
- **Not in scope:** machine-learning baseline models (a future track) and network
  vulnerability scanning (Cernity detects behavior and threats, it does not assess CVEs).

---

## In one sentence

**Suricata sees the packets; Cernity turns what it sees into remembered, explained,
prioritized, self-hosted NDR findings — the analytics, correlation, enrichment, and
response tier a standalone IDS doesn't have.**
