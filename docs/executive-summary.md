# Cernity — Executive Summary

## In one sentence

**Cernity is a central analytics tier that extends a Suricata sensor toward a full Network
Detection & Response (NDR) posture** — a source-available service that consumes a sensor's raw
telemetry, performs the central, cross-host, long-window behavioral analysis an edge sensor is
not built to do, and delivers a stream of enriched, prioritized, ATT&CK-tagged **security
findings** to an existing SIEM.

> **Scope note (post-audit):** an [independent audit](cernity-independent-audit.md) verified the
> core analytics path but found the confirmed-threat finalization loop, fleet trust boundary,
> and several deployment paths incomplete. This summary describes the **intended, largely-built
> architecture**; see the [audit response](audit-response.md) for what is verified today versus
> on the v0.4 remediation roadmap.

The governing principle the whole architecture is built around:

> **Raw network telemetry is analytics input. Security findings are SIEM input.**

---

## The problem

Suricata is a world-class **edge IDS**: it inspects packets at line rate and emits signature
alerts plus rich EVE telemetry (flow, DNS, TLS, HTTP, SMB, Kerberos, files, JA3/JA4). But an IDS
is not an NDR, and the gap is three distinct, compounding problems:

1. **The capability gap — no central, cross-host behavioral memory.** Suricata has flow state,
   flowbits, and cross-flow tracking, but those are edge- and rule-scoped. It is not built to
   hold rolling per-host windows across the whole network and reason over behaviors that unfold
   over time and across entities: a host beaconing every 60 seconds for ten minutes, one source
   touching 40 internal hosts on port 445 (lateral spread), or a workstation dribbling gigabytes
   out across a hundred small connections (low-and-slow exfil). That central behavioral analysis
   is exactly what operators historically bolt on with **Zeek + RITA**.

2. **The firehose problem — alerts are not answers.** A tuned Suricata on a busy link emits a
   torrent of events and signature alerts. An analyst drowning in a firehose is not more secure.
   A SOC needs a *small* number of *high-fidelity, explainable, ready-to-act* findings.

3. **The placement/scale problem — you cannot do this on the sensor.** Running Zeek/RITA-style
   stateful analysis on the sensor forces the box that must inspect packets at line rate to also
   hold rolling per-host windows and run correlation, competing for the CPU/RAM it needs for
   capture — and a single stateful box cannot serve a fleet of a thousand sensors.

Cernity's thesis: these problems share one solution — **move the stateful analysis off the edge
into a horizontally-scalable central tier, and change the output from a firehose of events into
a curated stream of findings.**

---

## The architecture — a tiered pipeline

```
SENSOR (unchanged)          CENTRAL (Cernity)                              YOUR SIEM
Suricata ─EVE─► Fluent Bit ─► Redpanda bus ─► single-job detectors ─► finding-service ─► findings-forwarder ─► Splunk/Elastic/…
              (tiny shipper)   (Kafka API)     behavioral · dns · http ·   (lifecycle,       (pluggable adapters,
                                                protocol · east-west ·       dedup, gating,    fan-out)
                                                anomaly · threat-intel        MITRE, enrich)
```

The design choices are the substance:

- **The sensor stays light.** It runs stock Suricata plus a tiny Fluent Bit shipper that tails
  EVE and forwards it. No detection logic on the edge — keeping load off the sensor is
  architectural, not aspirational.
- **A Kafka-API message bus (Redpanda) is the spine.** Detectors are **stateless consumer-group
  workers**; add replicas, partition the high-volume topics, and throughput scales. The same
  code runs on a single Docker host or a large Kubernetes fleet. Being Kafka-API keeps it
  broker-agnostic (Redpanda bundled; Apache Kafka, MSK, Confluent, Aiven all work).
- **~25 small single-job services.** Each detector does one thing. State (rolling windows) is
  externalized to **Redis** with a stable cross-process dedup hash and partition-tagged keys, so
  N replicas of a detector never double-emit — the difference between scaling in theory and in
  practice.
- **Detection logic is pure functions** (`detectors.py`, `ew.py`, `proto.py`), unit-tested as a
  **Docker build gate** (a failing test fails the image build); the I/O shell (`app.py`) only
  does Kafka + Redis. This keeps the engine auditable and its behavior provable.

---

## How detection works

The behavioral core reimplements **RITA's** published methods rather than naive thresholds:

- **Beaconing** uses **Bowley skewness** and **median absolute deviation** on inter-arrival
  intervals — outlier-robust statistics that survive *jitter* — plus **strobe** detection and
  **DNS tunneling** via exploded-subdomain entropy. Domain-aggregated (IP-rotating) beaconing is
  implemented but under active correctness work (a CDN-exclusion filter currently suppresses it —
  see the audit response).
- **East-west (AD/lateral):** internal scanning (horizontal/vertical), lateral & RDP fan-out,
  **kerberoasting** (distinct SPNs + RC4 downgrade), **AS-REP roasting**, **password spraying**
  (one source → many accounts, the inverse of brute force), **ransomware-over-SMB** (write-heavy
  file flood), **PsExec/WMI/scheduled-task lateral-exec** (named-pipe/DCERPC signatures), and
  **LLMNR/mDNS poisoning** (a Responder-style host answering names it does not own).
- **Protocol / encrypted traffic:** **JA4/JA3 fingerprint rarity** (fleet-wide seen-set),
  server-fingerprint rarity, TLS cert anomalies, DoH to unapproved resolvers, cloud-staging
  exfil, port/protocol mismatch, and reframed domain-fronting (ECH usage or cleartext `Host` ≠
  TLS `SNI`).
- **Threat intel:** abuse.ch feeds (Feodo C2 IPs, SSLBL certs, malicious JA3) plus an
  operator-supplied known-C2 **server-fingerprint** blocklist (JA3S/JA4S/JARM — e.g. Cobalt
  Strike, Sliver).

Detection is **heuristic and explainable** by default — findings carry the detection math the
detector produced, and Cernity does not claim ML it cannot back. ML is an **opt-in** layer via a
**SLIPS** sidecar (the recognized Suricata + Zeek + SLIPS ensemble). SLIPS's per-module
provenance is not yet carried through, so the current "ML × heuristic corroboration" is better
read as "SLIPS-verdict × heuristic" until that provenance is preserved (audit F12).

---

## The findings lifecycle — the firehose becomes findings

`finding-service` runs a lifecycle state machine, the core differentiator over "just point
Suricata at your SIEM":

`CANDIDATE → enrichment decision → severity/suppression gate → FINAL → delivered`

- **Enrichment routing:** structural detections answerable from metadata finalize directly;
  ambiguous *content* findings are designed to trigger **on-demand bounded packet capture** for
  adjudication — the `capture-agent` self-arms over the bus (no inbound socket on the sensor),
  grabs a bounded PCAP, and hands it to a central Zeek. **The finalize back-half of this loop is
  not yet closed at runtime** (audit F01, the top v0.4 priority): confirmed-threat findings
  currently route to capture but no service consumes the enrichment result to complete them, so
  they must be finalized-with-pending-evidence before this path is production-ready.
- **Suppression gate:** low-severity, non-threat-anchored findings are kept in the store for
  correlation but **not delivered** to the analyst — the mechanism that makes the output a
  stream of findings, not a re-labeled firehose.
- **Enrichment:** GeoIP/ASN (offline), reverse-DNS, RDAP domain-age / newly-registered-domain
  flagging, and IP reputation (GreyNoise/VirusTotal) — **external-IP-only**, never leaking
  internal addresses to third parties.
- **MITRE ATT&CK** where defensible, with detectors emitting precise sub-techniques that
  override the coarse category map (some categories have no technique fallback yet).
- **Correlation:** time-decayed per-entity risk (deduped per detector so one chatty detector
  cannot inflate it) plus **kill-chain progression** across ATT&CK stages, turning scattered
  findings into a single narrated incident.

---

## Deployment, scale, and security

- **Three paths, one architecture:** single-host Compose → manual multi-server → Kubernetes
  (Helm). The same stateless-worker model scales all three.
- **Emit-only and pluggable:** Cernity ships **no SIEM** — it forwards findings to yours via
  adapters (Elasticsearch/OpenSearch, Splunk HEC, syslog/CEF, webhook, Devo, file), with
  comma-list **fan-out**. The console, dashboards, and case management are deliberately the
  SIEM's job.
- **Secure by default (central Compose):** the external bus listener uses **SASL/SCRAM-SHA-512
  over TLS** out of the box (an unauthenticated client is refused); the internal listener stays
  plaintext on the private network for the central services; containers are hardened
  (`cap_drop: ALL`, `no-new-privileges`, read-only root). Extending this to the scale/Helm paths,
  and replacing the current shared-superuser sensor credential with per-sensor produce-only ACLs,
  is on the v0.4 roadmap (audit F02/F03).

---

## What makes it credible

- **Honest about its boundaries.** The docs disclose the intentional non-goals — heuristic (not
  ML) by default, no vulnerability/CVE scanning, tiered DPI, and the analyst console being the
  SIEM's job. An independent audit confirmed those boundaries are disclosed, not defects; it also
  found real gaps between some claims and the code, tracked in the [audit response](audit-response.md).
- **Inspectable, and being made provable.** The engine is pure-function + build-gated, and a
  Docker e2e replays a beacon end-to-end to the sink. A **Suricata-vs-Cernity benchmark harness**
  (with a Zeek reference arm) exists and its report always includes a "where Cernity does *not*
  add value" section — but it is a **smoke harness today**, not yet a scored accuracy measurement
  (audit F10); accuracy/noise claims are on the roadmap, not asserted.
- **Source-available and sovereign.** Licensed under **PolyForm Perimeter 1.0.1**: run, modify,
  self-host, and redistribute freely — the restriction is on providing it as a competing product
  (note: broader than "cannot resell"). Self-hosted with **no vendor telemetry**; the only
  outbound calls are opt-in threat-feed and enrichment lookups.

---

## The name

**Cernity** — from the Latin *cernere*, "to sift, separate, **discern**." That is precisely what
an NDR does: sift a flood of network telemetry and discern the real threats from the noise.

---

## Bottom line

Suricata gives you eyes at the edge; **Cernity adds the central memory, judgment, and
prioritization that turn seeing into knowing** — without loading the sensor and without locking
you into a vendor SIEM. The foundation is real and inspectable: genuine RITA-derived statistics,
a pure-function build-gated engine, working central hardening, and a verified beacon-to-sink
path. It is **not yet an operationally-validated, fleet-scale NDR** — the confirmed-threat
finalization loop, the per-sensor trust boundary, and the non-central deployment paths are the
[roadmap](audit-response.md). This document describes the intended system honestly, including
where it is not there yet.
