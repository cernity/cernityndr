# How Cernity works

This explains the whole system in plain language — the idea, the pieces, and how a
packet on the wire becomes a security finding in your SIEM. No prior knowledge of
the internals is assumed. If you just want to run it, see the README quickstart; if
you want to understand it, read on.

---

## 1. The problem it solves

You have Suricata sensors watching network traffic. Suricata is good at inspecting
packets and matching known-bad signatures, but a lot of real attacks don't trip a
signature — they show up as *patterns over time*: a host calling home every 60
seconds (command-and-control beaconing), a slow trickle of data leaving the network
(exfiltration), thousands of odd DNS lookups (tunneling), one machine reaching out to
many others (lateral movement).

Catching those patterns needs **stateful analysis** — you have to remember what a
host did over the last ten minutes and do math on it. Tools like Zeek and RITA do
this, but running them *on the sensor* is expensive: they compete with Suricata for
CPU and memory, and at fleet scale they produce far more data than a SIEM can afford.

**Cernity's answer:** inspect packets once, at the edge, with Suricata. Ship only the
lightweight *telemetry* (not the packets) to a central place. Do all the heavy,
stateful analysis there, on hardware that has room for it. Send **findings** — "this
looks like C2" — to your SIEM, not raw logs.

> The rule everything follows: **raw network telemetry is analytics input; security
> findings are SIEM input.** Telemetry stops at Cernity. Only findings go onward.

---

## 2. The shape of it: three tiers

```
   Sensor (per Suricata box)        Central (Cernity)              Your SIEM
   ------------------------         -----------------              ---------
   Suricata  ->  eve logs  ->       message bus  ->  detectors ->  findings out
                 shipper            (Redpanda)       finding-svc   (Devo, Splunk,
   (optional) capture-agent  <----- capture loop ->  Zeek         Elastic, syslog…)
```

- **Sensor tier** — your Suricata box plus a tiny log *shipper*. No analysis happens
  here. It just produces logs and forwards them. Optionally a small *capture-agent*
  grabs packets on demand (explained later).
- **Central tier** — a set of small, single-job services connected by a message bus.
  This is where detection happens.
- **Your SIEM** — Cernity delivers findings to it and stops there.

Each central service does one thing, reads from the bus, and writes back to the bus.
That's what lets you run many copies of a busy service to handle more load.

---

## 3. The message bus, and why everything is keyed by source IP

The central services don't call each other directly. They pass messages through a
**bus** (Redpanda, which speaks the Kafka protocol). A service *subscribes* to a
topic (a named stream, e.g. `suricata.flow.v1`) and *publishes* to another
(e.g. `ndr.finding.candidate.v1`).

Two properties matter:

- **Topics are split into partitions.** A partition is a lane. More lanes = more
  copies of a service can work in parallel (one copy per lane). This is the knob you
  turn to scale.
- **Every record is keyed by the source IP.** The bus guarantees all records with the
  same key land on the same partition, in order. So *one host's whole story stays
  together on one lane* — which is exactly what stateful, per-host detection needs.

The message shapes are pinned in `contracts/` (JSON schemas + the topic list). That
folder is Cernity's public interface: if you write your own producer or consumer, you
build against those schemas.

---

## 4. From packet to finding, step by step

1. **Suricata** inspects packets and writes **EVE** logs (JSON, one event per line) —
   flows, DNS, TLS, HTTP, alerts, and so on. See `docs/suricata-config.md`.
2. The **shipper** (Fluent Bit) tails those logs, routes each event to its topic by
   type (`flow` → `suricata.flow.v1`, `dns` → `suricata.dns.v1`, …), keys it by source
   IP, and sends it to the bus. It does no analysis.
3. The **detectors** read those topics, keep rolling per-host windows, and when a
   pattern crosses a threshold they publish a **candidate finding**.
4. **finding-service** takes candidates, removes duplicates, tags them with MITRE
   ATT&CK techniques, decides whether packet-level proof is worth fetching, and
   publishes a **final finding**.
5. **findings-forwarder** delivers final findings to your SIEM.

Everything after step 2 is central. The sensor only did steps 1–2.

---

## 5. The pieces, explained

Each of these is a small container that reads from the bus and writes back to it.

### Ingestion
- **shipper (Fluent Bit)** — *on the sensor.* Tails Suricata's split EVE files, maps
  each event type to its topic, keys by source IP, ships to the bus. Replaceable with
  Filebeat/Vector; any Kafka-API shipper works.
- **normalizer** — reads the raw telemetry topics and writes typed rows into
  ClickHouse for retention and hunting. (Optional; only needed if you keep telemetry.)
- **ids-alerts** — turns Suricata's own signature alerts into finding candidates, so
  signature hits and behavioral detections flow through the same pipeline.

### Detectors (the analysis)
Each keeps rolling per-host windows (default 10 minutes, re-scored every 30 seconds)
and publishes candidates when something looks wrong.
- **behavioral-detectors** — the core. Beaconing (a host calling home at a suspiciously
  regular interval), data exfiltration (outbound byte volume), DNS tunneling (query
  volume and randomness), long connections, "first time I've seen this host talk to
  that destination," and a fleet-prevalence check that raises the priority of
  destinations almost nobody else contacts. The regularity math follows RITA's method.
- **dns-detector** — DNS-specific signals: bursts of failed lookups (NXDOMAIN) and
  tunneling fingerprints.
- **http-detector** — anomalies in HTTP traffic.
- **protocol-detectors** — TLS/certificate oddities (self-signed, very short-lived,
  rare fingerprints), DNS-over-HTTPS to unapproved resolvers, SSH brute force,
  port/protocol mismatch, and domain-fronting (ECH usage or a cleartext HTTP Host
  that disagrees with the flow's TLS SNI).
- **east-west-detectors** — internal-to-internal traffic that looks like an attacker
  spreading between machines: SMB/RDP/DCE-RPC/Kerberos fan-out, internal scanning,
  **password spraying** (one source failing auth across many accounts), **AS-REP
  roasting**, **ransomware over SMB** (a write-heavy file flood across many shares),
  **remote-exec lateral movement** (PsExec/WMI/scheduled-task named pipes), and
  **LLMNR/mDNS poisoning** (a Responder-style host answering many names it doesn't own).
  These need east-west Windows/AD traffic to fire, so they stay quiet on a flat network
  with none — to see them work, replay the bundled attack fixture (below).
- **anomaly-detector** — statistical outliers over the flow telemetry.
- **coverage-detector** — a health signal: is the sensor actually mirroring the traffic
  we expect to see? Silence can mean a blind spot, not safety.
- **threat-intel** — matches live traffic against abuse.ch blocklists (known C2 IPs,
  bad TLS certificates, malicious JA3 fingerprints) plus an operator-supplied
  known-C2 **server-fingerprint** list (JA3S/JA4S/JARM — e.g. Cobalt Strike, Sliver).

### Findings lifecycle
- **finding-service** — the brain of the output. De-duplicates candidates (the same
  beacon seen repeatedly becomes one finding), tags MITRE techniques, **enriches** the
  finding (GeoIP/ASN and community-ID always; optionally reverse-DNS, domain age /
  newly-registered-domain, fingerprint naming, and IP reputation — see
  `docs/enrichment.md`), and emits the **final** finding. A confirmed threat (an IDS
  signature, threat-intel hit, or known-bad file hash) is **delivered to your SIEM
  immediately** — if packets are also worth fetching, the capture loop *enriches* that
  finding later with the evidence; it never withholds delivery waiting on capture, so a
  confirmed threat reaches you even when the optional forensics overlay isn't deployed.
  Every capture-bound finding is finalized on the capture result, a refusal, or a
  timeout — nothing is left dangling. Optionally records findings in ClickHouse.
- **findings-forwarder** — the exit. Delivers final findings to your SIEM through a
  pluggable adapter (Devo, Splunk, Elasticsearch/OpenSearch, syslog/CEF, webhook, or a
  file), or several at once. Delivery is durable: each sink retries then dead-letters on
  a SIEM outage (never a silent drop), offsets commit only after delivery (at-least-once),
  and duplicates are dropped by finding id. See `docs/siem-integrations.md`.
- **correlation-service** — links related findings together (reads ClickHouse).
- **asset-service** — keeps an inventory of hosts and whether they're internal or
  external, which several detectors use for context.

### Optional: on-demand packet forensics (the Zeek loop)
Most detection needs only telemetry. Sometimes you want the actual packets — to prove
a finding or carve a file. Cernity fetches packets *only when it's worth it*, and only
for the one connection involved. This loop **enriches** a finding (attaching evidence);
for a confirmed threat the finding is already on your SIEM before the capture runs:
- **finding-service** decides a finding warrants packets and sends a **capture request**
  carrying the sensor identity and the exact value to capture.
- **capture-orchestrator** — *central.* Checks safety limits (is the sensor healthy,
  are we within budget) and, if allowed, sends an **arm** instruction to the sensor.
- **capture-agent** — *on the sensor.* Receives the arm instruction over the bus (no
  inbound access needed), tells the local Suricata to write a small packet capture for
  that one connection, and uploads it to central object storage. It does no packet
  inspection itself — the packets only exist on the sensor, so the fetch has to happen
  there. This is why it runs on the sensor; see the note below.
- **zeek-central** — *central.* Runs Zeek over the uploaded capture (offline, on demand)
  to extract deep protocol detail, files, and certificates.
- **zeek-notice** — turns Zeek's findings into finding candidates.
- **reconstruction** — builds a timeline and entity graph for a host from stored data.
- **file-threat / file-yara** — when Suricata carves a file out of the stream, these
  hash-check it and scan it with YARA rules to catch malware with no known hash.

> **Why capture-agent is on the sensor and not central:** the raw packets only exist
> where Suricata is sniffing them — on the sensor. Central Cernity only ever has
> *telemetry*. So when central decides it wants packets, it sends a *request back to
> the sensor*, and the agent (which is the only thing that can see those packets) grabs
> them. Central decides *when*; only the sensor *can* capture.

### Response
- **soar-forwarder** — runs automated response playbooks on final findings and can
  notify or call a SOAR (TheHive, Shuffle, n8n).

### Streaming detectors (optional)
- **flink** — the same scan-detection and session-stitching logic expressed as Flink
  SQL, for teams that prefer a streaming-SQL engine. The Python detectors cover the
  core without it.

### ntop integration (optional)
- **nDPI** — build Suricata with ntop's nDPI plugin and its flow-risk verdict
  (`ndpi.flow_risk`: malicious JA3/JA4, DGA, cleartext creds, bad TLS…) flows into the
  behavioral detector automatically. The single highest-value edge add-on; see
  `docs/suricata-config.md`.
- **PF_RING (ZC)** — ntop's kernel-bypass capture for line-rate (10 Gbps+) sensors.

---

## 6. Where state and data live

- **Redis** — the detectors' short-term memory. Each host's rolling window (call-back
  times, byte counters, seen-destinations) lives here with a time-to-live so it can't
  grow forever. Because the state is shared in Redis and keyed by the host (not by
  which copy of the service handled it), you can run many copies of a detector and any
  copy can handle any host correctly.
- **ClickHouse** *(optional)* — long-ish retention of telemetry and findings, for
  hunting and pivoting ("show me everything this host did").
- **MinIO** *(optional)* — object storage for the on-demand packet captures and carved
  files.

Findings themselves are the durable output and go to your SIEM; the raw telemetry is
kept only as long as you choose (short by default).

---

## 7. How you run it, and how it scales

Three deployment paths, same architecture (details in the README and
`deploy/scale/README.md`):

- **Single host** (Docker Compose) — evaluation and small sites.
- **Manual multi-server** (Compose, no orchestration) — put the bus/state/storage on
  one or more hosts, run detector copies on others, scale by setting replica counts.
- **Kubernetes** (Helm) — detectors as autoscaled Deployments.

Scaling in one sentence: **more partitions on a topic let you run more copies of the
detectors that read it, and each copy takes a share of the partitions.** For a large
fleet you cluster the bus/state/storage, give the busy topics plenty of partitions,
and add detector copies until consumer-group *lag* stops rising.

The sensor side scales by itself — every sensor runs its own shipper (and optional
agent), self-arming over the bus, with no central coordinator holding keys.

---

## 8. Configuration and observability

- **Everything is set through one file** (`.env`, copied from `cernity.env.example`):
  bus address, tenant name, state backend, findings sink, ClickHouse, log level. No
  editing compose files or code for a normal deployment.
- **Logging** is a health signal, not a firehose: services log startup and periodic
  activity at INFO (per-event detail is DEBUG), and container logs are size-capped so
  they can't fill a disk.
- Each service exposes Prometheus metrics and health endpoints.

---

## 9. What Cernity is and isn't

- It **is** the central analytics tier: it turns Suricata telemetry into findings and
  hands them to your SIEM.
- It **does not** ship a SIEM, replace Suricata, or run detection on your sensors.
- It reproduces Zeek/RITA-style behavioral analysis centrally; on real traffic, the
  optional Zeek loop is mostly *forensic depth* (packet-level proof, file carving),
  not additional detections — so treat it as enrichment you turn on when you want it.
- Put another way: **Cernity is the add-on that completes Suricata into a full NDR** —
  the analytics, correlation, enrichment, prioritization, and response tier a standalone
  IDS doesn't have. See `docs/ndr-coverage.md` for how each NDR capability area is covered
  (and the honest boundaries — no ML models, no vuln scanning, console delegated to your SIEM).

For configuring Suricata, deploying the sensor, and wiring your SIEM, see the other
files in `docs/`.
