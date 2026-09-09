# Cernity

**Central network detection and response (NDR) analytics for Suricata sensors.**

Cernity is the middle tier of a tiered NDR architecture. Suricata inspects packets
at the edge and emits telemetry; Cernity does the heavy, stateful analysis
centrally — behavioral detection (beaconing, exfiltration, DNS tunneling, long
connections, rare destinations), protocol anomalies, lateral movement, threat-intel
matching, and optional on-demand packet forensics — and emits **security findings**
to your existing SIEM.

The governing principle:

> **Raw network telemetry is analytics input. Security findings are SIEM input.**

Cernity reimplements the stateful, Zeek/RITA-style analysis that people usually run
at the edge, and moves it to a central box with CPU and memory to spare — so the
sensor keeps inspecting packets at line rate instead of competing for resources.

> **Status:** early. The engine has run in production against live traffic and is
> being packaged into this repository. Code and deployment docs land incrementally.

## How it fits together

```text
                SENSOR (per Suricata box)          CENTRAL (Cernity)                 YOUR SIEM
                ------------------------            ------------------                ---------
  packets ─▶ Suricata ─▶ eve-*.json ─▶ Fluent Bit ─▶ bus (Redpanda) ─▶ normalizer ─▶ detectors ─▶ finding-service
                              │                                                                        │
                     (optional) cernity-capture-agent ◀── on-demand packet capture ──┐                │
                              │                                                        │                ▼
                              └──▶ bounded PCAP ─▶ object store ─▶ central Zeek (enrichment) ─▶ findings-forwarder ─▶ OpenSearch / Splunk / webhook / syslog
```

- **On the sensor:** stock Suricata + a light log shipper (Fluent Bit), plus an
  optional `cernity-capture-agent` for on-demand packet forensics. No detection
  runs on the sensor — it only produces and forwards logs.
- **Central:** a set of small single-job services on a message bus, backed by
  Redpanda, Redis, ClickHouse, and object storage.
- **Output:** Cernity emits findings only. It does **not** ship a SIEM — it forwards
  findings to yours. OpenSearch is the documented reference; any SIEM is a config
  or adapter swap.

## What you bring

- A Suricata sensor (any deployment — containerized or bare-metal). Cernity ships a
  containerized reference sensor for evaluators, and a bind-mount mode for existing
  tuned sensors.
- A SIEM to receive findings (or use the emit-to-file / webhook adapters).

## Quickstart

_Coming as the extraction lands. The plan: one `docker compose up` brings up the
central stack with a replay feeder so you can see findings end to end without a live
sensor, then a documented Suricata config snippet points a real sensor at it._

## License — source-available, not open source

Cernity is licensed under the **[PolyForm Perimeter License 1.0.1](LICENSE)**.

In plain terms: you can do anything with Cernity — run it, modify it, self-host it,
redistribute it — except provide to others a product that competes with Cernity.
This is a source-available (Fair Source) license, not an OSI-approved open-source
license. The distinction is deliberate: it keeps Cernity free for every operator to
use however they want, while preventing a vendor from reselling it as their own
product.

- Run it on your own network, at any scale, for any purpose
- Modify it, fork it, build on it
- Redistribute it (with the license and required notice)
- Not permitted: selling or hosting it to others as a competing product or service

**Scope:** this license covers **only the Cernity Project's own original code** —
the Cernity services, detectors, contracts, shared libraries, and docs. It does
**not** cover the independent third-party software Cernity uses, bundles, or depends
on (Suricata, Zeek, Fluent Bit, Redpanda, Redis, ClickHouse, MinIO, OpenSearch,
Python libraries), each of which is governed by its own license. See
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

"Cernity" is a trademark of the Cernity Project — see [TRADEMARK.md](TRADEMARK.md).
Contributions are covered by [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

- Architecture overview — _coming_
- Suricata configuration guide — _coming_
- OpenSearch reference integration — _coming_
