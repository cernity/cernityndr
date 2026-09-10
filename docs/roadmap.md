# Roadmap — where Cernity is going

Cernity is early and moving fast. This page is an **honest** forward view: what's actively
being built, what's on the radar (often tracking upstream Suricata/Zeek releases), and what
is deliberately *not* planned. Items here are directional, not promises — the honest label
matters more than the hype.

Legend: **Building** = in progress · **Next** = committed, not started · **Exploring** =
evaluating, may or may not happen.

---

## Detection coverage — closing MITRE gaps

Cernity is strong on C2/beaconing and DNS; the work now is breadth.

- **Building** — Discovery & evasion: internal scanning (horizontal/vertical), port/protocol
  mismatch, low-and-slow exfiltration, server-side fingerprint rarity.
- **Next** — Credential-access breadth: password spraying, AS-REP roasting (Kerberos
  telemetry is already parsed); Impact: ransomware-over-SMB (mass file-op bursts);
  Lateral-exec: PsExec / WMI / WinRM named-pipe patterns.
- **Exploring** — **Machine-learning behavioral detection.** Cernity's detectors are
  heuristic and explainable today (the honest current gap vs ML-heavy NDRs). A future ML
  track — anomaly/sequence models to complement, not replace, the heuristics — mirrors the
  recognized *Suricata + Zeek + SLIPS* ensemble pattern. This is the single biggest planned
  capability, and the hardest.

---

## Tracking upstream — Suricata 9 and Zeek 9

Cernity's detection surface grows automatically as the sensors it feeds on get richer.

**Suricata 9** (in development; stable is 8.0.x). Its theme is **protocol keyword/output
parity** — exposing far more of MIME/email, SMTP, LDAP, FTP, and DNS in EVE telemetry.

- **Next / Exploring** — new detectors that light up as those fields land: **email/SMTP-based
  exfil and phishing-infrastructure**, **LDAP reconnaissance**, **FTP anomalies**. More
  telemetry fields = more behavioral detectors, with no change to the tiered architecture.
- **Note** — pin **nDPI 4.14** for now; nDPI 5.0 does not yet build against Suricata (see
  [suricata-config.md](suricata-config.md)). We'll adopt it when upstream catches up.

**Zeek 9.0** (LTS, expected summer 2026; 8.2 shipped May 2026). Relevant to the on-demand
`zeek-central` forensics loop.

- **Exploring** — adopt Zeek 9 in `zeek-central` for: **extensible flow tuples**
  (VLAN/VXLAN/Geneve context — better flow disambiguation in segmented and cloud/overlay
  networks); the new **Redis protocol analyzer** (a fresh lateral-movement / data-access
  detector surface); and **encrypted, authenticated ZeroMQ clustering** (a reference for
  hardening Cernity's own bus).

---

## Integrations & enrichment

- **Building** — enrichment depth (GeoIP/ASN, reverse DNS, domain age / NRD, IP reputation,
  fingerprint naming).
- **Exploring** — **threat-intel platform integration** (MISP / OpenCTI feeds, beyond the
  built-in abuse.ch matching); **Sigma rule support** (a standard detection-rule format);
  a **full-PCAP forensics handoff** (e.g. Arkime) for regulated SOCs that need a DORA/NIS2
  evidence trail — Cernity's on-demand capture pivots into the full-capture store.

---

## Platform & operability

- **Building** — turnkey onboarding (see [getting-started.md](getting-started.md)),
  structured logging/health, multi-arch images.
- **Next** — bus hardening (authentication/TLS on the external listener), a Grafana/Prometheus
  observability bundle over the real metric names.
- **Exploring** — a queryable flow/telemetry dashboard over ClickHouse (the scalable,
  Cernity-native flow-visualization answer — see the design notes on why single-node
  flow-console tools don't fit a 1000-sensor fleet).

---

## Deliberately *not* planned

These are intentional scope choices, not gaps to close (see
[ndr-coverage.md](ndr-coverage.md)):

- **A SIEM or analyst console** — Cernity is a *findings engine*; the console, dashboards,
  and case management live in your SIEM.
- **Continuous central deep-packet inspection** — DPI stays at the edge (Suricata + nDPI)
  and on-demand (Zeek). The tiered model is the point.
- **Network vulnerability scanning** — Cernity detects behavior and threats, not CVEs.

---

*Want something moved up, or have a detector idea? Open an issue — the detector framework is
designed to be extended (see [development.md](development.md)).*
