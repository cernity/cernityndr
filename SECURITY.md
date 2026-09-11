# Security Policy

Cernity is defensive security software that processes network telemetry and produces
findings. We take its security seriously.

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities. Instead, report
privately via GitHub's **Security Advisories** ("Report a vulnerability" on the
repository's Security tab), or open a minimal issue asking for a private contact and
we will follow up.

Include, where possible: affected component/version, a description, reproduction
steps, and impact. We aim to acknowledge reports promptly and coordinate a fix and
disclosure timeline with you.

## Deployment hardening notes

- **Findings only leave Cernity** — raw telemetry stays in the analytics tier. Keep
  ClickHouse/MinIO/Redis on a trusted network; do not expose them publicly.
- **The bus is trust-sensitive — authenticated and authorized by default.** Both Redpanda
  listeners require **SASL/SCRAM-SHA-512** and `kafka_enable_authorization` is enforced: the
  external listener (`:19092`, remote sensors) is SASL over TLS; the internal listener
  (`redpanda:9092`) is SASL over plaintext on the private Docker network (keep that network
  private). Three separate principals mean **no component holds another's blast radius**: the
  **sensor** credential is **produce-only** on `suricata.*` (it cannot forge `ndr.finding.final.v1`,
  read other topics, or alter cluster config), while central-only **pipeline** and **admin**
  superuser credentials never leave the central host. Generate all three + certs with
  `deploy/security/gen-bus-certs.sh`; `deploy/security/test_bus_acls.sh` proves the confinement
  against a real broker. `CERNITY_INSECURE_BUS=1` (plus `CERNITY_BUS_CENTRAL_MECHANISM=`) drops
  both listeners to plaintext for throwaway demos only (it warns loudly); never on an untrusted
  network.
- **Secrets** (SIEM tokens, ES/Devo credentials, Docker registry auth) are supplied via
  environment/secret managers, never committed. Rotate them if exposed.
- **TLS verification** is on by default for sink adapters. The `*_TLS_VERIFY=false`
  options exist only for internal/self-signed CAs — prefer adding your CA to the trust
  store over disabling verification.
- **Least privilege** — service containers run as an unprivileged user (`USER nobody`), and
  the compose files harden them: Cernity's own services run with `cap_drop: ALL`,
  `no-new-privileges`, and a read-only root filesystem (writable paths are explicit tmpfs or
  named volumes); infra containers get `no-new-privileges`. The sensor-side capture-agent needs
  access to Suricata's local socket and capture directory by design; nothing requires inbound
  network access to a sensor (it self-arms over the bus). It authenticates to the bus with the
  **produce-only sensor credential** (never a superuser) and uses a **least-privilege object-store
  key** — scoped to `PutObject` on the `ndr-pcap`/`ndr-files` buckets, not the MinIO root key.

## Supported versions

Cernity is pre-1.0 and evolving; security fixes target the latest `main` and the most
recent published images.
