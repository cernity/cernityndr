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
- **The bus is trust-sensitive.** Restrict access to Redpanda/Kafka; in production use
  authentication and TLS between sensors, workers, and the bus.
- **Secrets** (SIEM tokens, ES/Devo credentials, Docker registry auth) are supplied via
  environment/secret managers, never committed. Rotate them if exposed.
- **TLS verification** is on by default for sink adapters. The `*_TLS_VERIFY=false`
  options exist only for internal/self-signed CAs — prefer adding your CA to the trust
  store over disabling verification.
- **Least privilege** — service containers run as an unprivileged user with dropped
  capabilities where possible. The sensor-side capture-agent needs access to Suricata's
  local socket and capture directory by design; nothing requires inbound network access
  to a sensor (it self-arms over the bus).

## Supported versions

Cernity is pre-1.0 and evolving; security fixes target the latest `main` and the most
recent published images.
