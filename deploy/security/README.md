# deploy/security — bus TLS certs + SCRAM credentials

The bus authenticates with **SASL/SCRAM-SHA-512** and authorization is **enforced** by
default: the internal listener (`redpanda:9092`) is SASL over plaintext on the private Docker
net, the external listener (`:19092`) is SASL over TLS for remote sensors. This directory holds
the helper that produces the CA, broker server cert, and the three SCRAM passwords it needs.
Everything it writes lands in `deploy/security/secrets/`, which is **gitignored** — never
commit certs or passwords.

## Three principals, three blast radii (F02)

A compromised sensor must not be able to forge findings or read another tenant's traffic, so no
credential is shared across trust boundaries:

| Principal | Where it lives | Rights |
|---|---|---|
| **sensor** (`cernity-sensor`) | every remote sensor | **produce-only** on `suricata.*` — cannot write `ndr.*`, cannot read, cannot alter config |
| **central** (`cernity-central`) | central host only | the trusted pipeline (detectors, finding-service, forwarder); superuser on the private net |
| **admin** (`cernity-admin`) | central host only | bootstrap / break-glass superuser |

The Redpanda entrypoint seeds these principals plus the sensor's produce-only ACL,
sets the superuser set to `[admin, central]`, then enables authorization. The optional
forensics overlay provisions a fourth, separate capture principal. See
[U1b apply and verification](../../docs/decisions/003-forensics-bus-acls.md).
`deploy/security/test_bus_acls.sh` now checks capture ACLs and metadata authorization
against an existing live broker; it does not create a disposable broker or prove
packet delivery. The clone gate is `deploy/security/test_forensics_config.py`.

## Generate

```bash
CERNITY_ADVERTISE_HOST=<central-host-ip-or-dns> ./deploy/security/gen-bus-certs.sh
```

It prints the exact env to set on the central host (all three credentials) and on each remote
sensor (only the produce-only one). Regenerate with `--force`.

## Bring your own

Prefer your own PKI? Drop these into `deploy/security/secrets/` and skip the script:

- `ca.crt` — the CA the sensors will trust
- `broker.crt` / `broker.key` — the Redpanda server cert (SAN must include the advertised host)
- `bus_user.txt` / `bus_password.txt` — the produce-only **sensor** SCRAM username / password
- `bus_central_password.txt` / `bus_admin_password.txt` — the central + admin SCRAM passwords

## Demo escape hatch

For a throwaway local demo with no certs, set `CERNITY_INSECURE_BUS=1` before bringing up
`deploy/central` — both listeners fall back to plaintext, unauthenticated, and it logs a loud
warning. Also set `CERNITY_BUS_CENTRAL_MECHANISM=` (empty) so the central services skip SASL.
**Never** use this on a network you don't fully trust.

## Rotation

Re-run with `--force`, redistribute `ca.crt` to the sensors, and restart the bus + shippers.
The SCRAM password is rotated the same way (update the central and sensor env).
