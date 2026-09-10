# deploy/security — bus TLS certs + SCRAM credential

The external bus listener (`:19092`) is **SASL/SCRAM-SHA-512 over TLS** by default. This
directory holds the helper that produces the CA, broker server cert, and SCRAM password it
needs. Everything it writes lands in `deploy/security/secrets/`, which is **gitignored** —
never commit certs or passwords.

## Generate

```bash
CERNITY_ADVERTISE_HOST=<central-host-ip-or-dns> ./deploy/security/gen-bus-certs.sh
```

It prints the exact env to set on the central host and on each remote sensor. Regenerate with
`--force`.

## Bring your own

Prefer your own PKI? Drop these into `deploy/security/secrets/` and skip the script:

- `ca.crt` — the CA the sensors will trust
- `broker.crt` / `broker.key` — the Redpanda server cert (SAN must include the advertised host)
- `bus_user.txt` / `bus_password.txt` — the SCRAM-SHA-512 username / password

## Demo escape hatch

For a throwaway local demo with no certs, set `CERNITY_INSECURE_BUS=1` before bringing up
`deploy/central` — the external listener falls back to plaintext (today's pre-hardening
behavior) and logs a loud warning. **Never** use this on a network you don't fully trust.

## Rotation

Re-run with `--force`, redistribute `ca.crt` to the sensors, and restart the bus + shippers.
The SCRAM password is rotated the same way (update the central and sensor env).
