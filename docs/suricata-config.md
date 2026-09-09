# Configuring Suricata for Cernity

Cernity consumes Suricata's EVE output. You do not run any detection logic on the
sensor — Suricata produces telemetry, and the Cernity shipper (Fluent Bit) forwards
it to the central bus. This page shows the EVE configuration Cernity expects.

## Split the EVE output into two files

Cernity reads two files so alerts and network telemetry are shipped separately:

- `eve-alerts.json` — signature alerts
- `eve-nsm.json` — network-security-monitoring records (flow, dns, tls, http, ssh,
  fileinfo, anomaly)

In `suricata.yaml`, configure two EVE outputs:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve-alerts.json
      types:
        - alert

  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve-nsm.json
      types:
        - flow
        - dns
        - tls:
            extended: yes
        - http:
            extended: yes
        - ssh
        - files
        - anomaly
```

## Recommended: richer metadata (no extra cost)

These give the detectors more to work with and are worth enabling:

- **community-id** — a stable flow hash so records for one connection line up:
  ```yaml
  outputs:
    - eve-log:
        community-id: true
  ```
- **JA3 / JA4 TLS fingerprints** (under `app-layer.protocols.tls`):
  ```yaml
  app-layer:
    protocols:
      tls:
        ja3-fingerprints: yes
        ja4-fingerprints: yes
  ```
- **File hashing** (feeds hash-based and, with the file overlay, YARA detection):
  ```yaml
  outputs:
    - eve-log:
        types:
          - files:
              force-magic: yes
              force-hash: [sha256]
  ```

## Point the shipper at these files

The Cernity shipper defaults to `/var/log/suricata/eve-alerts.json` and
`/var/log/suricata/eve-nsm.json`. If your Suricata writes elsewhere, set
`SURICATA_LOG_DIR` (or the individual `SURICATA_EVE_ALERTS` / `SURICATA_EVE_NSM`
paths) when you start the sensor bundle — see `docs/deploy-sensor.md`.

## What Cernity does with each event type

| EVE event | Topic | Used by |
|---|---|---|
| alert | `suricata.raw.v1` | ids-alerts |
| flow | `suricata.flow.v1` | behavioral, east-west, anomaly, coverage |
| dns | `suricata.dns.v1` | dns-detector, behavioral (tunneling) |
| tls | `suricata.tls.v1` | protocol-detectors |
| http | `suricata.http.v1` | http-detector |
| ssh | `suricata.ssh.v1` | protocol-detectors |
| fileinfo | `suricata.file.v1` | file overlay (hash / YARA) |
| anomaly | `suricata.anomaly.v1` | anomaly-detector |
