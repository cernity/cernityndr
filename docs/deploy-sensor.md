# Deploying the Cernity sensor bundle

The sensor bundle is the one Cernity component that runs on the box already running
Suricata. It is a single container — a Fluent Bit shipper that tails Suricata's EVE
logs and forwards them to the central bus. It does no detection and holds no state
beyond its file read offsets.

## Prerequisites

1. Suricata configured to write split EVE output — see `docs/suricata-config.md`.
2. Network reachability from the sensor to the central bus (Redpanda/Kafka).

## Run it

From the repo root on the sensor:

```bash
REDPANDA_BOOTSTRAP=<central-bus-host>:9092 \
SURICATA_LOG_DIR=/var/log/suricata \
docker compose -f deploy/sensor/docker-compose.yml up -d
```

Or put those in the `.env` file (copy `cernity.env.example`) and just run the
compose command.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `REDPANDA_BOOTSTRAP` | `redpanda:9092` | central bus address |
| `SURICATA_LOG_DIR` | `/var/log/suricata` | host directory holding the EVE files |
| `SURICATA_EVE_ALERTS` | `/var/log/suricata/eve-alerts.json` | alerts file (inside the container) |
| `SURICATA_EVE_NSM` | `/var/log/suricata/eve-nsm.json` | NSM file (inside the container) |
| `LOG_LEVEL` | `info` | Fluent Bit log level |

## Confirm it is working

```bash
docker logs cernity-fluent-bit
```

You should see Fluent Bit start, open the two EVE files, and connect to the bus. On
the central side, the detectors begin emitting findings as matching traffic arrives.

## Bare-metal Suricata

If Suricata runs directly on the host (not in a container), this still works: the
shipper bind-mounts the host log directory read-only. Nothing about Suricata's
deployment needs to change beyond the EVE output configuration.
