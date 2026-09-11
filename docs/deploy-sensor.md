# Deploying the Cernity sensor bundle

The sensor bundle runs on the box already running Suricata. It has two parts:

- **Fluent Bit shipper** (always on) — tails Suricata's split EVE logs and forwards them
  to the central bus. It does no detection and holds no state beyond its file read offsets.
- **capture-agent** (optional, `--profile capture`) — on-demand packet forensics. It
  self-arms over the bus (no inbound access), actuates Suricata's conditional PCAP on the
  local command socket, and ships bounded PCAP/file slices to the central object store.

Both authenticate to the bus with the **produce-only sensor credential** — never a
superuser (see [SECURITY.md](../SECURITY.md) and `deploy/security`). A compromised sensor
cannot forge findings, read another tenant's traffic, or alter the cluster.

## Prerequisites

1. Suricata configured to write split EVE output — see `docs/suricata-config.md`.
2. Network reachability from the sensor to the central **external** bus listener
   (`CENTRAL_HOST:19092`).
3. The `ca.crt` and the sensor SCRAM credential from the central host's
   `deploy/security/gen-bus-certs.sh` run (see [getting-started.md](getting-started.md)).

## Run the shipper

From the repo root on the sensor (copy `ca.crt` over first):

```bash
REDPANDA_BOOTSTRAP=CENTRAL_HOST:19092 \
SURICATA_LOG_DIR=/var/log/suricata \
CERNITY_BUS_USER=cernity-sensor \
CERNITY_BUS_PASSWORD=<from gen-bus-certs.sh> \
CERNITY_BUS_CA=/path/to/ca.crt \
docker compose -f deploy/sensor/docker-compose.yml up -d
```

Or put those in `.env` (copy `cernity.env.example`) and just run the compose command. For a
throwaway plaintext demo bus, set `NDR_BUS_SASL_MECHANISM=` (empty) and drop the
`rdkafka.sasl.*` lines from `deploy/fluent-bit/fluent-bit.conf`.

## Enable on-demand capture (optional)

The capture-agent is gated behind the `capture` profile. It needs the sensor's produce-only
bus credential (same as the shipper) **and** a least-privilege object-store key — a MinIO key
scoped to `PutObject` on the `ndr-pcap`/`ndr-files` buckets, **not** the MinIO root key.
Create that key on the central MinIO first, then:

```bash
CERNITY_MINIO_CAPTURE_USER=<scoped key id> \
CERNITY_MINIO_CAPTURE_PASSWORD=<scoped secret> \
docker compose -f deploy/sensor/docker-compose.yml --profile capture up -d
```

The agent reads/writes Suricata's local command socket and capture directory by design;
nothing requires inbound network access to the sensor (it self-arms over the bus).

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `REDPANDA_BOOTSTRAP` | `redpanda:9092` | central bus address — set to `CENTRAL_HOST:19092` on a remote sensor |
| `CERNITY_BUS_USER` / `CERNITY_BUS_PASSWORD` | `cernity-sensor` / — | produce-only SCRAM credential (from `gen-bus-certs.sh`) |
| `CERNITY_BUS_CA` | `./ca.crt` | CA that signed the bus server cert (copied from the central host) |
| `NDR_BUS_SASL_MECHANISM` | `SCRAM-SHA-512` | set empty for a plaintext demo bus |
| `NDR_TENANT` / `NDR_SENSOR` | `default` / `sensor-1` | trusted identity the shipper stamps on every record (F08) |
| `SURICATA_LOG_DIR` | `/var/log/suricata` | host directory holding the EVE files |
| `SURICATA_EVE_ALERTS` | `/var/log/suricata/eve-alerts.json` | alerts file (inside the container) |
| `SURICATA_EVE_NSM` | `/var/log/suricata/eve-nsm.json` | NSM file (inside the container) |
| `CERNITY_MINIO_CAPTURE_USER` / `_PASSWORD` | `cernity` / `cernitydemo` | least-privilege object-store key for `--profile capture` |
| `LOG_LEVEL` | `info` | log level |

## Confirm it is working

```bash
docker logs cernity-fluent-bit        # (and cernity-capture-agent with --profile capture)
```

You should see Fluent Bit start, open the two EVE files, and connect to the bus. On the
central side, the detectors begin emitting findings as matching traffic arrives.

## Bare-metal Suricata

If Suricata runs directly on the host (not in a container), this still works: the shipper
bind-mounts the host log directory read-only. Nothing about Suricata's deployment needs to
change beyond the EVE output configuration.
