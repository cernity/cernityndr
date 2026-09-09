# Placing Cernity across your own servers

Cernity lets **you decide what runs where**. Every service is stateless and reaches
the others only through the shared bus, so you can spread the pieces across as many
servers as you like — matching each piece to the hardware that suits it — with no
orchestrator. This is the manual, you-choose model; for Kubernetes see `deploy/helm/`.

## The idea

- **Shared infra** (bus, state, storage) lives on a host — or a cluster — everyone can
  reach. `deploy/scale/infra.yml` runs it, or point at your own Redpanda/Redis/ClickHouse.
- **Workers** (`deploy/scale/workers.yml`) are placed by you: on each server you start
  exactly the services you want there, by **role profile** or by **name**.
- Every host's `.env` points at the shared infra. Services self-arm off the bus — no
  central key-holder, no per-host coordination.

Two knobs: **placement** (which services on which host) and **replicas** (how many
copies of a service, bounded by that topic's partition count — see
`deploy/scale/README.md`).

## Selecting services on a host

```bash
# a whole role:
docker compose -f deploy/scale/workers.yml --profile detection up -d
# specific services (naming overrides the profile gate):
docker compose -f deploy/scale/workers.yml up -d behavioral-detectors dns-detector
# scale a placed service:
docker compose -f deploy/scale/workers.yml up -d --scale behavioral-detectors=8
```

Role profiles: `ingest` (ids-alerts), `detection` (the eight detectors),
`findings` (finding-service + findings-forwarder). Storage and forensics are their own
overlays (`clickhouse.yml`, `forensics.yml`) — run them on the host you dedicate to
disk or packets.

## A worked topology (heterogeneous hardware)

Say you have six boxes with different strengths. One way to lay it out:

| Box | Hardware strength | Runs | Command |
|---|---|---|---|
| **infra-1** | fast disk, steady | Redpanda + Redis | `docker compose -f deploy/scale/infra.yml up -d redpanda redis` |
| **store-1** | big disk | ClickHouse + MinIO | `docker compose -f deploy/scale/infra.yml up -d clickhouse minio` |
| **det-1** | many CPU cores | heavy detectors, scaled | `... workers.yml up -d --scale behavioral-detectors=8 behavioral-detectors dns-detector` |
| **det-2** | many CPU cores | the rest of detection | `... workers.yml --profile detection up -d` (or name the remaining detectors) |
| **forensics-1** | NIC + disk for pcaps | Zeek loop + file scanning | `... -f deploy/overlays/forensics.yml up -d` |
| **out-1** | small | ingest + findings out | `... workers.yml --profile ingest --profile findings up -d` |

Each box's `.env` points at the shared infra:

```bash
# .env on every worker/forensics/out box
REDPANDA_BOOTSTRAP=infra-1:19092
NDR_REDIS_URL=redis://infra-1:6379/0
CLICKHOUSE_HOST=store-1
CLICKHOUSE_PASSWORD=•••
MINIO_ENDPOINT=http://store-1:9002
```

Add capacity by starting more copies (`--scale`) or by bringing up the same services on
another box — new copies join the consumer group and take a share of the partitions
automatically. Nothing else needs to change.

## Rules of thumb

- **Match piece to hardware:** detection is CPU-bound (fast cores), ClickHouse/MinIO are
  disk-bound (big disk), the Zeek loop is NIC/disk-bound. Place accordingly.
- **Partitions cap parallelism:** a detector's useful replica count across all hosts is
  ≤ its topic's partition count. Give busy topics plenty of partitions up front.
- **Watch consumer-group lag** (`rpk group describe ndr-<detector>`): rising lag on a
  topic means add replicas/hosts for that detector (up to the partition ceiling) or add
  partitions.
- **Infra can split or cluster:** run bus and storage on separate boxes by naming their
  services, or replace `infra.yml` with real clusters — the workers only need the address.
- **Health per host:** each service exposes `/healthz` `/readyz` `/metrics`; point
  Prometheus at them to see load per box (see `docs/logging.md`).
