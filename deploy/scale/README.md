# Scaling Cernity across your own servers (no Kubernetes)

The single-host `deploy/central` compose is for evaluation and small sites. For a
large fleet — up to ~1,000 sensors and ~10 Gbps of edge inspection — you run
Cernity across several servers you manage yourself, with no dynamic orchestration.
Nothing about the services changes: they are stateless consumer-group workers that
share state in Redis and read partitioned topics off the bus, so you scale by
**placing tiers on hosts and running more replicas**.

If you want Kubernetes instead, see `deploy/helm/` — same architecture, dynamic
scaling. This directory is the manual path.

## The tiers

```
  1,000 sensors                Infra host(s)                 Worker hosts (N)
  ------------                 -------------                 ----------------
  Suricata + Fluent Bit  ->    Redpanda (bus)         <-     detectors (M replicas each)
  (+ optional capture)         Redis (shared state)   <-     finding-service
                               ClickHouse (retention)        findings-forwarder
                               MinIO (pcap/files)     ->      normalizer -> ClickHouse
```

- **Sensors** already scale horizontally — each runs `deploy/sensor` independently
  (self-arming, no central key-holder). 1,000 sensors = 1,000 independent shippers.
- **Infra tier** (`infra.yml`): the bus, shared state, retention, object store. Start
  as single nodes; swap in a Redpanda cluster / Redis Cluster / ClickHouse cluster as
  volume grows — the workers only need the address.
- **Worker tier** (`workers.yml`): the stateless services. Deploy on as many hosts as
  you need and set replica counts. Every replica of a service joins the same consumer
  group and takes a share of the partitions.

## The one rule that governs throughput: partitions

A topic's **partition count is the parallelism ceiling** for the detectors that read
it. `N` replicas of a detector split that topic's partitions between them, so useful
replicas ≤ partitions. To scale a detector, you need enough partitions.

Everything is keyed by `src_ip`, so one source's whole window always lands on one
partition (correct windowing) while different sources spread across partitions.

Create the high-volume topics with plenty of partitions up front (they can't shrink):

```bash
# on the infra host — size to your peak; 256 is a sane start for a large fleet
for t in suricata.flow.v1 suricata.dns.v1 suricata.tls.v1 suricata.http.v1; do
  docker exec cernity-redpanda rpk topic create "$t" -p 256 -r 1 2>/dev/null || \
  docker exec cernity-redpanda rpk topic alter-config "$t" --set retention.ms=3600000
done
```

Rule of thumb: **partitions ≥ the largest replica count you expect for any detector
on that topic.** 256 partitions lets you run up to 256 `behavioral-detectors`
replicas across your worker hosts.

## Deploy it

**1. Infra host** — set its reachable address and secrets, bring up the bus/state/storage:

```bash
BUS_ADVERTISE_ADDR=10.0.0.10 \
CLICKHOUSE_PASSWORD=<pw> MINIO_ROOT_PASSWORD=<pw> \
docker compose -f deploy/scale/infra.yml up -d
```

**2. Each worker host** — point `.env` at the infra host and choose replica counts:

```bash
# .env on a worker host
REDPANDA_BOOTSTRAP=10.0.0.10:19092
NDR_REDIS_URL=redis://10.0.0.10:6379/0
CLICKHOUSE_HOST=10.0.0.10
CLICKHOUSE_PASSWORD=<pw>
BEHAVIORAL_REPLICAS=8
DNS_REPLICAS=4
PROTOCOL_REPLICAS=4
# ...

docker compose -f deploy/scale/workers.yml up -d
```

Add worker hosts by repeating step 2 on more machines with the same `.env` — the new
replicas join the consumer groups and the fleet rebalances automatically. To grow a
single host's replicas: `docker compose -f deploy/scale/workers.yml up -d --scale behavioral-detectors=12`.

## Sizing for ~1,000 sensors / ~10 Gbps

- **10 Gbps is edge packet-inspection**, done by Suricata across the 1,000 sensors —
  not central. Cernity ingests **EVE telemetry** (flow/DNS/TLS/HTTP metadata), the
  aggregate of which is a fraction of the packet rate. Size the central tier to that
  metadata rate, not to 10 Gbps.
- **Bus**: a Redpanda **cluster** (3+ brokers), high partition counts (start 256 on
  `flow`, scale up), short retention on raw topics (findings are the durable output).
- **State**: Redis single node handles a lot; move to **Redis Cluster** when the
  window keyspace or throughput demands it (the store shards by partition already).
- **Retention**: **ClickHouse cluster** (sharded + replicated) for telemetry/findings.
- **Workers**: scale each detector's replicas to its topic's load; watch Kafka
  consumer-group **lag** as the signal to add replicas/hosts. Behavioral and protocol
  detectors are usually the heaviest; scale them first.
- **Findings out**: `findings-forwarder` is light (findings are rare relative to
  telemetry); a couple of replicas suffice.

## Health / monitoring

Every worker exposes Prometheus metrics and health endpoints. Watch consumer-group
lag per topic (`rpk group describe <group>`) — rising lag on a topic means that
detector needs more replicas (up to the partition ceiling) or more partitions.
