# NDR Kafka / Redpanda topic families

Origin: `suricata-ndr` v2 §14.1. These names are the contract between the shipper
(Vector, U5), normalizer (U6), detectors (U8), finding service (U9), capture
orchestrator (U10), and central enrichment (U11). `test_contracts.py` asserts this
list matches the canonical set — edit both together or the test fails.

Partition key convention (fleet-scale, see plan Enterprise Scale-Out Blueprint):
every keyed topic is keyed by `(tenant_id, entity)` so all events about an entity
reach the same stateful worker. `tenant_id` is always the leading key component —
tenant isolation is a partition invariant, never a downstream filter.

## Ingest (raw telemetry — analytics input, never SIEM input)

```text
suricata.raw.v1
suricata.flow.v1
suricata.dns.v1
suricata.tls.v1
suricata.http.v1
suricata.ssh.v1
suricata.windows.v1
suricata.file.v1
suricata.anomaly.v1
suricata.stats.v1
```

## Findings (the only thing that reaches the SIEM plane)

```text
ndr.finding.candidate.v1
ndr.finding.final.v1
```

## Capture / enrichment control plane

```text
ndr.capture.request.v1
ndr.capture.arm.v1        # orchestrator -> sensor capture-agent (gated arm directive)
ndr.capture.status.v1
ndr.enrichment.request.v1
ndr.enrichment.result.v1
```
