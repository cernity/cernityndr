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
suricata.modbus.v1
```

`suricata.modbus.v1` carries Suricata's native Modbus app-layer EVE (consumed by
`ot-detectors`); enabled per-deployment via the opt-in OT sensor profile.

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

## Sensor health telemetry

```text
ndr.sensor.health.v1
```

Carries `sensor-health.v1` (`sensor-health.schema.json`) from the mandatory
`sensor-agent`, independently of optional packet capture. No existing topic uses
this binding. Key is UTF-8 JSON `[tenant, sensor_uuid]`; consumers must verify the
asserted tenant/sensor against enrollment and authenticated ingress identity.
This is health telemetry, not a finding or SIEM input. The secure bus grants the
sensor principal write/describe/create on this exact topic only.

## Canonical evidence

```text
ndr.observation.normalized.v1
```

Carries `cernity.observation.v1` (`observation.schema.json`) from the normalizer
following insertion into the typed evidence row. Key is UTF-8 JSON
`[tenant, first_entity_value]`, or `[tenant, sensor_id]` if no entity is present.
At-least-once delivery: consumers deduplicate by `(tenant, obs_id)`.
This is evidence telemetry, not a SIEM finding. `source_ref` resolves the named
ClickHouse table by `tenant_id = tenant AND obs_id = source_ref.obs_id`; its
`raw_record` contains the preserved decoded bus object. No raw sensor-byte or
MinIO-delivery claim is made. Findings can reference the exact `obs_id` string
in `evidence_refs`; existing flow/community references are not exact event IDs.

`ts.sensor` retains the sensor timestamp. `ts.normalized` uses a trusted measured
sensor-minus-reference offset if supplied to the transform; otherwise the live
service uses the Kafka record timestamp with `method = ingest-fallback` and a
null offset. The service requires broker `LogAppendTime` on these input topics and stops
without committing on `CreateTime` records, which cannot establish ingest time.
Health-to-normalizer offset lookup and correlation skew tolerance are not
implemented by U4. Consumers must inspect `ts.method` before clock-sensitive use.
