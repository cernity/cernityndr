# U2: mandatory sensor health agent and measured clock correction

Status: implemented, pending independent review.

U2 and architecture §6.2 require a sensor-agent distinct from optional packet
capture. Add it to the normal sensor compose without a profile. Do not modify
capture behavior, enroll sensors, implement a registry, or apply policies.

Use `ndr.sensor.health.v1` for the `sensor-health.v1` contract. Existing topics
have no collision. Permit the sensor bus principal to produce only to this
additional literal topic; retain its existing restrictions on all other ndr
control/findings topics. Tenant + sensor UUID form an unambiguous JSON key.
Identity verification remains a trusted ingress/registry responsibility.

Read the host chronyd's current measured system correction over its read-only
localhost monitoring interface. This uses the existing disciplined host clock,
requires no clock-changing privilege, and avoids introducing a competing NTP
client. The wire sign is sensor minus source. Missing/unsynchronized sources
are explicit unknowns, not a fabricated zero or the last successful sample.

Keep all health metric slots required but nullable. The daemon measures host
resources and bounded EVE line rates. Optional fresh host-exporter snapshots
supply capture/shipper measurements; absent exporters leave those metrics
unknown. This preserves heartbeat availability on sensors without capture and
avoids asserting unsupported measurements. Collector details and operational
requirements are in `services/sensor-agent/README.md`.
