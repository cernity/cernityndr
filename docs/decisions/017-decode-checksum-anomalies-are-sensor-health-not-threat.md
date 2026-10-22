# 017: decode-layer checksum anomalies are sensor health, never threat evidence

Status: implemented, pending independent review.

Anomaly-detector keeps filtering decode-layer anomalies out of threat findings:
bad checksums and malformed L2/L3 are engine noise, not attacker evidence.
`is_threat_anomaly`, the `protocol_anomaly` candidate and its output are
unchanged. Discarding those events entirely, however, discarded the only
evidence that an upstream sensor is rejecting traffic instead of inspecting it,
which is how a platform reports "no findings" from a sensor that saw almost
nothing.

They therefore feed a second, independent assessment. `stream.checksum-validation:
yes` means reject incorrect checksums; on a SPAN, tap or mirror port the capturing
NIC has not recomputed the checksums of mirrored packets, so the engine refuses a
whole interface of traffic for reassembly and inspection while staying up and
logging flows.

The result is a distinct `sensor_checksum_rejection` candidate in category
`sensor_health`, not a threat finding, carrying the observed share, the sample
size, a verdict and the remediation. Severity 6 keeps it above the
delivery-suppression floor for the same reason the coverage-detector's findings
sit there: a health warning whose job is to stop silence being read as safety has
to reach the operator. Health is reported, never used to discount or suppress a
threat finding; ADR 013 remains the only path from sensor state to confidence.

Defaults, all parameters:

- `CHECKSUM_HEALTH_SHARE=0.5` — share of the window's anomaly events that must be
  invalid-checksum events. A working capture path produces them as a trickle;
  one rejecting offload-stripped mirror traffic fails essentially every TCP/UDP
  packet and drives the share towards 1 (a field case ran at 0.96). Half lies in
  the empty space between the two regimes rather than near either, so it does not
  depend on the event mix a particular ruleset and protocol spread produce.
- `CHECKSUM_HEALTH_MIN_SAMPLE=200` — anomaly events required before any share is
  reported, so a near-idle sensor cannot be flagged on a handful of events and the
  empty window is a no-signal case rather than a division by zero.
- `CHECKSUM_HEALTH_WINDOW_SECS=600` — wall-clock window, like the existing dedup
  bucket: this is a property of the engine over an interval of reporting, not of
  event time.

Two verdicts separate the causes as far as the data allows. Corruption damages
whole frames and so also trips length, header and truncation decode events;
stripped checksum offload leaves the packet intact with only the checksum field
disagreeing. More than `mixed_decode_share` (0.05, a parameter with no
environment override) of other non-threat anomalies alongside the checksum ones
yields
`link_corruption_suspected`, otherwise `checksum_validation_suspected`; absent
counts yield `undetermined` rather than a fabricated cause. Spatial spread is
rejected as a discriminator because a faulty uplink affects every endpoint pair
crossing it.

The signal proves only that invalid-checksum anomalies dominate one sensor's
anomaly stream over the window. It does not measure the share of traffic rejected
(the anomaly stream is not a packet census and the engine throttles events), does
not read the sensor's configuration, and does not prove any traffic went
uninspected — with validation disabled the same packets produce the same
anomalies and are still inspected. Confirmation needs the sensor's configuration
or its stats counters. Each replica tallies only its assigned partitions, so the
share is per-replica. Operator guidance, including the two configuration knobs to
set when the interface is a mirror, is in `services/anomaly-detector/README.md`.

Related: ADR 001 (sensor health agent — host and clock health, not inspection
coverage) and the coverage-detector's `coverage_degraded` finding, which measures
capture loss and application-layer blindness from Suricata's stats counters. This
signal covers a third blinding mode those two cannot see: capture and stats look
healthy because the packets do arrive and are decoded; they are rejected after
decode.
