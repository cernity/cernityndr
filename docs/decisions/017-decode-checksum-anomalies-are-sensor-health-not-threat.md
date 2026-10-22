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
NIC has not recomputed the checksums of mirrored packets, so the engine can refuse
a whole interface of traffic for reassembly and inspection while staying up and
logging flows.

The result is a distinct `sensor_checksum_rejection` candidate in category
`sensor_health`, not a threat finding, carrying the observed share, the sample
size, a verdict and the remediation. The assessment is a pure function of the
counts and the window's epoch bounds, which are required arguments: the service
owns the clock and converts its window bucket back into bounds when it flushes,
so the same window of counts always assesses to the same candidate — replayable,
and dedup-stable across processes. Severity 6 keeps it above the
delivery-suppression floor for the same reason the coverage-detector's findings
sit there: a health warning whose job is to stop silence being read as safety has
to reach the operator. Health is reported, never used to discount or suppress a
threat finding; ADR 013 remains the only path from sensor state to confidence.

Defaults, all parameters:

- `CHECKSUM_HEALTH_SHARE=0.5` — share of the window's anomaly events that must be
  invalid-checksum events. A deliberately coarse dominance test: at half, checksum
  anomalies outnumber every other anomaly the engine reported, combined. No value
  here corresponds to a packet-level rate — the denominator is events the engine
  chose to report, whose mix varies with the ruleset and protocol spread — so the
  threshold is chosen only to sit far from both regimes seen in practice: an
  incidental trickle of checksum events among many other anomaly types, and a
  capture path whose every TCP/UDP packet fails validation, which runs near 1 (a
  field case ran at 0.96). The exact value is therefore not load-bearing.
- `CHECKSUM_HEALTH_MIN_SAMPLE=200` — anomaly events required before any share is
  reported, so a near-idle sensor cannot be flagged on a handful of events and the
  empty window is a no-signal case rather than a division by zero.
- `CHECKSUM_HEALTH_WINDOW_SECS=600` — wall-clock window, like the existing dedup
  bucket: this is a property of the engine over an interval of reporting, not of
  event time.

Two verdicts *order* the candidate causes; neither determines one. Corruption in
flight damages whole frames and so tends to also trip the decoder's length,
header and truncation events, while checksum offload stripped from a mirrored
copy leaves the packet intact with only the checksum field disagreeing. Both
implications are weak — a damaged link can corrupt a checksum field and nothing
else, and a mirrored feed can carry malformed packets of its own — so this only
decides which cause the remediation names first, the remediation names both
either way, and the confidence is identical across verdicts. More than
`mixed_decode_share` (0.05, a parameter with no environment override) of
accompanying *decode-layer* anomalies yields `link_corruption_suspected`,
otherwise `checksum_validation_suspected`; absent counts yield `undetermined`.
Only decode-layer anomalies count as frame-integrity evidence: stream and
app-layer events remain in the denominator but say nothing about whether the
frame arrived intact. Spatial spread is rejected as a discriminator because a
faulty uplink affects every endpoint pair crossing it.

The signal is a dominance heuristic, not a measurement. It reports that
invalid-checksum anomalies outnumbered everything else one sensor called
anomalous over the window, which is a reason to read that sensor's configuration
and nothing more. It does not measure the share of traffic affected (the
denominator is anomaly events, not packets, and the engine throttles its own
events); it does not establish that the capture path is unhealthy at all, since a
sensor reporting few other anomaly types can cross the threshold on genuinely
sporadic corruption; it does not establish the cause; and it does not prove any
traffic went uninspected, which depends on which validation knobs are set.
Confirmation comes from the sensor's running configuration and its stats
counters, and deliberately not from watching this share change — depending on
which knob is set, the same packets may keep reporting the same checksums.
Disabling validation is therefore conditioned on first confirming the interface
is a SPAN, tap or mirror port. Each replica tallies only its assigned partitions,
so the share is per-replica. Operator guidance, including the two configuration
knobs, is in `services/anomaly-detector/README.md`.

Related: ADR 001 (sensor health agent — host and clock health, not inspection
coverage) and the coverage-detector's `coverage_degraded` finding, which measures
capture loss and application-layer blindness from Suricata's stats counters. This
signal points at a third blinding mode those two cannot see: capture and stats
look healthy because the packets do arrive and are decoded, and any rejection
happens after decode.
