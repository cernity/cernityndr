# anomaly-detector

Two independent signals from one service:

- **`protocol_anomaly`** — promotes Suricata application-layer and stream-evasion
  anomalies (`suricata.anomaly.v1`) to threat finding candidates.
- **`outbound_bytes_anomaly`** — median/MAD outbound-volume baseline over
  normalized observations (`ndr.observation.normalized.v1`).
- **`sensor_checksum_rejection`** — a sensor-health signal, described below. Not a
  threat finding.

Detection capability, inputs, tunables and backing evidence are recorded in
[`detections/manifest/anomaly-detector.manifest.json`](../../detections/manifest/anomaly-detector.manifest.json).

## Sensor health: decode-layer checksum rejection

### What goes wrong

Suricata's `stream.checksum-validation: yes` means *reject packets whose checksum
is incorrect*. On a SPAN, tap or mirror port the capturing NIC has not recomputed
the checksums of the packets it is handed, so the engine sees an entire interface
of apparently-corrupt traffic and refuses it for stream reassembly and
inspection.

### What the operator sees

Nothing. The engine stays up, the service is healthy, flow logs keep flowing, and
alerts go to zero. The only trace is a flood of invalid-checksum anomalies, which
the threat path correctly discards as engine noise. A sensor in this state can
inspect a small fraction of its traffic for days without a single finding, so
"no findings" is read as "no threat" when it actually means "almost nothing was
inspected".

### How to avoid it

When the capture interface is a SPAN, tap or mirror port, in `suricata.yaml`:

```yaml
stream:
  checksum-validation: no     # mirrored packets carry un-recomputed checksums
af-packet:                    # and the same on the capture method in use
  - interface: <capture interface>
    checksum-checks: no
```

Both knobs matter: the capture-method setting governs the decoder's own
validation, the `stream` setting governs admission to reassembly. On a physical
capture of live traffic, a sustained rate of checksum failures is cabling,
transceiver or NIC damage instead — fix the link rather than disabling
validation, which would only hide it.

### Why Cernity surfaces it

A detection platform whose own blindness is invisible is worse than no platform,
because the silence is read as safety. The decode-layer anomalies stay out of
threat findings — they are not evidence of an attacker — but they are the only
evidence that the upstream sensor is rejecting traffic, so they are assessed
separately and reported as sensor health.

### The signal

Per sensor, per window, the detector counts the anomaly events it sees and the
share of them that are invalid-checksum events. Above the threshold it emits a
`sensor_checksum_rejection` candidate in category `sensor_health`, carrying the
observed share, the sample size, a verdict and the remediation. Severity is above
the delivery-suppression floor on purpose: a sensor-health warning has to reach
the operator, since its whole job is to stop silence being mistaken for safety.

| Variable | Default | Meaning |
|---|---|---|
| `CHECKSUM_HEALTH_SHARE` | `0.5` | share of the window's anomaly events that must be checksum failures |
| `CHECKSUM_HEALTH_MIN_SAMPLE` | `200` | anomaly events required before any share is reported |
| `CHECKSUM_HEALTH_WINDOW_SECS` | `600` | window length, on the wall clock |
| `NDR_SENSOR_ID` | `sensor` | sensor identity for records that carry none |

The threshold sits in the wide empty space between two regimes. A working capture
path produces checksum failures as a trickle — corruption that survives to the
engine is a small fraction of a percent of packets, and a link mangling enough
frames to dominate an anomaly stream would not carry usable traffic at all. A
capture path rejecting offload-stripped mirror traffic fails essentially every
TCP/UDP packet, driving the share towards 1; one field case ran at 0.96. Half is
therefore far from either regime and insensitive to the exact event mix a given
ruleset and protocol spread produce.

Two verdicts separate the causes as far as the data allows. Real corruption
damages whole frames, so it also trips length, header and truncation decode
events; stripped checksum offload leaves the packet structurally intact with only
the checksum field disagreeing. More than a few percent of other non-threat
anomalies alongside the checksum ones therefore yields
`link_corruption_suspected` rather than `checksum_validation_suspected`. Spatial
spread is deliberately not used as a discriminator: a faulty uplink or
transceiver affects every endpoint pair crossing it, so it does not separate the
two cases.

### What this signal proves, and what it does not

It proves that over the window invalid-checksum anomalies dominate the engine's
own anomaly stream, which no healthy capture path produces. It does **not**:

- measure the share of *traffic* rejected — the anomaly stream is not a packet
  census, and the engine's event throttling makes the ratio an indicator, not a
  rate;
- read the sensor's configuration, so it reports a suspicion and the knobs to
  check, never a confirmed misconfiguration;
- prove that anything went uninspected: with validation disabled the same
  offload-stripped packets produce the same anomalies and are still inspected.
  Confirming blindness needs the sensor's config or its stats counters.

Each replica tallies only the partitions assigned to it, so the share is
per-replica. Treat it as a dominance indicator for one sensor, not a fleet-wide
rate.
