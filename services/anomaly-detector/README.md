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
the checksums of the packets it is handed, so the engine can see an entire
interface of apparently-corrupt traffic and refuse it for stream reassembly and
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
validation, the `stream` setting governs admission to reassembly. Confirm the
interface really is a mirrored feed before setting either, because the other
cause of sustained checksum failures is a damaged capture path — cabling,
transceiver or NIC faults, visible in the interface error counters on the sensor
and on the mirroring device. There, fix the link: disabling validation would hide
it rather than fix it.

Verify the change from the running configuration and from Suricata's own stats
counters, not from the anomaly share — depending on which validation knob is set,
the same packets may keep reporting the same checksums.

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
observed share, the sample size, a verdict and the remediation. The assessment
itself is a pure function of the counts and the window bounds — the service owns
the clock and passes the window in — so a window of counts always assesses to the
same candidate. Severity is above
the delivery-suppression floor on purpose: a sensor-health warning has to reach
the operator, since its whole job is to stop silence being mistaken for safety.

| Variable | Default | Meaning |
|---|---|---|
| `CHECKSUM_HEALTH_SHARE` | `0.5` | share of the window's anomaly events that must be checksum failures |
| `CHECKSUM_HEALTH_MIN_SAMPLE` | `200` | anomaly events required before any share is reported |
| `CHECKSUM_HEALTH_WINDOW_SECS` | `600` | window length, on the wall clock |
| `NDR_SENSOR_ID` | `sensor` | sensor identity for records that carry none |

The threshold is a deliberately coarse dominance test: at `0.5`, checksum
anomalies outnumber every other anomaly the engine reported, combined. No value
here corresponds to a packet-level rate, because the denominator is events the
engine chose to report and that mix varies with the ruleset and the protocol
spread. `0.5` sits far from both regimes that matter in practice — an incidental
trickle of checksum events among many other anomaly types, and a capture path
whose every TCP/UDP packet fails validation, which runs near 1 (one field case
ran at 0.96) — so the exact value is not load-bearing.

Two verdicts *order* the candidate causes; neither determines one. Corruption in
flight damages whole frames, so it tends to also trip the decoder's length,
header and truncation events, while checksum offload stripped from a mirrored
copy leaves the packet structurally intact with only the checksum field
disagreeing. Neither implication is reliable — a damaged link can corrupt a
checksum field and nothing else, and a mirrored feed can carry malformed packets
of its own — so more than a few percent of accompanying *decode-layer* anomalies
yields `link_corruption_suspected` rather than `checksum_validation_suspected`,
the remediation names both causes either way, and the confidence is the same.
Only decode-layer anomalies count as frame-integrity evidence: stream and
app-layer events are in the denominator but say nothing about whether the frame
arrived intact. Spatial spread is deliberately not used as a discriminator: a
faulty uplink or transceiver affects every endpoint pair crossing it, so it does
not separate the two cases.

### What this signal proves, and what it does not

It is a dominance heuristic over the engine's own anomaly stream, not a
measurement of the capture path. It reports that invalid-checksum anomalies
outnumbered everything else the engine called anomalous over the window, which is
a reason to go and read the sensor's configuration — nothing more. It does
**not**:

- measure the share of *traffic* affected — the denominator is anomaly events,
  not packets, and the engine throttles its own events, so the ratio is not a
  rate and does not scale to one;
- establish that the capture path is unhealthy at all. A sensor that reports few
  other anomaly types can cross the threshold on genuinely sporadic corruption;
  the minimum sample reduces that case but does not exclude it;
- establish the cause. It cannot read the configuration, so both candidate causes
  stay open and the remediation is conditioned on confirming which one applies;
- prove that anything went uninspected. That depends on which validation knobs
  are set, and is visible in the running configuration and in Suricata's stats
  counters, not in this ratio.

Each replica tallies only the partitions assigned to it, so the share is
per-replica. Treat it as a dominance indicator for one sensor, not a fleet-wide
rate.
