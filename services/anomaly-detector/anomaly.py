"""Promote Suricata protocol-anomaly events to findings (re-eval gap G4).

`suricata.anomaly.v1` was produced but consumed by nobody. Application-layer
anomalies (protocol violations, unexpected events) are evasion/exploit tells;
decode-layer anomalies (bad checksums, malformed L2/L3) are engine noise. This
filters to the threat-relevant ones and emits finding candidates. Pure + testable.

Discarding the decode layer entirely would throw away the only evidence that the
upstream sensor is rejecting traffic rather than inspecting it, so those events
feed a separate sensor-health assessment instead (see the sensor-health section
below). Health results carry their own detector_id and category and never enter
the threat path.
"""
from __future__ import annotations

import hashlib
import json
import time

from features import iso


def _stable(*parts) -> int:
    """Stable cross-process id (F07): built-in hash() is PYTHONHASHSEED-randomized, so
    the same anomaly produced a different finding_id per process and dedup never fired."""
    s = "|".join("" if p is None else str(p) for p in parts)
    return int(hashlib.sha1(s.encode()).hexdigest()[:15], 16) % 10**10

_THREAT_TYPES = ("applayer",)          # app-layer protocol anomalies = threat-relevant
_KEEP_STREAM = ("overlap_different_data", "data_after_reset", "reassembly",
                "3whs", "wrong_thread")   # evasion/injection stream tells worth keeping


def is_threat_anomaly(anom: dict) -> bool:
    if not anom:
        return False
    t = str(anom.get("type", "")).lower()
    ev = str(anom.get("event", "")).lower()
    if t in _THREAT_TYPES:
        return True
    if t == "stream" and any(k in ev for k in _KEEP_STREAM):
        return True
    return False


def to_candidate(eve: dict, tenant: str = "homelab") -> dict | None:
    if eve.get("event_type") != "anomaly":
        return None
    anom = eve.get("anomaly") or {}
    if not is_threat_anomaly(anom):
        return None
    src, dst = eve.get("src_ip"), eve.get("dest_ip")
    ev = anom.get("event")
    entities = json.dumps([{"type": "ip", "role": "src", "value": src},
                           {"type": "ip", "role": "dst", "value": dst},
                           {"type": "anomaly", "value": ev},
                           {"type": "app_proto", "value": eve.get("app_proto")}])
    ts = eve.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {"finding_id": f"anom-{_stable(ev, src, dst)}",
            "tenant_id": tenant, "detector_id": "protocol_anomaly", "detector_version": "1.0",
            "category": "anomaly", "severity": 5, "confidence": 0.5,
            "first_seen": ts, "last_seen": ts,
            "entities": entities, "state": "CANDIDATE"}


# --- Sensor health: decode-layer checksum rejection ---------------------------
#
# `is_threat_anomaly` drops decode-layer anomalies because, as threat evidence,
# they are engine noise. They are also the only evidence of one specific way a
# sensor goes blind, so they are assessed here instead of being discarded.
#
# Cause. Suricata's `stream.checksum-validation: yes` means "reject packets
# whose checksum is incorrect". On a SPAN, tap or mirror port the capturing NIC
# never recomputes the checksums of mirrored packets, so the engine can see an
# entire interface of apparently-corrupt traffic and refuse it for stream
# reassembly and inspection.
#
# Symptom. The engine stays up, keeps logging flows and reports no alerts while
# inspecting only the fraction of traffic whose checksums happen to validate.
# "No findings" then means "almost nothing was inspected", which is the one
# failure a detection platform must never report as quiet. In one field case
# 96% of a sensor's alerts were invalid-checksum events and a multi-day
# exploitation campaign against an exposed service produced no alerts at all.
#
# What this is. A dominance heuristic over the engine's own anomaly stream, not
# a measurement of the capture path. It reports that invalid-checksum anomalies
# outnumbered everything else the engine called anomalous over the window, which
# is a reason to go and read the sensor's configuration — nothing more.
#
# What it cannot establish:
#   - the share of *traffic* affected. The denominator is anomaly events, not
#     packets, and the engine throttles its own events, so the ratio is not a
#     rate and does not scale to one.
#   - that the capture path is unhealthy at all. A sensor that reports few other
#     anomaly types can cross the threshold on genuinely sporadic corruption;
#     the event mix depends on the ruleset and the protocol spread. The large
#     minimum sample reduces that case but does not exclude it.
#   - the cause. It cannot read the configuration, so both candidate causes stay
#     explicitly uncertain and the remediation is conditioned on the operator
#     confirming which one applies.
#   - that any traffic went uninspected. That depends on which validation knobs
#     are set, and is visible in the running configuration and the engine's own
#     stats counters, not in this ratio.

# Share of the window's anomaly events that must be invalid-checksum events.
# Half means "checksum anomalies outnumber every other anomaly the engine
# reported, combined" — a deliberately coarse dominance test, because the
# alternative readings of this ratio are not comparable quantities: the
# denominator is events the engine chose to report, whose mix varies with the
# ruleset and protocol spread, so no value here corresponds to a packet-level
# rate. It sits far from both regimes that matter in practice (an incidental
# trickle of checksum events among many other anomaly types, and a capture path
# whose every TCP/UDP packet fails validation and which runs near 1), so the
# exact value is not load-bearing.
CHECKSUM_SHARE_THRESHOLD = 0.5

# Anomaly events required in the window before any share is reported. Guards the
# ratio against small samples — a near-idle sensor with three anomalies, two of
# them checksum failures, is evidence of nothing — and makes the empty window a
# no-signal case rather than a division by zero.
CHECKSUM_MIN_SAMPLE = 200

# Weak discriminator between the two candidate causes, and the only one the data
# supports at all. Corruption in flight damages whole frames, so it tends to also
# trip the decoder's length, header and truncation events; checksum offload
# stripped from a mirrored copy leaves the packet structurally intact with only
# the checksum field disagreeing. Neither implication is reliable — a damaged
# link can corrupt a checksum field and nothing else, and a mirrored feed can
# carry malformed packets of its own — so this only orders which cause the
# remediation names first. Only decode-layer anomalies are counted: stream and
# app-layer events say nothing about frame integrity. Spatial spread (how many
# endpoint pairs are affected) is deliberately not used: a faulty uplink or
# transceiver affects every pair crossing it, so it does not separate the cases.
CHECKSUM_MIXED_DECODE_SHARE = 0.05

# Episode bucket for the finding id, matching the coverage detector's default:
# a persistent condition is one finding per hour, and a recovery followed by a
# relapse is a distinct finding rather than one permanent record.
SENSOR_HEALTH_EPISODE_SECS = 3600

_CHECKSUM_FIX = (
    "Identify the capture interface. If it is a SPAN, tap or mirror port, the checksums of "
    "the mirrored copies were never recomputed: set stream.checksum-validation: no in "
    "suricata.yaml and checksum-checks: no on the capture method (af-packet, pcap or dpdk) "
    "for that interface. Verify the result from the running configuration and the engine's "
    "stats counters, not from this share — depending on which knob is set the same packets "
    "may keep reporting the same checksums."
)
_CHECKSUM_LINK = (
    "A damaged capture path is the other cause consistent with this sample: cabling, "
    "transceiver or NIC faults corrupt frames in flight. Check the interface error counters "
    "on the sensor and on the mirroring device; if they are rising, fix the link rather than "
    "disabling validation, which would hide it."
)
_CHECKSUM_BOTH = " Both causes remain open until one is confirmed from the sensor itself."
_CHECKSUM_REMEDIATION = {
    # No other decode-layer events alongside: order the mirrored-feed cause first.
    "checksum_validation_suspected": (
        "Checksum anomalies dominate and no other decode-layer anomalies accompany them, "
        "which is consistent with an offload-stripped SPAN, tap or mirror feed but does not "
        "establish it. " + _CHECKSUM_FIX + " " + _CHECKSUM_LINK + _CHECKSUM_BOTH),
    # Other decode-layer events alongside: order the damaged-link cause first.
    "link_corruption_suspected": (
        "Checksum anomalies dominate and other decode-layer anomalies accompany them, which "
        "is somewhat more consistent with frames arriving damaged — though a mirrored feed "
        "can also carry malformed packets. " + _CHECKSUM_LINK + " " + _CHECKSUM_FIX
        + _CHECKSUM_BOTH),
    # Counts of other decode anomalies were not supplied: no ordering is justified.
    "undetermined": (
        "Checksum anomalies dominate the anomaly stream. Other decode-layer anomalies were "
        "not counted, so a mirrored feed and a damaged capture path are equally consistent "
        "with this sample. " + _CHECKSUM_FIX + " " + _CHECKSUM_LINK + _CHECKSUM_BOTH),
}
_CHECKSUM_WHY = ("invalid-checksum anomalies dominate this sensor's anomaly stream; if "
                 "stream.checksum-validation is enabled the engine rejects that traffic from "
                 "reassembly and inspection, in which case an absence of findings from this "
                 "sensor proves nothing — check the sensor's configuration")


def is_checksum_anomaly(anom: dict) -> bool:
    """A decode/stream-layer invalid-checksum anomaly.

    Disjoint from `is_threat_anomaly` by construction, so the health signal can
    never reclassify an anomaly the threat path promotes. Matches on the event
    name rather than an enumerated list because the engine names these per
    protocol layer (decoder.ipv4/tcp/udp/icmpv4.invalid_checksum and the stream
    equivalents) and the set grows between releases.
    """
    if not anom or is_threat_anomaly(anom):
        return False
    return "checksum" in str(anom.get("event", "")).lower()


def tally_checksum_anomalies(events, tally: dict | None = None) -> dict:
    """Fold a window of EVE records into checksum counts.

    `anomalies` counts every anomaly event examined (the share's denominator),
    `checksum` the invalid-checksum ones, and `other_decode` only the remaining
    *decode-layer* anomalies — the frame-integrity evidence behind the verdict.
    Stream and app-layer anomalies deliberately land in the denominator alone:
    they report protocol behaviour, not whether the frame arrived intact. Pass a
    previous tally to accumulate across several polls of the same window;
    non-anomaly records are ignored, so the full EVE stream can be fed in
    directly.
    """
    t = tally if tally is not None else {"checksum": 0, "other_decode": 0, "anomalies": 0}
    for eve in events:
        if not isinstance(eve, dict) or eve.get("event_type") != "anomaly":
            continue
        anom = eve.get("anomaly") or {}
        t["anomalies"] += 1
        if is_checksum_anomaly(anom):
            t["checksum"] += 1
        elif str(anom.get("type", "")).lower() == "decode":
            t["other_decode"] += 1
    return t


def to_sensor_health(checksum_count: int, total_count: int, sensor: str = "sensor",
                     tenant: str = "homelab", *, window_start: float, window_end: float,
                     other_decode_count: int | None = None,
                     share_threshold: float = CHECKSUM_SHARE_THRESHOLD,
                     min_sample: int = CHECKSUM_MIN_SAMPLE,
                     mixed_decode_share: float = CHECKSUM_MIXED_DECODE_SHARE,
                     episode_secs: int = SENSOR_HEALTH_EPISODE_SECS) -> dict | None:
    """Sensor-health candidate when checksum anomalies dominate, else None.

    Pure: every field, the timestamps and the finding id included, is a function
    of the arguments. `window_start`/`window_end` are the window's epoch bounds
    and are required — the caller owns the clock, so the same window of counts
    always assesses to the same result (replayable, and dedup-stable across
    processes).

    `total_count` is the number of anomaly events examined in the window, not a
    packet count. A caller that instead passes a count of all EVE events has a
    much larger denominator and must lower `share_threshold` to match.

    This is a sensor-health result, not a threat finding: its own detector_id
    and `sensor_health` category keep it off the threat path, and severity sits
    above the delivery-suppression floor because its entire job is to stop "no
    findings" being read as "no threat".
    """
    if not 0 < share_threshold <= 1:
        raise ValueError("share_threshold must be in (0, 1]")
    if min_sample < 1 or not 0 <= mixed_decode_share <= 1 or episode_secs < 1:
        raise ValueError("invalid checksum-health configuration")
    if not window_end > window_start:
        raise ValueError("window_end must be after window_start")
    if total_count < min_sample or checksum_count < 0:
        return None                      # too small to divide, let alone conclude
    share = checksum_count / total_count
    if share < share_threshold:
        return None
    # Confidence is in the dominance observation, not in the cause: the mixed
    # case is no less certain than the clean one, only less cleanly attributed.
    if other_decode_count is None:
        verdict = "undetermined"
    elif other_decode_count / (checksum_count + other_decode_count) > mixed_decode_share:
        verdict = "link_corruption_suspected"
    else:
        verdict = "checksum_validation_suspected"
    entities = json.dumps([
        {"type": "sensor", "value": sensor},
        {"type": "sensor_health", "value": "decode_checksum_rejection"},
        {"type": "metric", "value": round(share, 4)},
        {"type": "why", "value": _CHECKSUM_WHY},
    ])
    return {"finding_id": f"chksum-{_stable(sensor)}-{int(window_start // episode_secs)}",
            "tenant_id": tenant, "sensor_ids": [sensor],
            "detector_id": "sensor_checksum_rejection", "detector_version": "1.0",
            "category": "sensor_health", "severity": 6, "confidence": 0.6,
            "first_seen": iso(window_start), "last_seen": iso(window_end),
            "entities": entities,
            "summary": {"sensor_health": {
                "schema": "cernity.sensor_health.v1",
                "signal": "decode_checksum_rejection",
                "sensor_id": sensor,
                "verdict": verdict,
                "checksum_anomaly_share": round(share, 4),
                "checksum_anomalies": checksum_count,
                "other_decode_anomalies": other_decode_count,
                "sample_size": total_count,
                "sample": "anomaly events examined in the window; not a packet census",
                "window": {"start": iso(window_start), "end": iso(window_end)},
                "share_threshold": share_threshold,
                "min_sample": min_sample,
                "remediation": _CHECKSUM_REMEDIATION[verdict],
                "proves": ("invalid-checksum anomalies outnumbered every other anomaly this "
                           "sensor reported over the window"),
                "does_not_prove": ("the share of traffic affected, that the capture path is "
                                   "unhealthy, the cause, or that any traffic went "
                                   "uninspected; confirm against the sensor's running "
                                   "configuration and its stats counters"),
            }},
            "state": "CANDIDATE"}


def assess_sensor_health(events, sensor: str = "sensor", tenant: str = "homelab",
                         **kwargs) -> dict | None:
    """`tally_checksum_anomalies` + `to_sensor_health` over one window of events."""
    t = tally_checksum_anomalies(events)
    return to_sensor_health(t["checksum"], t["anomalies"], sensor, tenant,
                            other_decode_count=t["other_decode"], **kwargs)


# U8: deterministic statistical model; independent of asset-service/U7.
from statistics import median
from itertools import groupby


class OutboundBytesModel:
    VERSION = '1.0.0'

    def __init__(self, history_windows=288, min_samples=3, min_peers=2,
                 threshold=6.0, scale_floor=1024, *, store=None,
                 retention_seconds=28 * 86400, clock=time.time):
        if history_windows < min_samples or min_samples < 1 or min_peers < 1 or threshold <= 0 or scale_floor <= 0:
            raise ValueError('invalid baseline configuration')
        self.history_windows = history_windows
        self.min_samples = min_samples
        self.min_peers = min_peers
        self.threshold = threshold
        self.scale_floor = scale_floor
        self.history = []
        if retention_seconds <= 0:
            raise ValueError('retention_seconds must be positive')
        self.store = store
        self.retention_seconds = retention_seconds
        self._clock = clock
        self._snapshot = None

    def baseline(self, rows):
        values = [r['bytes_out'] for r in rows]
        if not values:
            return {'available': False, 'samples': 0}
        center = median(values)
        mad = median(abs(v - center) for v in values)
        return {'available': len(values) >= self.min_samples,
                'samples': len(values), 'median': center, 'mad': mad,
                'scale': max(1.4826 * mad, self.scale_floor, center * 0.1),
                'trained_from': iso(min(r['start'] for r in rows)),
                'trained_to': iso(max(r['end'] for r in rows))}

    @staticmethod
    def history_prefix(row):
        # Hash structured identity: tenant delimiters and IPv6 cannot collide or
        # inject Redis glob patterns into the cohort lookup.
        identity = json.dumps([row['tenant'], row['cohort']], sort_keys=True)
        return 'ob:v1:' + hashlib.sha256(identity.encode()).hexdigest() + ':'

    def _stored_history(self, row):
        prefix = self.history_prefix(row)
        cutoff = row['start'] - self.history_windows * (row['end'] - row['start'])
        return [r for key in self.store.keys_matching(prefix)
                if cutoff <= float(key.rsplit(':', 1)[1]) < row['start']
                and (r := self.store.kv_get(key)) is not None]

    def _learn(self, row):
        # History needs only these six fields; retaining per-flow evidence for four
        # weeks would make storage proportional to traffic, not entity windows.
        value = {k: row[k] for k in ('tenant', 'cohort', 'entity', 'start', 'end', 'bytes_out')}
        identity = json.dumps(row['entity'])
        key = (self.history_prefix(row) + hashlib.sha256(identity.encode()).hexdigest()
               + ':' + str(row['start']))
        ttl = row['end'] + self.retention_seconds - self._clock()
        self.store.kv_set_once(key, value, ttl)

    def score(self, row):
        history = self.history
        if self.store is not None:
            history = (self._stored_history(row) if self._snapshot is None
                       else self._snapshot[self.history_prefix(row)])
        relevant = [r for r in history if r['tenant'] == row['tenant']
                    and r['cohort'] == row['cohort'] and r['end'] <= row['start']]
        own = self.baseline([r for r in relevant if r['entity'] == row['entity']])
        peers = [r for r in relevant if r['entity'] != row['entity']]
        peer = self.baseline(peers)
        members = sorted({r['entity'] for r in peers})
        peer['available'] = peer['available'] and len(members) >= self.min_peers
        deviations = {name: max(0.0, (row['bytes_out'] - b['median']) / b['scale'])
                      for name, b in [('entity', own), ('peer', peer)] if b['available']}
        # No entity-only fallback: both baselines, or explicitly peer-only cold start.
        if not peer['available']:
            return None
        score = min(deviations.values())
        if score <= self.threshold:
            return None
        explanation = {
            'schema': 'cernity.anomaly.v1',
            'features': {'bytes_out': row['bytes_out'], 'unit': 'bytes',
                         'schema_version': 'outbound-bytes.v1',
                         'semantics': 'conn bytes_toserver attributed at normalized observation time',
                         'time_methods': row['time_methods']},
            'window': {'start': iso(row['start']), 'end': iso(row['end'])},
            'entity_baseline': own, 'peer_baseline': peer,
            'cohort': {**row['cohort'], 'tenant': row['tenant'],
                       'entity': row['entity'], 'peer_members': members,
                       'excludes_scored_entity': True},
            'model': {'name': 'outbound-bytes-baseline', 'version': self.VERSION,
                      'type': 'median-mad', 'history_windows': self.history_windows,
                      'min_samples': self.min_samples, 'min_peers': self.min_peers,
                      'scale_floor_bytes': self.scale_floor, 'relative_scale_floor': 0.1,
                      'mad_multiplier': 1.4826},
            'mode': 'entity-and-peer' if own['available'] else 'peer-only-cold-start',
            'score': score, 'threshold': self.threshold, 'deviations': deviations,
            'top_contributors': [{'feature': 'bytes_out', 'contribution': 1.0}],
            'evidence_refs': row['evidence_refs']}
        identity = json.dumps([row['tenant'], row['entity'], row['start'], self.VERSION], separators=(',', ':'))
        return {'finding_id': 'outbytes-' + hashlib.sha256(identity.encode()).hexdigest(),
                'tenant_id': row['tenant'], 'sensor_ids': row['sensor_ids'],
                'detector_id': 'outbound_bytes_anomaly', 'detector_version': self.VERSION,
                'category': 'anomaly', 'severity': 6,
                'confidence': 0.8 if own['available'] else 0.5,
                'first_seen': iso(row['start']), 'last_seen': iso(row['end']),
                'entities': json.dumps([{'type': 'ip', 'role': 'src', 'value': row['entity']}]),
                'evidence_refs': row['evidence_refs'], 'summary': {'anomaly': explanation},
                'state': 'CANDIDATE'}

    def evaluate(self, rows):
        findings = []
        for start, batch in groupby(sorted(rows, key=lambda r: (r['start'], r['tenant'], r['entity'])),
                                    key=lambda r: r['start']):
            batch = list(batch)
            width = batch[0]['end'] - start
            self.history = [r for r in self.history if r['start'] >= start - self.history_windows * width]
            # Score the whole window before learning any of it: no order-dependent peer leakage.
            if self.store is not None:
                # One cohort read per window, shared by every entity's score. The
                # snapshot also prevents mid-batch arrivals changing peer membership.
                self._snapshot = {}
                for row in batch:
                    prefix = self.history_prefix(row)
                    if prefix not in self._snapshot:
                        self._snapshot[prefix] = self._stored_history(row)
            try:
                findings.extend(c for row in batch if (c := self.score(row)) is not None)
            finally:
                self._snapshot = None
            if self.store is None:
                self.history.extend(batch)
            else:
                for row in batch:
                    self._learn(row)
        return findings
