"""Promote Suricata protocol-anomaly events to findings (re-eval gap G4).

`suricata.anomaly.v1` was produced but consumed by nobody. Application-layer
anomalies (protocol violations, unexpected events) are evasion/exploit tells;
decode-layer anomalies (bad checksums, malformed L2/L3) are engine noise. This
filters to the threat-relevant ones and emits finding candidates. Pure + testable.
"""
from __future__ import annotations

import hashlib
import json
import time


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


# U8: deterministic statistical model; independent of asset-service/U7.
from statistics import median
from itertools import groupby
from features import iso


class OutboundBytesModel:
    VERSION = '1.0.0'

    def __init__(self, history_windows=288, min_samples=3, min_peers=2,
                 threshold=6.0, scale_floor=1024):
        if history_windows < min_samples or min_samples < 1 or min_peers < 1 or threshold <= 0 or scale_floor <= 0:
            raise ValueError('invalid baseline configuration')
        self.history_windows = history_windows
        self.min_samples = min_samples
        self.min_peers = min_peers
        self.threshold = threshold
        self.scale_floor = scale_floor
        self.history = []

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

    def score(self, row):
        relevant = [r for r in self.history if r['tenant'] == row['tenant']
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
            findings.extend(c for row in batch if (c := self.score(row)) is not None)
            self.history.extend(batch)
        return findings
