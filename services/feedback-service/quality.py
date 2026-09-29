"""Read-only disposition quality, joined to the tenant-scoped findings store.

Units are accepted disposition records, not unique findings. Windowing uses the
source disposition timestamp, [from,to). Benign and explicit FP are negative
outcomes. Rates describe reviewed feedback, not recall or population FPR.
"""
from datetime import datetime, timezone
import json
import math
import sqlite3
from pathlib import Path

MIN_SAMPLE = 30


def parse_window(start, end):
    def parse(value):
        dt = datetime.fromisoformat(value.upper().replace('Z', '+00:00'))
        if dt.tzinfo is None:
            raise ValueError('timezone required')
        return dt.astimezone(timezone.utc)
    a, b = parse(start), parse(end)
    if b <= a:
        raise ValueError('to must be after from')
    return a, b


def authenticate(tokens, authorization, now):
    token = authorization[7:] if authorization.startswith('Bearer ') else None
    session = tokens.get(token)
    if not isinstance(session, dict):
        raise PermissionError('unauthorized')
    expiry = session.get('expires_at')
    tenant = session.get('tenant')
    if (not isinstance(tenant, str) or not tenant.strip()
            or session.get('quality_read') is not True
            or type(expiry) not in (int, float) or not math.isfinite(expiry)
            or now >= expiry):
        raise PermissionError('unauthorized')
    return tenant


def rate(numerator, denominator):
    """95% Wilson score interval; no observations means unknown, never zero."""
    if not denominator:
        return {'numerator': numerator, 'denominator': 0, 'value': None,
                'confidence_interval': None, 'low_confidence': True}
    p, z = numerator / denominator, 1.959963984540054
    scale = 1 + z * z / denominator
    center = (p + z * z / (2 * denominator)) / scale
    half = z * math.sqrt(p * (1 - p) / denominator + z * z / (4 * denominator**2)) / scale
    return {'numerator': numerator, 'denominator': denominator, 'value': p,
            'confidence_interval': {'lower': max(0, center - half), 'upper': min(1, center + half)},
            'low_confidence': denominator < MIN_SAMPLE}


class FindingsStore:
    """Use the existing finding-service ClickHouse table; bind all identifiers."""
    def __init__(self, client):
        self.client = client

    def detectors(self, tenant, finding_ids):
        out = {}
        ids = sorted(finding_ids)
        for offset in range(0, len(ids), 1000):
            result = self.client.query(
                'SELECT finding_id, argMax(detector_id, tuple(revision, ingested_at)) '
                'FROM ndr.finding WHERE tenant_id = {tenant:String} '
                'AND finding_id IN {ids:Array(String)} GROUP BY finding_id',
                parameters={'tenant': tenant, 'ids': ids[offset:offset + 1000]})
            out.update({fid: detector for fid, detector in result.result_rows if detector})
        return out


def report(database, findings, tenant, start, end):
    # mode=ro ensures metrics never create/mutate a database or its feedback.
    db = sqlite3.connect(Path(database).resolve().as_uri() + '?mode=ro', uri=True)
    records = []
    try:
        for (raw,) in db.execute('SELECT record FROM feedback WHERE tenant = ?', (tenant,)):
            record = json.loads(raw)
            ts = datetime.fromisoformat(record['source_ts'].upper().replace('Z', '+00:00'))
            if start <= ts < end:
                records.append(record)
    finally:
        db.close()
    linked = [r for r in records if r['verdict'] != 'allowlist']
    if linked and findings is None:
        raise RuntimeError('findings store unavailable')
    mapping = findings.detectors(tenant, {r['finding_id'] for r in linked}) if linked else {}
    groups, unresolved = {}, 0
    for record in linked:
        detector = mapping.get(record['finding_id'])
        if not detector:
            unresolved += 1
            continue
        counts = groups.setdefault(detector, {'true_positive': 0, 'false_positive': 0, 'benign': 0})
        counts[record['verdict']] += 1
    detectors = []
    for detector, counts in sorted(groups.items()):
        total = sum(counts.values())
        detectors.append({'detector_id': detector, 'counts': counts,
                          'precision': rate(counts['true_positive'], total),
                          'fp_rate': rate(counts['false_positive'] + counts['benign'], total)})
    return {'schema_version': 'quality.v1', 'tenant': tenant,
            'window': {'from': start.isoformat(), 'to': end.isoformat(),
                       'time_basis': 'disposition.ts', 'bounds': '[from,to)'},
            'unit': 'disposition_records', 'interval_method': 'wilson_95',
            'low_confidence_below': MIN_SAMPLE, 'advisory_only': True,
            'total_dispositions': len(records), 'unattributed_dispositions': unresolved,
            'detectors': detectors,
            'entity_allowlist_suggestion_rate': rate(len(records) - len(linked), len(records))}
