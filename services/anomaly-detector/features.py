"""U4 conn features. Bytes sent by the source, not inferred Internet egress.

Counters are attributed to the observation's normalized-time window, not spread
across the flow lifetime. No missing windows or missing counters become zeros.
"""
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network


def iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace('+00:00', 'Z')


class FeatureExtractor:
    def __init__(self, window_seconds=300):
        if window_seconds <= 0:
            raise ValueError('window_seconds must be positive')
        self.window_seconds = window_seconds
        self.pending = {}
        self.closed_before = float('-inf')
        self.late_observations = 0

    def add(self, obs):
        if obs.get('schema') != 'cernity.observation.v1' or obs.get('type') != 'conn':
            return
        fields = obs.get('fields', {})
        value = fields.get('flow', {}).get('bytes_toserver')
        if type(value) is not int or value < 0:
            return
        try:
            tenant, obs_id, sensor = obs['tenant'], obs['obs_id'], obs['sensor_id']
            src = str(ip_address(fields['src_ip']))
            if not any(e.get('type') == 'ip' and e.get('role') == 'src'
                       and e.get('value') == fields['src_ip'] for e in obs['entities']):
                return
            stamp = datetime.fromisoformat(obs['ts']['normalized'].replace('Z', '+00:00'))
            if stamp.tzinfo is None or not all(isinstance(v, str) and v for v in (tenant, obs_id, sensor)):
                return
            start = int(stamp.timestamp() // self.window_seconds) * self.window_seconds
        except (KeyError, ValueError, TypeError):
            return
        if start < self.closed_before:
            self.late_observations += 1
            return
        subnet = str(ip_network(f'{src}/{24 if ip_address(src).version == 4 else 64}', strict=False))
        key = (start, tenant, src)
        row = self.pending.setdefault(key, {
            'tenant': tenant, 'entity': src, 'start': start,
            'end': start + self.window_seconds, 'bytes_out': 0,
            'cohort': {'subnet': subnet, 'role': 'src', 'method': 'source-ip-subnet-v1'},
            'evidence_refs': set(), 'sensor_ids': set(), 'time_methods': set()})
        if obs_id in row['evidence_refs']:
            return
        row['bytes_out'] += value
        row['evidence_refs'].add(obs_id)
        row['sensor_ids'].add(sensor)
        row['time_methods'].add(obs['ts'].get('method', 'unknown'))

    def close(self, watermark):
        """Caller supplies event-time watermark; older arrivals are counted/dropped."""
        boundary = int(watermark // self.window_seconds) * self.window_seconds
        rows = []
        for key in sorted(self.pending):
            if self.pending[key]['end'] <= boundary:
                row = self.pending.pop(key)
                rows.append({k: sorted(v) if isinstance(v, set) else v for k, v in row.items()})
        self.closed_before = max(self.closed_before, boundary)
        return rows
