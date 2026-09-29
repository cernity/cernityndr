"""U6 bounded preserve contract, signatures and reservation accounting.

Policy and signing keys are local administrator configuration, never bus claims.
The secure bus and tenant-bound producer ACLs remain a U1b deployment prerequisite.
"""
import hashlib
import hmac
import ipaddress
import json
import math
import os
import tempfile
import threading
import time

TOPIC = 'ndr.capture.request.v2'


def canonical(doc):
    return json.dumps(doc, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sign(doc, key):
    if not isinstance(key, str) or len(key) < 32:
        raise ValueError('preserve signing key must be at least 32 characters')
    return hmac.new(key.encode(), canonical(doc), hashlib.sha256).hexdigest()


def validate(doc, now):
    """Structural AND semantic checks; no coercion of booleans/NaN into budgets."""
    try:
        allowed = {'schema_version', 'mode', 'request_id', 'tenant_id', 'sensor_id',
                   'finding_id', 'reason', 'policy_id', 'capture_profile', 'value',
                   'window', 'limits', 'expires_at', 'authorization'}
        if not isinstance(doc, dict) or set(doc) - allowed:
            raise ValueError('unknown request fields')
        if set(doc['window']) != {'start', 'end'} or set(doc['limits']) != {'max_bytes', 'max_duration_s', 'retention_s'}:
            raise ValueError('unknown window or limit fields')
        for field in ('request_id', 'tenant_id', 'sensor_id', 'finding_id', 'reason', 'policy_id'):
            if not isinstance(doc[field], str) or not doc[field].strip() or len(doc[field]) > 128:
                raise ValueError(field)
        if doc['schema_version'] != 'capture-request.v2' or doc['mode'] != 'preserve':
            raise ValueError('version/mode')
        if doc['capture_profile'] != 'ip':
            raise ValueError('only IP selectors are supported')
        ipaddress.ip_address(doc['value'])
        for value in (doc['window']['start'], doc['window']['end'], doc['expires_at']):
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError('timestamp')
        limits = doc['limits']
        for name in ('max_bytes', 'max_duration_s', 'retention_s'):
            if type(limits[name]) is not int or limits[name] <= 0:
                raise ValueError(name)
        start, end = doc['window']['start'], doc['window']['end']
        if not start < end <= now or end - start > limits['max_duration_s']:
            raise ValueError('window must be bounded and fully elapsed')
        if not now < doc['expires_at'] <= end + 300:
            raise ValueError('expired or excessive request lifetime')
        if limits['max_bytes'] < 40:
            raise ValueError('object budget too small')
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise ValueError('invalid preserve request') from exc


def validate_policy(policy, now):
    if policy.get('enabled') is not True or policy.get('sensitive') is not False:
        raise PermissionError('preserve policy denied')
    for name in ('tenant_id', 'sensor_id', 'policy_id'):
        if not isinstance(policy.get(name), str) or not policy[name].strip():
            raise PermissionError('invalid preserve policy identity')
    for name in ('expires_at', 'ring_seconds'):
        value = policy.get(name)
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise PermissionError('invalid preserve policy duration')
    if now >= policy['expires_at']:
        raise PermissionError('preserve policy expired')
    for name in ('max_bytes', 'max_duration_s', 'retention_s', 'max_jobs',
                 'requests_per_hour', 'bytes_per_hour', 'tenant_bytes_per_hour'):
        if type(policy.get(name)) is not int or policy[name] <= 0:
            raise PermissionError('invalid preserve policy budget')
    if not isinstance(policy.get('signing_key'), str) or len(policy['signing_key']) < 32:
        raise PermissionError('invalid preserve policy signing key')


def authorize(doc, policy, now, verify=True):
    validate(doc, now)
    validate_policy(policy, now)
    if (policy.get('enabled') is not True or policy.get('sensitive') is not False
            or doc['tenant_id'] != policy.get('tenant_id')
            or doc['sensor_id'] != policy.get('sensor_id')
            or doc['policy_id'] != policy.get('policy_id')
            or now >= policy.get('expires_at', 0)):
        raise PermissionError('preserve policy denied')
    for name in ('max_bytes', 'max_duration_s', 'retention_s'):
        if doc['limits'][name] > policy.get(name, 0):
            raise PermissionError('preserve policy budget exceeded')
    if doc['window']['start'] < now - policy.get('ring_seconds', 0):
        raise PermissionError('window outside policy retention')
    if verify:
        unsigned = {k: v for k, v in doc.items() if k != 'authorization'}
        supplied = doc.get('authorization', '')
        if not isinstance(supplied, str) or not hmac.compare_digest(supplied, sign(unsigned, policy.get('signing_key'))):
            raise PermissionError('invalid preserve authorization')


class Budget:
    """Rolling-hour reservations, charged at requested maximum (no refund on failure).

    Active reservations and dedup are bounded by requests/hour. One authoritative
    orchestrator instance is required; fleet-wide distributed accounting is deferred.
    """
    def __init__(self, clock=time.time, state_path=None):
        self.clock, self.state_path = clock, state_path
        self.entries = {}
        self.lock = threading.Lock()
        if state_path and os.path.exists(state_path):
            with open(state_path) as source:
                saved = json.load(source)
            self.entries = {(row['tenant'], row['request']): row for row in saved}

    def _save(self):
        if not self.state_path:
            return
        directory = os.path.dirname(os.path.abspath(self.state_path))
        # Parent must be an administrator-provisioned persistent private volume.
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', dir=directory, delete=False) as out:
                tmp = out.name
                json.dump(list(self.entries.values()), out, allow_nan=False)
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp, self.state_path)
            fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)

    def reserve(self, doc, policy):
        with self.lock:
            now = self.clock()
            self.entries = {k: v for k, v in self.entries.items() if v['active'] or now - v['ts'] < 3600}
            key = (doc['tenant_id'], doc['request_id'])
            if key in self.entries:
                raise ValueError('duplicate preserve request')
            sensor = [v for v in self.entries.values() if v['sensor'] == doc['sensor_id']]
            tenant = [v for v in self.entries.values() if v['tenant'] == doc['tenant_id']]
            size = doc['limits']['max_bytes']
            if (sum(v['active'] for v in sensor) >= policy['max_jobs']
                    or len(sensor) >= policy['requests_per_hour']
                    or sum(v['bytes'] for v in sensor) + size > policy['bytes_per_hour']
                    or sum(v['bytes'] for v in tenant) + size > policy['tenant_bytes_per_hour']):
                raise ValueError('preserve budget exhausted')
            self.entries[key] = dict(ts=now, active=True, sensor=doc['sensor_id'],
                                     tenant=doc['tenant_id'], request=doc['request_id'], bytes=size)
            self._save()

    def finish(self, doc):
        with self.lock:
            item = self.entries.get((doc.get('tenant_id'), doc.get('request_id')))
            if item and item['sensor'] == doc.get('sensor_id'):
                item['active'] = False
                self._save()
