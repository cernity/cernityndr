"""Load service under a unique namespace to avoid other services' app.py imports."""
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).parent
# Production runs with this directory on sys.path. Tests restore generic modules
# after loading so repository-wide collection cannot change their dependencies.
def load(name):
    spec = importlib.util.spec_from_file_location('investigation_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

saved = {name: sys.modules.get(name) for name in ('playbooks', 'auth', 'queries', 'engine')}
sys.path.insert(0, str(HERE))
try:
    # Avoid inheriting an unrelated playbooks package in combined test runs.
    sys.modules.pop('playbooks', None)
    auth = load('auth')
    sys.modules['auth'] = auth
    queries = load('queries')
    sys.modules['queries'] = queries
    engine = load('engine')
    sys.modules['engine'] = engine
    app = load('app')
finally:
    sys.path.remove(str(HERE))
    for name, previous in saved.items():
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous

import copy
import pytest

REQUEST = {'entity_id': '192.0.2.1', 'finding_ids': ['f-beacon'], 'reason': 'Triage seeded finding',
           'window': {'from': '2026-09-28T00:00:00Z', 'to': '2026-09-29T00:00:00Z'}}


class SeededSources:
    def __init__(self):
        self.dns = [{'schema': 'cernity.observation.v1', 'sensor_id': 'sensor-a', 'obs_id': 'obs:' + 'a' * 64, 'tenant': 'A', 'type': 'dns',
                     'ts': {'normalized': '2026-09-28T01:00:00Z',
                            'sensor': '2026-09-28T01:00:00Z', 'ingested': '2026-09-28T01:00:00Z',
                            'method': 'ingest-fallback', 'clock_offset_ms': None},
                     'fields': {'dns': {'query': 'example.test'}},
                     'capabilities': ['dns-transaction'],
                     'source_ref': {'kind': 'clickhouse-row', 'table': 'ndr.dns_transaction',
                                    'tenant': 'A', 'obs_id': 'obs:' + 'a' * 64,
                                    'sha256': 'b' * 64, 'topic': 'suricata.dns.v1',
                                    'partition': 0, 'offset': 1},
                     'entities': [{'type': 'ip', 'role': 'src', 'value': '192.0.2.1'}]}]
        self.rows = [dict(finding_id=fid, tenant_id='A', detector_id=detector,
                          entities=[{'type': 'ip', 'value': '192.0.2.1'}],
                          first_seen='2026-09-28T01:00:00Z', last_seen='2026-09-28T02:00:00Z',
                          revision=1, state='FINAL', confidence=0.9, category='c2',
                          detector_version='1.0', severity=8)
                     for fid, detector in [('f-beacon', 'beacon'), ('f-intel', 'threat_intel')]]
        self.case_doc = {'case_id': 'c1', 'tenant': 'A', 'title': 'Triage',
                         'owner': None, 'assignees': [], 'status': 'new', 'notes': [],
                         'created': '2026-09-28T01:00:00Z', 'updated': '2026-09-28T01:00:00Z',
                         'audit': [{'event': 'created', 'actor': 'analyst', 'ts': '2026-09-28T01:00:00Z'}],
                         'linked_entities': [{'type': 'ip', 'value': '192.0.2.1'}],
                         'linked_findings': ['f-beacon', 'f-intel']}
        self.reads = []

    def observations(self, tenant, request):
        self.reads.append(('observations', tenant))
        return copy.deepcopy([r for r in self.dns if r['tenant'] == tenant])

    def findings(self, tenant, request):
        self.reads.append(('findings', tenant))
        return copy.deepcopy([r for r in self.rows if r['tenant_id'] == tenant])

    def case(self, tenant, case_id):
        self.reads.append(('case', tenant))
        return copy.deepcopy(self.case_doc)


@pytest.fixture
def service():
    from types import SimpleNamespace
    return SimpleNamespace(app=app, auth=auth, engine=engine, queries=queries,
                           sources=SeededSources(), request=copy.deepcopy(REQUEST))
