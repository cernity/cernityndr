import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest
from jsonschema import Draft202012Validator, FormatChecker

spec = importlib.util.spec_from_file_location('quality_app_test', Path(__file__).with_name('app.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
q = app.quality


@pytest.fixture
def service(tmp_path):
    tokens = {token: {'tenant': tenant, 'emitter': 'vantage', 'analyst': 'alice',
                     'expires_at': 2000, 'disposition_write': True, 'quality_read': True}
              for token, tenant in [('a', 'a'), ('b', 'b')]}
    return app.router.Router(str(tmp_path / 'feedback.db'), tokens, now=lambda: 1000)


def add(service, verdict='true_positive', fid='f1', tenant='a', ts='2026-09-28T12:00:00Z'):
    return service.consume({'finding_id': fid, 'verdict': verdict,
                            'entity': {'type': 'ip', 'value': '192.0.2.1'},
                            'reason': 'Reviewed', 'analyst': 'forged', 'tenant': 'forged',
                            'scope': 'entity' if verdict == 'allowlist' else 'finding', 'ts': ts},
                           'Bearer ' + tenant)


class Store:
    def __init__(self):
        self.calls = []

    def detectors(self, tenant, ids):
        self.calls.append((tenant, ids))
        rows = {('a', 'f1'): 'dns', ('a', 'f2'): 'dns', ('a', 'f3'): 'beacon',
                ('b', 'f1'): 'other-detector'}
        return {fid: rows[(tenant, fid)] for fid in ids if (tenant, fid) in rows}


def report(service, store=None, tenant='a'):
    return q.report(service.database, store or Store(), tenant,
                    *q.parse_window('2026-09-28T12:00:00Z', '2026-09-29T12:00:00Z'))


def validate(result):
    schema = json.loads((Path(__file__).resolve().parents[2] / 'contracts/quality.schema.json').read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(result)


def test_join_and_allowlist(service):
    add(service)
    add(service, 'false_positive', 'f2')
    add(service, 'benign', 'f2')
    add(service, 'true_positive', 'f3')
    add(service, 'allowlist', None)
    # Legacy schema also permits finding ids on allowlists: still entity-only.
    add(service, 'allowlist', 'f1')
    store = Store()
    result = report(service, store)
    assert store.calls == [('a', {'f1', 'f2', 'f3'})]
    dns = result['detectors'][1]
    assert dns['detector_id'] == 'dns'
    assert dns['counts'] == {'true_positive': 1, 'false_positive': 1, 'benign': 1}
    assert dns['precision']['value'] == pytest.approx(1/3)
    assert dns['fp_rate']['value'] == pytest.approx(2/3)
    assert dns['precision']['denominator'] == 3
    allow = result['entity_allowlist_suggestion_rate']
    assert (allow['numerator'], allow['denominator'], allow['value']) == (2, 6, 1/3)
    assert result['advisory_only'] is True
    validate(result)


def test_thin_and_empty(service):
    empty = report(service)
    assert empty['detectors'] == []
    assert empty['entity_allowlist_suggestion_rate']['value'] is None
    validate(empty)
    add(service)
    metric = report(service)['detectors'][0]['precision']
    assert metric['low_confidence'] and metric['value'] == 1
    assert metric['confidence_interval']['lower'] == pytest.approx(0.2065493144)
    assert metric['confidence_interval']['upper'] == pytest.approx(1)
    assert not q.rate(20, 30)['low_confidence']


def test_half_open_source_window(service):
    for ts in ['2026-09-28T11:59:59.999999Z', '2026-09-28T12:00:00Z',
               '2026-09-29T11:59:59.999999Z', '2026-09-29T12:00:00Z',
               '2026-09-28T14:00:00+02:00']:
        add(service, ts=ts)
    result = report(service)
    assert result['total_dispositions'] == 3
    assert result['detectors'][0]['precision']['denominator'] == 3


def test_tenant_isolation_and_missing_findings(service):
    add(service)
    add(service, 'false_positive', tenant='b')
    add(service, fid='missing')
    a, b = report(service), report(service, tenant='b')
    assert a['detectors'][0]['detector_id'] == 'dns'
    assert a['detectors'][0]['precision']['value'] == 1
    assert a['unattributed_dispositions'] == 1
    assert b['detectors'][0]['detector_id'] == 'other-detector'
    assert b['detectors'][0]['fp_rate']['value'] == 1
    assert b['total_dispositions'] == 1


def request(service, path=None, token='a', store=None):
    handler = object.__new__(app.make_handler(service, lambda: store or Store()))
    handler.path = path or '/quality?' + urlencode({'from': '2026-09-28T12:00:00Z',
                                                   'to': '2026-09-29T12:00:00Z'})
    handler.headers = {'Authorization': 'Bearer ' + token, 'X-Tenant': 'b'}
    responses = []
    handler.send_json = lambda code, value: responses.append((code, value))
    handler.do_GET()
    return responses[0]


def test_read_only_http_auth_and_window(service):
    add(service)
    with service.connect() as db:
        before = list(db.iterdump())
    service.tokens['a']['disposition_write'] = False
    code, result = request(service)
    assert code == 200 and result['tenant'] == 'a'
    validate(result)
    with service.connect() as db:
        assert list(db.iterdump()) == before
    assert request(service, token='bad')[0] == 401
    service.tokens['a']['quality_read'] = False
    assert request(service)[0] == 401
    service.tokens['a']['quality_read'] = True
    service.tokens['a']['expires_at'] = 1000
    assert request(service)[0] == 401


@pytest.mark.parametrize('query', [
    '', 'from=bad&to=bad', 'from=2026-09-28&to=2026-09-29',
    'from=2026-09-29T12:00:00Z&to=2026-09-28T12:00:00Z',
    'from=2026-09-28T12:00:00Z&to=2026-09-28T12:00:00Z',
    'from=2026-09-28T12:00:00Z&to=2026-09-29T12:00:00Z&tenant=b',
    'from=x&from=y&to=z'])
def test_bad_query(service, query):
    assert request(service, '/quality?' + query)[0] == 400


def test_unavailable_not_empty(service):
    class Broken:
        def detectors(self, *args):
            raise RuntimeError('database unavailable')
    add(service)
    assert request(service, store=Broken()) == (503, {'error': 'quality unavailable'})
    with pytest.raises(RuntimeError):
        q.report(service.database, None, 'a',
                 *q.parse_window('2026-09-28T00:00:00Z', '2026-09-29T00:00:00Z'))


def test_clickhouse_join_is_bound_tenant_scoped_and_revision_aware():
    calls = []
    class Client:
        def query(self, sql, parameters):
            calls.append((sql, parameters))
            return SimpleNamespace(result_rows=[('f1', 'dns')])
    assert q.FindingsStore(Client()).detectors("tenant'", {'f1'}) == {'f1': 'dns'}
    sql, params = calls[0]
    assert 'tenant_id = {tenant:String}' in sql
    assert 'finding_id IN {ids:Array(String)}' in sql
    assert 'argMax(detector_id, tuple(revision, ingested_at))' in sql
    assert params == {'tenant': "tenant'", 'ids': ['f1']}
    assert "tenant'" not in sql


def test_production_factory_and_client_cleanup(service, monkeypatch):
    import sys
    calls, closed = [], []
    class Client:
        def query(self, sql, parameters):
            assert parameters == {'tenant': 'a', 'ids': ['f1']}
            return SimpleNamespace(result_rows=[('f1', 'actual-detector')])

        def close(self):
            closed.append(True)

    def connect(**kwargs):
        calls.append(kwargs)
        return Client()

    monkeypatch.setitem(sys.modules, 'clickhouse_connect', SimpleNamespace(get_client=connect))
    monkeypatch.setenv('CLICKHOUSE_HOST', 'test-host')
    monkeypatch.setenv('CLICKHOUSE_USER', 'quality-reader')
    monkeypatch.setenv('CLICKHOUSE_PASSWORD', 'test-password')
    add(service)
    handler = object.__new__(app.make_handler(service, app.findings_store))
    handler.path = '/quality?from=2026-09-28T12:00:00Z&to=2026-09-29T12:00:00Z'
    handler.headers = {'Authorization': 'Bearer a'}
    responses = []
    handler.send_json = lambda status, value: responses.append((status, value))
    handler.do_GET()
    assert responses[0][0] == 200
    assert responses[0][1]['detectors'][0]['detector_id'] == 'actual-detector'
    assert calls[0]['host'] == 'test-host' and calls[0]['username'] == 'quality-reader'
    assert calls[0]['password'] == 'test-password'
    assert closed == [True]


def test_clickhouse_batches_all_ids():
    seen = []
    class Client:
        def query(self, sql, parameters):
            ids = parameters['ids']
            assert len(ids) <= 1000
            seen.extend(ids)
            return SimpleNamespace(result_rows=[(fid, 'detector') for fid in ids])
    ids = {str(i) for i in range(2001)}
    result = q.FindingsStore(Client()).detectors('a', ids)
    assert set(result) == ids and set(seen) == ids and len(seen) == 2001
