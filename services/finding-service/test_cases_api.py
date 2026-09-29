"""U8 HTTP tests against real SQLite, including authentication and audit atomicity."""
import io
import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

import app

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('u8_case_store', HERE / 'store.py')
store_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(store_module)
VALIDATOR = Draft202012Validator(json.loads(
    (HERE.parents[1] / 'contracts/case.schema.json').read_text()), format_checker=FormatChecker())


@pytest.fixture
def api(tmp_path):
    store = store_module.CaseStore(str(tmp_path / 'cases.sqlite3'))
    sessions = {key: {'tenant': tenant, 'analyst': actor, 'expires_at': expiry,
                      'case_write': write}
                for key, tenant, actor, expiry, write in [
                    ('alice', 'a', 'alice', 2000, True),
                    ('bob', 'a', 'bob', 2000, True),
                    ('other', 'b', 'mallory', 2000, True),
                    ('reader', 'a', 'auditor', 2000, False),
                    ('expired', 'a', 'alice', 999, True)]}
    handler = app.make_case_handler(store, sessions, now=lambda: 1000)

    class Connection:
        def __init__(self, raw):
            self.input = io.BytesIO(raw)
            self.output = io.BytesIO()

        def makefile(self, *args):
            return self.input

        def sendall(self, data):
            self.output.write(data)

        def settimeout(self, value):
            pass

    def request(method='GET', path='/cases', data=None, token='alice', headers=None):
        hs = {'Authorization': 'Bearer ' + token} if token else {}
        body = json.dumps(data).encode() if data is not None else b''
        hs['Content-Length'] = str(len(body))
        hs.update(headers or {})
        raw = (f'{method} {path} HTTP/1.1\r\nHost: localhost\r\n'
               + ''.join(f'{k}: {v}\r\n' for k, v in hs.items()) + '\r\n').encode() + body
        connection = Connection(raw)
        handler(connection, ('127.0.0.1', 1234), None)
        head, payload = connection.output.getvalue().split(b'\r\n\r\n', 1)
        result = int(head.split()[1]), json.loads(payload)
        if result[0] < 300:
            if 'case_id' in result[1]:
                VALIDATOR.validate(result[1])
            for doc in result[1].get('cases', []):
                VALIDATOR.validate(doc)
        return result

    yield request, store
    store._db.close()


def create(request, token='alice', **fields):
    code, doc = request('POST', '/cases', {'title': 'Triage', **fields}, token)
    assert code == 201
    return doc


@pytest.mark.parametrize('token', [None, 'unknown', 'expired'])
@pytest.mark.parametrize('method,path,body', [
    ('GET', '/cases', None), ('GET', '/cases/c1', None),
    ('POST', '/cases', {'title': 'x'}), ('POST', '/cases/c1/notes', {'text': 'x'}),
    ('DELETE', '/cases/c1/findings', {'finding_id': 'x'})])
def test_unauthenticated(api, token, method, path, body):
    request, _ = api
    assert request(method, path, body, token)[0] == 401


def test_lifecycle_and_audit(api):
    request, store = api
    doc = create(request)
    cid = doc['case_id']
    assert doc['tenant'] == 'a' and doc['owner'] == 'alice'
    actions = [
        ('POST', 'owner', {'owner': 'bob'}, 'owner_changed'),
        ('POST', 'assign', {'assignee': 'bob'}, 'assignee_added'),
        ('POST', 'assign', {'assignee': 'bob'}, 'assignee_added'),  # audited no-op
        ('POST', 'notes', {'text': 'Investigating'}, 'note_added'),
        ('POST', 'findings', {'finding_id': 'f1'}, 'finding_linked'),
        ('POST', 'entities', {'entity': {'type': 'ip', 'value': '192.0.2.1'}}, 'entity_linked'),
        ('POST', 'status', {'status': 'investigating'}, 'status_changed'),
        ('POST', 'status', {'status': 'resolved'}, 'status_changed'),
        ('POST', 'status', {'status': 'closed'}, 'status_changed'),
        ('DELETE', 'findings', {'finding_id': 'f1'}, 'finding_unlinked'),
        ('DELETE', 'entities', {'entity': {'type': 'ip', 'value': '192.0.2.1'}}, 'entity_unlinked'),
        ('DELETE', 'assign', {'assignee': 'bob'}, 'assignee_removed'),
    ]
    for method, route, body, event in actions:
        code, after = request(method, f'/cases/{cid}/{route}', body, 'bob')
        assert code == 200
        assert after['audit'][:-1] == doc['audit']
        assert after['audit'][-1]['event'] == event
        assert after['audit'][-1]['actor'] == 'bob'
        assert after['audit'][-1]['detail']['outcome'] == 'success'
        assert after == store.get(cid, {'a'})
        doc = after
    assert doc['status'] == 'closed' and doc['owner'] == 'bob'
    assert doc['notes'][0]['author'] == 'bob'
    assert doc['linked_findings'] == doc['linked_entities'] == doc['assignees'] == []
    assert request('GET', f'/cases/{cid}')[1] == doc
    assert len({e['detail']['audit_id'] for e in doc['audit']}) == len(doc['audit'])


def test_cross_tenant_and_read_only(api):
    request, store = api
    doc = create(request)
    path = '/cases/' + doc['case_id']
    assert request('GET', path, token='other')[0] == 404
    for method, route, body in [
        ('POST', 'owner', {'owner': 'mallory'}), ('POST', 'assign', {'assignee': 'mallory'}),
        ('POST', 'notes', {'text': 'attack'}), ('POST', 'status', {'status': 'investigating'}),
        ('POST', 'findings', {'finding_id': 'f'}),
        ('DELETE', 'findings', {'finding_id': 'f'}),
        ('POST', 'entities', {'entity': {'type': 'ip', 'value': 'x'}}),
        ('DELETE', 'entities', {'entity': {'type': 'ip', 'value': 'x'}}),
    ]:
        assert request(method, path + '/' + route, body, 'other')[0] == 404
        assert request(method, path + '/' + route, body, 'reader')[0] == 403
    assert store.get(doc['case_id'], {'a'}) == doc
    assert request(token='other')[1]['cases'] == []
    assert request('GET', path, token='reader')[0] == 200


@pytest.mark.parametrize('field', ['tenant', 'tenant_id', 'actor', 'analyst', 'author', 'audit', 'case_id', 'ts'])
def test_identity_claims_rejected(api, field):
    request, _ = api
    assert request('POST', '/cases', {'title': 'x', field: 'spoof'})[0] == 400
    doc = create(request)
    assert request('POST', '/cases/' + doc['case_id'] + '/notes', {'text': 'x', field: 'spoof'})[0] == 400
    assert request(path='/cases?' + field + '=b')[0] == 400


def test_identity_headers_are_not_grants(api):
    request, _ = api
    code, doc = request('POST', '/cases', {'title': 'x'}, headers={
        'X-Tenant': 'b', 'X-Analyst': 'mallory', 'X-Forwarded-User': 'mallory'})
    assert code == 201
    assert doc['tenant'] == 'a' and doc['audit'][0]['actor'] == 'alice'


def test_invalid_transition_is_atomic(api):
    request, store = api
    before = create(request)
    assert request('POST', '/cases/' + before['case_id'] + '/status', {'status': 'resolved'})[0] == 400
    assert store.get(before['case_id'], {'a'}) == before


def test_pagination_filters_in_sql(api):
    request, store = api
    docs = [create(request, owner='alice') for _ in range(3)]
    create(request, owner='bob')
    create(request, token='other')
    queries = []
    store._db.set_trace_callback(queries.append)
    first = request(path='/cases?owner=alice&status=new&limit=2')[1]
    second = request(path='/cases?owner=alice&status=new&limit=2&offset=2')[1]
    assert first['next_offset'] == 2 and second['next_offset'] is None
    assert [d['case_id'] for d in first['cases'] + second['cases']] == sorted(d['case_id'] for d in docs)
    assert any('LIMIT 3 OFFSET 2' in q and "tenant='a'" in q for q in queries)
    for query in ['limit=0', 'limit=201', 'offset=-1', 'limit=x', 'status=bad', 'owner=', 'limit=1&limit=2']:
        assert request(path='/cases?' + query)[0] == 400


@pytest.mark.parametrize('body', [None, [], {'title': ''}, {'title': ' '}, {'title': 'x' * 1025},
                                  {'title': 'x', 'owner': 1}])
def test_bad_create(api, body):
    request, _ = api
    assert request('POST', '/cases', body)[0] == 400


def test_store_failure_returns_unavailable(api, monkeypatch):
    request, store = api
    def fail(*args):
        raise RuntimeError('storage unavailable')
    monkeypatch.setattr(store, 'create', fail)
    assert request('POST', '/cases', {'title': 'x'})[0] == 503


@pytest.mark.parametrize('route,body', [
    ('assign', {'assignee': ''}), ('owner', {'owner': []}),
    ('notes', {'text': 'x' * 8193}), ('notes', {'text': ' '}),
    ('status', {'status': []}), ('findings', {'finding_id': 3}),
    ('entities', {'entity': {'type': 'mac', 'value': 'x'}}),
    ('entities', {'entity': {'type': 'ip', 'value': ''}}),
    ('entities', {'entity': {'type': 'ip', 'value': 'x', 'tenant': 'b'}}),
])
def test_invalid_mutations_leave_state_unchanged(api, route, body):
    request, store = api
    before = create(request)
    assert request('POST', f"/cases/{before['case_id']}/{route}", body)[0] == 400
    assert store.get(before['case_id'], {'a'}) == before


def test_database_failure_rolls_back_audit_and_note(api):
    request, store = api
    before = create(request)
    store._db.execute("CREATE TRIGGER reject_update BEFORE UPDATE ON cases "
                      "BEGIN SELECT RAISE(ABORT, 'write rejected'); END")
    assert request('POST', f"/cases/{before['case_id']}/notes", {'text': 'triage'})[0] == 503
    assert store.get(before['case_id'], {'a'}) == before
    store._db.execute('DROP TRIGGER reject_update')
    code, after = request('POST', f"/cases/{before['case_id']}/notes", {'text': 'retry'})
    assert code == 200 and len(after['audit']) == 2
    assert [note['text'] for note in after['notes']] == ['retry']


def test_body_and_page_bounds(api):
    request, _ = api
    assert request('POST', '/cases', {'title': 'x'}, headers={'Content-Length': '65537'})[0] == 400
    assert request('POST', '/cases', {'title': 'x'}, headers={'Transfer-Encoding': 'chunked'})[0] == 400
    assert request(path='/cases?offset=1000001')[0] == 400
    page = request()[1]
    assert page == {'cases': [], 'limit': 50, 'offset': 0, 'next_offset': None}
