import importlib.util
import json
from pathlib import Path
import sqlite3

import pytest
from jsonschema import ValidationError


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


app = load('feedback_app_test', 'app.py')
router = app.router


def payload(verdict='true_positive'):
    return {'finding_id': 'f1', 'entity': {'type': 'ip', 'value': '192.0.2.1'},
            'verdict': verdict, 'reason': 'Reviewed evidence', 'analyst': 'forged',
            'tenant': 'victim', 'ts': '2026-09-28T12:00:00Z',
            'scope': 'entity' if verdict == 'allowlist' else 'tenant'}


@pytest.fixture
def service(tmp_path):
    tokens = {token: {'emitter': 'vantage', 'analyst': actor, 'tenant': tenant,
                     'expires_at': 2000, 'disposition_write': True}
              for token, actor, tenant in [('secret', 'alice', 'a'), ('other', 'bob', 'b')]}
    return router.Router(str(tmp_path / 'feedback.db'), tokens, ttl_seconds=60, now=lambda: 1000)


@pytest.mark.parametrize('verdict,sink', [('true_positive', 'anomaly_ground_truth'),
    ('benign', 'anomaly_ground_truth'), ('false_positive', 'detector_fp_candidate'),
    ('allowlist', 'ignore_list')])
def test_routing_and_identity(service, verdict, sink):
    record = service.consume(payload(verdict), 'Bearer secret')
    assert record['sink'] == sink
    assert record['tenant'] == 'a' and record['owner'] == record['analyst'] == 'alice'
    assert record['scope'] == ('entity' if verdict == 'allowlist' else 'finding')
    assert record['emitter'] == 'vantage' and record['status'] == 'suggested'
    assert record['expires_at'] == 1060 and record['justification'] == 'Reviewed evidence'
    with service.connect() as db:
        event = json.loads(db.execute('SELECT event FROM audit').fetchone()[0])
        assert event['record'] == record and event['audit_id'] == record['audit_id']
        assert event['action'] == 'disposition.accepted'
    other = service.consume(payload(verdict), 'Bearer other')
    assert other['tenant'] == 'b' and other['owner'] == 'bob'


@pytest.mark.parametrize('auth', ['', 'Bearer bad', 'Basic secret'])
def test_unauthenticated(service, auth):
    with pytest.raises(PermissionError):
        service.consume(payload(), auth)
    with service.connect() as db:
        assert db.execute('SELECT count(*) FROM feedback').fetchone()[0] == 0


def test_expired_session_and_missing_permission(service):
    service.tokens['secret']['expires_at'] = 1000
    with pytest.raises(PermissionError):
        service.consume(payload(), 'Bearer secret')
    service.tokens['other']['disposition_write'] = False
    with pytest.raises(PermissionError):
        service.consume(payload(), 'Bearer other')


def test_malformed_no_writes(service):
    with pytest.raises(ValidationError):
        service.consume({'verdict': 'allowlist'}, 'Bearer secret')
    with service.connect() as db:
        assert db.execute('SELECT count(*) FROM audit').fetchone()[0] == 0


def test_audit_failure_rolls_back_route(service):
    with service.connect() as db:
        db.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END")
    with pytest.raises(sqlite3.IntegrityError):
        service.consume(payload(), 'Bearer secret')
    with service.connect() as db:
        assert db.execute('SELECT count(*) FROM feedback').fetchone()[0] == 0


def test_ignore_expiry_and_advisory_default(service):
    entry = service.consume(payload('allowlist'), 'Bearer secret')
    check = router.ignore_entry_suppresses
    assert not check(entry, 'a', entry['entity'], 1001)
    # Simulate separate, audited human approval; U9 has no path that does this.
    entry.update(status='applied', approval_audit_id='external-approval')
    assert check(entry, 'a', entry['entity'], 1059)
    assert not check(entry, 'a', entry['entity'], 1060)
    assert not check(entry, 'b', entry['entity'], 1001)
    assert not check(entry, 'a', {'type': 'ip', 'value': '192.0.2.2'}, 1001)


def test_persistence(service):
    record = service.consume(payload(), 'Bearer secret')
    reopened = router.Router(service.database, service.tokens)
    with reopened.connect() as db:
        assert json.loads(db.execute('SELECT record FROM feedback').fetchone()[0]) == record
        assert db.execute('SELECT count(*) FROM audit').fetchone()[0] == 1


def test_http_boundary(service):
    # Exercise the real handler without a listening socket (sandbox restriction).
    from io import BytesIO
    from types import SimpleNamespace
    def request(body, token):
        raw = json.dumps(body).encode()
        handler = object.__new__(app.make_handler(service))
        handler.path = '/dispositions'
        handler.headers = {'Authorization': token, 'Content-Length': str(len(raw)),
                           'X-Analyst': 'forged', 'X-Tenant': 'victim'}
        handler.rfile = BytesIO(raw)
        handler.connection = SimpleNamespace(settimeout=lambda _: None)
        handler.client_address = ('127.0.0.1', 12345)
        responses = []
        handler.send_json = lambda status, value: responses.append((status, value))
        handler.do_POST()
        return responses[0]
    status, record = request(payload(), 'Bearer secret')
    assert status == 202 and record['tenant'] == 'a' and record['owner'] == 'alice'
    assert request(payload(), 'Bearer bad')[0] == 401
    assert request({}, 'Bearer secret')[0] == 400
    with service.connect() as db:
        db.execute("CREATE TRIGGER fail_http BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'failure'); END")
    assert request(payload(), 'Bearer secret')[0] == 503


@pytest.mark.parametrize('ts', ['bad', '2026-02-30T12:00:00Z', '2026-09-28T12:00:00'])
def test_invalid_timestamp(service, ts):
    doc = payload()
    doc['ts'] = ts
    with pytest.raises(ValidationError):
        service.consume(doc, 'Bearer secret')
