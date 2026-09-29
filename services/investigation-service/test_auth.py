import io
import json

import pytest


@pytest.mark.parametrize('header,session,error', [
    ('', {}, 'unauthorized'), ('Bearer unknown', {}, 'unauthorized'),
    ('Bearer tok', {'tenant': 'A', 'expires_at': 1, 'investigation_read': True}, 'unauthorized'),
    ('Bearer tok', {'tenant': ['A', 'B'], 'expires_at': 9999, 'investigation_read': True}, 'unauthorized'),
    ('Bearer tok', {'tenant': 'A', 'expires_at': float('nan'), 'investigation_read': True}, 'unauthorized'),
    ('Bearer tok', {'tenant': 'A', 'expires_at': 9999}, 'forbidden'),
])
def test_auth_fails_closed(service, header, session, error):
    with pytest.raises(PermissionError, match=error):
        service.auth.authorize({'tok': session}, header, now=10)


@pytest.fixture
def api(service):
    sessions = {token: {'tenant': tenant, 'expires_at': 4102444800, 'investigation_read': reader}
                for token, tenant, reader in [('tokA', 'A', True), ('tokB', 'B', True), ('writer', 'A', False)]}
    events = []
    handler = service.app.make_handler(service.sources, sessions, events.append)

    class Connection:
        def __init__(self, raw):
            self.input = io.BytesIO(raw)
            self.output = io.BytesIO()

        def makefile(self, *args):
            return self.input

        def sendall(self, data):
            self.output.write(data)

    def call(method, path, token=None, body=None):
        payload = json.dumps(body).encode() if body is not None else b''
        headers = {'Content-Length': str(len(payload))}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        raw = (f'{method} {path} HTTP/1.1\r\nHost: localhost\r\n'
               + ''.join(f'{k}: {v}\r\n' for k, v in headers.items()) + '\r\n').encode() + payload
        connection = Connection(raw)
        handler(connection, ('127.0.0.1', 1234), None)
        head, content = connection.output.getvalue().split(b'\r\n\r\n', 1)
        return int(head.split()[1]), json.loads(content)

    yield call, events


def test_http_auth_and_cross_tenant_investigation_denied(service, api):
    call, events = api
    assert call('POST', '/investigations', body=service.request)[0] == 401
    assert call('POST', '/investigations', 'unknown', service.request)[0] == 401
    assert call('POST', '/investigations', 'writer', service.request)[0] == 403
    assert not service.sources.reads
    status, result = call('POST', '/investigations', 'tokA', service.request)
    assert status == 200
    path = '/investigations/' + result['investigation_id']
    assert call('GET', path, 'tokA') == (200, result)
    assert call('GET', path, 'tokB')[0] == 404
    assert call('POST', '/investigations', 'tokB', service.request)[0] == 404
    assert 'tokA' not in json.dumps(events) and 'tokB' not in json.dumps(events)
    assert [e['status'] for e in events] == [401, 401, 403, 200, 200, 404, 404]


def test_tenant_spoofing_and_actions_rejected(service, api):
    call, _ = api
    for extra in ({'tenant': 'B'}, {'tenant_id': 'B'}, {'recommended_actions': ['execute']}, {'role': 'admin'}):
        assert call('POST', '/investigations', 'tokA', {**service.request, **extra})[0] == 400
    assert call('POST', '/investigations?tenant=B', 'tokA', service.request)[0] == 400
    assert not service.sources.reads


def test_backend_failure_is_controlled(service, api):
    call, _ = api

    def fail(*args):
        raise RuntimeError('private backend details')

    service.sources.observations = fail
    status, body = call('POST', '/investigations', 'tokA', service.request)
    assert status == 503
    assert 'private' not in json.dumps(body)
