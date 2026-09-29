"""POST /investigations runs read-only triage; GET /investigations/{id} reads it.

Results are a bounded process-local cache, not a durable investigation store.
Restart/eviction returns 404; repeat POST against the same snapshot reproduces ID.
"""
import copy
import hashlib
import json
import logging
import os
import threading
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import auth
import engine
import queries

log = logging.getLogger('investigation-service')


def make_handler(sources, sessions, audit=None):
    sessions = copy.deepcopy(sessions)
    results, lock = OrderedDict(), threading.Lock()
    audit = audit or (lambda event: log.info(json.dumps(event, sort_keys=True)))

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, status, value):
            body = json.dumps(value, allow_nan=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def handle_request(self):
            url = urlsplit(self.path)
            if self.command == 'GET' and url.path == '/healthz':
                return self.send(200, {'status': 'ok'})
            tenant, status = None, 503
            header = self.headers.get('Authorization', '')
            actor = 'token:' + hashlib.sha256(header[7:].encode()).hexdigest()[:12] if header.startswith('Bearer ') else 'anonymous'
            try:
                tenant = auth.authorize(sessions, header)
                if url.query:
                    raise ValueError('query parameters are not supported')
                if self.command == 'POST' and url.path == '/investigations':
                    lengths = self.headers.get_all('Content-Length', [])
                    if len(lengths) != 1 or self.headers.get('Transfer-Encoding'):
                        raise ValueError('invalid body length')
                    length = int(lengths[0])
                    if not 0 < length <= 65536:
                        raise ValueError('body must be 1..65536 bytes')
                    request = queries.validate_request(json.loads(self.rfile.read(length)))
                    snapshot = queries.materialize(sources, tenant, request)
                    result = engine.run(request, snapshot)
                    with lock:
                        results[(tenant, result['investigation_id'])] = result
                        if len(results) > 256:
                            results.popitem(last=False)
                elif self.command == 'GET' and url.path.startswith('/investigations/'):
                    with lock:
                        result = results.get((tenant, url.path[len('/investigations/'):]))
                    if result is None:
                        raise KeyError('not found')
                else:
                    raise KeyError('not found')
                status, body = 200, result
            except PermissionError as exc:
                status = 401 if str(exc) == 'unauthorized' else 403
                body = {'error': 'unauthorized' if status == 401 else 'forbidden'}
            except KeyError:
                status, body = 404, {'error': 'not found'}
            except (ValueError, TypeError):
                status, body = 400, {'error': 'invalid investigation request'}
            except Exception:
                log.exception('investigation read failed')
                status, body = 503, {'error': 'investigation backend unavailable'}
            finally:
                audit({'action': 'investigation.read', 'actor': actor,
                       'tenant': tenant, 'status': status})
            return self.send(status, body)

        do_GET = handle_request
        do_POST = handle_request

    return Handler


def main():
    import clickhouse_connect
    logging.basicConfig(level=logging.INFO)
    client = clickhouse_connect.get_client(
        host=os.environ.get('CLICKHOUSE_HOST', 'clickhouse'),
        username=os.environ.get('CLICKHOUSE_USER', 'ndr'),
        password=os.environ['CLICKHOUSE_PASSWORD'], autogenerate_session_id=False)
    sources = queries.Sources(client, os.environ.get('CASE_API_URL'),
                              json.loads(os.environ.get('INVESTIGATION_CASE_TOKENS', '{}')))
    sessions = json.loads(os.environ.get('INVESTIGATION_SESSIONS', '{}'))
    ThreadingHTTPServer(('0.0.0.0', int(os.environ.get('PORT', '8097'))),
                        make_handler(sources, sessions)).serve_forever()


if __name__ == '__main__':
    main()
