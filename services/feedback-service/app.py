"""Authenticated HTTP consumer for disposition.v1; no direct untrusted bus ingress.

Run behind a TLS gateway. FEEDBACK_SESSIONS is a server-owned JSON token map,
with emitter/analyst/tenant/expires_at/disposition_write for each session. Empty
configuration denies all writes. GET /quality requires quality_read=True and a
single tenant in that same session map. See docs/decisions/003-disposition-quality.md
for metric semantics and ClickHouse configuration. Mount a private persistent /data volume.
"""
import importlib.util
import json
import os
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from jsonschema import ValidationError

_spec = importlib.util.spec_from_file_location('feedback_router', Path(__file__).with_name('router.py'))
router = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(router)

_spec = importlib.util.spec_from_file_location('feedback_quality', Path(__file__).with_name('quality.py'))
quality = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(quality)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Never log authorization credentials or payload claims.

    def send_json(self, code, value):
        body = json.dumps(value).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == '/healthz':
            return self.send_json(200, {'capabilities': router.CAPABILITIES})
        if url.path != '/quality':
            return self.send_json(404, {'error': 'not found'})
        try:
            tenant = quality.authenticate(self.router.tokens,
                                          self.headers.get('Authorization', ''), self.router.now())
            params = parse_qs(url.query, keep_blank_values=True)
            if set(params) != {'from', 'to'} or any(len(v) != 1 for v in params.values()):
                raise ValueError('only from and to are accepted')
            start, end = quality.parse_window(params['from'][0], params['to'][0])
        except PermissionError:
            return self.send_json(401, {'error': 'unauthorized'})
        except ValueError:
            return self.send_json(400, {'error': 'expected timezone-aware from and to, with from < to'})
        findings = None
        try:
            findings = self.findings_factory() if self.findings_factory else None
            result = quality.report(self.router.database, findings, tenant, start, end)
        except Exception:
            return self.send_json(503, {'error': 'quality unavailable'})
        finally:
            if findings is not None and hasattr(findings, 'client'):
                findings.client.close()
        return self.send_json(200, result)

    def do_POST(self):
        if self.path != '/dispositions':
            return self.send_json(404, {'error': 'not found'})
        authorization = self.headers.get('Authorization', '')
        try:
            router.authenticate(self.router.tokens, authorization, self.router.now())
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 65536 or self.headers.get('Transfer-Encoding'):
                return self.send_json(400, {'error': 'invalid body length'})
            self.connection.settimeout(10)
            payload = json.loads(self.rfile.read(length))
            result = self.router.consume(payload, authorization, self.client_address[0])
        except PermissionError:
            return self.send_json(401, {'error': 'unauthorized'})
        except (ValueError, ValidationError):
            return self.send_json(400, {'error': 'invalid disposition.v1'})
        except Exception:
            return self.send_json(503, {'error': 'feedback unavailable'})
        return self.send_json(202, result)


def make_handler(service, findings_factory=None):
    return type('FeedbackHandler', (Handler,), {'router': service,
                'findings_factory': staticmethod(findings_factory) if findings_factory else None})


def findings_store():
    import clickhouse_connect
    return quality.FindingsStore(clickhouse_connect.get_client(
        host=os.environ.get('CLICKHOUSE_HOST', 'clickhouse'),
        username=os.environ.get('CLICKHOUSE_USER', 'ndr'),
        password=os.environ.get('CLICKHOUSE_PASSWORD', ''),
        connect_timeout=5, send_receive_timeout=30))


def main():
    service = router.Router(os.environ.get('FEEDBACK_DB', '/data/feedback.sqlite3'),
                            json.loads(os.environ.get('FEEDBACK_SESSIONS', '{}')),
                            ttl_seconds=float(os.environ.get('FEEDBACK_TTL_SECONDS', '86400')))
    ThreadingHTTPServer(('0.0.0.0', int(os.environ.get('PORT', '8094'))), make_handler(service, findings_store)).serve_forever()


if __name__ == '__main__':
    main()
