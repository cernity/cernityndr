"""Optional PCAP download HTTP adapter. Bind loopback behind a TLS gateway.

The gateway does not supply tenant claims: the bearer token maps to a local
server-side PCAP grant. Never expose the MinIO bucket publicly.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote, urlsplit
import agent


def make_handler(s3, tokens, audit):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            ref = unquote(urlsplit(self.path).path.removeprefix('/pcap/'))
            try:
                data = agent.retrieve_pcap(ref, self.headers.get('Authorization'), tokens, s3, audit)
                code = 200
            except PermissionError:
                code, data = 403, b'PCAP access denied'
            except Exception:
                code, data = 503, b'PCAP unavailable'
            self.send_response(code)
            self.send_header('Content-Type', 'application/vnd.tcpdump.pcap' if code == 200 else 'text/plain')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(data)
    return Handler


def serve(s3, tokens, audit, port):
    HTTPServer(('127.0.0.1', port), make_handler(s3, tokens, audit)).serve_forever()
