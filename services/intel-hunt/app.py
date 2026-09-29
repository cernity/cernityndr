"""Authenticated HTTP worker: POST advances one page; GET reads bounded results."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import hunt
from jsonschema import ValidationError

HuntStore = hunt.load_module("hunt_store", Path(__file__).with_name("store.py")).HuntStore


def make_handler(worker, tokens):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, status, data):
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def handle_request(self, write=False):
            url = urlparse(self.path)
            if not write and url.path == "/healthz":
                return self.send(200, {"status": "ok"})
            auth = self.headers.get("Authorization", "")
            tenant = tokens.get(auth[7:]) if auth.startswith("Bearer ") else None
            # A credential binds exactly one tenant. Multiple-tenant grants cannot
            # produce merged results or authorize caller-selected tenant identity.
            if not isinstance(tenant, str) or not tenant:
                return self.send(401, {"error": "unauthorized"})
            try:
                if write and url.path == "/hunts":
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 262144:
                        return self.send(413, {"error": "body must be 1..262144 bytes"})
                    job = json.loads(self.rfile.read(length))
                    result = worker.step(job, tenant)
                elif not write and url.path.startswith("/hunts/"):
                    params = parse_qs(url.query)
                    result = worker.store.results(tenant, url.path[len("/hunts/"):],
                        params.get("after", [""])[0], int(params.get("limit", ["500"])[0]))
                else:
                    return self.send(404, {"error": "not found"})
                return self.send(200, result)
            except PermissionError:
                return self.send(403, {"error": "tenant mismatch"})
            except KeyError:
                return self.send(404, {"error": "not found"})
            except (ValueError, ValidationError) as exc:
                return self.send(400, {"error": str(exc)[:512]})
            except Exception:
                return self.send(503, {"error": "hunt backend unavailable; retry same request"})

        def do_POST(self):
            self.handle_request(True)

        def do_GET(self):
            self.handle_request()

    return Handler


def main():
    import clickhouse_connect
    client = clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST", "clickhouse"),
        username=os.environ.get("CLICKHOUSE_USER", "ndr"),
        password=os.environ["CLICKHOUSE_PASSWORD"], autogenerate_session_id=False)
    sets_path = os.environ.get("HUNT_INTEL_SETS")
    saved_sets = json.loads(Path(sets_path).read_text()) if sets_path else {}
    worker = hunt.HuntWorker(hunt.EvidenceClient(client),
                            HuntStore(os.environ.get("HUNT_DB", "/data/hunts.db")), saved_sets)
    tokens = json.loads(os.environ.get("HUNT_TOKENS", "{}"))
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8096"))),
                        make_handler(worker, tokens)).serve_forever()


if __name__ == "__main__":
    main()
