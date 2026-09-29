"""coverage-service (U4): read-only REST over the ATT&CK coverage map.

  GET /healthz
  GET /coverage    -> {techniques[], gaps[], summary{}} for the caller's tenants

The fleet-global detector->technique map is server config (COVERAGE_DETECTOR_MAP,
a JSON list of {detector_id, techniques}); it is the same for every tenant, as is
the reporting universe (COVERAGE_TECHNIQUE_CATALOG, a JSON list of technique ids)
over which every report ranges so uncovered techniques surface as gaps regardless
of whether any tenant has observed them. The observed overlay is tenant-scoped and
derived server-side from the bearer token
(§21) — tenant is NEVER a query param, and one tenant's findings never leak into
another's map. No writes: coverage is a pure read over detector metadata + the
findings store.

A live ClickHouse isn't available in the clone, so coverage.py is unit-tested
against a fake client (test_coverage.py); the real SQL is verified in the real
environment.
"""
import importlib.util
import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

_spec = importlib.util.spec_from_file_location("coverage", Path(__file__).with_name("coverage.py"))
coverage = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(coverage)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("coverage-service")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # never log bearer credentials

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path  # any tenant= query param is ignored (§21)
        if path == "/healthz":
            return self._send(200, {"status": "ok"})
        if path != "/coverage":
            return self._send(404, {"error": "not found"})
        grants = coverage.grants_for_token(self.tokens, self.headers.get("Authorization", ""))
        if not grants:
            return self._send(401, {"error": "unauthorized"})
        try:
            sql, params = coverage.observed_query(grants)
            rows = [row[0] for row in self.client.query(sql, parameters=params).result_rows]
        except Exception:  # backend failure -> controlled 5xx, never an escaped stack
            log.exception("coverage query failed")
            return self._send(503, {"error": "coverage unavailable"})
        return self._send(200, coverage.build_coverage(self.detector_map, rows, self.catalog))


def make_handler(client, tokens, detector_map, catalog=()):
    return type("CoverageHandler", (_Handler,),
                {"client": client, "tokens": tokens, "detector_map": detector_map, "catalog": catalog})


def main():
    import clickhouse_connect
    client = clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST", "clickhouse"),
        username=os.environ.get("CLICKHOUSE_USER", "default"),
        password=os.environ["CLICKHOUSE_PASSWORD"],
        autogenerate_session_id=False,  # shared client safe across ThreadingHTTPServer threads
    )
    tokens = json.loads(os.environ.get("COVERAGE_READER_TOKENS", "{}"))
    detector_map = coverage.load_detector_map(json.loads(os.environ.get("COVERAGE_DETECTOR_MAP", "[]")))
    catalog = json.loads(os.environ.get("COVERAGE_TECHNIQUE_CATALOG", "[]"))  # fleet reporting universe
    port = int(os.environ.get("PORT", "8095"))
    log.info("coverage-service API on :%d", port)
    # ponytail: read-only, no Kafka consumer -> /healthz on the API port is enough.
    ThreadingHTTPServer(("0.0.0.0", port), make_handler(client, tokens, detector_map, catalog)).serve_forever()


if __name__ == "__main__":
    main()
