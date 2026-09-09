"""Observability (plan U6): Prometheus metrics + liveness/readiness endpoints.

prometheus_client is imported lazily and the whole module degrades to a no-op if
it is absent, so detectors.py/app.py stay importable and the unit tests stay
dependency-light. When present (it is in the image), `/metrics` exposes per-detector
finding counts, records processed/dropped, and evaluate() duration; `/healthz` is
liveness (process up) and `/readyz` gates on the consumer having joined the group
and the state store being reachable, so an orchestrator only routes traffic to a
replica that can actually work.
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
    _ON = True
except Exception:                       # prometheus_client not installed -> no-op
    _ON = False

if _ON:
    FINDINGS = Counter("ndr_findings_total", "Findings emitted", ["detector_id", "tenant"])
    RECORDS = Counter("ndr_records_total", "Bus records processed", ["event_type"])
    DROPPED = Counter("ndr_records_dropped_total", "Records skipped", ["reason"])
    CONFIG_RELOADS = Counter("ndr_config_reloads_total", "Config snapshots applied")
    EVAL_SECONDS = Histogram("ndr_evaluate_seconds", "evaluate() duration")

_ready = {}   # component -> ready?; a service declares its components (plan 003 observability)


def finding(detector_id, tenant):
    if _ON:
        FINDINGS.labels(detector_id, tenant).inc()


def record(event_type):
    if _ON:
        RECORDS.labels(event_type or "unknown").inc()


def dropped(reason):
    if _ON:
        DROPPED.labels(reason).inc()


def config_reloaded():
    if _ON:
        CONFIG_RELOADS.inc()


def observe_evaluate(seconds):
    if _ON:
        EVAL_SECONDS.observe(seconds)


def set_ready(component, value=True):
    _ready[component] = bool(value)


def is_ready():
    return bool(_ready) and all(_ready.values())


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, b"ok", "text/plain")
        elif self.path == "/readyz":
            ok = is_ready()
            self._send(200 if ok else 503, b"ready" if ok else b"not-ready", "text/plain")
        elif self.path == "/metrics" and _ON:
            self._send(200, generate_latest(), CONTENT_TYPE_LATEST)
        else:
            self._send(404, b"", "text/plain")

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start(port=9108):
    """Start the metrics/health HTTP server on a daemon thread."""
    srv = ThreadingHTTPServer(("0.0.0.0", port), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
