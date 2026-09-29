"""sensor-registry (U3a): ingest sensor-health.v1 → SQLite, serve a read-only
fleet API with reader-side tenant authz and clock-skew flags.

Two seams:
  1) background: consume ndr.sensor.health.v1 (exactly what U2's sensor-agent
     emits) and upsert each heartbeat as UNVERIFIED (producer_verified=False —
     the Kafka key/headers are producer-set, not authenticated identity; that is
     U3b).
  2) HTTP API (read-only):
       GET /healthz
       GET /sensors            -> sensors across the caller's granted tenants
       GET /sensors/<uuid>     -> one sensor (404 if not in the grant)
       GET /groups             -> group -> member sensor_uuids

The reader's tenant grant is SERVER-DERIVED from an authenticated bearer token
(§21); tenant is NEVER a caller query param, and any query string is ignored.
Store logic is in store.py (tested by test_registry.py); this is the I/O shell.
"""
import importlib.util
import json
import os
import pathlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import ndr_runtime

# store.py must be loaded by PATH, not `import store`: shared/store.py (the
# detectors' WindowStore) already owns the name `store` on PYTHONPATH=shared, so
# a bare import would resolve to the wrong module in a single-process test run.
_spec = importlib.util.spec_from_file_location(
    "sensor_registry_store", pathlib.Path(__file__).with_name("store.py"))
store = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(store)
RegistryStore, sensor_view = store.RegistryStore, store.sensor_view

HEALTH_TOPIC = "ndr.sensor.health.v1"


class _Handler(BaseHTTPRequestHandler):
    # Bound per-instance by make_handler().
    store = None
    tokens = {}
    skew_ms = 100.0
    stale_s = 90.0
    now = staticmethod(__import__("time").time)

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _grants(self):
        """The caller's granted tenants, derived server-side from the bearer
        token. None means unauthenticated (no/unknown token) → 401."""
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else None
        return self.tokens.get(token) if token else None

    def _view(self, row):
        return sensor_view(row, self.now(), self.skew_ms, self.stale_s)

    def do_GET(self):
        path = urlparse(self.path).path          # query string deliberately unused (§21)
        if path == "/healthz":
            return self._send(200, {"status": "ok"})
        grants = self._grants()
        if grants is None:
            return self._send(401, {"error": "unauthorized"})
        if path == "/sensors":
            return self._send(200, {"sensors": [self._view(r) for r in self.store.list_sensors(grants)]})
        if path == "/groups":
            return self._send(200, {"groups": self.store.list_groups(grants)})
        if path.startswith("/sensors/"):
            row = self.store.get(path[len("/sensors/"):], grants)
            return self._send(404, {"error": "not found"}) if row is None else self._send(200, self._view(row))
        return self._send(404, {"error": "not found"})


def make_handler(store, tokens, skew_ms=100.0, stale_s=90.0, now=None):
    import time
    return type("Handler", (_Handler,), {
        "store": store, "tokens": tokens, "skew_ms": skew_ms,
        "stale_s": stale_s, "now": staticmethod(now or time.time)})


def _deserialize(raw):
    """Tolerant value_deserializer for the health consumer: parse the JSON wire
    bytes but NEVER raise. kafka-python runs the deserializer inside the consumer's
    __next__, so a bad-bytes record would otherwise blow up `for msg in consumer`
    and take the whole ingest loop (and the replica) down over ONE garbage message.
    Undeserializable bytes become a None sentinel the loop skips with a metric; good
    JSON yields the dict, identical to ndr_runtime's default serde."""
    try:
        return json.loads(raw.decode())
    except Exception:                              # noqa: BLE001 — bad bytes are a skip, not a crash
        return None


def ingest_loop(reg, consumer=None, log=None):
    """Consume heartbeats and upsert them. The payload's identity is a CLAIM:
    producer_verified stays False (U3b) — we never treat the Kafka key/headers as
    verified identity.

    `consumer` is a seam: production passes None (a real KafkaConsumer is built with
    the tolerant _deserialize serde), tests inject one that yields msg.value already
    through the same JSON path.

    Three distinct failure classes, handled differently on purpose (the reviewer's
    blockers 1 and 2):
      * undeserializable wire bytes -> _deserialize returned None -> skip the record
        with a metric/log. ONE garbage message must never terminate ingestion.
      * malformed (deserialized but not a well-formed sensor-health.v1) ->
        upsert_heartbeat returns False (never raises) -> skip with a metric/log.
      * STORAGE failure -> upsert_heartbeat RAISES. This is NOT a bad message, so we
        do not swallow it as one (that would silently drop a real heartbeat while
        /readyz stayed green). It falls through to the outer handler, which marks the
        consumer not-ready and re-raises so supervision restarts the replica and the
        record is re-consumed from the last committed offset — surfaced, not lost.

    Consumer CONSTRUCTION is inside the failure boundary: if the broker is
    unreachable at startup, make_consumer raises and we mark 'consumer' not-ready
    and re-raise — otherwise a construction failure would leave the thread dead
    behind a green /healthz. The 'consumer' component is flipped READY only once
    the consumer object exists (subscribed); until then main() has already declared
    it not-ready, so /readyz gates traffic off the replica the whole startup window.
    A FATAL loop exit (broker gone mid-run) flips it back off and re-raises so the
    caller can terminate for supervision to restart."""
    try:
        if consumer is None:
            consumer = ndr_runtime.make_consumer(
                HEALTH_TOPIC, group_id="ndr-sensor-registry",
                auto_offset_reset="earliest", value_deserializer=_deserialize)
        ndr_runtime.metrics.set_ready("consumer", True)   # consumer built/subscribed -> serve reads
        for msg in consumer:
            if msg.value is None:                  # undeserializable bytes -> skip, never crash
                ndr_runtime.metrics.dropped("undeserializable")
                if log:
                    log.warning("skipping undeserializable heartbeat")
                continue
            # No try/except here: a False return is a bad-message skip, but any
            # EXCEPTION is a storage failure that must surface (outer except), not be
            # discarded as if the heartbeat were garbage.
            if not reg.upsert_heartbeat(msg.value, producer_verified=False):
                ndr_runtime.metrics.dropped("malformed")
                if log:
                    log.warning("dropping malformed heartbeat")
    except Exception:
        ndr_runtime.metrics.set_ready("consumer", False)
        if log:
            log.exception("ingest consumer failed; marking not-ready")
        raise


def main():
    import threading
    log = ndr_runtime.setup_logging("sensor-registry")
    reg = RegistryStore(os.environ.get("REGISTRY_DB_PATH", "/data/registry.db"))
    # token -> [granted tenants]; unset => no reader is authorized (secure default).
    tokens = json.loads(os.environ.get("REGISTRY_READER_TOKENS", "{}"))
    skew = float(os.environ.get("SKEW_THRESHOLD_MS", "100"))
    stale = float(os.environ.get("STALE_AFTER_SECONDS", "90"))
    port = int(os.environ.get("PORT", "8091"))
    # Declare NOT-ready before anything starts, and start_health(ready=()) so the
    # health server cannot mark the consumer ready — only ingest_loop does, after it
    # actually has a consumer. /readyz therefore reports 503 until ingestion is live.
    ndr_runtime.metrics.set_ready("consumer", False)
    ndr_runtime.start_health(ready=())       # /healthz /readyz /metrics on 9108
    # HTTP API runs on a daemon thread; ingestion owns the main thread so a fatal
    # consumer failure terminates the process (os._exit) and supervision restarts it —
    # a dead daemon thread would otherwise strand a permanently non-consuming service.
    threading.Thread(
        target=lambda: ThreadingHTTPServer(("0.0.0.0", port), make_handler(reg, tokens, skew, stale)).serve_forever(),
        daemon=True).start()
    log.info("sensor-registry API on :%d", port)
    try:
        ingest_loop(reg, log=log)
    except Exception:
        os._exit(1)              # ponytail: rely on the container restart policy, not in-proc retry


if __name__ == "__main__":
    main()
