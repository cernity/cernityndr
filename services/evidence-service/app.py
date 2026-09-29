"""evidence-service (U5): read-only REST over U4's ndr.evidence_observations view.

  GET /healthz
  GET /observations?entity=&from=&to=&type=&page_size=

The caller's tenants are SERVER-DERIVED from the bearer token (§21); tenant is
NEVER a caller query param, and a `tenant=` in the query string is ignored (same
rule as U3a's sensor-registry). Authz, windowing and bounding live in query.py;
this is the ClickHouse + HTTP shell. A live ClickHouse isn't available in this
clone, so query.py is unit-tested against a fake client (test_query.py) and the
live query is verified in the real environment.

Three properties the HTTP shell owns (all regression-tested in test_query.py):
  * shared ClickHouse client is safe across ThreadingHTTPServer threads
    (autogenerate_session_id=False — see make_client);
  * a backend failure becomes a controlled JSON 5xx, never an escaped exception;
  * every evidence read and every rejected access emits a structured, append-only
    audit event (§21.2) that identifies the server-derived actor and tenant scope
    but never the bearer credential.
"""
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import ndr_runtime
import query

log = ndr_runtime.setup_logging("evidence-service")


def _now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _actor(auth_header):
    """Stable pseudonymous actor id derived server-side from the bearer token — the
    token's SHA-256 prefix, NEVER the token itself (§21.2 forbids logging the
    credential). None/"anonymous" when unauthenticated."""
    token = auth_header[7:] if (auth_header or "").startswith("Bearer ") else None
    if not token:
        return None
    return "token:" + hashlib.sha256(token.encode()).hexdigest()[:12]


def _default_audit(event):
    # ponytail: append-only == structured stdout via the shared JSON logger; upgrade
    # path is the ndr.audit.v1 bus / audit-service (§arch 21.2) when the durable audit
    # plane lands. Do that then, not speculatively now.
    ndr_runtime.log_event(log, "audit", **event)


class _Handler(BaseHTTPRequestHandler):
    # Bound per-instance by make_handler().
    client = None
    tokens = {}
    audit = staticmethod(_default_audit)

    def log_message(self, *a):
        pass  # HTTP access logging is superseded by the structured audit trail below.

    def _send(self, code, obj):
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _grants(self):
        return query.grants_for_token(self.tokens, self.headers.get("Authorization", ""))

    def _audit(self, request_id, actor, tenants, parsed_url, outcome, **extra):
        """Emit one append-only audit event (§21.2). Resource + window come from the
        raw query string so a rejected/bad request is still audited; the bearer is
        never included (only the derived `actor`)."""
        q = parse_qs(parsed_url.query)
        event = {
            "action": "evidence.query",
            "resource_type": "observations",
            "actor": actor or "anonymous",
            "tenant_scope": list(tenants) if tenants else [],
            "source_ip": self.client_address[0],
            "request_id": request_id,
            "entity": q.get("entity", [""])[0][:255],   # bounded; user-influenced field
            "from": q.get("from", [""])[0][:64],
            "to": q.get("to", [""])[0][:64],
            "type": q.get("type", [""])[0][:32],
            "outcome": outcome,
            "timestamp": _now_iso(),
        }
        event.update(extra)
        self.audit(event)

    def do_GET(self):
        u = urlparse(self.path)                       # tenant= in the query string is deliberately ignored (§21)
        if u.path == "/healthz":
            return self._send(200, {"status": "ok"})
        request_id = self.headers.get("X-Request-Id") or uuid.uuid4().hex
        actor = _actor(self.headers.get("Authorization", ""))
        grants = self._grants()
        if grants is None:
            self._audit(request_id, actor, None, u, "denied")
            return self._send(401, {"error": "unauthorized", "request_id": request_id})
        if u.path != "/observations":
            return self._send(404, {"error": "not found"})
        q = parse_qs(u.query)
        try:
            entity = query.validate_entity(q.get("entity", [""])[0])
            frm, to = query.parse_window(q.get("from", [""])[0], q.get("to", [""])[0])
            obs_type = query.validate_type(q.get("type", [None])[0])
            page_size = query.clamp_page_size(q.get("page_size", [None])[0])
            after = q.get("after", [""])[0]          # keyset continuation cursor (obs_id); bound as a param
        except ValueError as e:
            self._audit(request_id, actor, grants, u, "bad_request", reason=str(e))
            return self._send(400, {"error": str(e), "request_id": request_id})
        try:
            result = query.fetch_observations(
                self.client, grants, entity, frm, to, obs_type, page_size, after)
        except Exception:                            # noqa: BLE001 — any backend failure -> controlled 5xx
            # Diagnostics stay server-side; the client gets a generic message + the
            # request_id to correlate, never the ClickHouse error detail.
            log.exception("evidence query failed request_id=%s", request_id)
            self._audit(request_id, actor, grants, u, "error")
            return self._send(503, {"error": "evidence backend unavailable",
                                    "request_id": request_id})
        self._audit(request_id, actor, grants, u, "success",
                    returned=len(result["observations"]))
        return self._send(200, result)


def make_handler(client, tokens, audit=None):
    return type("Handler", (_Handler,), {
        "client": client, "tokens": tokens,
        "audit": staticmethod(audit or _default_audit)})


def make_client():
    """Build the shared ClickHouse client. autogenerate_session_id=False is required
    because ThreadingHTTPServer runs each request on its own thread and they share
    this one client: ClickHouse forbids concurrent queries within a single session,
    so a session-bearing shared client raises ProgrammingError under overlap
    (clickhouse-connect driver-api, "Multi-threaded applications"). Disabling
    per-client session ids makes concurrent queries safe."""
    import clickhouse_connect
    return clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST", "clickhouse"),
        username=os.environ.get("CLICKHOUSE_USER", "ndr"),
        password=os.environ["CLICKHOUSE_PASSWORD"],
        autogenerate_session_id=False)


def main():
    client = make_client()
    # token -> [granted tenants]; unset => no reader is authorized (secure default).
    tokens = json.loads(os.environ.get("EVIDENCE_READER_TOKENS", "{}"))
    port = int(os.environ.get("PORT", "8092"))
    log.info("evidence-service API on :%d", port)
    # ponytail: read-only, no Kafka consumer -> /healthz on the API port is enough;
    # no readiness gating to add (nothing to become ready).
    ThreadingHTTPServer(("0.0.0.0", port), make_handler(client, tokens)).serve_forever()


if __name__ == "__main__":
    main()
