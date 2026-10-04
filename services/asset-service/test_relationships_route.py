"""U3c GET /entity/{id}/relationships route — mirrors the shipped /timeline route
(grants_for_token -> 401, validate_entity -> 400, 404 on a non-matching path, a
fetch_relationships read, 503 on backend failure, audit on every outcome).
"""
import http.client
import importlib.util
import json as _json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import resolution as r


def _load_app():
    spec = importlib.util.spec_from_file_location(
        "asset_app_rel", Path(__file__).resolve().parent / "app.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.resolution = r
    return m


class _Result:
    def __init__(self, column_names, result_rows):
        self.column_names, self.result_rows = column_names, result_rows


class FakeRelCH:
    """Serves fetch_relationships' per-tenant edge query (src OR dst match)."""

    def __init__(self, edges, raise_on_query=False):
        self.edges, self.raise_on_query = edges, raise_on_query

    def query(self, sql, parameters):
        if self.raise_on_query:
            raise RuntimeError("relationship backend down")
        tenant, entity = parameters["tenant"], parameters["entity"]
        cols = ["tenant_id", "src_entity", "dst_entity", "kind",
                "first_seen", "last_seen", "evidence"]
        rows = [[e["tenant"], e["src_entity"], e["dst_entity"], e["kind"],
                 e["first_seen"], e["last_seen"], e["evidence"]]
                for e in self.edges
                if e["tenant"] == tenant and entity in (e["src_entity"], e["dst_entity"])]
        return _Result(cols, rows)


EDGE = {"tenant": "A", "src_entity": "ip:10.0.0.5", "dst_entity": "ip:93.184.216.34",
        "kind": "resolves", "first_seen": "2026-09-28T12:00:00Z",
        "last_seen": "2026-09-28T12:00:00Z",
        "evidence": _json.dumps({"event_type": "dns", "observed_at": "2026-09-28T12:00:00Z",
                                 "detail": "example.com"})}


def _serve(ch, tokens, events):
    app = _load_app()
    srv = ThreadingHTTPServer(("127.0.0.1", 0),
                              app.make_handler(ch, tokens, audit=events.append))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _get(srv, path, token=None):
    c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1])
    c.request("GET", path, headers={"Authorization": f"Bearer {token}"} if token else {})
    resp = c.getresponse()
    body = resp.read()
    c.close()
    return resp.status, (_json.loads(body) if body else None)


# ── (10) authorized GET returns the entity's edges ─────────────────────────────

def test_authorized_get_returns_entity_edges():
    events = []
    srv = _serve(FakeRelCH([EDGE]), {"s3cr3t": ["A"]}, events)
    try:
        st, body = _get(srv, "/entity/ip:10.0.0.5/relationships", token="s3cr3t")
        assert st == 200 and body["entity"] == "ip:10.0.0.5"
        edges = body["tenants"]["A"]
        assert len(edges) == 1 and edges[0]["kind"] == "resolves"
        assert edges[0]["evidence"]["detail"] == "example.com"   # evidence JSON decoded
    finally:
        srv.shutdown()
    assert any(e["action"] == "entity.relationships" and e["outcome"] == "success"
               for e in events)                                  # (14) success audited
    assert "s3cr3t" not in _json.dumps(events)                   # bearer never logged


# ── (11) missing / ungranted token -> 401 ──────────────────────────────────────

def test_missing_or_unknown_token_401_and_audited():
    events = []
    srv = _serve(FakeRelCH([EDGE]), {"s3cr3t": ["A"]}, events)
    try:
        assert _get(srv, "/entity/ip:10.0.0.5/relationships")[0] == 401
        assert _get(srv, "/entity/ip:10.0.0.5/relationships", token="bogus")[0] == 401
    finally:
        srv.shutdown()
    assert any(e["outcome"] == "denied" for e in events)         # (14) denial audited


# ── (12) bad entity -> 400 ──────────────────────────────────────────────────────

def test_bad_entity_400_and_audited():
    events = []
    srv = _serve(FakeRelCH([EDGE]), {"s3cr3t": ["A"]}, events)
    try:
        assert _get(srv, "/entity/has%20space/relationships", token="s3cr3t")[0] == 400
    finally:
        srv.shutdown()
    assert any(e["outcome"] == "bad_request" for e in events)    # (14) bad request audited


# ── (13) backend raise -> 503 ───────────────────────────────────────────────────

def test_backend_failure_503_and_audited():
    events = []
    srv = _serve(FakeRelCH([], raise_on_query=True), {"s3cr3t": ["A"]}, events)
    try:
        assert _get(srv, "/entity/ip:10.0.0.5/relationships", token="s3cr3t")[0] == 503
    finally:
        srv.shutdown()
    assert any(e["outcome"] == "error" for e in events)          # (14) error audited


def test_non_matching_path_404_and_audited():
    events = []
    srv = _serve(FakeRelCH([EDGE]), {"s3cr3t": ["A"]}, events)
    try:
        assert _get(srv, "/entity/ip:10.0.0.5/bogus", token="s3cr3t")[0] == 404
    finally:
        srv.shutdown()
    assert any(e["outcome"] == "not_found" and e["action"] == "entity.route"
               for e in events)                                  # (14) routing miss audited
