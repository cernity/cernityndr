"""evidence-service (U5) tests: query-builder + authz/tenant-scoping + half-open
windowing, exercised against a fake ClickHouse client that faithfully implements
the ndr.evidence_observations view's filtering (tenant IN, has(entity), half-open
time, type, order, limit). A live ClickHouse isn't available in this clone; the
real SQL is verified in the real env. HTTP-level authz is exercised through
app.make_handler.

Loaded by PATH (not `import app`): several services share the module name `app`,
so path-loading keeps a single pytest process collision-free (see U3a).
"""
import http.client
import importlib.util
import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


query = _load("evidence_query", Path(__file__).with_name("query.py"))
app = _load("evidence_app", Path(__file__).with_name("app.py"))
app.query = query  # bind the same path-loaded query module the tests use

T0 = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)


def obs(tenant, entity, secs, obs_id, type_="conn", caps=("flow-only",), extra_entities=()):
    """A minimal-but-real canonical observation.v1 record as the view's `observation`
    column would hold it, timestamped T0+secs."""
    ts = (T0 + timedelta(seconds=secs)).isoformat().replace("+00:00", "Z")
    entities = [{"type": "ip", "role": "src", "value": entity}]
    entities += [{"type": "ip", "role": "dst", "value": e} for e in extra_entities]
    return {
        "schema": "cernity.observation.v1",
        "obs_id": f"obs:{obs_id:064x}",
        "tenant": tenant,
        "sensor_id": "s1",
        "ts": {"sensor": ts, "normalized": ts, "ingested": ts,
               "method": "clock-offset", "clock_offset_ms": 0.0},
        "entities": entities,
        "type": type_,
        "fields": {"src_ip": entity},
        "capabilities": list(caps),
        "source_ref": {"kind": "clickhouse", "table": "network_flow",
                       "tenant": tenant, "obs_id": f"obs:{obs_id:064x}"},
    }


class _Result:
    def __init__(self, column_names, result_rows):
        self.column_names = column_names
        self.result_rows = result_rows


class FakeCH:
    """Implements the ndr.evidence_observations view's read semantics from the bound
    parameters (it ignores the SQL text — the SQL itself is verified in the real env).
    This genuinely exercises tenant scoping, has(entity), half-open time and paging."""

    def __init__(self, rows):
        self.rows = list(rows)
        self.last_sql = None
        self.last_params = None

    def query(self, sql, parameters):
        self.last_sql, self.last_params = sql, parameters
        p = parameters
        tenants = set(p["tenants"])
        matched = []
        for o in self.rows:
            if o["tenant"] not in tenants:                      # tenant_id IN {tenants}
                continue
            values = [e["value"] for e in o.get("entities", [])]
            if p["entity"] not in values:                       # has(entity_values, {entity})
                continue
            nt = query._parse_ts(o["ts"]["normalized"])
            if nt >= p["until"]:                                # normalized_time < until
                continue
            # keyset lower bound: strictly after (frm, after); after='' => >= frm.
            if not (nt > p["frm"] or (nt == p["frm"] and o["obs_id"] > p["after"])):
                continue
            if p.get("type") and o["type"] != p["type"]:        # type = {type}
                continue
            matched.append((nt, o["obs_id"], o))
        matched.sort(key=lambda x: (x[0], x[1]))                # ORDER BY normalized_time, obs_id
        rows = [[o["obs_id"], nt, json.dumps(o)] for nt, _id, o in matched[:p["limit"]]]
        return _Result(["obs_id", "normalized_time", "observation"], rows)


def _ids(result):
    return [o["obs_id"] for o in result["observations"]]


def _drain(ch, grants, entity, frm, to, page_size):
    """Walk every page via (next, next_after), returning all obs_ids in order."""
    seen, after = [], ""
    for _ in range(50):                                      # loop guard
        r = query.fetch_observations(ch, grants, entity, frm, to, page_size=page_size, after=after)
        seen += _ids(r)
        assert len(r["observations"]) <= page_size
        if r["next"] is None:
            return seen
        frm, after = query._parse_ts(r["next"]), r["next_after"]
    raise AssertionError("pagination did not terminate")


# ── query builder ────────────────────────────────────────────────────────────

def test_build_query_is_parameterized_half_open_and_tenant_scoped():
    sql, params = query.build_query(["A"], "10.0.0.1", T0, T0 + timedelta(hours=1), "dns", 50)
    assert "tenant_id IN {tenants:Array(String)}" in sql
    assert "has(entity_values, {entity:String})" in sql
    assert "normalized_time < {until:" in sql                             # half-open upper bound
    assert "obs_id > {after:String}" in sql                              # keyset lower bound
    assert "type = {type:String}" in sql
    assert "10.0.0.1" not in sql                                          # entity value bound, not interpolated
    assert params["tenants"] == ["A"] and params["entity"] == "10.0.0.1"
    assert params["limit"] == 51                                          # page_size + 1


def test_build_query_omits_type_filter_when_absent():
    sql, params = query.build_query(["A"], "10.0.0.1", T0, T0 + timedelta(hours=1), None, 50)
    assert "type =" not in sql and "type" not in params


# ── entity + window returns expected observations ────────────────────────────

def test_entity_window_returns_expected_observations():
    ch = FakeCH([
        obs("A", "10.0.0.1", 0, 1),
        obs("A", "10.0.0.1", 30, 2),
        obs("A", "10.0.0.2", 10, 3),          # different entity
        obs("A", "10.0.0.1", 5000, 4),        # outside a 1h... but within window; keep as later
    ])
    r = query.fetch_observations(ch, ["A"], "10.0.0.1", T0, T0 + timedelta(hours=2))
    assert _ids(r) == [obs("A", "10.0.0.1", 0, 1)["obs_id"],
                       obs("A", "10.0.0.1", 30, 2)["obs_id"],
                       obs("A", "10.0.0.1", 5000, 4)["obs_id"]]
    assert r["capabilities"] == ["flow-only"]
    assert r["next"] is None


def test_type_filter_scopes_results():
    ch = FakeCH([obs("A", "e", 0, 1, type_="conn"),
                 obs("A", "e", 1, 2, type_="dns"),
                 obs("A", "e", 2, 3, type_="dns")])
    r = query.fetch_observations(ch, ["A"], "e", T0, T0 + timedelta(hours=1), obs_type="dns")
    assert [o["type"] for o in r["observations"]] == ["dns", "dns"]


# ── half-open [from,next) windowing: no double-count ─────────────────────────

def test_half_open_boundary_row_counted_once_across_adjacent_windows():
    boundary = T0 + timedelta(minutes=30)
    ch = FakeCH([obs("A", "e", 0, 1),                    # inside first window
                 obs("A", "e", 1800, 2)])               # exactly on the boundary (T0+30m)
    first = query.fetch_observations(ch, ["A"], "e", T0, boundary)          # [T0, boundary)
    second = query.fetch_observations(ch, ["A"], "e", boundary, T0 + timedelta(hours=1))
    assert _ids(first) == [obs("A", "e", 0, 1)["obs_id"]]                   # boundary row excluded
    assert _ids(second) == [obs("A", "e", 1800, 2)["obs_id"]]              # boundary row included here
    assert set(_ids(first)) & set(_ids(second)) == set()                   # no double-count


def test_paged_pages_partition_the_result_no_double_count():
    # 5 observations, page_size=2 -> walk pages via (next, next_after); union == full set, no dups.
    ch = FakeCH([obs("A", "e", i, i + 1) for i in range(5)])
    seen = _drain(ch, ["A"], "e", T0, T0 + timedelta(hours=1), page_size=2)
    assert len(seen) == 5 and len(set(seen)) == 5                          # every row exactly once


def test_paging_through_tied_timestamps_loses_and_dups_nothing():
    # Rows sharing an identical timestamp, page_size=1: a bare-time cursor would drop
    # or duplicate one; the (time, obs_id) keyset walks through them exactly once.
    ch = FakeCH([obs("A", "e", 0, 1),
                 obs("A", "e", 60, 2),
                 obs("A", "e", 60, 3),                  # tie with #2 at T0+60s
                 obs("A", "e", 60, 4)])                 # three-way tie at T0+60s
    seen = _drain(ch, ["A"], "e", T0, T0 + timedelta(hours=1), page_size=1)
    assert len(seen) == 4 and len(set(seen)) == 4


# ── oversize window is bounded / paged ───────────────────────────────────────

def test_oversize_window_is_capped_and_returns_next():
    # 3-day request; MAX_WINDOW=1d caps it. Row on day 2 is only reachable after paging.
    ch = FakeCH([obs("A", "e", 0, 1),
                 obs("A", "e", int(timedelta(days=2).total_seconds()), 2)])
    to = T0 + timedelta(days=3)
    r1 = query.fetch_observations(ch, ["A"], "e", T0, to)
    assert _ids(r1) == [obs("A", "e", 0, 1)["obs_id"]]
    assert r1["next"] == query._iso(T0 + query.MAX_WINDOW)                 # capped at 1 day
    assert r1["next_after"] == ""                                          # fresh window boundary
    # draining the whole 3-day request must still surface the day-2 row via window paging
    seen = _drain(ch, ["A"], "e", T0, to, page_size=query.DEFAULT_PAGE_SIZE)
    assert set(seen) == {obs("A", "e", 0, 1)["obs_id"],
                         obs("A", "e", int(timedelta(days=2).total_seconds()), 2)["obs_id"]}


def test_page_size_is_clamped_to_max():
    assert query.clamp_page_size("999999") == query.MAX_PAGE_SIZE
    assert query.clamp_page_size(None) == query.DEFAULT_PAGE_SIZE
    assert query.clamp_page_size("1") == 1
    for bad in ("0", "-3", "abc"):
        try:
            query.clamp_page_size(bad)
            raise AssertionError(f"expected ValueError for {bad!r}")
        except ValueError:
            pass


# ── authz + tenant isolation ─────────────────────────────────────────────────

def test_grants_for_token_rejects_unauthenticated():
    tokens = {"tokA": ["A"]}
    assert query.grants_for_token(tokens, "") is None                     # no header
    assert query.grants_for_token(tokens, "Bearer bogus") is None         # unknown token
    assert query.grants_for_token(tokens, "tokA") is None                 # missing "Bearer "
    assert query.grants_for_token(tokens, "Bearer tokA") == ["A"]


def test_authenticated_caller_cannot_read_another_tenant():
    ch = FakeCH([obs("A", "e", 0, 1), obs("B", "e", 1, 2)])
    a = query.fetch_observations(ch, ["A"], "e", T0, T0 + timedelta(hours=1))
    assert _ids(a) == [obs("A", "e", 0, 1)["obs_id"]]                     # only A's row
    b = query.fetch_observations(ch, ["B"], "e", T0, T0 + timedelta(hours=1))
    assert _ids(b) == [obs("B", "e", 1, 2)["obs_id"]]                     # only B's row
    assert set(_ids(a)) & set(_ids(b)) == set()


def test_shared_entity_value_does_not_leak_across_tenants():
    # Same entity value present in two tenants -> a grant for one never returns the other's.
    ch = FakeCH([obs("A", "10.0.0.1", 0, 1), obs("B", "10.0.0.1", 0, 2)])
    r = query.fetch_observations(ch, ["A"], "10.0.0.1", T0, T0 + timedelta(hours=1))
    assert _ids(r) == [obs("A", "10.0.0.1", 0, 1)["obs_id"]]


def test_multi_tenant_grant_returns_all_granted_tenants():
    ch = FakeCH([obs("A", "e", 0, 1), obs("B", "e", 1, 2), obs("C", "e", 2, 3)])
    r = query.fetch_observations(ch, ["A", "C"], "e", T0, T0 + timedelta(hours=1))
    assert set(_ids(r)) == {obs("A", "e", 0, 1)["obs_id"], obs("C", "e", 2, 3)["obs_id"]}


# ── unknown entity returns empty, not error ──────────────────────────────────

def test_unknown_entity_returns_empty_not_error():
    ch = FakeCH([obs("A", "e", 0, 1)])
    r = query.fetch_observations(ch, ["A"], "does-not-exist", T0, T0 + timedelta(hours=1))
    assert r["observations"] == [] and r["capabilities"] == [] and r["next"] is None


# ── validation ───────────────────────────────────────────────────────────────

def test_bad_window_and_entity_and_type_raise_valueerror():
    for frm, to in [("", "2026-01-01T00:00:00Z"),                 # missing from
                    ("2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z"),  # inverted
                    ("nonsense", "2026-01-01T00:00:00Z")]:         # unparseable
        try:
            query.parse_window(frm, to)
            raise AssertionError("expected ValueError")
        except ValueError:
            pass
    for bad in ("", "has space", "a" * 300):
        try:
            query.validate_entity(bad)
            raise AssertionError("expected ValueError")
        except ValueError:
            pass
    try:
        query.validate_type("ftp")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert query.validate_type("") is None and query.validate_type("dns") == "dns"


# ── HTTP shell: authz enforced end-to-end; tenant query param ignored ────────

def _serve(client, tokens, audit=None):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app.make_handler(client, tokens, audit=audit))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _get(srv, path, token=None):
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1])
    conn.request("GET", path, headers={"Authorization": f"Bearer {token}"} if token else {})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, (json.loads(body) if body else None)


def test_http_unauthenticated_rejected():
    ch = FakeCH([obs("A", "e", 0, 1)])
    srv = _serve(ch, {"tokA": ["A"]})
    try:
        win = "from=2026-09-28T12:00:00Z&to=2026-09-28T13:00:00Z"
        assert _get(srv, f"/observations?entity=e&{win}")[0] == 401           # no token
        assert _get(srv, f"/observations?entity=e&{win}", token="bogus")[0] == 401
        assert _get(srv, "/healthz")[0] == 200                               # health is open
    finally:
        srv.shutdown()


def test_http_tenant_query_param_is_ignored():
    ch = FakeCH([obs("A", "e", 0, 1), obs("B", "e", 1, 2)])
    srv = _serve(ch, {"tokA": ["A"]})
    try:
        win = "from=2026-09-28T12:00:00Z&to=2026-09-28T13:00:00Z"
        st, body = _get(srv, f"/observations?entity=e&tenant=B&{win}", token="tokA")  # param must not broaden
        assert st == 200
        assert [o["tenant"] for o in body["observations"]] == ["A"]
    finally:
        srv.shutdown()


def test_http_bad_request_returns_400():
    ch = FakeCH([])
    srv = _serve(ch, {"tokA": ["A"]})
    try:
        assert _get(srv, "/observations?entity=e", token="tokA")[0] == 400   # missing window
        assert _get(srv, "/observations?from=2026-09-28T12:00:00Z&to=2026-09-28T13:00:00Z",
                    token="tokA")[0] == 400                                   # missing entity
    finally:
        srv.shutdown()


WIN = "from=2026-09-28T12:00:00Z&to=2026-09-28T13:00:00Z"


# ── shared ClickHouse client is safe & correct across ThreadingHTTPServer threads ─

def test_make_client_disables_session_id_for_shared_thread_use():
    # The production fix for the shared-client concurrency blocker: make_client must
    # pass autogenerate_session_id=False so overlapping request threads sharing the
    # one client don't collide inside a single ClickHouse session.
    import sys
    import types
    captured = {}
    fake = types.ModuleType("clickhouse_connect")
    fake.get_client = lambda **kw: (captured.update(kw) or object())
    real = sys.modules.get("clickhouse_connect")
    sys.modules["clickhouse_connect"] = fake
    import os as _os
    _os.environ.setdefault("CLICKHOUSE_PASSWORD", "x")
    try:
        app.make_client()
    finally:
        if real is not None:
            sys.modules["clickhouse_connect"] = real
        else:
            sys.modules.pop("clickhouse_connect", None)
    assert captured.get("autogenerate_session_id") is False


def test_concurrent_requests_share_client_without_cross_talk():
    # Regression for the shared-client blocker at the handler layer: fire overlapping
    # requests for two tenants against ONE shared client and prove (a) they genuinely
    # overlap and (b) each thread gets ONLY its own tenant's rows — no per-request
    # state bleeds across threads.
    import time
    lock = threading.Lock()

    class SlowCH(FakeCH):
        def __init__(self, rows):
            super().__init__(rows)
            self.active = self.peak = 0

        def query(self, sql, parameters):
            with lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
            time.sleep(0.05)                       # widen the overlap window
            try:
                return super().query(sql, parameters)
            finally:
                with lock:
                    self.active -= 1

    ch = SlowCH([obs("A", "e", 0, 1), obs("B", "e", 1, 2)])
    srv = _serve(ch, {"tokA": ["A"], "tokB": ["B"]})
    results = {}

    def hit(i):
        tok = "tokA" if i % 2 == 0 else "tokB"
        st, body = _get(srv, f"/observations?entity=e&{WIN}", token=tok)
        results[i] = (st, [o["tenant"] for o in body["observations"]])

    threads = [threading.Thread(target=hit, args=(i,)) for i in range(8)]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        srv.shutdown()
    assert ch.peak > 1                             # requests really did overlap on the shared client
    for i, (st, tenants) in results.items():
        assert st == 200
        assert tenants == (["A"] if i % 2 == 0 else ["B"])   # no cross-tenant leak under concurrency


# ── backend failures become a controlled JSON 5xx, never an escaped exception ─────

def test_db_failure_returns_controlled_503_not_crash():
    class BoomCH:
        def __init__(self, exc):
            self.exc = exc

        def query(self, sql, parameters):
            raise self.exc

    for exc in (RuntimeError("clickhouse unavailable"), TimeoutError("query timed out")):
        srv = _serve(BoomCH(exc), {"tokA": ["A"]})
        try:
            st, body = _get(srv, f"/observations?entity=e&{WIN}", token="tokA")
        finally:
            srv.shutdown()
        assert st == 503
        assert body["error"] == "evidence backend unavailable"
        assert body["request_id"]                 # correlator returned to the caller
        assert "clickhouse" not in json.dumps(body) and "timed out" not in json.dumps(body)  # detail stays server-side


# ── audit trail: every read and every rejected access is audited (§21.2) ──────────

def test_audit_event_emitted_on_successful_read():
    ch = FakeCH([obs("A", "e", 0, 1)])
    events = []
    srv = _serve(ch, {"tokA": ["A"]}, audit=events.append)
    try:
        assert _get(srv, f"/observations?entity=e&{WIN}", token="tokA")[0] == 200
    finally:
        srv.shutdown()
    assert len(events) == 1
    ev = events[0]
    assert ev["action"] == "evidence.query" and ev["outcome"] == "success"
    assert ev["tenant_scope"] == ["A"]            # server-derived scope, not a query param
    assert ev["entity"] == "e" and ev["returned"] == 1
    assert ev["actor"].startswith("token:") and ev["request_id"]
    assert "tokA" not in json.dumps(ev)           # bearer credential never appears in the audit record


def test_audit_event_emitted_on_denied_access():
    ch = FakeCH([obs("A", "e", 0, 1)])
    events = []
    srv = _serve(ch, {"tokA": ["A"]}, audit=events.append)
    try:
        assert _get(srv, f"/observations?entity=e&{WIN}")[0] == 401                 # no token
        assert _get(srv, f"/observations?entity=e&{WIN}", token="bogus")[0] == 401  # unknown token
    finally:
        srv.shutdown()
    assert len(events) == 2
    assert all(e["outcome"] == "denied" for e in events)
    assert events[0]["actor"] == "anonymous"      # no bearer -> anonymous actor
    assert events[1]["actor"].startswith("token:")
    assert "bogus" not in json.dumps(events)      # rejected bearer never logged


def test_audit_event_emitted_on_db_error():
    class BoomCH:
        def query(self, sql, parameters):
            raise RuntimeError("down")

    events = []
    srv = _serve(BoomCH(), {"tokA": ["A"]}, audit=events.append)
    try:
        assert _get(srv, f"/observations?entity=e&{WIN}", token="tokA")[0] == 503
    finally:
        srv.shutdown()
    assert [e["outcome"] for e in events] == ["error"]


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f()
            print("ok  " + _n)
    print("\nall evidence-service tests passed")
