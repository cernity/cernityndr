"""Mocked evidence page tests; live ClickHouse remains a deployment smoke test."""
import io
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from jsonschema import ValidationError

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("hunt", HERE / "hunt.py")
hunt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hunt)
sys.modules["hunt"] = hunt
app = hunt.load_module("hunt_app", HERE / "app.py")
Store = app.HuntStore


def job(kind="ip", value="192.0.2.1", **extra):
    return {"schema": "hunt.v1", "hunt_id": "h1", "tenant": "a",
            "from": "2026-09-01T00:00:00Z", "to": "2026-09-02T00:00:00Z",
            "indicators": [{"type": kind, "indicator": value,
                            "intel_known_at": "2026-09-01T12:00:00Z"}], **extra}


def obs(id="1", tenant="a", ts="2026-09-01T00:00:00Z", fields=None):
    return {"tenant": tenant, "obs_id": id, "type": "conn",
            "ts": {"sensor": ts, "normalized": ts, "method": "clock-offset"},
            "fields": fields or {"src_ip": "192.0.2.1"},
            "source_ref": {"tenant": tenant, "obs_id": id}}


class Evidence:
    def __init__(self, rows=()):
        self.rows, self.calls = rows, []

    def page(self, tenant, frm, to, page_size, after):
        self.calls.append((tenant, frm, to, page_size, after))
        start, end = hunt.query.parse_window(frm, to)
        end = min(end, start + hunt.query.MAX_WINDOW)
        rows = sorted([r for r in self.rows if r["tenant"] == tenant
                       and (hunt.query._parse_ts(r["ts"]["normalized"]), r["obs_id"]) > (start, after)
                       and hunt.query._parse_ts(r["ts"]["normalized"]) < end],
                      key=lambda r: (r["ts"]["normalized"], r["obs_id"]))
        if len(rows) > page_size:
            nxt, cursor = rows[page_size-1]["ts"]["normalized"], rows[page_size-1]["obs_id"]
        elif end < hunt.query._parse_ts(to):
            nxt, cursor = end.isoformat(), ""
        else:
            nxt, cursor = None, None
        return {"observations": rows[:page_size], "next": nxt, "next_after": cursor}


def test_dates_and_idempotent_restart(tmp_path):
    path = str(tmp_path / "hunts.db")
    evidence = Evidence([obs()])
    first = hunt.HuntWorker(evidence, Store(path)).step(job(), "a")
    hit = first["hits"][0]
    assert hit["observed_at"] == "2026-09-01T00:00:00Z"
    assert hit["intel_known_at"] == "2026-09-01T12:00:00Z"
    assert hit["learned_after_observation"] is True
    assert hunt.HuntWorker(evidence, Store(path)).step(job(), "a") == first
    assert len(evidence.calls) == 1


@pytest.mark.parametrize("known,expected", [("2026-08-31T00:00:00Z", False),
                                            ("2026-09-01T00:00:00Z", False)])
def test_known_before_or_at_traffic(known, expected):
    request = job()
    request["indicators"][0]["intel_known_at"] = known
    result = hunt.HuntWorker(Evidence([obs()]), Store()).step(request, "a")
    assert result["hits"][0]["learned_after_observation"] is expected


def test_half_open_windows_and_keyset_ties():
    evidence = Evidence([obs("1"), obs("2"), obs("3", ts="2026-09-02T00:00:00Z")])
    store = Store()
    worker = hunt.HuntWorker(evidence, store)
    request = job(page_size=1)
    assert worker.step(request, "a")["status"] == "pending"
    first = worker.step(request, "a")
    assert {h["obs_id"] for h in first["hits"]} == {"1", "2"}
    assert first["status"] == "complete"
    second = worker.step(job(hunt_id="h2", **{"from": request["to"], "to": "2026-09-03T00:00:00Z"}), "a")
    assert [h["obs_id"] for h in second["hits"]] == ["3"]
    page = store.results("a", "h1", limit=1)
    following = store.results("a", "h1", after=page["next_after"], limit=1)
    assert page["hits"][0]["hit_id"] != following["hits"][0]["hit_id"]
    assert following["next_after"] is None


def test_empty_days_continue_and_empty_is_success():
    evidence = Evidence()
    worker = hunt.HuntWorker(evidence, Store())
    request = job(to="2026-09-04T00:00:00Z")
    for status in ["pending", "pending", "complete"]:
        result = worker.step(request, "a")
        assert result["status"] == status and result["hits"] == []


@pytest.mark.parametrize("kind,value", [("hash", "f"*64), ("url", "https://example.test/path")])
def test_deferred(kind, value):
    evidence = Evidence([obs()])
    result = hunt.HuntWorker(evidence, Store()).step(job(kind, value), "a")
    assert result["unsupported"][0]["status"] == "dimension not yet supported"
    assert result["hits"] == [] and result["status"] == "complete"
    assert not evidence.calls


@pytest.mark.parametrize("kind,value,fields", [
    ("ip", "192.0.2.0/24", {"dest_ip": "192.0.2.7"}),
    ("domain", "EXAMPLE.TEST", {"dns": {"queries": [{"rrname": "example.test"}]}}),
    ("domain", "example.test", {"http": {"hostname": "Example.Test"}}),
    ("domain", "example.test", {"tls": {"sni": "example.test"}}),
    ("ja3", "abc", {"tls": {"ja3": {"hash": "ABC"}}}),
    ("ja3", "abc", {"tls": {"ja3s": {"hash": "abc"}}}),
    ("ja4", "abc", {"tls": {"ja4s": "ABC"}}),
    ("cert", "ab:cd", {"tls": {"fingerprint": "AB:CD"}}),
])
def test_dimensions(kind, value, fields):
    assert len(hunt.HuntWorker(Evidence([obs(fields=fields)]), Store()).step(job(kind, value), "a")["hits"]) == 1


def test_tenant_isolation_and_conflict():
    evidence, store = Evidence([obs(tenant="a"), obs(tenant="b")]), Store()
    worker = hunt.HuntWorker(evidence, store)
    with pytest.raises(PermissionError):
        worker.step(job(), "b")
    worker.step(job(), "a")
    with pytest.raises(KeyError):
        store.results("b", "h1")
    with pytest.raises(ValueError, match="different request"):
        worker.step(job(value="192.0.2.9"), "a")
    result = worker.step(job(tenant="b"), "b")
    assert {h["tenant"] for h in result["hits"]} == {"b"}
    assert [c[0] for c in evidence.calls] == ["a", "b"]


def test_failures_do_not_advance_checkpoint():
    evidence, store = Evidence([obs(tenant="b")]), Store()
    def wrong(*args):
        return {"observations": [obs(tenant="b")], "next": None}
    evidence.page = wrong
    worker = hunt.HuntWorker(evidence, store)
    with pytest.raises(ValueError, match="tenant mismatch"):
        worker.step(job(), "a")
    assert store.results("a", "h1")["hits"] == []
    worker.evidence = Evidence([obs()])
    assert worker.step(job(), "a")["status"] == "complete"


def test_saved_snapshot_and_missing_acquisition():
    record = {"tenant": "a", "type": "ip", "indicator": "192.0.2.1",
              "first_seen": "2020-01-01T00:00:00Z",
              "provenance": [{"observed_at": "2026-09-01T12:00:00Z"}]}
    request = job()
    del request["indicators"]
    request["intel_set"] = "feed"
    sets = {"a": {"feed": [record]}}
    worker = hunt.HuntWorker(Evidence([obs()]), Store(), sets)
    assert worker.step(request, "a")["hits"][0]["learned_after_observation"]
    record["provenance"] = []
    assert worker.step(request, "a")["status"] == "complete"  # persisted snapshot
    with pytest.raises(ValueError, match="acquisition"):
        hunt.HuntWorker(Evidence(), Store(), sets).step(request, "a")
    record["tenant"] = "b"
    with pytest.raises(ValueError, match="tenant mismatch"):
        hunt.HuntWorker(Evidence(), Store(), sets).step(request, "a")


@pytest.mark.parametrize("changes", [{"page_size": 1001}, {"indicators": []},
                                     {"intel_set": "both"}, {"from": "bad"}])
def test_contract_rejects_invalid(changes):
    with pytest.raises(ValidationError):
        hunt.HuntWorker(Evidence(), Store()).step(job(**changes), "a")


def test_evidence_layer_parameter_binding():
    class Client:
        def query(self, sql, parameters):
            assert "tenant_id IN {tenants:Array(String)}" in sql
            assert "has(entity_values" not in sql
            assert "normalized_time <" in sql
            assert parameters["tenants"] == ["a"]
            assert parameters["limit"] == 11
            assert parameters["until"] - parameters["frm"] == hunt.query.MAX_WINDOW
            return type("Result", (), {"column_names": [], "result_rows": []})()
    result = hunt.EvidenceClient(Client()).page("a", "2026-09-01T00:00:00Z", "2026-09-03T00:00:00Z", 10, "")
    assert result["next"] == "2026-09-02T00:00:00Z"


def test_http_auth_and_scoping():
    worker = hunt.HuntWorker(Evidence([obs()]), Store())
    handler_class = app.make_handler(worker, {"ta": "a", "tb": "b", "multi": ["a", "b"]})
    def call(method, path, token=None, body=None):
        handler = handler_class.__new__(handler_class)
        raw = json.dumps(body).encode() if body is not None else b""
        handler.path = path
        handler.rfile = io.BytesIO(raw)
        handler.headers = {"Content-Length": str(len(raw))}
        if token:
            handler.headers["Authorization"] = f"Bearer {token}"
        responses = []
        handler.send = lambda status, data: responses.append((status, data))
        handler.handle_request(method == "POST")
        return responses[0]
    assert call("POST", "/hunts", body=job())[0] == 401
    assert call("POST", "/hunts", "multi", job())[0] == 401
    assert call("POST", "/hunts", "tb", job())[0] == 403
    assert call("POST", "/hunts", "ta", job())[0] == 200
    assert call("GET", "/hunts/h1?tenant=a", "tb")[0] == 404
    assert call("GET", "/hunts/h1?limit=1001", "ta")[0] == 400
    assert call("GET", "/hunts/h1", "ta")[1]["hits"]
    assert call("POST", "/hunts", "ta", {})[0] == 400


def test_mixed_unsupported_and_no_matching_observation():
    request = job(value="192.0.2.99")
    request["indicators"].append({"type": "hash", "indicator": "f"*64,
                                   "intel_known_at": "2026-09-01T12:00:00Z"})
    result = hunt.HuntWorker(Evidence([obs()]), Store()).step(request, "a")
    assert result["hits"] == [] and result["status"] == "complete"
    assert result["unsupported"][0]["type"] == "hash"


def test_restart_pending_and_backend_failure(tmp_path):
    path = str(tmp_path / "hunts.db")
    request = job(page_size=1)
    evidence = Evidence([obs("1"), obs("2")])
    first = hunt.HuntWorker(evidence, Store(path)).step(request, "a")
    assert first["status"] == "pending"
    class Down:
        def page(self, *args):
            raise RuntimeError("offline")
    reopened = Store(path)
    with pytest.raises(RuntimeError):
        hunt.HuntWorker(Down(), reopened).step(request, "a")
    assert reopened.results("a", "h1") == first
    final = hunt.HuntWorker(evidence, reopened).step(request, "a")
    assert final["status"] == "complete"
    assert {h["obs_id"] for h in final["hits"]} == {"1", "2"}


def test_duplicates_and_clock_provenance():
    row = obs()
    row["ts"]["sensor"] = "2026-08-31T23:59:59Z"
    row["ts"]["method"] = "ingest-fallback"
    result = hunt.HuntWorker(Evidence([row, row]), Store()).step(job(), "a")
    assert len(result["hits"]) == 1
    assert result["hits"][0]["observed_at"] == row["ts"]["sensor"]
    assert result["hits"][0]["observation_ts"]["method"] == "ingest-fallback"


def test_window_and_cursor_bounds():
    worker = hunt.HuntWorker(Evidence(), Store())
    with pytest.raises(ValueError, match="31 days"):
        worker.step(job(to="2026-11-01T00:00:00Z"), "a")
    with pytest.raises(ValueError, match="after from"):
        worker.step(job(to="2026-09-01T00:00:00Z"), "a")
    class Stuck:
        def page(self, *args):
            return {"observations": [obs()], "next": args[1], "next_after": ""}
    worker.evidence = Stuck()
    with pytest.raises(ValueError, match="cursor"):
        worker.step(job(), "a")
    assert worker.store.results("a", "h1")["hits"] == []
