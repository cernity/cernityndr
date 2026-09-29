"""sensor-registry (U3a) tests: real U2 heartbeat ingestion, SQLite round-trip,
staleness/skew derivations, and reader-side tenant authz over the HTTP API.

Modules are loaded by PATH (not `import store`/`import app`): shared/store.py
owns the name `store` on PYTHONPATH=shared, and several services share the module
name `app` — path-loading keeps this collision-free in a single pytest process.
"""
import http.client
import importlib.util
import json
import threading
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


store_mod = _load("registry_store", Path(__file__).with_name("store.py"))
app = _load("registry_app", Path(__file__).with_name("app.py"))
agent_mod = _load("sensor_health_agent", ROOT / "services/sensor-agent/agent.py")
contract = _load("sensor_health_contract", ROOT / "contracts/test_sensor_health.py")


def real_heartbeat(tenant="acme", site="dc1", offset_ms=-12.5, sensor_uuid=None):
    """A genuine U2 sensor-agent heartbeat (Agent.heartbeat), validated against
    the sensor-health.v1 contract so ingestion is proven against the REAL wire
    format, not a fabricated dict."""
    if offset_ms is None:
        clock = lambda: {"clock_offset_ms": None, "time_source": None, "clock_status": "unavailable"}
    else:
        clock = lambda: {"clock_offset_ms": offset_ms, "time_source": "192.0.2.1", "clock_status": "synchronized"}
    agent = agent_mod.Agent(sensor_uuid or str(uuid.uuid4()), tenant, site, clock=clock)
    record = agent.heartbeat()
    contract.VALIDATOR.validate(record)          # it really is sensor-health.v1
    return record


def fresh():
    return store_mod.RegistryStore(":memory:")


def _view(reg, record, now=None, skew_ms=100.0, stale_s=90.0):
    row = reg.get(record["sensor_uuid"], [record["tenant"]])
    # freshness is keyed off the server receipt time, so default `now` to it -> fresh.
    return store_mod.sensor_view(row, now if now is not None else row["received_at"],
                                 skew_ms, stale_s)


# ── ingestion / round-trip ──────────────────────────────────────────────────

def test_real_u2_heartbeat_populates_inventory():
    reg = fresh()
    record = real_heartbeat(tenant="acme", site="dc1")
    assert reg.upsert_heartbeat(record) is True
    row = reg.get(record["sensor_uuid"], ["acme"])
    assert row is not None
    assert row["tenant"] == "acme" and row["site"] == "dc1"
    assert json.loads(row["versions"])["agent"] == agent_mod.VERSION


def test_upsert_then_read_updates_in_place():
    reg = fresh()
    record = real_heartbeat(offset_ms=-12.5)
    reg.upsert_heartbeat(record)
    newer = dict(record, observed_at="2099-01-01T00:00:00Z", clock_offset_ms=5.0)
    reg.upsert_heartbeat(newer)
    assert len(reg.list_sensors([record["tenant"]])) == 1      # upsert, not a second insert
    row = reg.get(record["sensor_uuid"], [record["tenant"]])
    assert row["last_seen"] == "2099-01-01T00:00:00Z" and row["clock_offset_ms"] == 5.0


def test_ingested_records_are_producer_unverified():
    reg = fresh()
    record = real_heartbeat()
    reg.upsert_heartbeat(record)                                # ingest path
    assert _view(reg, record)["producer_verified"] is False


def test_malformed_heartbeat_dropped_not_raised():
    reg = fresh()
    assert reg.upsert_heartbeat({"schema_version": "v2"}) is False
    assert reg.upsert_heartbeat({"schema_version": "sensor-health.v1", "sensor_uuid": "x"}) is False
    assert reg.upsert_heartbeat("nonsense") is False
    assert reg.list_sensors(["acme"]) == []


def test_upsert_handles_unbindable_values_without_raising():
    # Values a naive type check passes but SQLite cannot bind, reproduced from the
    # reviewer's evidence: 10**30 overflows the 64-bit INTEGER bind (but is a finite
    # double), 10**400 is not float-representable, NaN/inf are not measurements, and a
    # lone surrogate is not UTF-8 encodable. upsert must normalize or drop each — never
    # raise (which ingest_loop would mistake for a storage failure) — and a valid
    # heartbeat must still ingest afterward.
    reg = fresh()
    base = real_heartbeat(tenant="A")
    assert reg.upsert_heartbeat({**base, "sensor_uuid": "big", "clock_offset_ms": 10**30}) is True
    assert reg.upsert_heartbeat({**base, "sensor_uuid": "huge", "clock_offset_ms": 10**400}) is False
    assert reg.upsert_heartbeat({**base, "sensor_uuid": "nan", "clock_offset_ms": float("nan")}) is False
    assert reg.upsert_heartbeat({**base, "sensor_uuid": "inf", "clock_offset_ms": float("inf")}) is False
    assert reg.upsert_heartbeat({**base, "sensor_uuid": "surr", "tenant": "A\ud800"}) is False
    assert reg.get("big", ["A"])["clock_offset_ms"] == float(10**30)   # normalized to REAL, stored
    good = real_heartbeat(tenant="A")
    assert reg.upsert_heartbeat(good) is True                          # valid heartbeat still lands
    assert reg.get(good["sensor_uuid"], ["A"]) is not None


# ── derived signals: staleness → offline, skew → skew_flag (A7) ─────────────

def test_staleness_marks_offline():
    reg = fresh()
    record = real_heartbeat()
    reg.upsert_heartbeat(record, received_at=1000.0)
    assert _view(reg, record, now=1001.0, stale_s=90)["status"] == "online"
    assert _view(reg, record, now=2000.0, stale_s=90)["status"] == "offline"


def test_freshness_uses_server_receipt_not_sensor_clock():
    # Liveness must key off the SERVER's receipt time, never the sensor's
    # self-reported observed_at — a drifted sensor clock (fast OR slow) must not
    # fake freshness. This is the exact bug the reviewer flagged: a sensor an hour
    # ahead reported "online" forever after it stopped.
    reg = fresh()

    # sensor clock ~decades AHEAD: observed_at is far in the future.
    ahead = real_heartbeat(tenant="A")
    ahead["observed_at"] = "2099-01-01T00:00:00Z"
    reg.upsert_heartbeat(ahead, received_at=1000.0)
    st = lambda now: _view(reg, ahead, now=now, stale_s=90)["status"]
    assert st(1001.0) == "online"       # 1s since receipt
    assert st(2000.0) == "offline"      # 1000s since receipt -> offline despite future observed_at

    # sensor clock ~decades BEHIND: observed_at is far in the past.
    behind = real_heartbeat(tenant="B")
    behind["observed_at"] = "1970-01-01T00:00:00Z"
    reg.upsert_heartbeat(behind, received_at=5000.0)
    st2 = lambda now: _view(reg, behind, now=now, stale_s=90)["status"]
    assert st2(5001.0) == "online"      # fresh despite ancient observed_at
    assert st2(6000.0) == "offline"     # 1000s since receipt -> offline


def test_clock_skew_beyond_threshold_flags():
    reg = fresh()
    hi = real_heartbeat(offset_ms=250.0)
    lo = real_heartbeat(offset_ms=12.5)
    un = real_heartbeat(offset_ms=None)                         # clock unavailable
    for r in (hi, lo, un):
        reg.upsert_heartbeat(r)
    assert _view(reg, hi, skew_ms=100)["skew_flag"] is True
    assert _view(reg, lo, skew_ms=100)["skew_flag"] is False
    assert _view(reg, un, skew_ms=100)["skew_flag"] is False    # absence is not skew


# ── tenant isolation at the store layer ─────────────────────────────────────

def test_tenant_isolation_store_level():
    reg = fresh()
    a = real_heartbeat(tenant="A")
    b = real_heartbeat(tenant="B")
    reg.upsert_heartbeat(a)
    reg.upsert_heartbeat(b)
    assert [r["sensor_uuid"] for r in reg.list_sensors(["A"])] == [a["sensor_uuid"]]
    assert reg.get(b["sensor_uuid"], ["A"]) is None             # A cannot read B's sensor
    assert reg.get(b["sensor_uuid"], ["B"]) is not None


def test_same_uuid_cross_tenant_heartbeat_refused_metadata_preserved():
    # A spoofable heartbeat must not move a sensor (or its enrollment metadata)
    # from tenant A to tenant B by reusing the UUID — verified identity is U3b.
    reg = fresh()
    a = real_heartbeat(tenant="A")
    reg.upsert_heartbeat(a)
    with reg._lock:                                             # simulate U3b enrollment on A's row
        reg._db.execute("UPDATE sensors SET tags=?, groups=?, cert_fingerprint=? WHERE sensor_uuid=?",
                        (json.dumps(["edge"]), json.dumps(["g1"]), "AA:BB", a["sensor_uuid"]))
        reg._db.commit()
    b = real_heartbeat(tenant="B", sensor_uuid=a["sensor_uuid"])   # same UUID, different tenant
    assert reg.upsert_heartbeat(b) is False                    # refused, not reassigned
    assert reg.list_sensors(["B"]) == []                       # B never acquires the sensor
    row = reg.get(a["sensor_uuid"], ["A"])
    assert row["tenant"] == "A"
    assert json.loads(row["tags"]) == ["edge"] and json.loads(row["groups"]) == ["g1"]
    assert row["cert_fingerprint"] == "AA:BB"                  # enrollment metadata stayed put


# ── HTTP API: reader authz + surfaced flags ─────────────────────────────────

def _serve(reg, tokens, **kw):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app.make_handler(reg, tokens, **kw))
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
    reg = fresh()
    reg.upsert_heartbeat(real_heartbeat(tenant="acme"))
    srv = _serve(reg, {"tok": ["acme"]})
    try:
        assert _get(srv, "/sensors")[0] == 401                 # no token
        assert _get(srv, "/sensors", token="bogus")[0] == 401  # unknown token
        assert _get(srv, "/healthz")[0] == 200                 # health is open
    finally:
        srv.shutdown()


def test_http_reader_cannot_read_ungranted_tenant():
    reg = fresh()
    a = real_heartbeat(tenant="A")
    b = real_heartbeat(tenant="B")
    reg.upsert_heartbeat(a)
    reg.upsert_heartbeat(b)
    srv = _serve(reg, {"tokA": ["A"], "tokB": ["B"]})
    try:
        st, body = _get(srv, "/sensors", token="tokA")
        assert st == 200
        assert {s["sensor_uuid"] for s in body["sensors"]} == {a["sensor_uuid"]}
        assert _get(srv, f"/sensors/{b['sensor_uuid']}", token="tokA")[0] == 404  # no leak
        assert _get(srv, f"/sensors/{b['sensor_uuid']}", token="tokB")[0] == 200
    finally:
        srv.shutdown()


def test_http_tenant_query_param_is_ignored():
    reg = fresh()
    reg.upsert_heartbeat(real_heartbeat(tenant="A"))
    reg.upsert_heartbeat(real_heartbeat(tenant="B"))
    srv = _serve(reg, {"tokA": ["A"]})
    try:
        st, body = _get(srv, "/sensors?tenant=B", token="tokA")   # param must not broaden
        assert st == 200 and body["sensors"] and all(s["tenant"] == "A" for s in body["sensors"])
    finally:
        srv.shutdown()


def test_http_surfaces_skew_flag_and_unverified():
    reg = fresh()
    reg.upsert_heartbeat(real_heartbeat(tenant="A", offset_ms=250.0))
    srv = _serve(reg, {"tokA": ["A"]}, skew_ms=100.0, stale_s=1e12)  # never stale in this test
    try:
        st, body = _get(srv, "/sensors", token="tokA")
        s = body["sensors"][0]
        assert st == 200 and s["skew_flag"] is True and s["producer_verified"] is False
    finally:
        srv.shutdown()


def test_http_groups_endpoint_empty_until_enrollment():
    reg = fresh()
    reg.upsert_heartbeat(real_heartbeat(tenant="A"))
    srv = _serve(reg, {"tokA": ["A"]})
    try:
        st, body = _get(srv, "/groups", token="tokA")
        assert st == 200 and body["groups"] == {}      # heartbeats carry no groups (§6.4/U3b)
    finally:
        srv.shutdown()


# ── consumer-loop integration: exercise the REAL ingest_loop, not a store call ─

class _FakeMsg:
    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value


class _FakeConsumer:
    """A controlled consumer seam. Each record is pushed through the SAME JSON serde
    ndr_runtime's producer/consumer use (json.dumps().encode() -> json.loads()), so
    ingest_loop is proven against the real wire format, not an in-memory dict.
    `boom=True` raises on iteration to simulate a broker/consumer failure."""

    def __init__(self, records=(), boom=False):
        self._msgs = [_FakeMsg(json.loads(json.dumps(r).encode().decode())) for r in records]
        self._boom = boom

    def __iter__(self):
        if self._boom:
            raise RuntimeError("broker gone")
        return iter(self._msgs)


def test_ingest_loop_consumes_real_u2_heartbeat_end_to_end():
    reg = fresh()
    record = real_heartbeat(tenant="A", offset_ms=250.0)        # real Agent.heartbeat, schema-valid
    app.ingest_loop(reg, consumer=_FakeConsumer([record]))      # the ACTUAL loop, wire-serialized
    srv = _serve(reg, {"tokA": ["A"]}, skew_ms=100.0, stale_s=1e12)
    try:
        st, body = _get(srv, "/sensors", token="tokA")
        s = body["sensors"][0]
        assert st == 200 and s["sensor_uuid"] == record["sensor_uuid"]
        assert s["skew_flag"] is True and s["producer_verified"] is False
    finally:
        srv.shutdown()


def test_ingest_loop_survives_malformed_then_ingests_valid():
    reg = fresh()
    bad = {"schema_version": "sensor-health.v1", "sensor_uuid": "x", "tenant": {"nope": 1}}
    good = real_heartbeat(tenant="A")
    app.ingest_loop(reg, consumer=_FakeConsumer([bad, good]))   # the bad one must not stop ingestion
    assert len(reg.list_sensors(["A"])) == 1
    assert reg.get(good["sensor_uuid"], ["A"]) is not None


def test_ingest_loop_survives_unbindable_values_then_ingests_valid():
    # Reviewer's remaining blocker: clock_offset_ms=10**30 raised OverflowError and a
    # lone surrogate in tenant raised UnicodeEncodeError during the SQLite bind — both
    # were mistaken for STORAGE failures, crashing ingestion so the NEXT valid heartbeat
    # was never stored. Driven through the SAME wire serde, each must be a bad-message
    # skip (or normalized): readiness stays ready and the following valid record lands.
    import metrics
    reg = fresh()
    base = real_heartbeat(tenant="A")
    over = {**base, "sensor_uuid": "over", "clock_offset_ms": 10**30}   # INTEGER-bind overflow
    surr = {**base, "sensor_uuid": "surr", "tenant": "A\ud800"}         # non-UTF-8 tenant
    good = real_heartbeat(tenant="A")
    app.ingest_loop(reg, consumer=_FakeConsumer([over, surr, good]))    # real wire serde
    assert metrics.is_ready() is True                                  # a skip, not a storage failure
    assert reg.get(good["sensor_uuid"], ["A"]) is not None             # the valid one after each is stored


def test_ingest_loop_failure_marks_not_ready():
    import metrics
    metrics.set_ready("consumer", True)
    assert metrics.is_ready() is True
    try:
        app.ingest_loop(fresh(), consumer=_FakeConsumer(boom=True))
        raise AssertionError("expected the loop to propagate the broker failure")
    except RuntimeError:
        pass
    assert metrics.is_ready() is False                          # /readyz -> 503, not a silent death


def test_deserialize_tolerates_garbage_bytes():
    # The consumer serde must turn undeserializable wire bytes into a None sentinel,
    # never raise — a raising deserializer crashes `for msg in consumer` and kills
    # the whole loop over one bad message.
    assert app._deserialize(json.dumps(real_heartbeat()).encode())["schema_version"] == "sensor-health.v1"
    assert app._deserialize(b"not json at all") is None
    assert app._deserialize(b"\xff\xfe\x00") is None            # undecodable bytes


def test_ingest_loop_skips_undeserializable_then_ingests_valid():
    # A record the deserializer could not parse arrives as msg.value=None; it must be
    # skipped (not crash the loop, not stop ingestion) and the next valid one ingests.
    reg = fresh()
    good = _FakeMsg(json.loads(json.dumps(real_heartbeat(tenant="A")).encode().decode()))

    class _MixedConsumer:
        def __iter__(self):
            return iter([_FakeMsg(None), good])                 # None == deserializer gave up

    app.ingest_loop(reg, consumer=_MixedConsumer())
    assert len(reg.list_sensors(["A"])) == 1                    # bad one skipped, valid one ingested


def test_ingest_loop_storage_failure_surfaces_not_swallowed():
    # A STORAGE failure is NOT a bad message: it must surface (mark not-ready +
    # propagate), never be silently discarded while /readyz stays green. This is the
    # reviewer's blocker 2 — the loop must distinguish a bad heartbeat from a broken store.
    import metrics
    import sqlite3
    metrics.set_ready("consumer", True)

    class _BoomStore:
        def upsert_heartbeat(self, *a, **k):
            raise sqlite3.OperationalError("disk I/O error")

    try:
        app.ingest_loop(_BoomStore(), consumer=_FakeConsumer([real_heartbeat(tenant="A")]))
        raise AssertionError("a storage failure must not be swallowed as a bad message")
    except sqlite3.OperationalError:
        pass
    assert metrics.is_ready() is False                          # surfaced via readiness, not lost


def test_ingest_loop_construction_failure_marks_not_ready():
    # Broker unreachable at STARTUP: make_consumer raises. Construction is inside the
    # failure boundary, so the loop marks the consumer not-ready and re-raises instead
    # of a daemon thread dying behind a green /healthz with a stuck 'ready' state.
    import metrics
    metrics.set_ready("consumer", True)                         # pretend a prior run was ready
    orig = app.ndr_runtime.make_consumer
    app.ndr_runtime.make_consumer = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no broker"))
    try:
        app.ingest_loop(fresh(), consumer=None)                 # consumer=None -> real construction path
        raise AssertionError("expected consumer construction failure to propagate")
    except RuntimeError:
        pass
    finally:
        app.ndr_runtime.make_consumer = orig
    assert metrics.is_ready() is False                          # never false-ready on a dead consumer


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f()
            print("ok  " + _n)
    print("\nall sensor-registry tests passed")
