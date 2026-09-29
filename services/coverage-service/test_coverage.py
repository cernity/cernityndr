"""coverage-service (U4) tests: fleet-global detector map, tenant-scoped observed
overlay, exists-vs-observed distinction, malformed-metadata skipping, and tenant
isolation exercised end-to-end (token -> tenant grant -> ClickHouse filter)
against a fake client that faithfully models the `tenant_id IN %(tenants)s`
filter of observed_query's SQL.

Path-loaded (not `import app`): several services share the module name `app`, so
path-loading keeps a single pytest process collision-free (see evidence-service).
"""
import http.client
import importlib.util
import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


coverage = _load("coverage_logic", Path(__file__).with_name("coverage.py"))
app = _load("coverage_app", Path(__file__).with_name("app.py"))
app.coverage = coverage  # bind the same path-loaded module the tests use


class _Result:
    def __init__(self, rows):
        self.column_names = ["technique"]
        self.result_rows = rows


class _FakeClient:
    """Models `SELECT DISTINCT arrayJoin(mitre) FROM ndr.finding
    WHERE tenant_id IN %(tenants)s`: findings are (tenant, [techniques]); a query
    returns the distinct techniques whose finding's tenant is in the bound param."""

    def __init__(self, findings):
        self.findings = findings  # [(tenant, [technique, ...]), ...]

    def query(self, sql, parameters):
        tenants = set(parameters["tenants"])
        seen = set()
        for tenant, techniques in self.findings:
            if tenant in tenants:
                seen.update(t for t in techniques if t)
        return _Result([(t,) for t in sorted(seen)])


# --- load_detector_map / build_coverage (pure logic) -------------------------

DETECTOR_CONFIG = [
    {"detector_id": "east-west", "techniques": ["T1046", "T1021.002"]},
    {"detector_id": "dns-tunnel", "techniques": ["T1046"]},
]
# Fleet reporting universe. T1486 is catalogued but no detector claims it and it
# need never have fired for the report to flag it as a gap.
CATALOG = ["T1046", "T1021.002", "T1486"]


def test_technique_with_active_detector_is_covered():
    dmap = coverage.load_detector_map(DETECTOR_CONFIG)
    report = coverage.build_coverage(dmap, observed=[])
    t1046 = next(r for r in report["techniques"] if r["technique"] == "T1046")
    assert t1046["covered"] is True
    assert t1046["detectors"] == ["dns-tunnel", "east-west"]  # sorted, deduped


def test_catalogued_technique_without_detector_is_a_gap_unobserved():
    # The reporting universe (catalog), not observations, drives gap reporting: a
    # catalogued technique with no detector is a gap even with zero findings.
    dmap = coverage.load_detector_map(DETECTOR_CONFIG)
    report = coverage.build_coverage(dmap, observed=[], catalog=CATALOG)
    t1486 = next(r for r in report["techniques"] if r["technique"] == "T1486")
    assert t1486["covered"] is False
    assert t1486["observed"] is False
    assert "T1486" in report["gaps"]


def test_uncovered_technique_is_a_gap():
    dmap = coverage.load_detector_map(DETECTOR_CONFIG)
    # A technique that only ever fired, with no detector claiming it, is a gap.
    report = coverage.build_coverage(dmap, observed=["T1486"])
    t1486 = next(r for r in report["techniques"] if r["technique"] == "T1486")
    assert t1486["covered"] is False
    assert t1486["detectors"] == []
    assert "T1486" in report["gaps"]
    assert report["summary"]["gaps"] == 1


def test_exists_vs_observed_distinguished():
    dmap = coverage.load_detector_map(DETECTOR_CONFIG)
    # T1046 has a detector but never fired; T1486 fired but has no detector.
    report = coverage.build_coverage(dmap, observed=["T1486"])
    rows = {r["technique"]: r for r in report["techniques"]}
    assert rows["T1046"]["covered"] and not rows["T1046"]["observed"]  # exists, not observed
    assert rows["T1486"]["observed"] and not rows["T1486"]["covered"]  # observed, no detector


def test_malformed_metadata_skipped_not_fatal():
    config = [
        {"detector_id": "good", "techniques": ["T1046"]},
        "not-a-dict",                                        # skipped
        {"detector_id": "", "techniques": ["T1021"]},        # blank id -> skipped
        {"detector_id": "no-list", "techniques": "T1046"},   # techniques not a list -> skipped
        {"detector_id": "mixed", "techniques": ["nope", "T1110.003", 7]},  # keep only the valid id
    ]
    dmap = coverage.load_detector_map(config)
    assert dmap["T1046"] == ["good"]           # the good entry survives
    assert dmap["T1110.003"] == ["mixed"]      # valid technique kept from a mixed list
    assert "nope" not in dmap                  # malformed technique dropped
    # A malformed technique string coming back from findings is dropped too.
    assert coverage.observed_from_rows(["T1046", "junk", None, 5]) == {"T1046"}


# --- tenant isolation, end-to-end through the HTTP handler -------------------

def _serve(client, tokens, detector_map, catalog=()):
    server = ThreadingHTTPServer(("127.0.0.1", 0), app.make_handler(client, tokens, detector_map, catalog))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _get(port, token=None):
    conn = http.client.HTTPConnection("127.0.0.1", port)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    conn.request("GET", "/coverage", headers=headers)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, (json.loads(body) if body else None)


def test_observed_overlay_is_tenant_isolated():
    # Tenant A's findings fire T1046; tenant B's fire T1486. Neither must appear
    # in the other's observed overlay. The detector map (fleet-global) is shared.
    # Tenant A fires T1046 (has a detector); tenant B fires T1099 (off-catalog, no
    # detector). T1550 is catalogued, has no detector, and neither tenant fires it.
    client = _FakeClient([("tenant-a", ["T1046"]), ("tenant-b", ["T1099"])])
    tokens = {"tok-a": ["tenant-a"], "tok-b": ["tenant-b"]}
    dmap = coverage.load_detector_map(DETECTOR_CONFIG)
    catalog = ["T1046", "T1021.002", "T1550"]
    server = _serve(client, tokens, dmap, catalog)
    try:
        port = server.server_address[1]

        status_a, body_a = _get(port, "tok-a")
        assert status_a == 200
        observed_a = {r["technique"] for r in body_a["techniques"] if r["observed"]}
        assert observed_a == {"T1046"}  # A sees only its own firing

        status_b, body_b = _get(port, "tok-b")
        assert status_b == 200
        observed_b = {r["technique"] for r in body_b["techniques"] if r["observed"]}
        assert observed_b == {"T1099"}  # B's firing does not leak from A, and vice-versa

        # T1046 is covered (fleet-global) for both, but observed only for A.
        assert next(r for r in body_b["techniques"] if r["technique"] == "T1046")["observed"] is False

        # The catalogued, undetected, unobserved technique is a gap for BOTH tenants:
        # gap reporting is a fleet property, not derived from either tenant's firings.
        for body in (body_a, body_b):
            assert "T1550" in body["gaps"]
            row = next(r for r in body["techniques"] if r["technique"] == "T1550")
            assert row["covered"] is False and row["observed"] is False
    finally:
        server.shutdown()


def test_unauthenticated_is_denied():
    server = _serve(_FakeClient([]), {"tok": ["t"]}, {})
    try:
        assert _get(server.server_address[1], token=None)[0] == 401
        assert _get(server.server_address[1], token="wrong")[0] == 401
    finally:
        server.shutdown()


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
    print(f"ok ({len(fns)} tests)")
    sys.exit(0)
