"""B-U5 (plan 010 Track B, review R09): pending recovery is tenant-qualified and paginated — cross-tenant
finding ids no longer collapse, overflow past one page is still recovered, and hitting the safety cap is
observable (degraded readiness) rather than a silent partial recovery. capture_job carries tenant."""
import os
import re

os.environ.setdefault("LOG_FORMAT", "text")

import app  # noqa: E402
import state_machine as sm  # noqa: E402

COLS = ["finding_id", "tenant_id", "state", "enrichment_state", "revision", "last_seen"]


def _row(fid, tenant):
    return {"finding_id": fid, "tenant_id": tenant, "state": "CAPTURE_REQUESTED",
            "enrichment_state": "REQUIRED", "revision": 1, "last_seen": "2026-09-25 00:00:00"}


class PagedCH:
    """Fake ClickHouse: slices a preloaded row list by the LIMIT/OFFSET in the SQL."""
    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    def query(self, sql):
        self.queries.append(sql)
        m = re.search(r"LIMIT (\d+) OFFSET (\d+)", sql)
        lim, off = (int(m.group(1)), int(m.group(2))) if m else (len(self.rows), 0)
        chunk = self.rows[off:off + lim]

        class R:
            column_names = COLS
            result_rows = [[r[c] for c in COLS] for r in chunk]
        return R()


def test_query_is_tenant_qualified():
    ch = PagedCH([_row("f1", "t1")])
    app._load_pending_from_ch(ch, 120, 0.0)
    assert "LIMIT 1 BY tenant_id, finding_id" in ch.queries[0]


def test_pagination_recovers_all_beyond_one_page():
    orig = app.RECOVERY_PAGE
    app.RECOVERY_PAGE = 2
    try:
        pend, ok = app._load_pending_from_ch(PagedCH([_row("f%d" % i, "t") for i in range(5)]), 120, 0.0)
        assert ok and len(pend) == 5, (ok, len(pend))
    finally:
        app.RECOVERY_PAGE = orig


def test_cross_tenant_ids_do_not_collapse():
    pend, ok = app._load_pending_from_ch(PagedCH([_row("shared", "acme"), _row("shared", "globex")]), 120, 0.0)
    assert set(pend) == {("acme", "shared"), ("globex", "shared")}


def test_overflow_is_observable_degraded():
    op, om = app.RECOVERY_PAGE, app.RECOVERY_MAX
    app.RECOVERY_PAGE, app.RECOVERY_MAX = 2, 2
    try:
        pend, ok = app._load_pending_from_ch(PagedCH([_row("f%d" % i, "t") for i in range(6)]), 120, 0.0)
        assert ok is False, "hitting the safety cap must be observable, not a silent partial recovery"
    finally:
        app.RECOVERY_PAGE, app.RECOVERY_MAX = op, om


def test_capture_job_carries_tenant():
    assert sm.capture_job({"finding_id": "f", "tenant_id": "acme", "entities": "[]"})["tenant_id"] == "acme"


def test_ch_none_is_empty_ok():
    assert app._load_pending_from_ch(None, 120, 0.0) == ({}, True)


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok  " + _n)
    print("\nall B-U5 recovery tests passed")
