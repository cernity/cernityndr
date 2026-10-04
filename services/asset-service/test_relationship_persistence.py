"""U3c relationship-edge durability: the CUMULATIVE [first_seen, last_seen] span and
latest evidence survive separate flushes, a restart, replay, late observations, and a
failed insert before the offset commit — never regressing to a single observation's
instant under ReplacingMergeTree(updated_at). (Closes codex's flush-discards-history
blocker.)
"""
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

FLOW_TOPIC = "suricata.flow.v1"
KEY = ("ip:10.0.0.5", "ip:93.184.216.34", "communicates-with")


def fresh_app():
    spec = importlib.util.spec_from_file_location(
        "asset_rel_persist_app", Path(__file__).with_name("app.py"))
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    return app


class FakeCH:
    """Collects inserts; query() serves restore_state's reloads. Emulates
    ReplacingMergeTree(updated_at) by keeping the newest insert per edge key."""

    def __init__(self):
        self.edge_rows = []          # append log of EVERY inserted edge row
        self.fail_on = None          # table substring to fail inserts on (crash sim)

    def insert(self, table, rows, column_names):
        assert len(column_names) == len(set(column_names))
        assert all(len(row) == len(column_names) for row in rows)
        if self.fail_on and self.fail_on in table:
            raise RuntimeError("insert failed: " + table)
        if table == "ndr.entity_relationship":
            self.edge_rows.extend(
                copy.deepcopy([dict(zip(column_names, r)) for r in rows]))

    def final_edges(self):
        latest = {}
        for r in self.edge_rows:                 # last insert per key wins (updated_at)
            latest[(r["src_entity"], r["dst_entity"], r["kind"])] = r
        return latest

    def query(self, sql, parameters):
        if "FROM ndr.entity_relationship FINAL" in sql:
            cols = ["src_entity", "dst_entity", "kind", "first_seen", "last_seen", "evidence"]
            rows = [[r[c] for c in cols] for r in self.final_edges().values()
                    if r["tenant_id"] == parameters["tenant"]]
            return SimpleNamespace(column_names=cols, result_rows=copy.deepcopy(rows))
        # ndr.asset / ndr.asset_fact / ndr.identity_observation restore reads: nothing here.
        return SimpleNamespace(column_names=[], result_rows=[])


def _flow(app_proto):
    return {"event_type": "flow", "src_ip": "10.0.0.5", "dest_ip": "93.184.216.34",
            "app_proto": app_proto, "flow": {}}


def _observe_flush(app, ch, ts, offset, app_proto):
    app.observe(_flow(app_proto), FLOW_TOPIC, 0, offset, ts)
    app.flush(ch)


def _final(ch):
    return ch.final_edges()[KEY]


# ── separate flushes + late observation: span widens, never regresses ──────────

def test_separate_flushes_preserve_cumulative_span_and_latest_evidence():
    app, ch = fresh_app(), FakeCH()
    _observe_flush(app, ch, "2026-09-28T12:00:00Z", 1, "tls")
    _observe_flush(app, ch, "2026-09-28T13:00:00Z", 2, "http")
    _observe_flush(app, ch, "2026-09-28T11:00:00Z", 3, "ssh")   # LATE (before first_seen)
    assert len([r for r in ch.edge_rows if (r["src_entity"], r["dst_entity"],
                r["kind"]) == KEY]) == 3                         # three replacement rows
    row = _final(ch)                                            # ReplacingMergeTree keeps newest
    assert row["first_seen"] == app._dt("2026-09-28T11:00:00Z")  # widened back, not regressed
    assert row["last_seen"] == app._dt("2026-09-28T13:00:00Z")   # full span retained
    import json
    assert json.loads(row["evidence"])["detail"] == "http"       # evidence of the 13:00 last_seen


# ── restart reloads the span so a later late observation still widens it ────────

def test_restart_reloads_span_so_late_observation_widens():
    app, ch = fresh_app(), FakeCH()
    _observe_flush(app, ch, "2026-09-28T12:00:00Z", 1, "tls")
    _observe_flush(app, ch, "2026-09-28T13:00:00Z", 2, "http")

    restarted = fresh_app()
    restarted.restore_state(ch)                                 # reloads cumulative span
    assert restarted._edges[KEY]["first_seen"] == "2026-09-28T12:00:00.000Z"
    assert restarted._edges[KEY]["last_seen"] == "2026-09-28T13:00:00.000Z"
    assert not restarted._edges_dirty                           # reloaded edges are not dirty

    _observe_flush(restarted, ch, "2026-09-28T11:00:00Z", 3, "ssh")   # LATE after restart
    row = _final(ch)
    assert row["first_seen"] == restarted._dt("2026-09-28T11:00:00Z")  # widened from durable span
    assert row["last_seen"] == restarted._dt("2026-09-28T13:00:00Z")


# ── replay of an already-persisted record after restart is idempotent ──────────

def test_replay_after_restart_is_idempotent():
    app, ch = fresh_app(), FakeCH()
    _observe_flush(app, ch, "2026-09-28T12:00:00Z", 1, "tls")
    _observe_flush(app, ch, "2026-09-28T13:00:00Z", 2, "http")

    restarted = fresh_app()
    restarted.restore_state(ch)
    _observe_flush(restarted, ch, "2026-09-28T13:00:00Z", 2, "http")   # same record replays
    row = _final(ch)
    assert row["first_seen"] == restarted._dt("2026-09-28T12:00:00Z")  # span unchanged
    assert row["last_seen"] == restarted._dt("2026-09-28T13:00:00Z")   # no regression


# ── a failed edge insert keeps the edge dirty and does NOT commit the offset ────

def test_failed_edge_insert_keeps_dirty_and_does_not_commit():
    app, ch = fresh_app(), FakeCH()
    app.observe(_flow("tls"), FLOW_TOPIC, 0, 1, "2026-09-28T12:00:00Z")
    assert app._edges_dirty == {KEY}
    ch.fail_on = "ndr.entity_relationship"
    commits = []
    consumer = SimpleNamespace(commit=lambda: commits.append(True))
    with pytest.raises(RuntimeError, match="insert failed"):
        app.persist_and_commit(ch, consumer)
    assert app._edges_dirty == {KEY}                            # preserved for retry
    assert not commits                                          # offset not advanced

    ch.fail_on = None
    app.persist_and_commit(ch, consumer)
    assert commits == [True]
    assert not app._edges_dirty
    assert _final(ch)["first_seen"] == app._dt("2026-09-28T12:00:00Z")
