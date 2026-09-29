"""U7 multi-analyst case model tests: pure case logic (cases.py) + the SQLite
store seam (store.py), with every mutated document checked against the case.v1
contract so the code and the schema can't drift.

Modules are loaded by PATH under explicit names (the sensor-registry precedent):
shared/store.py owns the bare name `store` on PYTHONPATH=shared, so this service's
store.py is loaded as `finding_case_store` to avoid shadowing it in the repo-wide
`PYTHONPATH=shared pytest` gate. state_machine is loaded under its real name so
cases.py's `from state_machine import ...` resolves without putting this service
dir on sys.path (which would let a bare `import store` find the wrong module).
"""
import importlib.util
import json
import sqlite3
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_load("state_machine", HERE / "state_machine.py")     # cases.py imports it by real name
cases = _load("cases", HERE / "cases.py")
store_mod = _load("finding_case_store", HERE / "store.py")
CaseStore = store_mod.CaseStore

# Validate every case document against the shipped contract (case.v1).
_SCHEMA = json.loads((ROOT / "contracts/case.schema.json").read_text())
_FORMATS = FormatChecker()


@_FORMATS.checks("date-time", raises=ValueError)
def _valid_ts(value):
    return not isinstance(value, str) or datetime.fromisoformat(
        value.upper().replace("Z", "+00:00")).tzinfo is not None


_VALIDATOR = Draft202012Validator(_SCHEMA, format_checker=_FORMATS)


def _valid(case):
    _VALIDATOR.validate(case)          # raises if the code emits an off-contract doc
    return case


def _events(case):
    return [e["event"] for e in case["audit"]]


def ts(n):                              # monotonic, tz-aware timestamps
    return f"2026-09-28T12:00:0{n}Z"


def _new():
    return _valid(cases.new_case("c1", "acme", "Beaconing", "alice", "alice", ts(0)))


# --- create / assign / note / transition round-trip ------------------------------

def test_round_trip_persists_and_validates():
    store = CaseStore()
    assert store.create(_new()) is True

    def edits(x):                                      # applied atomically in the store
        x = cases.change_owner(x, "carol", "admin", ts(1))
        x = cases.assign(x, "bob", "carol", ts(2))
        x = cases.add_note(x, "bob", "Confirmed C2 pattern", ts(3))
        return cases.transition(x, "investigating", "carol", ts(4))

    _valid(store.mutate("c1", {"acme"}, edits))

    got = store.get("c1", {"acme"})
    assert got["owner"] == "carol"
    assert got["assignees"] == ["bob"]
    assert got["notes"][0]["text"] == "Confirmed C2 pattern"
    assert got["status"] == "investigating"
    assert got["updated"] == ts(4)
    assert _events(got) == [
        "created", "owner_changed", "assignee_added", "note_added", "status_changed"]


def test_create_is_not_upsert():
    store = CaseStore()
    assert store.create(_new()) is True
    assert store.create(_new()) is False       # duplicate case_id rejected


# --- invalid status transition rejected ------------------------------------------

def test_illegal_transition_rejected():
    c = _new()                                 # status new
    with pytest.raises(ValueError):
        cases.transition(c, "resolved", "alice", ts(1))   # must triage first
    # full legal chain incl. reopen
    c = cases.transition(c, "investigating", "alice", ts(1))
    c = cases.transition(c, "resolved", "alice", ts(2))
    c = cases.transition(c, "closed", "alice", ts(3))
    c = cases.transition(c, "investigating", "alice", ts(4))   # reopen
    assert c["status"] == "investigating"
    with pytest.raises(ValueError):
        cases.transition(c, "new", "alice", ts(5))            # can't regress to new


# --- linking findings / entities -------------------------------------------------

def test_link_finding_and_entity():
    c = _new()
    c = _valid(cases.link_finding(c, "f1", "alice", ts(1)))
    c = _valid(cases.link_finding(c, "f2", "alice", ts(2)))
    c = _valid(cases.link_finding(c, "f1", "alice", ts(3)))   # idempotent, no event
    c = _valid(cases.link_entity(c, {"type": "ip", "value": "192.0.2.9"}, "alice", ts(4)))
    assert c["linked_findings"] == ["f1", "f2"]
    assert c["linked_entities"] == [{"type": "ip", "value": "192.0.2.9"}]
    assert _events(c) == ["created", "finding_linked", "finding_linked", "entity_linked"]
    c = _valid(cases.unlink_finding(c, "f1", "alice", ts(5)))
    assert c["linked_findings"] == ["f2"]
    assert _events(c)[-1] == "finding_unlinked"


# --- every change writes an audit event ------------------------------------------

def test_every_change_audits():
    c = _new()
    before = len(c["audit"])
    steps = [
        lambda x: cases.change_owner(x, "z", "a", ts(1)),
        lambda x: cases.assign(x, "b", "a", ts(2)),
        lambda x: cases.add_note(x, "b", "note", ts(3)),
        lambda x: cases.link_finding(x, "f9", "a", ts(4)),
        lambda x: cases.link_entity(x, {"type": "domain", "value": "evil.test"}, "a", ts(5)),
        lambda x: cases.transition(x, "investigating", "a", ts(6)),
        lambda x: cases.unassign(x, "b", "a", ts(7)),
    ]
    for i, step in enumerate(steps, 1):
        c = _valid(step(c))
        assert len(c["audit"]) == before + i, f"step {i} wrote no audit event"
        assert c["audit"][-1]["ts"] == ts(i)   # updated audit carries the change ts


def test_idempotent_change_writes_no_audit():
    c = _valid(cases.assign(_new(), "bob", "a", ts(1)))
    n = len(c["audit"])
    c2 = cases.assign(c, "bob", "a", ts(2))        # already assigned
    assert len(c2["audit"]) == n and c2["updated"] == c["updated"]


# --- tenant isolation ------------------------------------------------------------

def test_tenant_isolation():
    store = CaseStore()
    store.create(cases.new_case("c-acme", "acme", "t", "a", "a", ts(0)))
    store.create(cases.new_case("c-globex", "globex", "t", "a", "a", ts(0)))

    assert store.get("c-acme", {"globex"}) is None            # cross-tenant read blocked
    assert store.get("c-acme", {"acme"})["case_id"] == "c-acme"

    # A listing is scoped to ONE selected tenant, validated against the grants.
    # A reader granted BOTH tenants must pick one — grants are never merged (KTD6).
    assert [c["case_id"] for c in store.list_cases("acme", {"acme"})] == ["c-acme"]
    assert [c["case_id"] for c in store.list_cases("acme", {"acme", "globex"})] == ["c-acme"]
    assert [c["case_id"] for c in store.list_cases("globex", {"acme", "globex"})] == ["c-globex"]
    assert store.list_cases("acme", {"globex"}) == []         # selected tenant not granted

    # a mutation from a caller without the grant does not write (returns None)
    assert store.mutate("c-acme", {"globex"},
                        lambda x: cases.transition(x, "investigating", "mallory", ts(1))) is None
    assert store.get("c-acme", {"acme"})["status"] == "new"   # untouched

    # tenant is immutable even with a valid grant
    def move_tenant(x):
        x = dict(x)
        x["tenant"] = "globex"
        return x
    with pytest.raises(ValueError):
        store.mutate("c-acme", {"acme", "globex"}, move_tenant)
    assert store.get("c-acme", {"acme"})["tenant"] == "acme"


# --- concurrency: two analysts can't silently erase each other's work ------------

def test_concurrent_mutations_lose_nothing():
    """Regression for the codex blocking issue: the old get()->modify->save() path
    let two analysts read one snapshot, each add a note, and the second save clobber
    the first's note + audit. mutate() reads inside the write lock, so every note and
    audit event from every concurrent analyst survives."""
    import threading

    store = CaseStore()
    store.create(_new())
    n = 24
    ready = threading.Barrier(n)

    def worker(i):
        ready.wait()                                   # maximize contention
        store.mutate("c1", {"acme"},
                     lambda x, i=i: cases.add_note(x, f"analyst{i}", f"note {i}", ts(1)))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    got = _valid(store.get("c1", {"acme"}))
    assert len(got["notes"]) == n                       # no note silently overwritten
    assert {note["text"] for note in got["notes"]} == {f"note {i}" for i in range(n)}
    assert _events(got).count("note_added") == n        # every audit event survives
    assert len(got["audit"]) == 1 + n                   # created + n note_added


# --- durable disposition handoff to the Inc-1 feedback loop -----------------------

_DISP_VALIDATOR = Draft202012Validator(
    json.loads((ROOT / "contracts/disposition.schema.json").read_text()), format_checker=_FORMATS)


def _resolve(store, case_id, tenants, status, actor, ts_, verdicts):
    """Transition a case to a resolution status AND enqueue its dispositions in one
    atomic store mutation (illegal move / misattribution rolls back the whole thing)."""
    def fn(x):
        nx = cases.transition(x, status, actor, ts_)
        return nx, cases.case_dispositions(nx, verdicts)
    return store.mutate(case_id, tenants, fn)


def _case_with_links(store):
    store.create(_new())                                # c1 / acme, status new
    store.mutate("c1", {"acme"}, lambda x: cases.link_finding(x, "f1", "a", ts(1)))
    store.mutate("c1", {"acme"}, lambda x: cases.link_finding(x, "f2", "a", ts(2)))
    store.mutate("c1", {"acme"}, lambda x: cases.link_entity(x, {"type": "ip", "value": "192.0.2.1"}, "a", ts(3)))
    store.mutate("c1", {"acme"}, lambda x: cases.transition(x, "investigating", "a", ts(4)))


def test_resolution_durably_enqueues_dispositions():
    store = CaseStore()
    _case_with_links(store)
    verdicts = [
        {"finding_id": "f1", "entity": {"type": "ip", "value": "192.0.2.1"},
         "verdict": "true_positive", "reason": "confirmed C2", "analyst": "alice", "ts": ts(5)},
        {"finding_id": "f2", "entity": {"type": "ip", "value": "192.0.2.1"},
         "verdict": "benign", "reason": "sanctioned scanner", "analyst": "alice", "ts": ts(5)},
    ]
    _resolve(store, "c1", {"acme"}, "resolved", "alice", ts(5), verdicts)

    disps = store.pending_dispositions("acme", {"acme"})
    assert {d["finding_id"] for d in disps} == {"f1", "f2"}
    for d in disps:
        assert d["tenant"] == "acme" and d["scope"] == "finding"
        _DISP_VALIDATOR.validate(d)                     # valid disposition.v1 for the loop
    # tenant isolation on the outbox too (KTD6): globex sees nothing
    assert store.pending_dispositions("globex", {"acme", "globex"}) == []


def test_dedup_keys_on_event_not_verdict_payload():
    """Dedup keys on the case STATE-CHANGE event (its audit sequence), NOT the verdict
    payload. Two DISTINCT resolution transitions carrying BYTE-IDENTICAL verdicts (same
    ts and all) are two real analyst decisions → both delivered. Re-enqueuing the SAME
    event (same resolved case, no new transition) is an idempotent replay → deduped."""
    store = CaseStore()
    _case_with_links(store)
    v = [{"finding_id": "f1", "entity": {"type": "ip", "value": "192.0.2.1"},
          "verdict": "true_positive", "reason": "confirmed", "analyst": "alice", "ts": ts(5)}]

    # two distinct transitions, identical verdict payload → two events, both delivered
    _resolve(store, "c1", {"acme"}, "resolved", "alice", ts(5), v)
    store.mutate("c1", {"acme"}, lambda x: cases.transition(x, "investigating", "alice", ts(6)))  # reopen
    _resolve(store, "c1", {"acme"}, "resolved", "alice", ts(7), v)   # SAME verdict payload, NEW transition
    assert len(store.pending_dispositions("acme", {"acme"})) == 2    # distinct events, not collapsed

    # replay the SAME event — same resolved case, no new transition → idempotent, no new row
    store.mutate("c1", {"acme"}, lambda x: (x, cases.case_dispositions(x, v)))
    assert len(store.pending_dispositions("acme", {"acme"})) == 2    # replay of the same event deduped


def test_failed_resolution_enqueues_nothing():
    """Atomic failure: an illegal transition or a misattributed verdict writes neither
    the case change nor any disposition."""
    store = CaseStore()
    _case_with_links(store)                             # status investigating

    # (a) illegal transition: investigating -> new is rejected by the state machine
    with pytest.raises(ValueError):
        _resolve(store, "c1", {"acme"}, "new", "alice", ts(5),
                 [{"finding_id": "f1", "entity": {"type": "ip", "value": "192.0.2.1"},
                   "verdict": "benign", "reason": "r", "analyst": "alice", "ts": ts(5)}])
    assert store.get("c1", {"acme"})["status"] == "investigating"   # unchanged
    assert store.pending_dispositions("acme", {"acme"}) == []

    # (b) misattribution: a verdict on a finding not linked to the case is rejected
    with pytest.raises(ValueError):
        _resolve(store, "c1", {"acme"}, "resolved", "alice", ts(5),
                 [{"finding_id": "not-linked", "entity": {"type": "ip", "value": "192.0.2.1"},
                   "verdict": "benign", "reason": "r", "analyst": "alice", "ts": ts(5)}])
    assert store.get("c1", {"acme"})["status"] == "investigating"   # rolled back
    assert store.pending_dispositions("acme", {"acme"}) == []


def test_failed_outbox_write_rolls_back_the_case():
    """Codex regression: a failed outbox INSERT must roll back the case UPDATE in the
    same transaction — not leave it pending for a LATER operation's commit to flush.
    A BEFORE-INSERT trigger rejects every disposition; the resolution's case UPDATE
    happens first, then the outbox INSERT aborts. Neither may survive."""
    store = CaseStore()
    _case_with_links(store)                                 # c1 acme, status investigating
    # reject every disposition insert mid-mutation (after the case UPDATE already ran)
    store._db.execute("CREATE TRIGGER reject_disp BEFORE INSERT ON dispositions "
                      "BEGIN SELECT RAISE(ABORT, 'no disp'); END")
    store._db.commit()

    v = [{"finding_id": "f1", "entity": {"type": "ip", "value": "192.0.2.1"},
          "verdict": "true_positive", "reason": "r", "analyst": "a", "ts": ts(5)}]
    with pytest.raises(sqlite3.IntegrityError):
        _resolve(store, "c1", {"acme"}, "resolved", "a", ts(5), v)

    # the case UPDATE must have rolled back with the failed outbox write
    assert store.get("c1", {"acme"})["status"] == "investigating"
    assert store._db.in_transaction is False                # no dangling pending write
    assert store.pending_dispositions("acme", {"acme"}) == []

    # a LATER committing operation must NOT resurrect the rolled-back mutation
    assert store.create(cases.new_case("c2", "acme", "t", "a", "a", ts(0))) is True
    assert store.get("c1", {"acme"})["status"] == "investigating"
    assert store.pending_dispositions("acme", {"acme"}) == []


# --- committed dispositions actually reach the Inc-1 feedback consumer -------------

def _feedback_router(tmp_path):
    """The real feedback-service consumer (U9 Router), loaded by path, with a valid
    server-owned session token. drain_dispositions delivers into THIS, and the test
    asserts on the consumer's own committed sink — not just our local outbox."""
    fb = _load("feedback_router", ROOT / "services/feedback-service/router.py")
    db = str(tmp_path / "feedback.sqlite3")
    tokens = {"tok": {"emitter": "finding-service", "analyst": "alice",
                      "tenant": "acme", "expires_at": 9_999_999_999,
                      "disposition_write": True}}
    return fb.Router(db, tokens), db


def test_dispositions_delivered_to_feedback_consumer(tmp_path):
    consumer, fbdb = _feedback_router(tmp_path)
    store = CaseStore()
    _case_with_links(store)
    verdicts = [
        {"finding_id": "f1", "entity": {"type": "ip", "value": "192.0.2.1"},
         "verdict": "true_positive", "reason": "confirmed C2", "analyst": "alice", "ts": ts(5)},
        {"finding_id": "f2", "entity": {"type": "ip", "value": "192.0.2.1"},
         "verdict": "benign", "reason": "sanctioned", "analyst": "alice", "ts": ts(5)},
    ]
    _resolve(store, "c1", {"acme"}, "resolved", "alice", ts(5), verdicts)

    def deliver(record):
        return consumer.consume(record, "Bearer tok")      # raises if the receiver rejects

    assert store.drain_dispositions("acme", {"acme"}, deliver) == 2

    # RECEIVER acceptance: the records landed in the feedback consumer's own committed sink
    db = sqlite3.connect(fbdb)
    accepted = [json.loads(r[0]) for r in db.execute("SELECT record FROM feedback").fetchall()]
    db.close()
    assert {r["finding_id"] for r in accepted} == {"f1", "f2"}
    assert all(r["status"] == "suggested" for r in accepted)

    # delivered records are marked and never re-sent
    assert store.pending_dispositions("acme", {"acme"}) == []
    assert store.drain_dispositions("acme", {"acme"}, deliver) == 0


def test_drain_delivers_allowlist_to_consumer(tmp_path):
    """An allowlist verdict (scope='entity') must be accepted by the real consumer end
    to end — the case where the old always-'finding' scope produced an invalid record."""
    consumer, fbdb = _feedback_router(tmp_path)
    store = CaseStore()
    _case_with_links(store)
    _resolve(store, "c1", {"acme"}, "resolved", "alice", ts(5),
             [{"finding_id": "f1", "entity": {"type": "ip", "value": "192.0.2.1"},
               "verdict": "allowlist", "reason": "sanctioned scanner", "analyst": "alice", "ts": ts(5)}])

    assert store.drain_dispositions("acme", {"acme"}, lambda r: consumer.consume(r, "Bearer tok")) == 1
    db = sqlite3.connect(fbdb)
    sinks = [r[0] for r in db.execute("SELECT sink FROM feedback").fetchall()]
    db.close()
    assert sinks == ["ignore_list"]                        # allowlist routed, receiver accepted


def test_drain_retries_then_succeeds():
    store = CaseStore()
    _case_with_links(store)
    _resolve(store, "c1", {"acme"}, "resolved", "a", ts(5),
             [{"finding_id": "f1", "entity": {"type": "ip", "value": "192.0.2.1"},
               "verdict": "benign", "reason": "r", "analyst": "a", "ts": ts(5)}])
    attempts = {"n": 0}

    def flaky(record):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise RuntimeError("consumer down")            # retryable failure
        return True

    assert store.drain_dispositions("acme", {"acme"}, flaky, max_attempts=3) == 1
    assert attempts["n"] == 3
    assert store.pending_dispositions("acme", {"acme"}) == []   # delivered after retries


def test_drain_leaves_undelivered_on_persistent_failure():
    store = CaseStore()
    _case_with_links(store)
    _resolve(store, "c1", {"acme"}, "resolved", "a", ts(5),
             [{"finding_id": "f1", "entity": {"type": "ip", "value": "192.0.2.1"},
               "verdict": "benign", "reason": "r", "analyst": "a", "ts": ts(5)}])

    def dead(record):
        raise RuntimeError("consumer down")

    assert store.drain_dispositions("acme", {"acme"}, dead, max_attempts=2) == 0
    assert len(store.pending_dispositions("acme", {"acme"})) == 1   # still pending for next drain


def test_drain_recovers_interrupted_delivery():
    """Codex regression: a drain interrupted mid-delivery — the process dying, or a
    BaseException (KeyboardInterrupt) escaping the callback BEFORE the receiver accepts —
    must NOT leave the row marked delivered-but-unreceived. The row stays pending and the
    next drain redelivers it, so no resolution's feedback is lost to an interruption."""
    store = CaseStore()
    _case_with_links(store)
    _resolve(store, "c1", {"acme"}, "resolved", "a", ts(5),
             [{"finding_id": "f1", "entity": {"type": "ip", "value": "192.0.2.1"},
               "verdict": "benign", "reason": "r", "analyst": "a", "ts": ts(5)}])

    def interrupted(record):
        raise KeyboardInterrupt("process killed mid-delivery, before ACK")

    with pytest.raises(KeyboardInterrupt):
        store.drain_dispositions("acme", {"acme"}, interrupted)

    # not lost, not marked delivered — still pending and recoverable
    assert len(store.pending_dispositions("acme", {"acme"})) == 1
    delivered = []
    assert store.drain_dispositions(
        "acme", {"acme"}, lambda r: delivered.append(r) or True) == 1
    assert [r["finding_id"] for r in delivered] == ["f1"]   # the next drain recovered it
    assert store.pending_dispositions("acme", {"acme"}) == []


def test_drain_tenant_isolation():
    store = CaseStore()
    _case_with_links(store)
    _resolve(store, "c1", {"acme"}, "resolved", "a", ts(5),
             [{"finding_id": "f1", "entity": {"type": "ip", "value": "192.0.2.1"},
               "verdict": "benign", "reason": "r", "analyst": "a", "ts": ts(5)}])
    seen = []
    assert store.drain_dispositions("globex", {"acme", "globex"}, lambda r: seen.append(r) or True) == 0
    assert seen == []                                      # never drains another tenant's outbox
    assert len(store.pending_dispositions("acme", {"acme"})) == 1


def test_return_to_previous_verdict_is_delivered():
    """A re-transition BACK to an earlier verdict is a NEW legitimate event and must be
    delivered — dedup keys on the state-change event (finding+entity+verdict+ts), not on
    'this verdict was seen before'. f1: TP -> FP -> TP again yields BOTH TP records."""
    store = CaseStore()
    _case_with_links(store)                                # f1/f2 linked, entity, investigating
    ent = {"type": "ip", "value": "192.0.2.1"}

    # Same ts on every verdict: only the state-change EVENT (audit sequence) may
    # distinguish the two TP decisions — a ts-based key would wrongly collapse them.
    def verdict(v):
        return [{"finding_id": "f1", "entity": ent, "verdict": v,
                 "reason": "r", "analyst": "alice", "ts": ts(5)}]

    _resolve(store, "c1", {"acme"}, "resolved", "alice", ts(5), verdict("true_positive"))
    store.mutate("c1", {"acme"}, lambda x: cases.transition(x, "investigating", "alice", ts(6)))
    _resolve(store, "c1", {"acme"}, "resolved", "alice", ts(7), verdict("false_positive"))
    store.mutate("c1", {"acme"}, lambda x: cases.transition(x, "investigating", "alice", ts(8)))
    _resolve(store, "c1", {"acme"}, "resolved", "alice", ts(9), verdict("true_positive"))  # RETURN

    disps = store.pending_dispositions("acme", {"acme"})
    assert len(disps) == 3                                 # the return-to-TP was not dropped
    assert [d["verdict"] for d in disps].count("true_positive") == 2
    for d in disps:
        _DISP_VALIDATOR.validate(d)                        # each is a valid disposition.v1


def test_concurrent_drains_deliver_each_disposition_once():
    """Exactly-once under concurrency: two overlapping drains together deliver each
    disposition exactly once (disjoint sets), never twice."""
    store = CaseStore()
    store.create(_new())                                   # c1 / acme, status new
    ent = {"type": "ip", "value": "192.0.2.1"}
    store.mutate("c1", {"acme"}, lambda x: cases.link_entity(x, ent, "a", ts(0)))
    fids = [f"f{i}" for i in range(8)]
    for i, f in enumerate(fids):
        store.mutate("c1", {"acme"}, lambda x, f=f: cases.link_finding(x, f, "a", ts(i + 1)))
    store.mutate("c1", {"acme"}, lambda x: cases.transition(x, "investigating", "a", ts(20)))
    verdicts = [{"finding_id": f, "entity": ent, "verdict": "benign",
                 "reason": "r", "analyst": "a", "ts": ts(21)} for f in fids]
    _resolve(store, "c1", {"acme"}, "resolved", "a", ts(21), verdicts)
    assert len(store.pending_dispositions("acme", {"acme"})) == len(fids)

    lock = threading.Lock()
    delivered = []

    def deliver(record):
        time.sleep(0.001)                                  # widen the interleave window
        with lock:
            delivered.append(record["finding_id"])
        return True

    results = []

    def run():
        results.append(store.drain_dispositions("acme", {"acme"}, deliver))

    t1, t2 = threading.Thread(target=run), threading.Thread(target=run)
    t1.start(); t2.start(); t1.join(); t2.join()

    assert sorted(delivered) == sorted(fids)               # each delivered exactly once, no dup
    assert sum(results) == len(fids)                       # the two drains' accepted sets are disjoint
    assert store.pending_dispositions("acme", {"acme"}) == []


# --- case resolution feeds the Inc-1 disposition loop ----------------------------

def test_resolution_yields_dispositions():
    c = _new()
    c = cases.link_finding(c, "f1", "a", ts(1))
    c = cases.link_finding(c, "f2", "a", ts(2))
    c = cases.link_entity(c, {"type": "ip", "value": "192.0.2.1"}, "a", ts(3))
    c = cases.transition(c, "investigating", "a", ts(4))
    c = cases.transition(c, "resolved", "a", ts(5))

    verdicts = [
        {"finding_id": "f1", "entity": {"type": "ip", "value": "192.0.2.1"},
         "verdict": "true_positive", "reason": "worked the case", "analyst": "alice", "ts": ts(6)},
        {"finding_id": "f2", "entity": {"type": "ip", "value": "192.0.2.1"},
         "verdict": "benign", "reason": "sanctioned", "analyst": "alice", "ts": ts(6)},
    ]
    disps = cases.case_dispositions(c, verdicts)
    assert [d["finding_id"] for d in disps] == ["f1", "f2"]
    assert [d["verdict"] for d in disps] == ["true_positive", "benign"]  # explicit, per-finding
    for d in disps:
        assert d["tenant"] == "acme" and d["scope"] == "finding"
        _DISP_VALIDATOR.validate(d)                # valid disposition.v1 for the feedback loop


def _resolved_case_with_f1():
    c = _new()
    c = cases.link_finding(c, "f1", "a", ts(1))
    c = cases.link_entity(c, {"type": "ip", "value": "192.0.2.1"}, "a", ts(2))
    c = cases.transition(c, "investigating", "a", ts(3))
    return cases.transition(c, "resolved", "a", ts(4))


@pytest.mark.parametrize("verdict", ["true_positive", "false_positive", "benign", "allowlist"])
def test_dispositions_valid_for_every_verdict(verdict):
    """Every supported verdict must produce a valid disposition.v1 — allowlist at
    scope='entity' (schema requirement), the rest at scope='finding' (codex blocker:
    the old code always emitted scope='finding', which is invalid for allowlist)."""
    disps = cases.case_dispositions(_resolved_case_with_f1(), [
        {"finding_id": "f1", "entity": {"type": "ip", "value": "192.0.2.1"},
         "verdict": verdict, "reason": "r", "analyst": "a", "ts": ts(5)}])
    assert len(disps) == 1
    assert disps[0]["scope"] == ("entity" if verdict == "allowlist" else "finding")
    _DISP_VALIDATOR.validate(disps[0])              # valid disposition.v1 for the loop


def test_dispositions_reject_unsupported_verdict():
    with pytest.raises(ValueError):
        cases.case_dispositions(_resolved_case_with_f1(), [
            {"finding_id": "f1", "entity": {"type": "ip", "value": "192.0.2.1"},
             "verdict": "not_a_verdict", "reason": "r", "analyst": "a", "ts": ts(5)}])


def test_dispositions_reject_misattributed_finding_or_entity():
    c = _new()
    c = cases.link_finding(c, "f1", "a", ts(1))
    c = cases.link_entity(c, {"type": "ip", "value": "192.0.2.1"}, "a", ts(2))
    c = cases.transition(c, "investigating", "a", ts(3))
    c = cases.transition(c, "resolved", "a", ts(4))

    with pytest.raises(ValueError):                # finding not linked to the case
        cases.case_dispositions(c, [
            {"finding_id": "f-ghost", "entity": {"type": "ip", "value": "192.0.2.1"},
             "verdict": "benign", "reason": "r", "analyst": "a", "ts": ts(5)}])
    with pytest.raises(ValueError):                # entity not linked to the case
        cases.case_dispositions(c, [
            {"finding_id": "f1", "entity": {"type": "ip", "value": "10.0.0.9"},
             "verdict": "benign", "reason": "r", "analyst": "a", "ts": ts(5)}])


def test_no_dispositions_before_resolution():
    c = _new()
    c = cases.link_finding(c, "f1", "a", ts(1))
    c = cases.link_entity(c, {"type": "ip", "value": "192.0.2.1"}, "a", ts(2))
    # status still 'new' -> no verdict to feed the loop yet
    verdicts = [{"finding_id": "f1", "entity": {"type": "ip", "value": "192.0.2.1"},
                 "verdict": "benign", "reason": "r", "analyst": "alice", "ts": ts(3)}]
    assert cases.case_dispositions(c, verdicts) == []
