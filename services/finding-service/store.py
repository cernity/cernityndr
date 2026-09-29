"""Case store in embedded SQLite (KTD3 — no Postgres), the persistence seam
behind cases.py's pure logic (plan U7; Addendum A6).

Same shape and rules as sensor-registry's RegistryStore:

  * Tenant isolation is enforced on every read and write against a server-derived
    grant set (`tenants`), never a client-supplied filter (§21). A case is
    invisible — and immutable — to a caller whose grant does not include its
    tenant, and a case's tenant can never be moved by an update. A listing is
    scoped to ONE selected tenant validated against the grants: a reader granted
    several tenants must pick one — grants are never merged (KTD6 / the U3a/U5 rule).
  * The whole case.v1 document is stored as one JSON blob keyed by case_id; the
    tenant is duplicated into its own column purely so isolation is an indexed
    WHERE clause, not a JSON scan. cases.py owns the document's shape (audit
    trail, status), so the store never rewrites case internals — it just persists
    what it is handed.
  * Mutations go through mutate(): the read, the cases.py change and the write all
    happen inside one write-locked critical section, so two analysts working the
    same case can never read a stale snapshot and silently clobber each other's
    notes / assignments / status / audit (the concurrency guarantee). There is no
    blind get()->modify->save() path to race.

A resolution can also durably enqueue disposition.v1 records (the Inc-1 feedback
handoff) in the SAME transaction as the case write: mutate()'s fn may return
(case, records) and the records land in the `dispositions` outbox atomically with
the case, deduped by a deterministic id so re-resolving never double-feeds the
loop. drain_dispositions() then delivers each committed record to the Inc-1
feedback consumer (feedback-service Router.consume), retrying on failure and
marking a row `delivered` only after the receiver ACCEPTS it — so a case
resolution actually reaches the feedback loop, exactly once, and a consumer
outage leaves the record pending for the next drain rather than dropping it.

Single-writer SQLite is fine at the case-management write rate (KTD3 ceiling).
If it ever isn't, swap this seam for Postgres — callers only touch CaseStore.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
  case_id  TEXT PRIMARY KEY,
  tenant   TEXT NOT NULL,
  doc      TEXT NOT NULL              -- full case.v1 document as JSON
);
CREATE INDEX IF NOT EXISTS idx_cases_tenant ON cases(tenant);

CREATE TABLE IF NOT EXISTS dispositions (
  id         TEXT PRIMARY KEY,        -- deterministic: dedupes re-resolution
  case_id    TEXT NOT NULL,
  tenant     TEXT NOT NULL,
  record     TEXT NOT NULL,           -- one disposition.v1 record as JSON
  delivered  INTEGER NOT NULL DEFAULT 0  -- 1 once the feedback consumer accepted it
);
CREATE INDEX IF NOT EXISTS idx_disp_tenant ON dispositions(tenant);
"""


def _disp_id(case_id: str, seq: int, record: dict) -> str:
    """Stable id for a disposition emitted by ONE case state-change EVENT.

    Keyed on the case + the state-change's audit SEQUENCE (its position in the
    append-only audit trail) + the record's (finding, entity, verdict). The audit
    sequence — NOT the verdict's `ts` — is the event identity, because `ts` is a
    caller-supplied payload field: two DISTINCT resolution transitions (reopen, then
    re-resolve) can carry byte-identical verdicts, yet each is a real, separate
    decision that must reach the feedback loop. They land at different audit
    sequences, so an analyst returning f1 to an earlier verdict (TP -> FP -> TP)
    enqueues a NEW record that is delivered, not swallowed.

    Re-enqueuing the SAME event — the same resolved case, no new transition, so the
    same audit sequence — collapses to one row (the INSERT OR IGNORE in mutate): an
    idempotent replay is deduped. Keying on the verdict payload alone (with or
    without its ts) collapsed two genuinely distinct transitions into one and
    silently dropped a legitimate return-to-verdict — the defect this fixes."""
    key = "\x00".join([
        case_id,
        str(seq),
        str(record.get("finding_id")),
        json.dumps(record.get("entity"), sort_keys=True),
        str(record.get("verdict")),
    ])
    return hashlib.sha1(key.encode()).hexdigest()


class CaseStore:
    def __init__(self, path=":memory:"):
        # check_same_thread=False: one or more HTTP threads share the connection;
        # a lock serializes the whole read-modify-write (SQLite is single-writer — KTD3).
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)
        self._lock = threading.Lock()
        # In-memory claim set: ids a drain is CURRENTLY delivering. It is the
        # single-writer exclusion between concurrent drain threads, and — being in
        # memory, never persisted — a drain interrupted mid-delivery (or the process
        # dying) leaves its rows delivered=0 and recoverable by the next drain.
        self._claimed: set[str] = set()

    def create(self, case: dict) -> bool:
        """Insert a new case. Returns False (no write) if the case_id already
        exists — create is not an upsert; use mutate() to persist a change. The
        case dict is trusted to be a well-formed case.v1 (cases.new_case built it,
        the contract validates it); the store only requires case_id + tenant to key
        the row."""
        with self._lock:
            try:
                with self._db:          # commit on success, roll back on any failure
                    self._db.execute(
                        "INSERT INTO cases (case_id, tenant, doc) VALUES (?, ?, ?)",
                        (case["case_id"], case["tenant"], json.dumps(case)))
            except sqlite3.IntegrityError:
                return False            # duplicate case_id
        return True

    def get(self, case_id: str, tenants) -> dict | None:
        """One case document, only if it belongs to a tenant in the caller's grant
        set. Returns None when absent or out of grant → API 404 (no existence
        leak across tenants). Read-only; to change a case use mutate()."""
        row = self._db.execute(
            "SELECT tenant, doc FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if row is None or row["tenant"] not in tenants:
            return None
        return json.loads(row["doc"])

    def mutate(self, case_id: str, tenants, fn):
        """Atomic read-modify-write — the ONLY way to change a persisted case.

        Reads the current document, applies `fn` (a cases.py mutation), and writes
        the result, all inside one write-locked, single-commit transaction. Because
        the read happens inside the lock, two concurrent analysts can never both act
        on a stale snapshot and silently overwrite each other's notes / assignees /
        status / audit — each fn sees the freshest committed state.

        `fn(case)` returns either a new case dict, or a (new_case, records) tuple to
        also durably enqueue disposition.v1 `records` in the SAME transaction (the
        resolution -> feedback handoff). If `fn` raises (illegal transition, a
        misattributed verdict), nothing is written — atomic failure.

        The case UPDATE and every disposition INSERT commit together or not at all:
        `with self._db` rolls the whole thing back on ANY failure (a rejected outbox
        write must not leave the case UPDATE pending for a later operation's commit to
        flush — codex regression). Nothing outside the block writes, so there is no
        blind commit that could resurrect a rolled-back mutation.

        Returns the new case dict, or None if the case is absent or out of grant.
        Raises ValueError if `fn` tries to move the case to another tenant (tenant
        is immutable — a mutation must not reassign ownership across tenants)."""
        with self._lock:
            row = self._db.execute(
                "SELECT tenant, doc FROM cases WHERE case_id=?", (case_id,)).fetchone()
            if row is None or row["tenant"] not in tenants:
                return None
            result = fn(json.loads(row["doc"]))
            new, records = result if isinstance(result, tuple) else (result, [])
            if new.get("tenant") != row["tenant"]:
                raise ValueError("tenant is immutable")
            # The disposition's event identity is the audit sequence at which this
            # mutation lands — a transition appends one audit event, so re-resolving
            # a reopened case lands at a LATER sequence and is a distinct event; a
            # replay that appends no audit event reuses the sequence and is deduped.
            seq = len(new.get("audit", []))
            with self._db:              # atomic: case + outbox commit together or roll back
                self._db.execute(
                    "UPDATE cases SET doc=? WHERE case_id=?", (json.dumps(new), case_id))
                for r in records:
                    self._db.execute(
                        "INSERT OR IGNORE INTO dispositions (id, case_id, tenant, record)"
                        " VALUES (?, ?, ?, ?)",
                        (_disp_id(case_id, seq, r), case_id, new["tenant"], json.dumps(r)))
            return new

    def list_cases(self, tenant: str, tenants) -> list:
        """Cases for ONE selected tenant, validated against the caller's grant set.
        A reader granted several tenants must SELECT one — grants are never merged
        into a single listing (KTD6 / the U3a/U5 rule). Returns [] when the selected
        tenant is not in the grant set."""
        if tenant not in tenants:
            return []
        return [json.loads(r["doc"]) for r in self._db.execute(
            "SELECT doc FROM cases WHERE tenant=? ORDER BY case_id", (tenant,)).fetchall()]

    def pending_dispositions(self, tenant: str, tenants) -> list:
        """UNDELIVERED disposition.v1 records for ONE selected, granted tenant — the
        durable feedback handoff still awaiting delivery to the Inc-1 loop. Same
        single-tenant isolation as list_cases (KTD6): never merged across grants.
        A record drops off this list once drain_dispositions() confirms the consumer
        accepted it (delivered=1)."""
        if tenant not in tenants:
            return []
        return [json.loads(r["record"]) for r in self._db.execute(
            "SELECT record FROM dispositions WHERE tenant=? AND delivered=0 ORDER BY id",
            (tenant,)).fetchall()]

    def drain_dispositions(self, tenant: str, tenants, deliver, max_attempts: int = 3) -> int:
        """Deliver this tenant's undelivered dispositions to the Inc-1 feedback consumer
        and mark each delivered ONLY after the receiver accepts it. Returns the count
        accepted this drain.

        `deliver(record)` is the handoff to the existing feedback loop — in production
        feedback-service's Router.consume (an authenticated POST /dispositions in a
        deployment). It must return truthy on acceptance and raise/return falsy on a
        retryable failure. Each record is retried up to `max_attempts` times; one that
        still fails is RELEASED back to pending (delivered=0) for the next drain, so a
        consumer outage never drops a resolution's feedback.

        Exactly-once under concurrency: a row is CLAIMED into an in-memory set under
        the lock (not persisted), delivered OUTSIDE the lock, and only then marked
        delivered=1 — after the receiver ACCEPTS it. Two overlapping drains skip any
        id already claimed (or already delivered), so they work DISJOINT sets and never
        deliver the same disposition twice. Because the claim lives only in memory,
        `delivered` never flips before acceptance: a drain interrupted mid-delivery —
        a raised BaseException, or the process dying — leaves the row delivered=0 and
        recoverable by the next drain, never marked-but-unreceived (the codex defect
        this fixes). A row whose delivery merely fails/retries out is likewise left
        pending. The claim is always dropped in a `finally`, so an interrupted drain
        releases its in-memory claim on the way out.

        ponytail: in-memory claim guarded by the process lock — the single-writer
        model KTD3 already assumes (threads sharing one connection). Ceiling: it
        excludes THREADS, not separate processes; if drains ever run cross-process,
        upgrade to a persisted lease column with a reclaim timeout. Delivery runs
        OUTSIDE the lock so a slow/HTTP consumer never blocks analyst mutations. A
        per-drain snapshot bounds the loop; a row left pending is retried by the NEXT
        drain, not re-walked here. Same single-tenant grant check as list_cases (KTD6)."""
        if tenant not in tenants:
            return 0
        with self._lock:
            rows = self._db.execute(
                "SELECT id, record FROM dispositions WHERE tenant=? AND delivered=0 ORDER BY id",
                (tenant,)).fetchall()
        accepted = 0
        for row in rows:
            rid = row["id"]
            # Claim without persisting: another drain thread that already holds this
            # id, or that already delivered it, is skipped — disjoint work, no dup.
            with self._lock:
                if rid in self._claimed:
                    continue
                still = self._db.execute(
                    "SELECT delivered FROM dispositions WHERE id=?", (rid,)).fetchone()
                if still is None or still["delivered"]:
                    continue                    # a concurrent drain already delivered it
                self._claimed.add(rid)
            try:
                record = json.loads(row["record"])
                ok = False
                for attempt in range(max_attempts):
                    try:
                        ok = bool(deliver(record))
                    except Exception:
                        ok = False
                    if ok:
                        break
                if ok:
                    # Persist delivered=1 ONLY now the receiver has accepted.
                    with self._lock, self._db:
                        self._db.execute(
                            "UPDATE dispositions SET delivered=1 WHERE id=?", (rid,))
                    accepted += 1
            finally:
                # Drop the in-memory claim even if delivery raised (BaseException /
                # interruption): the row stays delivered=0 and recoverable.
                with self._lock:
                    self._claimed.discard(rid)
        return accepted
