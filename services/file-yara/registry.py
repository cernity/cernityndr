"""YARA ruleset registry (Unit U3): versioned rulesets in embedded SQLite with a
staged, AUTHZ-GATED lifecycle (draft -> shadow -> active -> retired) and
content-addressed bytes verified by sha256 on load.

Why this exists: a scan worker must tie every scan to an EXACT ruleset version,
and an unauthorized or compromised caller must not be able to promote a malicious
or defanged ruleset to `active`. So a status change is an AUTHORIZED op with an
append-only audit trail, not anonymous CRUD, and the bytes a worker loads are
verified against the sha256 recorded at registration — a swapped or corrupted
blob is caught and refused, never scanned with.

Shape follows the repo's control-plane pattern:
  * sensor-registry/store.py — embedded SQLite CRUD, single-writer + lock (KTD3),
    server-derived authz rather than a client-supplied filter.
  * finding-service/state_machine.py — a status TRANSITION TABLE; an unlisted jump
    (e.g. retired -> active) is rejected so the lifecycle can't silently regress.

Rulesets are shared/global detection assets, so reads are not tenant-scoped; the
authz gate on promotion is the security boundary. The authorizer callable still
sees the ruleset's tenant, so a tenant-scoped promotion policy remains expressible.

ponytail: content-addressed bytes live in a SQLite blob table (the "object store"),
not a filesystem — one store, no fs to keep in sync. Single-writer SQLite fits one
refresh writer; swap the store seam for Postgres/S3 only if that ever changes.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
import json
import re
import sqlite3
import threading
import time
import uuid

# Lifecycle transition table (mirrors state_machine.CASE_TRANSITIONS). An unlisted
# move is rejected: retired is terminal, so retired -> active can never happen, and
# a status can only go forward through the staging gate or be retired/demoted.
STATUSES = ("draft", "shadow", "active", "retired")
TRANSITIONS = {
    "draft": {"shadow", "retired"},        # stage into canary, or drop a bad draft
    "shadow": {"active", "retired"},       # promote after canary, or drop
    "active": {"shadow", "retired"},       # demote back to canary, or retire
    "retired": set(),                      # terminal — never re-activated
}
# Moving INTO one of these is a promotion: it puts a ruleset in front of the scan
# worker, so it is the guarded op (poisoned-rule guard). Retiring/dropping is also
# authorized (a status change is never anonymous), but the audit names the intent.
_SERVED_STATUSES = {"active", "shadow"}


class IllegalTransition(ValueError):
    """A status move not permitted by TRANSITIONS (e.g. retired -> active)."""


class Unauthorized(PermissionError):
    """A status change the caller was not authorized to make (audited before raise)."""


class IntegrityError(Exception):
    """Stored ruleset bytes do not match the sha256 recorded on the registry row."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS rulesets (
  id                TEXT PRIMARY KEY,
  name              TEXT NOT NULL,
  version           TEXT NOT NULL,
  sha256            TEXT NOT NULL,              -- content address of the bytes
  source            TEXT NOT NULL,
  created_at        TEXT NOT NULL,
  promoted_by       TEXT,                        -- NULL until an authorized promotion
  promoted_at       TEXT,
  status            TEXT NOT NULL DEFAULT 'draft',
  target_mime_types TEXT NOT NULL DEFAULT '[]',  -- JSON list; [] = applies to all
  max_file_size     INTEGER NOT NULL,
  release_notes     TEXT,
  test_corpus_ref   TEXT,
  tenant            TEXT NOT NULL DEFAULT '*'     -- '*' = shared/global (not in wire schema)
);
CREATE INDEX IF NOT EXISTS idx_rulesets_status ON rulesets(status);

CREATE TABLE IF NOT EXISTS ruleset_bytes (       -- content-addressed object store
  sha256 TEXT PRIMARY KEY,
  data   BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS ruleset_audit (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ruleset_id  TEXT NOT NULL,
  ts          TEXT NOT NULL,
  actor       TEXT,
  event       TEXT NOT NULL,                     -- promoted | promotion_denied | retired ...
  from_status TEXT,
  to_status   TEXT,
  detail      TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ruleset ON ruleset_audit(ruleset_id);
"""

# Fields the wire schema (contracts/yara_ruleset.schema.json) carries, in its order.
# tenant is a store-internal scoping column and is intentionally NOT one of them.
_ROW_FIELDS = ("id", "name", "version", "sha256", "source", "created_at",
               "promoted_by", "promoted_at", "status", "target_mime_types",
               "max_file_size", "release_notes", "test_corpus_ref")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _row_to_dict(row: sqlite3.Row) -> dict:
    """A registry row as a schema-shaped dict (target_mime_types parsed from JSON)."""
    d = {k: row[k] for k in _ROW_FIELDS}
    d["target_mime_types"] = json.loads(row["target_mime_types"])
    return d


# --- input validation (trust boundary) --------------------------------------
# register_draft stages UNTRUSTED input (remote rules via rules_refresh), so the
# would-be row is checked against the wire contract BEFORE any write. These mirror
# contracts/yara_ruleset.schema.json field-for-field; a malformed input is refused
# up front so it never lands as a partial row or an orphan byte blob. (Inline, not
# jsonschema, to keep the scan worker free of a runtime jsonschema dependency; the
# contract test — test_yara_ruleset.py — is the schema's own guard.)
def _req_str(val, field, max_len, nonblank=True):
    if not isinstance(val, str) or not (1 <= len(val) <= max_len) or (nonblank and not val.strip()):
        raise ValueError(f"{field} must be a non-empty string of <= {max_len} chars")


# Matches contracts/yara_ruleset.schema.json $defs.datetime — created_at/promoted_at
# must be RFC3339 so a supplied (or refresh-supplied) timestamp can't land a row that
# fails the wire contract. _now() emits the trailing-Z form, which this accepts.
_DATETIME_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt](?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?([Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])")


def _req_datetime(val, field):
    if not isinstance(val, str) or not _DATETIME_RE.fullmatch(val):
        raise ValueError(f"{field} must be an RFC3339 date-time string")
    # Syntax alone accepts impossible dates; parse to check calendar and clock
    # ranges too. Preserve the wire contract's explicit offsets and lowercase t/z.
    try:
        datetime.fromisoformat(val.upper().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid RFC3339 date-time") from exc


# A ruleset id is used to name the materialised .yar file a scan worker compiles
# (rules_refresh.ensure_rules: os.path.join(cache_dir, f"served_{id}.yar")), so a
# caller-supplied id must NEVER be usable as a path: '../', a separator, a leading
# dot/dash or a NUL would escape the cache dir (path traversal). Restrict ids to a
# filesystem-safe token — first char alnum, then [A-Za-z0-9._-], no '..' anywhere.
# uuid4().hex and human ids like 'ruleset-2026-001' pass; traversal sequences don't.
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")


def _safe_id(val):
    _req_str(val, "id", 256)
    if ".." in val or not _SAFE_ID_RE.fullmatch(val):
        raise ValueError(
            "id must be a filesystem-safe token (start alnum, then [A-Za-z0-9._-], no '..' or separators)")


# Exact MIME type/subtype tokens only: parameters and wildcard filters are not
# supported by active_for_scan's equality matching. [] is the match-all filter.
_MIME_RE = re.compile(r"[A-Za-z0-9!#$%&'+.^_`|~-]+/[A-Za-z0-9!#$%&'+.^_`|~-]+")


def _validate_registration(name, version, source, target_mime_types,
                           max_file_size, release_notes, test_corpus_ref):
    _req_str(name, "name", 256)
    _req_str(version, "version", 128)
    _req_str(source, "source", 256, nonblank=False)   # schema has no \S pattern on source
    # bool is an int subclass — reject it explicitly so True/False can't be a size.
    if not isinstance(max_file_size, int) or isinstance(max_file_size, bool):
        raise ValueError("max_file_size must be an int")
    if not (1 <= max_file_size <= 4294967296):
        raise ValueError("max_file_size out of range [1, 4294967296]")
    # A bare string would be stored as a list of characters (schema violation) and
    # then never match a real MIME type — the exact silent misread the reviewer hit.
    mimes = target_mime_types if target_mime_types is not None else []
    if isinstance(mimes, (str, bytes)) or not isinstance(mimes, (list, tuple)):
        raise ValueError("target_mime_types must be a list of MIME strings")
    for m in mimes:
        _req_str(m, "target_mime_types item", 256)
        if not _MIME_RE.fullmatch(m):
            raise ValueError("target_mime_types items must be exact MIME type/subtype tokens")
    if release_notes is not None and (not isinstance(release_notes, str) or len(release_notes) > 8192):
        raise ValueError("release_notes must be a string of <= 8192 chars or None")
    if test_corpus_ref is not None:
        _req_str(test_corpus_ref, "test_corpus_ref", 512)


class RulesetRegistry:
    def __init__(self, path: str = ":memory:"):
        # check_same_thread=False + a lock: one refresh writer and N reader threads
        # share the connection; SQLite is single-writer (KTD3).
        #
        # isolation_level=None puts the driver in autocommit mode so WE control the
        # transaction boundary: every write op wraps its read-check-write in an
        # explicit BEGIN IMMEDIATE .. COMMIT. That takes the RESERVED write lock up
        # front, so the transaction is serialized ACROSS SEPARATE CONNECTIONS (each
        # instance has its own conn + its own self._lock) — a second connection can't
        # slip a stale-status write in between the SELECT and the UPDATE, which is the
        # retired->active lost-update / TOCTOU the reviewer flagged. busy_timeout lets
        # a competing writer WAIT for the lock instead of failing with SQLITE_BUSY.
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.executescript(_SCHEMA)
        self._lock = threading.Lock()

    # --- write path -----------------------------------------------------------
    def register_draft(self, name, version, data: bytes, source,
                        target_mime_types=None, max_file_size=64 * 1024 * 1024,
                        release_notes=None, test_corpus_ref=None,
                        tenant="*", ruleset_id=None, ts=None) -> dict:
        """Register ruleset `data` as a DRAFT row. The bytes are stored content-
        addressed by their sha256 (so identical content is stored once), and the
        row references them by that sha256. A fresh draft is never promoted, so
        promoted_by/promoted_at are NULL. Returns the created row as a dict."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("ruleset data must be bytes")
        # Validate the whole would-be row BEFORE computing sha or touching the DB,
        # so a rejected registration leaves no partial row and no orphan byte blob.
        # A caller-supplied id/timestamp is untrusted too (id='   '/ts='not-a-date'
        # would otherwise land a row that fails the wire contract) — check them here.
        _validate_registration(name, version, source, target_mime_types,
                               max_file_size, release_notes, test_corpus_ref)
        if ruleset_id is not None:
            _safe_id(ruleset_id)                # never a filesystem path (traversal guard)
        if ts is not None:
            _req_datetime(ts, "created_at")
        sha = hashlib.sha256(data).hexdigest()
        rid = ruleset_id or uuid.uuid4().hex
        ts = ts or _now()
        mimes = json.dumps(list(target_mime_types or []))
        with self._lock:
            # Atomic: a duplicate id (or any write failure) after the blob insert must
            # not leave an orphan blob and an open transaction — roll the whole thing back.
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute("INSERT OR IGNORE INTO ruleset_bytes(sha256, data) VALUES (?, ?)",
                                 (sha, bytes(data)))
                self._db.execute(
                    """INSERT INTO rulesets
                         (id, name, version, sha256, source, created_at, promoted_by,
                          promoted_at, status, target_mime_types, max_file_size,
                          release_notes, test_corpus_ref, tenant)
                       VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, 'draft', ?, ?, ?, ?, ?)""",
                    (rid, name, version, sha, source, ts, mimes, int(max_file_size),
                     release_notes, test_corpus_ref, tenant))
                self._audit(rid, ts, actor=None, event="registered",
                            from_status=None, to_status="draft")
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        return self.get(rid)

    def promote(self, ruleset_id, to_status, actor, authorize, ts=None) -> dict:
        """AUTHZ-GATED status transition. `authorize` is a callable
        (actor, tenant, to_status) -> bool, evaluated server-side. Order of checks:

          1. Transition validity (TRANSITIONS) — an illegal jump raises
             IllegalTransition and changes nothing.
          2. Authorization — if `authorize` denies, the attempt is AUDITED
             (event='promotion_denied') and Unauthorized is raised. This is the
             poisoned-rule guard: an unauthorized/compromised caller cannot move a
             ruleset in front of the scan worker, and the denial is on the record.

        On success the row's status/promoted_by/promoted_at are updated and an
        audit row is written. Returns the updated row."""
        # promoted_by is HONEST attribution recorded on the row and in the audit;
        # it must be a valid actor string (schema: non-empty, <= 256) even on a
        # denial (the denied attempt is attributed too). Validate before any write.
        _req_str(actor, "actor (promoted_by)", 256)
        if ts is not None:
            _req_datetime(ts, "promoted_at")
        with self._lock:
            # BEGIN IMMEDIATE takes the write lock BEFORE the read, so the whole
            # read-check-write is one serialized transaction across connections: a
            # competing connection can't read stale status and reactivate a retired
            # ruleset between our SELECT and UPDATE (no retired->active TOCTOU).
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute("SELECT * FROM rulesets WHERE id=?", (ruleset_id,)).fetchone()
                if row is None:
                    raise KeyError(ruleset_id)
                if to_status not in STATUSES:
                    raise IllegalTransition(f"unknown status {to_status!r}")
                current = row["status"]
                if to_status not in TRANSITIONS.get(current, set()):
                    raise IllegalTransition(f"illegal transition {current!r} -> {to_status!r}")
                ts = ts or _now()
                # A denial deliberately COMMITS its audit row then raises (the
                # poisoned-rule guard must leave the attempt on the record); any other
                # write failure rolls back so no half-applied promotion remains.
                if not authorize(actor, row["tenant"], to_status):
                    self._audit(ruleset_id, ts, actor=actor, event="promotion_denied",
                                from_status=current, to_status=to_status,
                                detail="caller not authorized for status change")
                    self._db.commit()
                    raise Unauthorized(
                        f"{actor!r} not authorized to move {ruleset_id!r} {current!r} -> {to_status!r}")
                # Compare-and-swap on status: belt-and-suspenders behind BEGIN
                # IMMEDIATE — the UPDATE only fires if status is STILL what we checked,
                # so a lost update can never silently regress the lifecycle.
                cur = self._db.execute(
                    "UPDATE rulesets SET status=?, promoted_by=?, promoted_at=? WHERE id=? AND status=?",
                    (to_status, actor, ts, ruleset_id, current))
                if cur.rowcount != 1:
                    raise IllegalTransition(
                        f"status of {ruleset_id!r} changed under a concurrent writer")
                event = "promoted" if to_status in _SERVED_STATUSES else to_status
                self._audit(ruleset_id, ts, actor=actor, event=event,
                            from_status=current, to_status=to_status)
                self._db.commit()
            except Unauthorized:
                raise                            # denial already committed its audit row
            except Exception:
                self._db.rollback()
                raise
        return self.get(ruleset_id)

    def _audit(self, ruleset_id, ts, actor, event, from_status, to_status, detail=None):
        # caller holds self._lock
        self._db.execute(
            """INSERT INTO ruleset_audit
                 (ruleset_id, ts, actor, event, from_status, to_status, detail)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (ruleset_id, ts, actor, event, from_status, to_status, detail))

    # --- read path ------------------------------------------------------------
    def get(self, ruleset_id) -> dict | None:
        row = self._db.execute("SELECT * FROM rulesets WHERE id=?", (ruleset_id,)).fetchone()
        return _row_to_dict(row) if row is not None else None

    def list_rulesets(self, status=None) -> list[dict]:
        if status is None:
            rows = self._db.execute("SELECT * FROM rulesets ORDER BY id").fetchall()
        else:
            rows = self._db.execute(
                "SELECT * FROM rulesets WHERE status=? ORDER BY id", (status,)).fetchall()
        return [_row_to_dict(r) for r in rows]

    def active_for_scan(self, mime: str | None = None) -> list[dict]:
        """Rulesets a scan worker should load: only `active` and `shadow` (draft
        and retired are excluded). If `mime` is given, a ruleset applies when its
        target_mime_types is empty (applies to everything) or contains that mime."""
        rows = self._db.execute(
            "SELECT * FROM rulesets WHERE status IN ('active','shadow') ORDER BY id").fetchall()
        out = []
        for r in rows:
            d = _row_to_dict(r)
            if mime is None or not d["target_mime_types"] or mime in d["target_mime_types"]:
                out.append(d)
        return out

    def load_bytes(self, ruleset_id) -> bytes:
        """Ruleset bytes, VERIFIED against the row's recorded sha256 (integrity
        check). Raises IntegrityError if the stored bytes were swapped/corrupted
        so a tampered ruleset is refused, never handed to the scanner. KeyError if
        the ruleset or its bytes are missing."""
        row = self._db.execute("SELECT sha256 FROM rulesets WHERE id=?", (ruleset_id,)).fetchone()
        if row is None:
            raise KeyError(ruleset_id)
        blob = self._db.execute(
            "SELECT data FROM ruleset_bytes WHERE sha256=?", (row["sha256"],)).fetchone()
        if blob is None:
            raise KeyError(f"no stored bytes for {ruleset_id!r}")
        data = bytes(blob["data"])
        actual = hashlib.sha256(data).hexdigest()
        if actual != row["sha256"]:
            raise IntegrityError(
                f"ruleset {ruleset_id!r} bytes sha256 {actual} != registered {row['sha256']}")
        return data

    def audit(self, ruleset_id) -> list[dict]:
        rows = self._db.execute(
            "SELECT ts, actor, event, from_status, to_status, detail "
            "FROM ruleset_audit WHERE ruleset_id=? ORDER BY id", (ruleset_id,)).fetchall()
        return [dict(r) for r in rows]


def allow_actors(*actors) -> callable:
    """A trivial authorizer: promotion allowed only for the named actors (tenant
    ignored). Real deployments pass their own (actor, tenant, to_status) callable;
    this exists so callers/tests have a default that is deny-by-default."""
    allowed = set(actors)
    return lambda actor, tenant, to_status: actor in allowed


def demo():
    """Self-check for the security-critical paths (ponytail: one runnable check)."""
    reg = RulesetRegistry()
    d = reg.register_draft("baseline", "1", b"rule a { condition: true }", "unit-test",
                           target_mime_types=["application/x-dosexec"])
    rid = d["id"]
    assert d["status"] == "draft" and d["promoted_by"] is None

    admin = allow_actors("secops-admin")
    # lifecycle progresses; illegal jump rejected
    reg.promote(rid, "shadow", "secops-admin", admin)
    reg.promote(rid, "active", "secops-admin", admin)
    assert reg.get(rid)["promoted_by"] == "secops-admin"
    reg.promote(rid, "retired", "secops-admin", admin)
    try:
        reg.promote(rid, "active", "secops-admin", admin)          # retired -> active
        raise AssertionError("retired->active should be illegal")
    except IllegalTransition:
        pass

    # unauthorized promotion is denied AND audited
    d2 = reg.register_draft("evil", "1", b"rule evil { condition: false }", "unit-test",
                            target_mime_types=["application/octet-stream"])
    reg.promote(d2["id"], "shadow", "secops-admin", admin)
    try:
        reg.promote(d2["id"], "active", "attacker", admin)         # attacker not allowed
        raise AssertionError("unauthorized promotion should raise")
    except Unauthorized:
        pass
    assert any(a["event"] == "promotion_denied" for a in reg.audit(d2["id"]))
    assert reg.get(d2["id"])["status"] == "shadow"                 # not moved

    # only active/shadow served; mime filter
    served = reg.active_for_scan()
    assert [s["id"] for s in served] == [d2["id"]]                 # rid retired, d2 shadow
    assert reg.active_for_scan(mime="text/plain") == []            # d2 has no matching mime
    reg.register_draft("mimed", "1", b"rule m { condition: true }", "t",
                       target_mime_types=["text/plain"])
    # (draft, so still not served) — promote it to check the filter
    m = reg.list_rulesets(status="draft")[0]["id"]
    reg.promote(m, "shadow", "secops-admin", admin)
    assert any(s["name"] == "mimed" for s in reg.active_for_scan(mime="text/plain"))

    # integrity check: tamper the stored bytes, load must raise
    reg._db.execute("UPDATE ruleset_bytes SET data=? WHERE sha256=?",
                    (b"defanged", reg.get(d2["id"])["sha256"]))
    reg._db.commit()
    try:
        reg.load_bytes(d2["id"])
        raise AssertionError("tampered bytes should raise IntegrityError")
    except IntegrityError:
        pass
    print("ok  registry self-check")


if __name__ == "__main__":
    demo()
