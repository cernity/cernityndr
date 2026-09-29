"""Intel store (plan U1) in embedded SQLite (KTD3 — no new datastore).

Per-tenant by construction: (tenant, type, indicator) is the indicator primary key,
and EVERY read takes the caller's granted-tenant set (§21/KTD6) so a reader granted
multiple tenants never sees them merged. Persistence only — the dedup/score/expiry
RULES live in lifecycle.py, which merges before calling upsert(). Suppression is a
separate, auditable, EXPIRING decision (suppressions table) with an audit trail,
mirroring the Inc-1 advisory ignore-list: checked live at match time, never a silent
permanent delete.

Single-writer SQLite is fine for one ingest worker (KTD3 ceiling); swap this seam for
Postgres if fleet intel-write throughput ever demands it — callers only touch IntelStore.

NB: this module is `store.py` but shared/store.py (the detectors' WindowStore) already
owns the name `store` on PYTHONPATH=shared, so it must be loaded by PATH, not
`import store` (see test_lifecycle.py / the U2 app wiring), same as sensor-registry.
"""
from __future__ import annotations

import json
import math
import sqlite3
import threading
import time
import uuid

_UPSERT = """INSERT INTO indicators
     (tenant, type, indicator, record, score, tlp, source_trust, disposition, expiry)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
   ON CONFLICT(tenant, type, indicator) DO UPDATE SET
     record=excluded.record, score=excluded.score, tlp=excluded.tlp,
     source_trust=excluded.source_trust, disposition=excluded.disposition,
     expiry=excluded.expiry"""


def _row(record: dict) -> tuple:
    """Flatten one intel.v1 record to the indicators-table column tuple (raises on a
    missing/uncoercible field before any SQL runs, so a bad batch never half-writes)."""
    return (record["tenant"], record["type"], record["indicator"], json.dumps(record),
            float(record["score"]), record["tlp"], float(record["source_trust"]),
            record["disposition"], record["expiry"])

_SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
  tenant        TEXT NOT NULL,
  type          TEXT NOT NULL,
  indicator     TEXT NOT NULL,
  record        TEXT NOT NULL,          -- full intel.v1 JSON (provenance et al.)
  score         REAL NOT NULL,
  tlp           TEXT NOT NULL,
  source_trust  REAL NOT NULL,
  disposition   TEXT NOT NULL,
  expiry        TEXT NOT NULL,
  PRIMARY KEY (tenant, type, indicator)
);
CREATE INDEX IF NOT EXISTS idx_ind_tenant ON indicators(tenant);
CREATE TABLE IF NOT EXISTS suppressions (
  id            TEXT PRIMARY KEY,
  tenant        TEXT NOT NULL,
  type          TEXT NOT NULL,
  indicator     TEXT NOT NULL,
  owner         TEXT NOT NULL,
  justification TEXT NOT NULL,
  created_at    REAL NOT NULL,
  expires_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_supp_key ON suppressions(tenant, type, indicator);
CREATE TABLE IF NOT EXISTS audit (
  id        TEXT PRIMARY KEY,
  tenant    TEXT NOT NULL,
  event     TEXT NOT NULL              -- full audit event JSON
);
"""


class IntelStore:
    def __init__(self, path=":memory:"):
        # check_same_thread=False: one ingest worker + N reader threads share the
        # connection; a lock serializes writes (SQLite is single-writer — KTD3).
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)
        self._lock = threading.Lock()

    # --- indicators -----------------------------------------------------------
    def upsert(self, record: dict) -> None:
        """Store one already-merged intel.v1 record (full replace by PK). lifecycle.merge
        must have folded provenance/score first — this layer does no merging."""
        self.upsert_many([record])

    def upsert_many(self, records, deletes=()) -> None:
        """Persist a batch of already-merged records, plus any (tenant, type, indicator)
        deletes, in ONE transaction: either all land or none do. Rows are flattened FIRST
        (a malformed record raises before any SQL), then upserts and deletes are written
        under a single commit with rollback on failure, so a feed refresh never leaves the
        store half-written (reviewer regression: transactional ingest). Deletes back a
        revocation whose last remaining assertion has been withdrawn."""
        rows = [_row(r) for r in records]              # raises here => nothing written
        dels = [(t, ty, ind) for (t, ty, ind) in deletes]
        if not rows and not dels:
            return
        with self._lock:
            try:
                if rows:
                    self._db.executemany(_UPSERT, rows)
                if dels:
                    self._db.executemany(
                        "DELETE FROM indicators WHERE tenant=? AND type=? AND indicator=?", dels)
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise

    def get(self, tenant: str, itype: str, indicator: str):
        """One indicator record (intel.v1 dict) for the exact (tenant, type, indicator),
        or None. Tenant is part of the key, so this never crosses tenants."""
        row = self._db.execute(
            "SELECT record FROM indicators WHERE tenant=? AND type=? AND indicator=?",
            (tenant, itype, indicator)).fetchone()
        return json.loads(row["record"]) if row else None

    def list(self, tenants) -> list:
        """All indicator records within the caller's granted tenants (§21), ordered
        stably. An empty grant returns nothing — never all tenants."""
        tenants = list(tenants)
        if not tenants:
            return []
        q = ("SELECT record FROM indicators WHERE tenant IN (%s) ORDER BY tenant, type, indicator"
             % ",".join("?" * len(tenants)))
        return [json.loads(r["record"]) for r in self._db.execute(q, tenants).fetchall()]

    # --- suppression (auditable, expiring) ------------------------------------
    def suppress(self, tenant, itype, indicator, owner, justification, expires_at, now=None) -> dict:
        """Record an auditable, EXPIRING suppression for one indicator (owner +
        justification + expiry all required) plus an audit event, atomically. Returns
        the suppression row. Suppression is ORTHOGONAL to the indicator's own lifecycle
        disposition (active/expired) — it is checked live at match time by is_suppressed
        and never mutates or deletes the indicator, so a lapsed suppression cleanly
        resumes matching (like the Inc-1 advisory ignore-list)."""
        if not (owner and str(owner).strip()) or not (justification and str(justification).strip()):
            raise ValueError("suppression requires owner and justification")
        now = time.time() if now is None else now
        expires_at = float(expires_at)
        # Reject inf/-inf/NaN: a suppression is an EXPIRING decision (like the Inc-1
        # ignore-list) — a permanent/undefined expiry would be a silent forever-drop.
        if not math.isfinite(expires_at):
            raise ValueError("suppression expiry must be a finite timestamp")
        if expires_at <= now:
            raise ValueError("suppression expiry must be in the future")
        sid, aid = uuid.uuid4().hex, uuid.uuid4().hex
        supp = {"id": sid, "tenant": tenant, "type": itype, "indicator": indicator,
                "owner": owner, "justification": justification,
                "created_at": now, "expires_at": float(expires_at)}
        event = {"id": aid, "tenant": tenant, "action": "intel.suppress",
                 "actor": owner, "resource_type": "indicator",
                 "resource_id": f"{itype}:{indicator}", "justification": justification,
                 "expires_at": float(expires_at), "timestamp": now}
        with self._lock:
            self._db.execute(
                "INSERT INTO suppressions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (sid, tenant, itype, indicator, owner, justification, now, float(expires_at)))
            self._db.execute("INSERT INTO audit VALUES (?, ?, ?)", (aid, tenant, json.dumps(event)))
            self._db.commit()
        return supp

    def is_suppressed(self, tenant, itype, indicator, now=None) -> bool:
        """True iff a LIVE (unexpired) suppression covers this indicator. Expiry is
        re-checked on every call, so a lapsed suppression resumes matching."""
        now = time.time() if now is None else now
        row = self._db.execute(
            "SELECT 1 FROM suppressions WHERE tenant=? AND type=? AND indicator=? AND expires_at>? LIMIT 1",
            (tenant, itype, indicator, now)).fetchone()
        return row is not None

    def suppressions(self, tenants) -> list:
        """Suppression rows within the caller's granted tenants (audit surface)."""
        tenants = list(tenants)
        if not tenants:
            return []
        q = ("SELECT * FROM suppressions WHERE tenant IN (%s) ORDER BY created_at"
             % ",".join("?" * len(tenants)))
        return [dict(r) for r in self._db.execute(q, tenants).fetchall()]

    def audit_log(self, tenants) -> list:
        """Audit events within the caller's granted tenants."""
        tenants = list(tenants)
        if not tenants:
            return []
        q = ("SELECT event FROM audit WHERE tenant IN (%s) ORDER BY id"
             % ",".join("?" * len(tenants)))
        return [json.loads(r["event"]) for r in self._db.execute(q, tenants).fetchall()]


    def networks(self, tenant):
        """Tenant-scoped CIDRs only; exact lookups still use the primary key."""
        rows = self._db.execute(
            "SELECT record FROM indicators WHERE tenant=? AND type='ip' AND indicator LIKE '%/%'",
            (tenant,)).fetchall()
        return [json.loads(row["record"]) for row in rows]

    def record_match(self, tenant, match, observation, now):
        """Persist non-prioritized hits locally; red intel never enters the SIEM path."""
        if match["tenant"] != tenant:
            raise ValueError("match tenant mismatch")
        event = {"id": uuid.uuid4().hex, "tenant": tenant, "action": "intel.match",
                 "timestamp": now, "intel_match": match,
                 "observation": {k: observation[k] for k in
                     ("src_ip", "dest_ip", "timestamp", "community_id", "flow_id", "tx_id")
                     if k in observation}}
        with self._lock:
            self._db.execute("INSERT INTO audit VALUES (?, ?, ?)",
                             (event["id"], tenant, json.dumps(event)))
            self._db.commit()
