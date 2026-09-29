"""Sensor-registry inventory in embedded SQLite (KTD3 — no Postgres).

Ingests `sensor-health.v1` heartbeats (U2's sensor-agent format, see
contracts/sensor-health.schema.json) and serves tenant-scoped reads. Three hard
rules live here:

  * Producer identity in a heartbeat is a CLAIM, not proof. Every ingested row
    is `producer_verified=0`; transport-authenticated producer identity is U3b
    (needs the secure bus + §6.3 enrollment). We never read a Kafka header/key
    as verified identity.
  * Enrollment-only facts (tags, groups, capabilities, cert_fingerprint per
    §6.4) are NOT carried by a heartbeat, so a heartbeat upsert must preserve
    them, never overwrite them with empties.
  * Liveness is decided on the SERVER's receipt time (received_at), never on the
    sensor's self-reported observed_at. A sensor clock can drift arbitrarily
    (chrony down, VM paused, deliberate skew), so observed_at is untrustworthy
    for freshness: a clock an hour fast would report "online" forever after the
    sensor died. observed_at is kept as last_seen for display/skew only.

Single-writer SQLite is fine for one ingest consumer per heartbeat (KTD3
ceiling). If fleet write-throughput/HA ever demands it, swap this seam for
Postgres — callers only touch RegistryStore/sensor_view.
"""
from __future__ import annotations

import json
import math
import sqlite3
import threading
import time


def _utf8_safe(s: str) -> bool:
    """SQLite binds TEXT as UTF-8. A lone surrogate (e.g. a crafted "\\udxxx" JSON
    escape that survives json.loads) raises UnicodeEncodeError at bind time — that is
    a malformed value, not a storage fault, so reject it here and DROP the message
    rather than let it surface as a broken database."""
    try:
        s.encode()
        return True
    except UnicodeEncodeError:
        return False


def _well_formed(record) -> bool:
    """Enough of sensor-health.v1 to safely key/store a row. The producer already
    validates the full schema; here we defend the consumer against a garbage bus
    message so it is DROPPED, never persisted as a type sqlite/sensor_view chokes on
    later (a dict tenant → sqlite3.InterfaceError, a str clock_offset_ms → TypeError
    in the skew compare) and never RAISED at bind time — which ingest_loop would
    otherwise mistake for a storage failure. Beyond types, reject values a naive type
    check passes but SQLite cannot bind: a string that is not UTF-8 encodable, and a
    number that is not a finite double (NaN/inf, or an int so large float() overflows).
    A big-but-representable int (e.g. 10**30) is fine — upsert binds it as REAL, not as
    an over-large INTEGER. Wrong type or unbindable == not a heartbeat == drop it."""
    if not isinstance(record, dict) or record.get("schema_version") != "sensor-health.v1":
        return False
    for key in ("sensor_uuid", "tenant", "site", "observed_at"):
        v = record.get(key)
        if not isinstance(v, str) or not v or not _utf8_safe(v):
            return False
    if not isinstance(record.get("versions"), dict):
        return False
    off = record.get("clock_offset_ms")            # number|null (bool is not a measurement)
    if off is not None:
        if isinstance(off, bool) or not isinstance(off, (int, float)):
            return False
        try:
            off = float(off)                       # 10**30 fine here; 10**400 overflows -> drop
        except (OverflowError, ValueError):
            return False
        if not math.isfinite(off):                 # NaN/inf (json.loads accepts them) aren't measurements
            return False
    cs = record.get("clock_status")
    if cs is not None and (not isinstance(cs, str) or not _utf8_safe(cs)):
        return False
    return True

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sensors (
  sensor_uuid       TEXT PRIMARY KEY,
  tenant            TEXT NOT NULL,
  site              TEXT,
  tags              TEXT NOT NULL DEFAULT '[]',   -- enrollment (§6.4), not from a heartbeat
  groups            TEXT NOT NULL DEFAULT '[]',   -- enrollment (§6.4)
  capabilities      TEXT NOT NULL DEFAULT '[]',   -- enrollment (§6.4)
  versions          TEXT NOT NULL DEFAULT '{}',
  last_seen         TEXT,                          -- sensor's observed_at (display/skew only)
  received_at       REAL,                          -- SERVER receipt epoch — the freshness clock
  cert_fingerprint  TEXT,                          -- enrollment (§6.4), verified in U3b
  clock_offset_ms   REAL,
  clock_status      TEXT,
  producer_verified INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sensors_tenant ON sensors(tenant);
"""


def sensor_view(row, now, skew_threshold_ms, stale_after_s) -> dict:
    """API projection of a stored row: parse JSON columns and derive the two
    read-time signals the fleet API surfaces (never stored, so a threshold change
    needs no rewrite):

      * skew_flag — |clock_offset_ms| > threshold (A7). No measurement (offset
        None, i.e. clock_status unavailable) means no flag: absence is not skew.
      * status — offline when the SERVER last received a heartbeat more than
        stale_after_s ago (§22.1 heartbeat freshness). Both `now` and received_at
        are server-clock times, so this comparison is immune to sensor clock skew;
        the sensor's observed_at (last_seen) is deliberately NOT used here. A row
        with no received_at (shouldn't happen post-ingest) reads as offline.
    """
    offset = row["clock_offset_ms"]
    received = row["received_at"]
    return {
        "sensor_uuid": row["sensor_uuid"],
        "tenant": row["tenant"],
        "site": row["site"],
        "tags": json.loads(row["tags"]),
        "groups": json.loads(row["groups"]),
        "capabilities": json.loads(row["capabilities"]),
        "versions": json.loads(row["versions"]),
        "last_seen": row["last_seen"],
        "received_at": received,
        "cert_fingerprint": row["cert_fingerprint"],
        "clock_offset_ms": offset,
        "clock_status": row["clock_status"],
        "skew_flag": offset is not None and abs(offset) > skew_threshold_ms,
        "status": "online" if (received is not None and (now - received) <= stale_after_s) else "offline",
        "producer_verified": bool(row["producer_verified"]),
    }


class RegistryStore:
    def __init__(self, path=":memory:"):
        # check_same_thread=False: one ingest thread + N HTTP threads share the
        # connection; a lock serializes writes (SQLite is single-writer — KTD3).
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)
        self._lock = threading.Lock()

    def upsert_heartbeat(self, record, producer_verified=False, received_at=None) -> bool:
        """Upsert one heartbeat as UNVERIFIED (producer_verified stays False on the
        ingest path — U3b flips it). `received_at` is the SERVER receipt time (epoch
        seconds) and defaults to now; it — not the sensor's observed_at — is what
        drives liveness, so a skewed sensor clock cannot fake freshness. Returns True
        if ingested, False if dropped — never raises, so one bad bus message cannot
        kill the ingest loop. A record is dropped when it is not a well-formed
        sensor-health.v1, OR when its sensor_uuid already exists under a DIFFERENT
        tenant: an UNVERIFIED heartbeat must not move a sensor (and its enrollment
        metadata) between tenants — that would be tenant crossover on a spoofable
        claim (verified identity is U3b). Enrollment fields (tags/groups/
        capabilities/cert) are left untouched."""
        if not _well_formed(record):
            return False
        if received_at is None:
            received_at = time.time()
        # _well_formed proved clock_offset_ms is a finite double: bind it as REAL so a
        # large int (10**30 — a valid float but overflowing SQLite's 64-bit INTEGER
        # bind) does not raise at execute() and get mistaken for a storage failure.
        offset = record.get("clock_offset_ms")
        if offset is not None:
            offset = float(offset)
        with self._lock:
            owner = self._db.execute(
                "SELECT tenant FROM sensors WHERE sensor_uuid=?",
                (record["sensor_uuid"],)).fetchone()
            if owner is not None and owner["tenant"] != record["tenant"]:
                return False                          # cross-tenant reassignment refused
            self._db.execute(
                """INSERT INTO sensors
                     (sensor_uuid, tenant, site, versions, last_seen, received_at,
                      clock_offset_ms, clock_status, producer_verified)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(sensor_uuid) DO UPDATE SET
                     tenant=excluded.tenant, site=excluded.site,
                     versions=excluded.versions, last_seen=excluded.last_seen,
                     received_at=excluded.received_at,
                     clock_offset_ms=excluded.clock_offset_ms,
                     clock_status=excluded.clock_status,
                     producer_verified=excluded.producer_verified""",
                (record["sensor_uuid"], record["tenant"], record.get("site"),
                 json.dumps(record.get("versions") or {}), record["observed_at"], received_at,
                 offset, record.get("clock_status"),
                 1 if producer_verified else 0))
            self._db.commit()
        return True

    def get(self, sensor_uuid, tenants):
        """One sensor row (as a dict), only if it belongs to a tenant the caller is
        granted. `tenants` is the server-derived grant set (§21) — never a query
        param. Returns None when absent or out of the grant → API 404 (no leak)."""
        row = self._db.execute(
            "SELECT * FROM sensors WHERE sensor_uuid=?", (sensor_uuid,)).fetchone()
        if row is None or row["tenant"] not in tenants:
            return None
        return dict(row)

    def list_sensors(self, tenants):
        """All sensor rows within the caller's granted tenants, ordered stably."""
        tenants = list(tenants)
        if not tenants:
            return []
        q = ("SELECT * FROM sensors WHERE tenant IN (%s) ORDER BY sensor_uuid"
             % ",".join("?" * len(tenants)))
        return [dict(r) for r in self._db.execute(q, tenants).fetchall()]

    def list_groups(self, tenants):
        """group name → member sensor_uuids, aggregated over the granted tenants.
        Empty until enrollment (U3b) populates per-sensor groups (§6.4)."""
        groups = {}
        for s in self.list_sensors(tenants):
            for g in json.loads(s["groups"]):
                groups.setdefault(g, []).append(s["sensor_uuid"])
        return groups
