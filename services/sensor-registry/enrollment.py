"""Sensor enrollment mapping (U3b, §6.3): authenticated producer PRINCIPAL →
(sensor_uuid, tenant), established at enrollment.

The principal is a TRANSPORT identity string — the mTLS/SPIFFE subject the secure
bus (U1b) proves for a producer — NOT anything the sensor puts in a heartbeat
payload. §6.3 step 4 registers the immutable sensor_uuid + tenant against that
identity at enrollment; this store is that registration.

The registry consumer uses `verifies(principal, sensor_uuid, tenant)` to flip
`producer_verified` true ONLY when the authenticated principal was enrolled for
exactly the sensor+tenant the heartbeat claims. A principal enrolled for a
different sensor, a different tenant, or not enrolled at all does not verify — so
a forged claimed-identity is rejected and enrollment stays per-tenant isolated (an
enrollment in tenant A confers no authority in tenant B).

Own SQLite table (KTD3, like store.py), keyed by principal since one transport
identity binds one sensor (§6.3 step 5: separate credentials, not one shared).
"""
from __future__ import annotations

import sqlite3
import threading

_SCHEMA = """
CREATE TABLE IF NOT EXISTS enrollments (
  principal   TEXT PRIMARY KEY,   -- mTLS/SPIFFE identity (transport-authenticated, never a payload field)
  sensor_uuid TEXT NOT NULL,
  tenant      TEXT NOT NULL
);
"""


class EnrollmentStore:
    def __init__(self, path=":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)
        self._lock = threading.Lock()

    def enroll(self, principal, sensor_uuid, tenant):
        """Bind an authenticated principal to a sensor+tenant (§6.3 step 4).
        Re-enrolling a principal replaces its binding (cert rotation keeps the same
        identity string; a fresh identity is a fresh row)."""
        with self._lock:
            self._db.execute(
                "INSERT INTO enrollments (principal, sensor_uuid, tenant) VALUES (?, ?, ?) "
                "ON CONFLICT(principal) DO UPDATE SET "
                "sensor_uuid=excluded.sensor_uuid, tenant=excluded.tenant",
                (principal, sensor_uuid, tenant))
            self._db.commit()

    def verifies(self, principal, sensor_uuid, tenant) -> bool:
        """True only if this authenticated principal was enrolled for exactly this
        sensor_uuid AND tenant. Missing principal, unknown principal, or a binding to
        a different sensor/tenant all return False — the caller rejects/flags those.
        Tenant is part of the match, so an enrollment under one tenant never verifies
        a claim under another (per-tenant isolation)."""
        if not principal:
            return False
        row = self._db.execute(
            "SELECT sensor_uuid, tenant FROM enrollments WHERE principal=?",
            (principal,)).fetchone()
        return row is not None and row["sensor_uuid"] == sensor_uuid and row["tenant"] == tenant
