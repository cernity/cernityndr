"""Tenant-qualified SQLite checkpoints; hits and page progress commit together."""
import json
import sqlite3
import threading


class HuntStore:
    def __init__(self, path=":memory:"):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS jobs (
                tenant TEXT, id TEXT, request TEXT NOT NULL, state TEXT NOT NULL,
                PRIMARY KEY (tenant, id));
            CREATE TABLE IF NOT EXISTS hits (
                tenant TEXT, job TEXT, id TEXT, record TEXT NOT NULL,
                PRIMARY KEY (tenant, job, id));
        """)

    def load(self, tenant, job_id):
        with self.lock:
            row = self.db.execute("SELECT request,state FROM jobs WHERE tenant=? AND id=?",
                                  (tenant, job_id)).fetchone()
            return (json.loads(row[0]), json.loads(row[1])) if row else None

    def save(self, tenant, job_id, request, state, hits=()):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO jobs VALUES (?,?,?,?)",
                            (tenant, job_id, json.dumps(request, sort_keys=True), json.dumps(state)))
            self.db.executemany("INSERT OR IGNORE INTO hits VALUES (?,?,?,?)",
                                [(tenant, job_id, h["hit_id"], json.dumps(h)) for h in hits])

    def results(self, tenant, job_id, after="", limit=500):
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be 1..1000")
        with self.lock:
            job = self.load(tenant, job_id)
            if job is None:
                raise KeyError(job_id)
            rows = self.db.execute(
                "SELECT id,record FROM hits WHERE tenant=? AND job=? AND id>? ORDER BY id LIMIT ?",
                (tenant, job_id, after, limit + 1)).fetchall()
            return {"hunt_id": job_id, "tenant": tenant, "status": job[1]["status"],
                    "unsupported": job[1]["unsupported"],
                    "hits": [json.loads(r[1]) for r in rows[:limit]],
                    "next_after": rows[limit-1][0] if len(rows) > limit else None}
