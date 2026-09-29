"""U9 advisory routing. Identity, scope and lifetime are server-owned.

SQLite is the skeleton's durable sink/outbox: no detector/model state is changed.
Audit and routed suggestion commit together, or neither is accepted.
"""
from contextlib import contextmanager
from datetime import datetime
import copy
import json
import math
from pathlib import Path
import sqlite3
import time
import uuid

from jsonschema import Draft202012Validator, FormatChecker

_SCHEMA = Path(__file__).resolve().parents[2] / 'contracts/disposition.schema.json'
FORMATS = FormatChecker()


@FORMATS.checks('date-time', raises=ValueError)
def valid_timestamp(value):
    if not isinstance(value, str):
        return True  # The schema type check rejects non-strings.
    return datetime.fromisoformat(value.upper().replace('Z', '+00:00')).tzinfo is not None


VALIDATOR = Draft202012Validator(json.loads(_SCHEMA.read_text()), format_checker=FORMATS)
SINKS = {'true_positive': 'anomaly_ground_truth', 'benign': 'anomaly_ground_truth',
         'false_positive': 'detector_fp_candidate', 'allowlist': 'ignore_list'}
CAPABILITIES = {'disposition_v1': True, 'advisory_only': True, 'auto_suppression': False}


def authenticate(tokens, authorization, now):
    """Opaque per-analyst session tokens; never accept caller identity headers."""
    token = authorization[7:] if authorization.startswith('Bearer ') else None
    session = tokens.get(token) if token else None
    if not isinstance(session, dict):
        raise PermissionError('unauthorized')
    required = ('emitter', 'analyst', 'tenant')
    if any(not isinstance(session.get(k), str) or not session[k].strip() for k in required):
        raise PermissionError('invalid session')
    expiry = session.get('expires_at')
    if (type(expiry) not in (int, float) or not math.isfinite(expiry) or now >= expiry
            or session.get('disposition_write') is not True):
        raise PermissionError('expired or unauthorized session')
    return {k: session[k] for k in required}


def ignore_entry_suppresses(entry, tenant, entity, now):
    """Evaluation seam for a separately reviewed/applied entry, NOT an apply API.

    U9 never creates applied entries. Expiry is checked at every evaluation.
    """
    return (entry.get('sink') == 'ignore_list' and entry.get('status') == 'applied'
            and entry.get('tenant') == tenant and entry.get('entity') == entity
            and bool(entry.get('owner')) and bool(entry.get('justification'))
            and bool(entry.get('audit_id')) and bool(entry.get('approval_audit_id'))
            and entry.get('created_at', math.inf) <= now < entry.get('expires_at', -math.inf))


class Router:
    def __init__(self, database, tokens, ttl_seconds=86400, now=time.time):
        if type(ttl_seconds) not in (int, float) or not math.isfinite(ttl_seconds) or not 0 < ttl_seconds <= 2592000:
            raise ValueError('TTL must be positive and at most 30 days')
        self.database, self.tokens, self.ttl, self.now = database, copy.deepcopy(tokens), ttl_seconds, now
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS feedback (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, sink TEXT NOT NULL, record TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS audit (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, event TEXT NOT NULL)')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.database)
        try:
            with db:
                yield db
        finally:
            db.close()

    def consume(self, payload, authorization, source_ip=''):
        now = self.now()
        identity = authenticate(self.tokens, authorization, now)
        VALIDATOR.validate(payload)
        # Scope claims are never grants: only the exact entity/finding is suggested.
        scope = 'entity' if payload['verdict'] == 'allowlist' else 'finding'
        identifier, audit_id = uuid.uuid4().hex, uuid.uuid4().hex
        record = {
            'id': identifier, 'audit_id': audit_id, 'tenant': identity['tenant'],
            'owner': identity['analyst'], 'analyst': identity['analyst'],
            'emitter': identity['emitter'], 'scope': scope,
            'finding_id': payload['finding_id'], 'entity': copy.deepcopy(payload['entity']),
            'verdict': payload['verdict'], 'justification': payload['reason'],
            'source_ts': payload['ts'], 'created_at': now, 'expires_at': now + self.ttl,
            'status': 'suggested', 'sink': SINKS[payload['verdict']],
            'capabilities': CAPABILITIES.copy(),
        }
        audit = {'audit_id': audit_id, 'tenant': identity['tenant'],
                 'actor': identity['analyst'], 'emitter': identity['emitter'],
                 'action': 'disposition.accepted', 'resource_type': 'feedback',
                 'resource_id': identifier, 'timestamp': now, 'source_ip': source_ip,
                 'outcome': 'suggested', 'reason': payload['reason'], 'record': record}
        with self.connect() as db:
            db.execute('INSERT INTO feedback VALUES (?, ?, ?, ?)',
                       (identifier, identity['tenant'], record['sink'], json.dumps(record)))
            db.execute('INSERT INTO audit VALUES (?, ?, ?)',
                       (audit_id, identity['tenant'], json.dumps(audit)))
        return record
