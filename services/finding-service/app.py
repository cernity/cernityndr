"""NDR finding service (plan U9; v0.4 U1 finalization loop): candidates -> lifecycle
-> findings.

Consumes ndr.finding.candidate.v1, runs the state machine (state_machine.py),
persists to ClickHouse ndr.finding (ReplacingMergeTree dedups by finding_id), and:
  * delivers a confirmed threat to ndr.finding.final.v1 IMMEDIATELY (deliver-now) and
    requests capture for evidence — it never dangles waiting on a forensics overlay;
  * requests capture for low-confidence content findings to adjudicate them;
  * closes the loop by consuming ndr.enrichment.result.v1 (evidence outcome) and
    ndr.capture.status.v1 (refusal/failure), plus a timeout sweep, so every capture-
    bound finding is finalized on success/failure/refusal/timeout and re-emitted (F01).
Lifecycle correctness is covered by test_state_machine.py; the finalization wiring by
test_finalization.py; this is the I/O shell.
"""
import json
import os
import signal
import time
from collections import OrderedDict
from datetime import datetime, timezone

import ndr_runtime                      # shared tuned consumer/producer (plan 003 U6 rollout)
import metrics                          # plan 011 R7: finalization + enrichment-pending observability

import geoenrich
import intel
import state_machine as sm

log = ndr_runtime.setup_logging("finding-service")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
CH_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse")
CH_USER = os.environ.get("CLICKHOUSE_USER", "ndr")
CH_PASS = os.environ.get("CLICKHOUSE_PASSWORD")
# ClickHouse persistence is optional: findings still flow to the bus without it.
# Treat an empty value as unset (compose passes an empty string when it is left
# blank), so persistence is off unless a real password is provided.
CH_ENABLED = bool(CH_PASS)

CANDIDATE_TOPIC = "ndr.finding.candidate.v1"
FINAL_TOPIC = "ndr.finding.final.v1"
CAPTURE_TOPIC = "ndr.capture.request.v1"
RESULT_TOPIC = "ndr.enrichment.result.v1"     # zeek-central outcome: ok/failed + evidence
STATUS_TOPIC = "ndr.capture.status.v1"        # orchestrator refusal / agent completion
LIFECYCLE_TOPIC = "ndr.lifecycle.ack.v1"      # §stage3: finding lifecycle disposition (pending capture work)
LIFECYCLE_ON = os.environ.get("CERNITY_LIFECYCLE_ACKS", "1").strip().lower() not in ("", "0", "false", "no")
# How long a capture-bound finding may stay unenriched before the sweep finalizes it
# (no overlay / unavailable). Confirmed threats are already delivered; this only
# resolves their dangling enrichment_state.
ENRICH_TIMEOUT_SECS = float(os.environ.get("NDR_ENRICH_TIMEOUT_SECS", "120"))
# F14 recovery scaling guard: only reload PENDING/REQUIRED findings still within this window and
# capped at this many. Reloading ALL historical un-finalized findings (e.g. a large CAPTURE_REQUESTED
# backlog when no capture path is deployed) loads millions into memory and floods finalization on start.
RECOVERY_WINDOW_SECS = int(os.environ.get("NDR_RECOVERY_WINDOW_SECS", "21600"))   # 6h
RECOVERY_MAX = int(os.environ.get("NDR_RECOVERY_MAX", "10000"))      # safety ceiling across all pages
RECOVERY_PAGE = int(os.environ.get("NDR_RECOVERY_PAGE", "5000"))     # B-U5: page size for paginated recovery

COLS = ["finding_id", "tenant_id", "sensor_ids", "detector_id", "detector_version",
        "category", "severity", "confidence", "first_seen", "last_seen", "entities",
        "evidence_refs", "mitre", "state", "enrichment_state", "capture_job_ids",
        "suppression_reason",
        # U4: enrichment + baseline provenance, persisted as JSON strings so they survive restart
        # recovery (the in-memory dict carries objects; _row serializes, _pending_from_rows parses back).
        "summary", "iocs", "source_events",
        # R03: persist the lifecycle revision so each transition is a DISTINCT, searchable row
        # (the table's sort key is revision-scoped); ingested_at is the ReplacingMergeTree version
        # so re-persisting the SAME revision (Kafka replay) is idempotent.
        "revision", "ingested_at"]

_running = True


def _stop(*_):
    global _running
    _running = False


def _dt(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _row(f: dict) -> list:
    r = dict(f)
    r["first_seen"] = _dt(r.get("first_seen"))
    r["last_seen"] = _dt(r.get("last_seen"))
    r["severity"] = int(r.get("severity", 0) or 0)
    r["confidence"] = float(r.get("confidence", 0) or 0)
    r["revision"] = int(r.get("revision") or 1)              # R03: durable per-revision row
    # ReplacingMergeTree version — the moment THIS revision was persisted. A re-persist of the
    # same (finding_id, revision) collapses to the latest insert; a new revision is a new row.
    r["ingested_at"] = datetime.now(timezone.utc)
    for k in ("sensor_ids", "evidence_refs", "mitre", "capture_job_ids"):
        r[k] = r.get(k) or []
    for k in ("entities", "suppression_reason", "enrichment_state"):
        r[k] = r.get(k) or ""
    # U4: enrichment/provenance objects -> JSON String columns (entities is already a wire string).
    for k in ("summary", "iocs", "source_events"):
        v = r.get(k)
        r[k] = json.dumps(v) if v not in (None, "", [], {}) else ""
    return [r.get(c) for c in COLS]


def _persist(ch, finding):
    if ch is not None:
        ch.insert("ndr.finding", [_row(finding)], column_names=COLS)


# Enrichment states that mean a capture-bound finding is STILL awaiting finalization (F14). A finalized
# finding is ENRICHED / ENRICHMENT_FAILED / TIMEOUT / NOT_REQUIRED and must NOT be reloaded.
_UNFINALIZED = ("PENDING", "REQUIRED")


def _pending_from_rows(rows, deadline_secs, now):
    """Reconstruct the in-memory `pending` map (F14) from ClickHouse rows — the CURRENT (max-revision)
    view of each finding whose enrichment is still un-finalized. Keyed by (tenant_id, finding_id) so two
    tenants sharing an id do not collide (§62.6). A `FINAL` row was a deliver-now confirmed threat
    (already on the SIEM, awaiting evidence) -> delivered=True; a `CAPTURE_REQUESTED` row is a
    low-confidence capture-only finding not yet delivered -> delivered=False.

    §62.6 deadline: a recovered finding is given an IMMEDIATE deadline (`now`), NOT a fresh full timeout —
    it was already pending before the restart, so the next sweep finalizes it promptly. Resetting a full
    window on every restart could postpone delivery indefinitely across a crash loop. Pure (no I/O)."""
    pending = {}
    for r in rows:
        f = dict(r)
        # U4: JSON String columns -> objects (or drop when empty), so a recovered finding carries
        # the same shapes a live one does through re-finalization and delivery.
        for k in ("summary", "iocs", "source_events"):
            v = f.get(k)
            if isinstance(v, str) and v:
                try:
                    f[k] = json.loads(v)
                except (ValueError, TypeError):
                    pass
            elif v in ("", None):
                f.pop(k, None)
        fid = f.get("finding_id")
        if not fid or f.get("enrichment_state") not in _UNFINALIZED:
            continue
        pending[_pk(f.get("tenant_id"), fid)] = {
            "finding": f, "delivered": f.get("state") == "FINAL", "deadline": now, "recovered": True}
    return pending


def _load_pending_from_ch(ch, deadline_secs, now):
    """F14 durable recovery: on startup, reload capture-bound findings that were mid-flight when a prior
    process stopped, so their finalization obligation survives a restart (previously the in-memory map
    was lost and a capture-only finding could dangle forever). Returns (pending, recovery_ok): a query
    FAILURE is OBSERVABLE (recovery_ok=False) so the caller can hold readiness and retry rather than
    silently claim zero pending (§62.6). ClickHouse disabled -> ({}, True) (nothing to recover)."""
    if ch is None:
        return {}, True
    try:
        # B-U5/R09: dedup the current (max-revision) row per (tenant_id, finding_id) — NOT finding_id
        # alone, which collapsed two tenants sharing an id before the tenant-keyed map ever saw them.
        # Paginate so overflow beyond one page is still recovered (was a silent LIMIT 10000 truncation);
        # a hard safety cap yields OBSERVABLE degraded readiness rather than a silent partial recovery.
        pending = {}
        offset, overflow = 0, False
        while True:
            res = ch.query(f"SELECT * FROM (SELECT * FROM ndr.finding "
                           f"WHERE last_seen > now() - INTERVAL {RECOVERY_WINDOW_SECS} SECOND "
                           f"ORDER BY revision DESC LIMIT 1 BY tenant_id, finding_id) "
                           f"WHERE enrichment_state IN ('PENDING', 'REQUIRED') "
                           f"ORDER BY tenant_id, finding_id LIMIT {RECOVERY_PAGE} OFFSET {offset}")
            names = list(res.column_names)
            rows = [dict(zip(names, row)) for row in res.result_rows]
            if not rows:
                break
            pending.update(_pending_from_rows(rows, deadline_secs, now))
            offset += len(rows)
            if len(rows) < RECOVERY_PAGE:
                break
            if offset >= RECOVERY_MAX:                    # safety ceiling
                overflow = True
                break
        if overflow:
            log.error("F14 pending recovery hit the safety cap %d — some obligations NOT recovered "
                      "(degraded readiness)", RECOVERY_MAX)
            return pending, False                         # observable, not a silent partial claim
        return pending, True
    except Exception as e:                                # noqa: BLE001 (recovery must not crash startup)
        log.error("F14 pending recovery FAILED (holding readiness, will retry): %s", e)
        return {}, False


def _pkey(finding: dict) -> bytes:
    """Kafka partition key so one entity's findings land on one partition (F08): the
    correlation consumer group then never splits a host's history across replicas.
    tenant_id is the trusted, detector-set tenant — not attacker-controlled traffic
    content — so a spoofed field cannot repartition another tenant's stream."""
    tenant = finding.get("tenant_id") or "default"
    ents = finding.get("entities")
    try:
        items = json.loads(ents) if isinstance(ents, str) else (ents or [])
    except (ValueError, TypeError):
        items = []
    items = items if isinstance(items, list) else []
    ip = next((e.get("value") for e in items if isinstance(e, dict) and e.get("type") == "ip"
               and e.get("role") in ("src", "subject", "client")), None)
    if ip is None:
        ip = next((e.get("value") for e in items if isinstance(e, dict) and e.get("type") == "ip"), None)
    base = f"ip:{ip}" if ip else (finding.get("finding_id") or "unkeyed")
    return f"{tenant}|{base}".encode()


def _deliver_now(finding, producer, geo):
    """First delivery of a finding to the SIEM: Tier-1/Tier-2 enrich, then emit."""
    geoenrich.enrich_finding(finding, geo)   # Tier-1: geo/asn + community-id
    intel.enrich(finding)                    # Tier-2: rDNS/RDAP/fingerprint/reputation (opt-in)
    producer.send(FINAL_TOPIC, finding, key=_pkey(finding))


def _emit_finalized(entry, done, producer, geo, ch):
    """Re-emit a finalized finding. A deliver-now finding (delivered=True) was already
    enriched at first delivery; a capture-only finding is enriched here on its first
    and only delivery. Re-persist so the ClickHouse row reflects the terminal state."""
    if not entry["delivered"]:
        geoenrich.enrich_finding(done, geo)
        intel.enrich(done)
    _persist(ch, done)
    producer.send(FINAL_TOPIC, done, key=_pkey(done))
    metrics.finalization("capture_complete")   # R7: capture-bound finding finalized on its delivery


def _pk(tenant, fid):
    """§62.6 tenant-safe pending key: (tenant_id, finding_id). Two tenants can legitimately share a
    finding_id — keying by id ALONE would collide/mix their capture state. tenant_id is the trusted,
    detector-set field (not attacker traffic content)."""
    return (tenant or "default", fid)


def _pop_pending(pending, tenant, fid):
    """Pop the pending entry for an enrichment result / capture status. Uses the composite key when the
    message carries tenant_id; if tenant is absent (a producer that does not echo it), fall back to a
    finding_id match ONLY when it is unambiguous across tenants — an ambiguous id is left in place and
    reported, never finalized against the wrong tenant."""
    if tenant is not None:
        return pending.pop(_pk(tenant, fid), None)
    matches = [k for k in pending if k[1] == fid]
    if len(matches) == 1:
        return pending.pop(matches[0])
    if len(matches) > 1:
        log.warning("ambiguous finalize for finding_id %s across %d tenants — deferring", fid, len(matches))
    return None


# B-U2: bounded cache of recently-finalized capture-bound findings so a late enrichment result
# (arriving after a timeout/failed finalization) re-opens as a NEW revision instead of being dropped.
_MAX_FINALIZED = int(os.environ.get("NDR_FINALIZED_CACHE", "5000"))
_finalized_capture = OrderedDict()          # (tenant, finding_id) -> {finding, delivered}


def _remember_finalized(finding, delivered):
    k = _pk(finding.get("tenant_id"), finding.get("finding_id"))
    _finalized_capture[k] = {"finding": finding, "delivered": delivered}
    _finalized_capture.move_to_end(k)
    while len(_finalized_capture) > _MAX_FINALIZED:
        _finalized_capture.popitem(last=False)


def _handle_candidate(cand, producer, geo, pending, deadline_secs, now, ch):
    """Build the finding, deliver-now if it is a confirmed threat, and request capture
    (tracking it for finalization) when packets are needed."""
    finding, route = sm.build_finding(cand)
    _persist(ch, finding)
    if route in ("final", "final_and_capture"):
        _deliver_now(finding, producer, geo)
    if route in ("capture", "final_and_capture"):
        producer.send(CAPTURE_TOPIC, sm.capture_job(finding))
        pending[_pk(finding.get("tenant_id"), finding["finding_id"])] = {
            "finding": finding,
            "delivered": route == "final_and_capture",
            "deadline": now + deadline_secs,
        }
    return finding, route


def _handle_result(result, producer, geo, pending, ch):
    """An enrichment result (ndr.enrichment.result.v1) attaches evidence and finalizes
    the pending finding. Unknown/duplicate finding is an idempotent no-op."""
    entry = _pop_pending(pending, result.get("tenant_id"), result.get("finding_id"))
    if entry is None:
        # B-U2/R02: a late enrichment result after a timeout/failed finalization -> a NEW revision,
        # not a silent drop. Unknown/duplicate (not in the finalized cache) stays an idempotent no-op.
        prev = _finalized_capture.pop(_pk(result.get("tenant_id"), result.get("finding_id")), None)
        if prev is None:
            return
        done = sm.apply_enrichment_result(prev["finding"], result)
        log.info("late enrichment result for %s: re-emitting as revision %s",
                 result.get("finding_id"), done.get("revision"))
        _emit_finalized({"finding": prev["finding"], "delivered": True}, done, producer, geo, ch)
        return
    done = sm.apply_enrichment_result(entry["finding"], result)
    _emit_finalized(entry, done, producer, geo, ch)


def _handle_status(status, producer, geo, pending, ch):
    """A capture status (ndr.capture.status.v1). B-U2/R02 state precedence: 'completed' means the
    capture SUCCEEDED and the enrichment result is still coming — do NOT finalize (a timeout-finalize
    here drops that result; the agent sets armed=False on completion, so 'armed' is not a refusal
    signal). Only a terminal state with no result to follow finalizes early: failed/rejected/refused/
    no_data."""
    state = status.get("state")
    if state == "completed":
        return                                   # capture succeeded — await the enrichment result
    # every OTHER terminal status finalizes early (no result will follow): an explicit
    # failed/rejected/refused/no_data, or a bare armed=False orchestrator refusal.
    if not (status.get("armed") is False or state in ("failed", "rejected", "refused", "no_data")):
        return                                   # armed / in-progress: nothing to finalize yet
    entry = _pop_pending(pending, status.get("tenant_id"), status.get("finding_id"))
    if entry is None:
        return
    done = sm.finalize_timeout(entry["finding"])
    _emit_finalized(entry, done, producer, geo, ch)
    _remember_finalized(done, entry["delivered"])    # a late result can still re-open this as a new revision


def _sweep_timeouts(producer, geo, pending, now, ch):
    """Finalize findings whose enrichment never completed (no overlay / unavailable):
    delivered rather than left dangling. A confirmed threat is already on the SIEM;
    this only resolves its enrichment_state so it does not sit PENDING forever."""
    for key in [k for k, e in pending.items() if e["deadline"] <= now]:
        entry = pending.pop(key)
        done = sm.finalize_timeout(entry["finding"])
        _emit_finalized(entry, done, producer, geo, ch)
        _remember_finalized(done, entry["delivered"])   # B-U2: a late result re-opens as a new revision


# U8 case API. Run behind a TLS gateway using server-owned CASE_SESSIONS:
# {token: {tenant, analyst, expires_at: unix_seconds, case_write: bool}}.
# Each session selects exactly one tenant; request identity claims are rejected.
# GET /cases?owner=...&status=...&limit=50&offset=0 and GET /cases/{id}.
# POST /cases {title, owner?}; POST /cases/{id}/{owner,assign,notes,status,
# findings,entities} with respectively {owner}, {assignee}, {text}, {status},
# {finding_id}, {entity:{type,value}}. DELETE supports assign/findings/entities
# with the same body. Owner/assignee are assignment TARGETS, never audit actors.
# CASE_API_PORT enables the listener alongside the existing consumer; CASE_DB
# must point at a persistent writable volume (default /data/cases.sqlite3).


def make_case_handler(store, sessions, now=time.time):
    import copy
    import hashlib
    import importlib.util
    import math
    import uuid
    from pathlib import Path
    from http.server import BaseHTTPRequestHandler
    from urllib.parse import parse_qs, urlsplit

    here = Path(__file__).resolve().parent
    model_path = here / 'cases.py'
    if not model_path.exists():  # Docker preserves U7 modules under this path.
        model_path = here / 'services/finding-service/cases.py'
    spec = importlib.util.spec_from_file_location('finding_cases_api_model', model_path)
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)
    sessions = copy.deepcopy(sessions)

    def string(value, maximum=256, nullable=False):
        if nullable and value is None:
            return value
        if not isinstance(value, str) or not value.strip() or len(value) > maximum:
            raise ValueError('invalid string')
        return value

    def digest(doc):
        # Hash business state only: the audit contains these hashes itself.
        state = {k: v for k, v in doc.items() if k != 'audit'} if doc else None
        return hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send_json(self, code, value):
            body = json.dumps(value).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def handle_case(self):
            try:
                auth = self.headers.get('Authorization', '')
                session = sessions.get(auth[7:]) if auth.startswith('Bearer ') else None
                if not isinstance(session, dict):
                    return self.send_json(401, {'error': 'unauthorized'})
                expiry = session.get('expires_at')
                if (type(expiry) not in (int, float) or not math.isfinite(expiry)
                        or now() >= expiry):
                    return self.send_json(401, {'error': 'unauthorized'})
                try:
                    tenant = string(session.get('tenant'))
                    actor = string(session.get('analyst'))
                except ValueError:
                    return self.send_json(401, {'error': 'unauthorized'})
                write = self.command != 'GET'
                if write and session.get('case_write') is not True:
                    return self.send_json(403, {'error': 'read only'})
                url = urlsplit(self.path)
                parts = url.path.strip('/').split('/')
                query = parse_qs(url.query, keep_blank_values=True)
                allowed = {'owner', 'status', 'limit', 'offset'} if parts == ['cases'] and not write else set()
                if set(query) - allowed or any(len(v) != 1 for v in query.values()):
                    raise ValueError('unsupported query parameters')
                if not parts or parts[0] != 'cases' or len(parts) > 3:
                    return self.send_json(404, {'error': 'not found'})
                if not write:
                    if len(parts) == 1:
                        limit = int(query.get('limit', ['50'])[0])
                        offset = int(query.get('offset', ['0'])[0])
                        if not 1 <= limit <= 200 or not 0 <= offset <= 1000000:
                            raise ValueError('invalid page')
                        clauses, params = ['tenant=?'], [tenant]
                        for field in ('owner', 'status'):
                            if field in query:
                                value = string(query[field][0])
                                if field == 'status' and value not in sm.CASE_TRANSITIONS:
                                    raise ValueError('invalid status')
                                clauses.append(f"json_extract(doc, '$.{field}')=?")
                                params.append(value)
                        # U7 list_cases materializes all rows. Page in SQL instead,
                        # under the same lock as atomic U7 writes.
                        with store._lock:
                            rows = store._db.execute(
                                'SELECT doc FROM cases WHERE ' + ' AND '.join(clauses)
                                + ' ORDER BY case_id LIMIT ? OFFSET ?',
                                params + [limit + 1, offset]).fetchall()
                        return self.send_json(200, {
                            'cases': [json.loads(r['doc']) for r in rows[:limit]],
                            'limit': limit, 'offset': offset,
                            'next_offset': offset + limit if len(rows) > limit else None})
                    if len(parts) != 2:
                        return self.send_json(404, {'error': 'not found'})
                    with store._lock:
                        doc = store.get(parts[1], {tenant})
                    return self.send_json(200 if doc else 404, doc or {'error': 'not found'})
                lengths = self.headers.get_all('Content-Length', [])
                if len(lengths) != 1 or self.headers.get('Transfer-Encoding'):
                    raise ValueError('invalid body length')
                length = int(lengths[0])
                if not 0 < length <= 65536:
                    raise ValueError('invalid body length')
                self.connection.settimeout(10)
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError('expected object')
                ts = datetime.fromtimestamp(now(), timezone.utc).isoformat()

                def audited(before, after, event):
                    if len(after['audit']) == len(before['audit']):
                        # U7 idempotent helpers omit no-ops; HTTP successes still
                        # record the requested action without duplicating links.
                        after = dict(after, updated=ts, audit=list(after['audit']) + [
                            {'event': event, 'actor': actor, 'ts': ts, 'detail': {'noop': True}}])
                    detail = after['audit'][-1].setdefault('detail', {})
                    detail.update(audit_id=uuid.uuid4().hex, tenant=tenant,
                                  resource_type='case', resource_id=after['case_id'],
                                  before_hash=digest(before), after_hash=digest(after),
                                  request_id=uuid.uuid4().hex, source_ip=self.client_address[0],
                                  outcome='success')
                    return after

                if len(parts) == 1 and self.command == 'POST':
                    if set(payload) - {'title', 'owner'} or 'title' not in payload:
                        raise ValueError('invalid create fields')
                    doc = model.new_case(uuid.uuid4().hex, tenant,
                                         string(payload['title'], 1024),
                                         string(payload.get('owner', actor), nullable=True), actor, ts)
                    doc = audited({'audit': []}, doc, 'created')
                    if not store.create(doc):
                        return self.send_json(409, {'error': 'case already exists'})
                    return self.send_json(201, doc)
                routes = {
                    ('POST', 'owner'): ('owner', model.change_owner, 'owner_changed'),
                    ('POST', 'assign'): ('assignee', model.assign, 'assignee_added'),
                    ('DELETE', 'assign'): ('assignee', model.unassign, 'assignee_removed'),
                    ('POST', 'notes'): ('text', None, 'note_added'),
                    ('POST', 'status'): ('status', model.transition, 'status_changed'),
                    ('POST', 'findings'): ('finding_id', model.link_finding, 'finding_linked'),
                    ('DELETE', 'findings'): ('finding_id', model.unlink_finding, 'finding_unlinked'),
                    ('POST', 'entities'): ('entity', model.link_entity, 'entity_linked'),
                    ('DELETE', 'entities'): ('entity', model.unlink_entity, 'entity_unlinked'),
                }
                route = routes.get((self.command, parts[2])) if len(parts) == 3 else None
                if route is None:
                    return self.send_json(404, {'error': 'not found'})
                field, fn, event = route
                if set(payload) != {field}:
                    raise ValueError('invalid mutation fields')
                value = payload[field]
                if field == 'entity':
                    if (not isinstance(value, dict) or set(value) != {'type', 'value'}
                            or value['type'] not in ('ip', 'hostname', 'domain', 'asset')):
                        raise ValueError('invalid entity')
                    string(value['value'], 512)
                else:
                    string(value, 8192 if field == 'text' else 256, nullable=field == 'owner')

                def mutate(doc):
                    changed = (model.add_note(doc, actor, value, ts) if field == 'text'
                               else fn(doc, value, actor, ts))
                    return audited(doc, changed, event)

                doc = store.mutate(parts[1], {tenant}, mutate)
                return self.send_json(200 if doc else 404, doc or {'error': 'not found'})
            except (ValueError, UnicodeError):
                return self.send_json(400, {'error': 'invalid case request'})
            except Exception:
                log.exception('case API unavailable')
                return self.send_json(503, {'error': 'case API unavailable'})

        do_GET = handle_case
        do_POST = handle_case
        do_DELETE = handle_case

    return Handler


def start_case_api():
    """Opt-in HTTP listener; no import-time DB writes or consumer changes."""
    import importlib.util
    import threading
    from pathlib import Path
    from http.server import ThreadingHTTPServer

    port = os.environ.get('CASE_API_PORT')
    if not port:
        return None
    here = Path(__file__).resolve().parent
    path = here / 'store.py'
    if not (here / 'cases.py').exists():
        path = here / 'services/finding-service/store.py'
    spec = importlib.util.spec_from_file_location('finding_case_api_store', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    store = module.CaseStore(os.environ.get('CASE_DB', '/data/cases.sqlite3'))
    handler = make_case_handler(store, json.loads(os.environ.get('CASE_SESSIONS', '{}')))
    server = ThreadingHTTPServer(('0.0.0.0', int(port)), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    case_server = start_case_api()
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    ch = None
    if CH_ENABLED:
        import clickhouse_connect
        ch = clickhouse_connect.get_client(host=CH_HOST, username=CH_USER, password=CH_PASS)
    producer = ndr_runtime.make_producer()
    consumer = ndr_runtime.make_consumer(
        CANDIDATE_TOPIC, RESULT_TOPIC, STATUS_TOPIC,
        group_id="ndr-finding-service", auto_offset_reset="earliest")
    geo = geoenrich.open_readers()      # offline GeoIP/ASN; {} (no-op) if DBs unmounted
    ndr_runtime.start_health()          # /healthz /readyz /metrics (plan 003 obs)
    # F14 durable recovery: reload capture-bound findings that were still awaiting finalization when a
    # prior process stopped, so a restart mid-capture does not lose their finalization obligation. A
    # recovery-query FAILURE holds readiness (§62.6) and is retried in the loop, rather than silently
    # claiming zero pending. With ClickHouse disabled this is a no-op ({}), matching prior behaviour.
    pending, recovery_ok = _load_pending_from_ch(ch, ENRICH_TIMEOUT_SECS, time.monotonic())
    for _attempt in range(3):                              # §62.6: retry a FAILED required recovery, don't proceed blind
        if recovery_ok:
            break
        time.sleep(2)
        pending, recovery_ok = _load_pending_from_ch(ch, ENRICH_TIMEOUT_SECS, time.monotonic())
    if not recovery_ok:
        log.error("F14: pending recovery still failing after retries — proceeding DEGRADED; "
                  "in-flight capture obligations from a prior run may not be finalized until CH recovers")
    if pending:
        log.info("F14: recovered %d un-finalized capture-bound finding(s) from ClickHouse", len(pending))
    import uuid
    worker, seq, delivered_now, capture_requested = uuid.uuid4().hex, 0, 0, 0   # §stage3 lifecycle acks
    log.info("finding-service up: %s (+%s, %s) -> ClickHouse %s (geoip=%s)",
             CANDIDATE_TOPIC, RESULT_TOPIC, STATUS_TOPIC,
             CH_HOST if CH_ENABLED else "(disabled)", "+".join(sorted(geo)) or "off")

    def emit_lifecycle():
        # §stage3: every candidate is disposed as delivered-now, capture-requested (then finalized on
        # result/status/timeout), so `pending` == capture-bound findings not yet finalized. A reader
        # confirms pending==0 at completion -> no undisposed lifecycle work; producer exit/offset
        # progress cannot show this. Best-effort — never disrupts the lifecycle.
        nonlocal seq
        if not LIFECYCLE_ON:
            return
        try:
            seq += 1
            producer.send(LIFECYCLE_TOPIC, {"svc": "finding-service", "worker": worker, "seq": seq,
                                            "delivered_now": delivered_now,
                                            "capture_requested": capture_requested, "pending": len(pending),
                                            "finalized": capture_requested - len(pending)})
        except Exception as ex:                       # noqa: BLE001
            log.warning("could not emit lifecycle ack: %s", ex)

    while _running:
        batch = consumer.poll(timeout_ms=1000, max_records=200)
        now = time.monotonic()
        for tp, records in batch.items():
            for rec in records:
                if tp.topic == CANDIDATE_TOPIC:
                    finding, route = _handle_candidate(
                        rec.value, producer, geo, pending, ENRICH_TIMEOUT_SECS, now, ch)
                    if route in ("final", "final_and_capture"):
                        delivered_now += 1
                    if route in ("capture", "final_and_capture"):
                        capture_requested += 1
                    log.info("%s %s (%s)",
                             "CAPTURE_REQUESTED" if route == "capture" else "FINAL",
                             finding["finding_id"], finding["category"])
                    if route in ("final", "final_and_capture"):
                        metrics.finalization(route)     # R7: finalized at candidate handling
                elif tp.topic == RESULT_TOPIC:
                    _handle_result(rec.value, producer, geo, pending, ch)
                elif tp.topic == STATUS_TOPIC:
                    _handle_status(rec.value, producer, geo, pending, ch)
        _sweep_timeouts(producer, geo, pending, time.monotonic(), ch)
        metrics.set_enrichment_pending(len(pending))     # R7: current findings awaiting enrichment
        emit_lifecycle()
        producer.flush()

    emit_lifecycle()                                  # final disposition on shutdown
    consumer.close()
    producer.close()
    if case_server is not None:
        case_server.shutdown()
        case_server.server_close()
    log.info("finding-service stopped")


if __name__ == "__main__":
    main()
