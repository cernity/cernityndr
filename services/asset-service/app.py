"""Asset service (plan U17 + U7). Consumes suricata.flow.v1 + suricata.raw.v1
(arp/dhcp carry L2 identity), resolves each observation to a stable asset_key
(resolution.py), upserts the ndr.asset entity table, and — U7 — derives temporal,
evidence-backed FACTS (resolution.derive_facts / fold_facts: value, validity
interval, confidence, source per §13.4; deterministic conflict resolution per
§13.5) into ndr.asset_fact, opening a new interval on every change (no overwrite).

It also serves a read-only timeline API on the same process:

  GET /healthz
  GET /entity/{id}/timeline   -> ordered observations + fact changes (normalized ts)

Tenant is SERVER-DERIVED from the bearer token (§21), never a path/query param.
Resolution + interval + timeline logic is pure and unit-tested (test_resolution.py);
this is the Kafka + ClickHouse + HTTP shell. Heavy imports (kafka, clickhouse) are
deferred into main()/make_client so the module stays importable for tests.
"""
import hashlib
import json
import os
import signal
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

import ndr_runtime
import relationships
import resolution

log = ndr_runtime.setup_logging("asset-service")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
CH_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse")
CH_USER = os.environ.get("CLICKHOUSE_USER", "ndr")
TENANT = os.environ.get("NDR_TENANT", "default")
SENSOR = os.environ.get("NDR_SENSOR", "sensor-1")   # fallback id (single-sensor lab)
FLUSH_SECS = float(os.environ.get("NDR_FLUSH_SECS", "15"))
API_PORT = int(os.environ.get("PORT", "8093"))
COLS = ["tenant_id", "asset_key", "first_seen", "last_seen", "ip_set", "mac_set",
        "hostname_set", "role_if_known", "evidence_sources", "confidence",
        "username", "role", "os_hint", "criticality", "owner", "applications",
        "listening_services", "certificates", "ja4", "attribute_provenance"]
FACT_COLS = ["tenant_id", "subject", "predicate", "value", "confidence",
             "valid_from", "valid_to", "source_type", "observation_id",
             "method", "classifier_version", "is_deleted"]
OBS_COLS = ["tenant_id", "obs_id", "normalized_time", "entity_values", "observation"]
EDGE_COLS = ["tenant_id", "src_entity", "dst_entity", "kind", "first_seen",
             "last_seen", "evidence"]

_running = True
_assets: dict = {}          # asset_key -> asset dict
_bindings: dict = {}        # ip -> [time-bounded IP<->MAC bindings] (§13.5)
_dirty: set = set()
_fact_state: dict = {}      # subject -> predicate -> {ts -> winner}  (U7 interval source)
_pending_facts: dict = {}   # (subject, predicate) -> authoritative interval set to flush
_emitted: dict = {}         # (subject, predicate) -> set of (valid_from, value) LAST
                            #   persisted (drives tombstoning of intervals a rebuild
                            #   dropped; value is in the key so a MAC's multiple IPs at
                            #   one instant are tracked as distinct intervals)
_pending_obs: dict = {}     # obs_id -> identity evidence row backing a fact's obs_id
_edges: dict = {}           # (src_entity, dst_entity, kind) -> {first_seen, last_seen,
                            #   evidence}  (U3c CUMULATIVE observed relationship spans —
                            #   kept across flushes, reloaded on restart; never cleared)
_edges_dirty: set = set()   # edge keys whose span/evidence changed since the last flush


def _stop(*_):
    global _running
    _running = False


def _dt(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _identity(eve: dict):
    """Trusted-ingress identity (mirrors normalizer.models.inject_identity): tenant
    is config-driven, never trusted from the wire; sensor prefers an edge-stamped id."""
    return TENANT, (eve.get("host") or eve.get("sensor_id") or SENSOR)


def _fold_observation(obs: dict, obs_id: str, tenant: str, ts: str) -> str:
    """Fold ONE evidence obs into temporal facts + time-bounded IP<->MAC bindings, and
    return its resolved asset_key. Shared by observe() and restore_state()'s evidence
    replay so a restart reconstructs identical state. Mutates _bindings, _fact_state,
    and the pending-write buffers. Idempotent per obs_id (record_binding dedups an
    identical record, fold is rebuild-based), so replay is safe."""
    expires = None
    has_binding = bool(obs.get("mac") and obs.get("ip"))
    if has_binding:
        expires = resolution.lease_expiry(ts, obs.get("lease_secs"))
        # The RAW lease is the single source of truth (§13.4): attribution and the
        # persisted interval cache both derive from _bindings, so they can never diverge.
        # obs_id + src ride along so a same-start lease tie breaks identically either way.
        resolution.record_binding(_bindings, obs["ip"], obs["mac"], ts, expires,
                                  obs_id, obs.get("src", ""))
    key = resolution.asset_key(obs, _bindings, ts)   # time-bounded identity (§13.5)
    # U7 facts: hostname/mac from identity evidence. A changed value opens a new interval
    # (no overwrite); conflicts resolve deterministically. The `ip` predicate is NOT folded
    # here — it is a DERIVED cache rebuilt from the raw leases below (owner_at), so no second
    # ownership path exists.
    cands = resolution.derive_facts(obs, obs_id, ts)
    if cands or has_binding:
        # Persist the identity (arp/dhcp) evidence row under THIS obs_id so the facts'
        # source.observation_id references a real, retrievable stored row (§13.4) — the
        # normalizer never types arp/dhcp, so nothing else stores it. It is ALSO the
        # durable reconstruction evidence restore_state replays after a restart.
        _pending_obs[obs_id] = resolution.identity_observation(obs, obs_id, tenant, ts)
    for pred, intervals in resolution.fold_facts(_fact_state, key, cands).items():
        _pending_facts[(key, pred)] = intervals            # re-emit authoritative set
    if has_binding:
        # Rebuild IP ownership ACROSS ALL claimants from the raw leases via owner_at, so it
        # is order-independent and a prior holder is capped at reassignment even though it
        # emits no new record (§13.5). An empty list tombstones a subject that owns none.
        for subj, intervals in resolution.rebuild_ip_ownership(_bindings).items():
            _pending_facts[(subj, "ip")] = intervals
    return key


def observe(eve: dict, topic: str, partition: int, offset: int, normalized_ts: str):
    """Fold one raw EVE record into asset state + temporal facts. obs_id and the
    normalized ts follow the established observation-identity contract (canonical +
    deterministic across replay), so facts are pinned to durable, retrievable
    observation identity. Folding is rebuild-based, so conflict resolution sees
    competing records and late/replayed events cannot invert or overlap intervals."""
    tenant, sensor = _identity(eve)
    obs_id = resolution.canonical_obs_id(tenant, sensor, topic, partition, offset)
    ts = normalized_ts
    for obs in resolution.extract_evidence(eve):
        key = _fold_observation(obs, obs_id, tenant, ts)
        _assets[key] = resolution.merge(_assets.get(key), obs, ts)
        _dirty.add(key)
    # U3c: observed entity-to-entity edges (dns/flow). Resolved AFTER the fold loop so
    # endpoints see this record's bindings; keyed by (src, dst, kind) so re-observations
    # advance the CUMULATIVE span rather than duplicating. _edges is the live span across
    # flushes/restarts (restore_state reloads it), so a late observation widens the durable
    # bounds instead of restarting at its own instant. Pure extraction in relationships.py.
    for edge in relationships.build_edges(eve, _bindings, ts):
        k = (edge["src_entity"], edge["dst_entity"], edge["kind"])
        slot = _edges.get(k)
        if slot is None:
            _edges[k] = {"first_seen": ts, "last_seen": ts, "evidence": edge["evidence"]}
            _edges_dirty.add(k)
        else:
            if resolution._instant(ts) < resolution._instant(slot["first_seen"]):
                slot["first_seen"] = ts           # late observation widens first_seen back
                _edges_dirty.add(k)
            if resolution._instant(ts) >= resolution._instant(slot["last_seen"]):
                slot["last_seen"] = ts            # widen the span; carry the latest evidence
                slot["evidence"] = edge["evidence"]
                _edges_dirty.add(k)


def flush(ch):
    if _dirty:
        rows = []
        for key in list(_dirty):
            a = _assets[key]
            rows.append([TENANT, key, _dt(a["first_seen"]), _dt(a["last_seen"]),
                         a["ip_set"], a["mac_set"], a["hostname_set"],
                         a.get("role_if_known", ""), a["evidence_sources"], a["confidence"],
                         *[a.get(attr) or None for attr in resolution._ATTR_SCALARS],
                         *[a.get(attr) or [] for attr in resolution._ATTR_LISTS],
                         json.dumps(a["attribute_provenance"], sort_keys=True,
                                    separators=(",", ":"), ensure_ascii=False)
                         if a.get("attribute_provenance") else ""])
        ch.insert("ndr.asset", rows, column_names=COLS)
        log.info("upserted %d assets (%d total tracked)", len(rows), len(_assets))
        _dirty.clear()
    if _pending_obs:
        rows = [[o["tenant_id"], o["obs_id"], _dt(o["normalized_time"]),
                 o["entity_values"], o["observation"]] for o in _pending_obs.values()]
        ch.insert("ndr.identity_observation", rows, column_names=OBS_COLS)
        log.info("wrote %d identity observation rows", len(rows))
        _pending_obs.clear()
    if _pending_facts:
        rows = []
        new_emitted = {}
        for (subject, pred), intervals in _pending_facts.items():
            current = set()
            for iv in intervals:
                vf = resolution._iso(iv["valid_from"])
                oid = iv["source"].get("observation_id") or ""
                # (valid_from, value, observation_id) is an interval's FULL identity — it
                # mirrors the asset_fact ORDER BY. value keeps a MAC's several IPs distinct;
                # the lease id (observation_id) additionally keeps two SAME-START intervals
                # for ONE ip (distinct leases at one instant) from colliding on the same
                # ORDER BY key and collapsing under ReplacingMergeTree.
                current.add((vf, iv["value"], oid))
                rows.append([
                    TENANT, subject, pred, iv["value"], iv["confidence"],
                    _dt(iv["valid_from"]), _dt(iv["valid_to"]) if iv["valid_to"] else None,
                    iv["source"]["type"], oid,
                    iv.get("method") or "", iv.get("classifier_version") or "", 0])
            # A rebuild can DROP an interval (a (valid_from, value, lease) that no longer
            # exists — a run that merged after a conflict re-resolved, or one of several
            # IPs a MAC no longer owns). Emit a tombstone (is_deleted=1) carrying that
            # interval's FULL key (value AND lease id) so it lands on the obsolete row's
            # exact ORDER BY key and is REMOVED at merge/read (ReplacingMergeTree keeps the
            # newest version) rather than lingering as a phantom interval.
            for vf, val, oid in _emitted.get((subject, pred), set()) - current:
                rows.append([TENANT, subject, pred, val, 0.0, _dt(vf), None,
                             "", oid, "", "", 1])
            new_emitted[(subject, pred)] = current
        ch.insert("ndr.asset_fact", rows, column_names=FACT_COLS)
        # Mark rebuilt intervals CLEAN only after the insert succeeds — if it raises,
        # both _emitted and _pending_facts are left intact so the next start repairs.
        _emitted.update(new_emitted)
        log.info("wrote %d fact interval rows", len(rows))
        _pending_facts.clear()
    if _edges_dirty:
        # U3c: persist observed relationship edges. Bounds are CUMULATIVE — _edges holds the
        # live span across flushes (NEVER cleared) and restarts (restore_state reloads it);
        # only the dirty keys re-emit. Same persist-before-commit ordering (§13.4) — this
        # runs inside flush(), before persist_and_commit() advances the offset. A raised
        # insert leaves _edges_dirty intact (cleared only AFTER insert) so the next flush
        # retries; ReplacingMergeTree(updated_at) collapses the at-least-once re-emit, keeping
        # the widened span + latest evidence rather than regressing to a single instant.
        rows = []
        for k in _edges_dirty:
            e = _edges[k]
            rows.append([TENANT, *k, _dt(e["first_seen"]), _dt(e["last_seen"]),
                         json.dumps(e["evidence"], sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False)])
        ch.insert("ndr.entity_relationship", rows, column_names=EDGE_COLS)
        log.info("wrote %d entity relationship edges", len(rows))
        _edges_dirty.clear()


def persist_and_commit(ch, consumer):
    """Durability ordering (§13.4, at-least-once): PERSIST every pending row FIRST, then
    commit the Kafka offset — NEVER the reverse. The offset must not advance ahead of a
    durable write, so a crash AFTER the flush but BEFORE the commit re-consumes those
    records from the last committed offset on restart. Reprocessing is idempotent (evidence
    is keyed by a canonical obs_id under ReplacingMergeTree; intervals rebuild from the raw
    leases via the single owner_at oracle) and restore_state() repairs any interval an
    interrupted persist left stale — so the rebuild is identical and no evidence is lost.
    flush() raising leaves the offset uncommitted (this returns before commit), which is the
    same recoverable state as a crash: the next start repairs and re-consumes."""
    flush(ch)
    consumer.commit()


def _load_emitted(ch):
    """Seed _emitted with the interval keys a PRIOR process persisted (authoritative,
    live rows only). Without this, restore starts with an empty _emitted, so the repair
    flush's tombstone reconciliation (below) has nothing to compare the rebuilt cache
    against and can NEVER remove an interval an interrupted persist left active — e.g. a
    former owner that the rebuild now determines owns nothing, or a boundary that
    coalesced away. Loading them makes the rebuilt cache reconcile against EVERY prior
    key, including obsolete ones, so the repair flush tombstones what the rebuild dropped
    (§13.4)."""
    sql = ("SELECT tenant_id, subject, predicate, value, valid_from, valid_to, "
           "observation_id, is_deleted, updated_at FROM ndr.asset_fact FINAL "
           "WHERE tenant_id = {tenant:String}")
    res = ch.query(sql, parameters={"tenant": TENANT})
    rows = [dict(zip(res.column_names, r)) for r in res.result_rows]
    for row in resolution._authoritative(rows):     # collapse ReplacingMergeTree versions
        _emitted.setdefault((row["subject"], row["predicate"]), set()).add(
            (resolution._iso(row["valid_from"]), row["value"], row["observation_id"]))


def _load_assets(ch):
    """Reload durable entity snapshots, keeping unobserved additions absent."""
    res = ch.query("SELECT " + ", ".join(COLS) +
                   " FROM ndr.asset FINAL WHERE tenant_id = {tenant:String}",
                   parameters={"tenant": TENANT})
    for row in resolution._rows(res):
        key = row.pop("asset_key")
        row.pop("tenant_id")
        row["first_seen"] = resolution._iso(row["first_seen"])
        row["last_seen"] = resolution._iso(row["last_seen"])
        provenance = row.pop("attribute_provenance", None)
        if provenance:
            decoded = json.loads(provenance)
            if decoded:
                row["attribute_provenance"] = decoded
        for attr in (*resolution._ATTR_SCALARS, *resolution._ATTR_LISTS):
            if not row.get(attr):
                row.pop(attr, None)
        _assets[key] = row


def _load_edges(ch):
    """Reload the CUMULATIVE relationship spans a prior process persisted so a re-observed
    edge widens [first_seen, last_seen] from the durable bounds instead of restarting at the
    new observation's instant — which would regress first_seen and lose the span under
    ReplacingMergeTree(updated_at). Reloaded edges are NOT marked dirty (already durable);
    only a fresh live observation re-flushes one. evidence is decoded back to the dict shape
    observe() holds so a later re-flush re-serializes it identically."""
    res = ch.query(
        "SELECT src_entity, dst_entity, kind, first_seen, last_seen, evidence "
        "FROM ndr.entity_relationship FINAL WHERE tenant_id = {tenant:String}",
        parameters={"tenant": TENANT})
    for row in resolution._rows(res):
        ev = row["evidence"]
        _edges[(row["src_entity"], row["dst_entity"], row["kind"])] = {
            "first_seen": resolution._iso(row["first_seen"]),
            "last_seen": resolution._iso(row["last_seen"]),
            "evidence": json.loads(ev) if isinstance(ev, str) and ev else ev}


def restore_state(ch):
    """Rebuild fact + binding state after a restart by REPLAYING the durable RAW evidence
    (ndr.identity_observation) through the SAME fold path observe() uses, so the interval
    cache rebuilds via the one owner_at oracle — identical and order-independent (§13.4).
    The raw evidence carries the COMPLETE reconstruction material — every source obs_id,
    each renewal's own ts, and the original lease bounds — so intervals and bindings come
    out byte-identical to uninterrupted processing.

    We NEVER assume the prior process's interval persist succeeded: _emitted is seeded
    from the persisted intervals (_load_emitted) so the rebuilt cache is reconciled
    against every prior key — an obsolete interval a partial persist left active is
    tombstoned by the repair flush, not left orphaned alongside the rebuilt one. The
    rebuilt intervals stay dirty and are re-persisted here (idempotent under
    ReplacingMergeTree); nothing is marked clean until that repair flush's insert
    succeeds."""
    _load_assets(ch)                        # entity attributes are not in raw identity evidence
    _load_edges(ch)                         # cumulative relationship spans (U3c)
    _load_emitted(ch)                       # reconcile against prior persisted intervals
    sql = ("SELECT tenant_id, obs_id, normalized_time, observation "
           "FROM ndr.identity_observation FINAL WHERE tenant_id = {tenant:String} "
           "ORDER BY normalized_time, obs_id")
    res = ch.query(sql, parameters={"tenant": TENANT})
    rows = [dict(zip(res.column_names, r)) for r in res.result_rows]
    for row in rows:
        doc = json.loads(row["observation"])
        _fold_observation(resolution.reconstruct_obs(doc), row["obs_id"],
                          row["tenant_id"], resolution._iso(row["normalized_time"]))
    _pending_obs.clear()                    # identity evidence is already durable (just read)
    flush(ch)                               # repair: re-persist the rebuilt interval cache
    log.info("restored %d identity observations and repaired interval cache", len(rows))


# ── read-only timeline API ────────────────────────────────────────────────────

def _now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _actor(auth_header):
    """Pseudonymous actor id: the bearer token's SHA-256 prefix, NEVER the token
    itself (§21.2). None when unauthenticated."""
    token = auth_header[7:] if (auth_header or "").startswith("Bearer ") else None
    return "token:" + hashlib.sha256(token.encode()).hexdigest()[:12] if token else None


def _default_audit(event):
    ndr_runtime.log_event(log, "audit", **event)


class _Handler(BaseHTTPRequestHandler):
    client = None
    tokens = {}
    audit = staticmethod(_default_audit)

    def log_message(self, *a):
        pass  # superseded by the structured audit trail below

    def _send(self, code, obj):
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _audit(self, request_id, actor, tenants, entity, outcome,
               action="entity.timeline", **extra):
        event = {"action": action, "resource_type": "entity",
                 "actor": actor or "anonymous",
                 "tenant_scope": list(tenants) if tenants else [],
                 "source_ip": self.client_address[0], "request_id": request_id,
                 "entity": (entity or "")[:255], "outcome": outcome,
                 "timestamp": _now_iso()}
        event.update(extra)
        self.audit(event)

    def do_GET(self):
        u = urlparse(self.path)                # tenant in the path/query is ignored (§21)
        if u.path == "/healthz":
            return self._send(200, {"status": "ok"})
        request_id = self.headers.get("X-Request-Id") or uuid.uuid4().hex
        auth = self.headers.get("Authorization", "")
        actor = _actor(auth)
        # /entity/{id}/timeline  and  /entity/{id}/relationships (U3c) — same shape:
        # auth (401) -> validate (400) -> per-tenant fetch (503 on backend failure),
        # audited on EVERY outcome, including a non-matching path (404 routing miss).
        parts = [p for p in u.path.split("/") if p]
        if not (len(parts) == 3 and parts[0] == "entity"
                and parts[2] in ("timeline", "relationships")):
            self._audit(request_id, actor, None,
                        unquote(parts[1]) if len(parts) > 1 else "", "not_found",
                        action="entity.route")
            return self._send(404, {"error": "not found"})
        view = parts[2]
        action = "entity." + view
        entity_raw = unquote(parts[1])
        grants = resolution.grants_for_token(self.tokens, auth)
        if grants is None:
            self._audit(request_id, actor, None, entity_raw, "denied", action=action)
            return self._send(401, {"error": "unauthorized", "request_id": request_id})
        try:
            entity = resolution.validate_entity(entity_raw)
        except ValueError as e:
            self._audit(request_id, actor, grants, entity_raw, "bad_request",
                        action=action, reason=str(e))
            return self._send(400, {"error": str(e), "request_id": request_id})
        fetch = (resolution.fetch_timeline if view == "timeline"
                 else resolution.fetch_relationships)
        try:
            result = fetch(self.client, grants, entity)
        except Exception:                      # noqa: BLE001 — any backend failure -> controlled 5xx
            log.exception("%s query failed request_id=%s", view, request_id)
            self._audit(request_id, actor, grants, entity, "error", action=action)
            return self._send(503, {"error": view + " backend unavailable",
                                    "request_id": request_id})
        returned = (sum(len(t["events"]) for t in result["tenants"].values())
                    if view == "timeline"
                    else sum(len(edges) for edges in result["tenants"].values()))
        self._audit(request_id, actor, grants, entity, "success",
                    action=action, returned=returned)
        return self._send(200, result)


def make_handler(client, tokens, audit=None):
    return type("Handler", (_Handler,), {
        "client": client, "tokens": tokens,
        "audit": staticmethod(audit or _default_audit)})


def make_client():
    """Shared ClickHouse client. autogenerate_session_id=False so overlapping HTTP
    request threads sharing this one client don't collide inside a single ClickHouse
    session (same fix as evidence-service)."""
    import clickhouse_connect
    return clickhouse_connect.get_client(
        host=CH_HOST, username=CH_USER, password=os.environ["CLICKHOUSE_PASSWORD"],
        autogenerate_session_id=False)


def poll_and_observe(consumer):
    """Process ONE poll batch (§13.4 at-least-once). A record whose timestamp validation
    or observe() fails is NOT skipped past: we SEEK its partition back to that offset and
    stop draining the partition, so the failed record — and, in order, those after it — are
    re-fetched next poll and can NEVER be committed ahead of a durable persist. (A bare
    commit() commits each partition's current position, which after the seek is the failed
    offset, so only contiguous successfully-observed records are acknowledged.) A config
    error such as a non-LogAppendTime topic fails every record, so the partition simply
    blocks and no evidence is lost.
    ponytail: a genuinely poison record blocks its partition in a tight re-fetch loop; add a
    dead-letter / skip-after-N path if a single bad record must not stall ingest."""
    for tp, records in consumer.poll(timeout_ms=1000, max_records=500).items():
        for rec in records:
            try:
                # Normalized ts follows the ingest-fallback contract: a durable
                # LogAppendTime ingest instant (same as normalizer), not the
                # spoofable sensor timestamp on the wire.
                if rec.timestamp_type != 1 or rec.timestamp is None or rec.timestamp < 0:
                    raise RuntimeError("asset-service requires input topics with LogAppendTime")
                normalized_ts = datetime.fromtimestamp(
                    rec.timestamp / 1000, timezone.utc).isoformat()
                observe(rec.value, rec.topic, rec.partition, rec.offset, normalized_ts)
            except Exception as e:
                # Rewind to the failed record and stop this partition: its offset must not
                # advance past evidence that was never persisted. It replays next poll.
                log.warning("observe error at %s[%s] offset %s: %s — rewinding to replay",
                            rec.topic, rec.partition, rec.offset, e)
                consumer.seek(tp, rec.offset)
                break


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    from kafka import KafkaConsumer

    ch = make_client()
    restore_state(ch)                       # §13.4 interval continuity across restart
    # token -> [granted tenants]; unset => no reader authorized (secure default).
    tokens = json.loads(os.environ.get("ASSET_READER_TOKENS", "{}"))
    srv = ThreadingHTTPServer(("0.0.0.0", API_PORT), make_handler(ch, tokens))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log.info("asset-service timeline API on :%d", API_PORT)

    # enable_auto_commit=False: we commit the offset OURSELVES, only AFTER a durable flush
    # (persist_and_commit) — auto-commit would advance the offset on its own timer, ahead of
    # the ClickHouse write, and lose evidence on a crash (§13.4 offset-after-persist).
    # auto_offset_reset="earliest": if this group/partition has NO committed offset yet
    # (first run, or a crash before its first commit), resume from the OLDEST retained
    # record — "latest" would jump to the tail and drop that uncommitted initial batch.
    consumer = KafkaConsumer(
        "suricata.flow.v1", "suricata.raw.v1", bootstrap_servers=BOOTSTRAP,
        group_id="ndr-asset-service", auto_offset_reset="earliest",
        enable_auto_commit=False,
        value_deserializer=lambda b: json.loads(b.decode()),
    )
    log.info("asset-service up (tenant=%s)", TENANT)
    last = time.monotonic()
    while _running:
        poll_and_observe(consumer)
        if time.monotonic() - last >= FLUSH_SECS:
            persist_and_commit(ch, consumer)     # durable write BEFORE the offset advances
            last = time.monotonic()
    persist_and_commit(ch, consumer)
    consumer.close()
    srv.shutdown()


if __name__ == "__main__":
    main()
