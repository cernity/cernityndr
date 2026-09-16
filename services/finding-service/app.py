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
import logging
import os
import signal
import time
from datetime import datetime, timezone

import ndr_runtime                      # shared tuned consumer/producer (plan 003 U6 rollout)

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

COLS = ["finding_id", "tenant_id", "sensor_ids", "detector_id", "detector_version",
        "category", "severity", "confidence", "first_seen", "last_seen", "entities",
        "evidence_refs", "mitre", "state", "enrichment_state", "capture_job_ids",
        "suppression_reason", "devo_delivery_state",
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
    for k in ("entities", "suppression_reason", "enrichment_state", "devo_delivery_state"):
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
        cols = ", ".join(f"argMax({c}, revision) AS {c}" for c in COLS if c != "finding_id")
        res = ch.query(f"SELECT finding_id, {cols}, max(revision) AS revision "
                       "FROM ndr.finding GROUP BY finding_id "
                       "HAVING argMax(enrichment_state, revision) IN ('PENDING','REQUIRED')")
        names = list(res.column_names)
        rows = [dict(zip(names, row)) for row in res.result_rows]
        return _pending_from_rows(rows, deadline_secs, now), True
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
        return
    done = sm.apply_enrichment_result(entry["finding"], result)
    _emit_finalized(entry, done, producer, geo, ch)


def _handle_status(status, producer, geo, pending, ch):
    """A capture status (ndr.capture.status.v1). Only a refusal (orchestrator gate) or
    an agent failure finalizes early — no enrichment result will follow. 'armed' True
    and 'completed' mean the evidence is still coming on the result topic."""
    refused = (status.get("armed") is False
               or status.get("state") in ("failed", "rejected", "refused"))
    if not refused:
        return
    entry = _pop_pending(pending, status.get("tenant_id"), status.get("finding_id"))
    if entry is None:
        return
    done = sm.finalize_timeout(entry["finding"])
    _emit_finalized(entry, done, producer, geo, ch)


def _sweep_timeouts(producer, geo, pending, now, ch):
    """Finalize findings whose enrichment never completed (no overlay / unavailable):
    delivered rather than left dangling. A confirmed threat is already on the SIEM;
    this only resolves its enrichment_state so it does not sit PENDING forever."""
    for key in [k for k, e in pending.items() if e["deadline"] <= now]:
        entry = pending.pop(key)
        done = sm.finalize_timeout(entry["finding"])
        _emit_finalized(entry, done, producer, geo, ch)


def main():
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
                elif tp.topic == RESULT_TOPIC:
                    _handle_result(rec.value, producer, geo, pending, ch)
                elif tp.topic == STATUS_TOPIC:
                    _handle_status(rec.value, producer, geo, pending, ch)
        _sweep_timeouts(producer, geo, pending, time.monotonic(), ch)
        emit_lifecycle()
        producer.flush()

    emit_lifecycle()                                  # final disposition on shutdown
    consumer.close()
    producer.close()
    log.info("finding-service stopped")


if __name__ == "__main__":
    main()
