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
# How long a capture-bound finding may stay unenriched before the sweep finalizes it
# (no overlay / unavailable). Confirmed threats are already delivered; this only
# resolves their dangling enrichment_state.
ENRICH_TIMEOUT_SECS = float(os.environ.get("NDR_ENRICH_TIMEOUT_SECS", "120"))

COLS = ["finding_id", "tenant_id", "sensor_ids", "detector_id", "detector_version",
        "category", "severity", "confidence", "first_seen", "last_seen", "entities",
        "evidence_refs", "mitre", "state", "enrichment_state", "capture_job_ids",
        "suppression_reason", "devo_delivery_state"]

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
    for k in ("sensor_ids", "evidence_refs", "mitre", "capture_job_ids"):
        r[k] = r.get(k) or []
    for k in ("entities", "suppression_reason", "enrichment_state", "devo_delivery_state"):
        r[k] = r.get(k) or ""
    return [r.get(c) for c in COLS]


def _persist(ch, finding):
    if ch is not None:
        ch.insert("ndr.finding", [_row(finding)], column_names=COLS)


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


def _handle_candidate(cand, producer, geo, pending, deadline_secs, now, ch):
    """Build the finding, deliver-now if it is a confirmed threat, and request capture
    (tracking it for finalization) when packets are needed."""
    finding, route = sm.build_finding(cand)
    _persist(ch, finding)
    if route in ("final", "final_and_capture"):
        _deliver_now(finding, producer, geo)
    if route in ("capture", "final_and_capture"):
        producer.send(CAPTURE_TOPIC, sm.capture_job(finding))
        pending[finding["finding_id"]] = {
            "finding": finding,
            "delivered": route == "final_and_capture",
            "deadline": now + deadline_secs,
        }
    return finding, route


def _handle_result(result, producer, geo, pending, ch):
    """An enrichment result (ndr.enrichment.result.v1) attaches evidence and finalizes
    the pending finding. Unknown/duplicate finding_id is an idempotent no-op."""
    entry = pending.pop(result.get("finding_id"), None)
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
    entry = pending.pop(status.get("finding_id"), None)
    if entry is None:
        return
    done = sm.finalize_timeout(entry["finding"])
    _emit_finalized(entry, done, producer, geo, ch)


def _sweep_timeouts(producer, geo, pending, now, ch):
    """Finalize findings whose enrichment never completed (no overlay / unavailable):
    delivered rather than left dangling. A confirmed threat is already on the SIEM;
    this only resolves its enrichment_state so it does not sit PENDING forever."""
    for fid in [fid for fid, e in pending.items() if e["deadline"] <= now]:
        entry = pending.pop(fid)
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
    # ponytail: pending map is in-memory. Confirmed threats are already delivered
    # (deliver-now), so a restart loses only a late enrichment *update*, never a
    # finding; a capture-only finding mid-flight would need a reload from ClickHouse
    # (F14) to survive a restart — add that when adjudication durability matters.
    pending: dict = {}
    log.info("finding-service up: %s (+%s, %s) -> ClickHouse %s (geoip=%s)",
             CANDIDATE_TOPIC, RESULT_TOPIC, STATUS_TOPIC,
             CH_HOST if CH_ENABLED else "(disabled)", "+".join(sorted(geo)) or "off")

    while _running:
        batch = consumer.poll(timeout_ms=1000, max_records=200)
        now = time.monotonic()
        for tp, records in batch.items():
            for rec in records:
                if tp.topic == CANDIDATE_TOPIC:
                    finding, route = _handle_candidate(
                        rec.value, producer, geo, pending, ENRICH_TIMEOUT_SECS, now, ch)
                    log.info("%s %s (%s)",
                             "CAPTURE_REQUESTED" if route == "capture" else "FINAL",
                             finding["finding_id"], finding["category"])
                elif tp.topic == RESULT_TOPIC:
                    _handle_result(rec.value, producer, geo, pending, ch)
                elif tp.topic == STATUS_TOPIC:
                    _handle_status(rec.value, producer, geo, pending, ch)
        _sweep_timeouts(producer, geo, pending, time.monotonic(), ch)
        producer.flush()

    consumer.close()
    producer.close()
    log.info("finding-service stopped")


if __name__ == "__main__":
    main()
