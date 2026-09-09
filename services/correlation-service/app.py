"""correlation-service (plan U9, Track B): the behavioral-analysis capstone.

Consumes final findings, keeps per-entity risk and kill-chain state over a
rolling window, and emits a single incident finding when an entity's findings
line up (correlate.py owns that logic). State is held in memory and persisted
to ClickHouse (ndr.entity_risk_state) so a restart keeps the window: the
Python-plus-ClickHouse durability decision (plan KTD1). Flink checkpointing is
the future hardening path.

Incidents are emitted as findings (detector_id=correlation_incident) to the
existing candidate topic, so finding-service, findings-sink, and soar-forwarder
deliver them unchanged (plan KTD7). Incident-typed inputs are ignored so an
incident never re-correlates into another incident.
"""
import json
import logging
import os
import signal
import time
from collections import defaultdict
from datetime import datetime

import ndr_runtime                      # shared tuned consumer/producer (plan 003 U6 rollout)
import clickhouse_connect

import correlate as corr

log = logging.getLogger("correlation-service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
CH_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse")
CH_USER = os.environ.get("CLICKHOUSE_USER", "ndr")
CH_PASS = os.environ["CLICKHOUSE_PASSWORD"]        # required, no default
TENANT = os.environ.get("NDR_TENANT", "default")
WINDOW = float(os.environ.get("WINDOW_SECS", "86400"))     # 24h rolling window
EVAL_EVERY = float(os.environ.get("EVAL_SECS", "30"))
PERSIST_EVERY = float(os.environ.get("PERSIST_SECS", "60"))
PARAMS = {
    "risk_threshold": float(os.environ.get("RISK_THRESHOLD", "12.0")),
    "min_tactics": int(os.environ.get("MIN_TACTICS", "2")),
    "half_life_secs": float(os.environ.get("HALF_LIFE_SECS", "3600")),
}
FINAL_TOPIC = "ndr.finding.final.v1"
CANDIDATE_TOPIC = "ndr.finding.candidate.v1"

_state = defaultdict(list)   # entity -> list[normalized finding dict] within window
_emitted = set()             # (entity, window-bucket, reason) dedupe
_running = True


def _stop(*_):
    global _running
    _running = False


def _src_ip(f):
    try:
        ents = f.get("entities")
        ents = json.loads(ents) if isinstance(ents, str) else (ents or [])
        for e in ents:
            if e.get("type") == "ip" and e.get("role") in ("src", "subject", "client"):
                return e.get("value")
        for e in ents:
            if e.get("type") == "ip":
                return e.get("value")
    except (ValueError, TypeError, AttributeError):
        pass
    return None


def _entity_of(f, ch):
    """Resolve a finding to an entity: prefer the asset_key from ndr.asset by
    IP, else fall back to the source IP."""
    ip = _src_ip(f)
    if not ip:
        return None
    try:
        r = ch.query(
            "SELECT asset_key FROM ndr.asset WHERE tenant_id=%(t)s AND has(ip_set, %(ip)s) LIMIT 1",
            parameters={"t": TENANT, "ip": ip})
        if r.result_rows:
            return r.result_rows[0][0]
    except Exception as e:                       # asset spine optional; fall back
        log.debug("asset lookup failed: %s", e)
    return f"ip:{ip}"


def _normalize(f, now):
    return {"finding_id": f.get("finding_id"), "detector_id": f.get("detector_id", ""),
            "category": f.get("category", ""), "severity": f.get("severity", 0),
            "mitre": f.get("mitre") or [], "ts": now}


def _prune(now):
    for ent in list(_state):
        _state[ent] = [x for x in _state[ent] if now - x["ts"] <= WINDOW]
        if not _state[ent]:
            del _state[ent]
    # drop emit-dedupe keys from windows that have rolled over, so _emitted
    # cannot grow without bound over the process lifetime.
    cur = int(now // WINDOW)
    _emitted.difference_update({k for k in _emitted if k[1] < cur})


def _persist(ch):
    # clickhouse-connect maps the DateTime64 column from a datetime, not a float
    now = datetime.utcnow()
    rows = [[TENANT, ent, json.dumps(items), now] for ent, items in _state.items()]
    if rows:
        ch.insert("ndr.entity_risk_state", rows,
                  column_names=["tenant_id", "entity", "findings_json", "updated"])


def _reload(ch):
    try:
        r = ch.query("SELECT entity, findings_json FROM ndr.entity_risk_state FINAL "
                     "WHERE tenant_id=%(t)s", parameters={"t": TENANT})
        for ent, js in r.result_rows:
            try:
                _state[ent] = json.loads(js)
            except ValueError:
                pass
        log.info("reloaded window state for %d entities", len(_state))
    except Exception as e:                       # first boot before table populated
        log.warning("state reload skipped: %s", e)


def evaluate(producer, now):
    for ent, items in list(_state.items()):
        fire, reason = corr.should_incident(items, now, PARAMS)
        if not fire:
            continue
        key = (ent, int(now // WINDOW), reason)
        if key in _emitted:
            continue
        inc = corr.build_incident(ent, items, now, tenant=TENANT, reason=reason, params=PARAMS)
        # Deterministic id per (entity, window-bucket, reason): a restart that
        # re-emits the same incident produces the same finding_id, so ClickHouse
        # (ReplacingMergeTree) and finding-service collapse it instead of
        # creating a duplicate.
        inc["finding_id"] = f"incident-{ent}-{int(now // WINDOW)}-{reason}"
        producer.send(CANDIDATE_TOPIC, inc)
        _emitted.add(key)
        log.info("INCIDENT %s reason=%s sev=%s findings=%d",
                 ent, reason, inc["severity"], len(items))


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    ch = clickhouse_connect.get_client(host=CH_HOST, username=CH_USER,
                                       password=CH_PASS, database="ndr")
    _reload(ch)
    producer = ndr_runtime.make_producer()
    consumer = ndr_runtime.make_consumer(FINAL_TOPIC, group_id="ndr-correlation-service", auto_offset_reset="earliest")
    ndr_runtime.start_health()          # /healthz /readyz /metrics (plan 003 obs)
    log.info("correlation-service up (window=%ss, thresholds=%s)", WINDOW, PARAMS)
    last_eval = last_persist = time.time()
    while _running:
        now = time.time()
        for _tp, recs in consumer.poll(timeout_ms=1000, max_records=500).items():
            for rec in recs:
                f = rec.value
                if corr.is_incident(f):          # never correlate incidents (no loop)
                    continue
                ent = _entity_of(f, ch)
                if ent:
                    _state[ent].append(_normalize(f, now))
        if now - last_eval >= EVAL_EVERY:
            _prune(now)
            evaluate(producer, now)
            producer.flush()
            last_eval = now
        if now - last_persist >= PERSIST_EVERY:
            _persist(ch)
            last_persist = now
    _persist(ch)
    consumer.close()
    producer.close()
    ch.close()


if __name__ == "__main__":
    main()
