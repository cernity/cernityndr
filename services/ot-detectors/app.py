"""OT/ICS detectors service (Modbus v1). Consumes suricata.modbus.v1 and emits
ndr.finding.candidate.v1 with ATT&CK-for-ICS tags. Pure scoring lives in ot.py
(covered by test_ot.py); this file is the stateful I/O shell (covered by
test_ot_state.py).

State is externalized to the shared Redis so the service scales horizontally with no
double-emit (mirrors protocol-detectors/east-west): the per-outstation authorized-
masters set is learned during a warmup window (like rare_ja4) and shared fleet-wide
so a master is "known" only if the WHOLE fleet has seen it; enumeration uses TTL'd
distinct-value sets per source; error bursts are TTL'd counters; emission dedup is
shared-Redis with a STABLE cross-process finding hash. OT_AUTHORIZED_MASTERS pins/
overrides the learned baseline (R4: a poisoned baseline must be correctable by config).

Findings use category `ics_control`; the master is entity role `src`, the outstation
role `dst`. Lifecycle, dedup, severity gating and forwarding are reused unchanged.
"""
import hashlib
import json
import os
import signal
import time

import ndr_runtime                      # shared tuned consumer/producer + metrics
import store as store_mod
import ot

log = ndr_runtime.setup_logging("ot-detectors")

TENANT = os.environ.get("NDR_TENANT", "default")
# Config pin/override: masters authorized on EVERY outstation regardless of the learned
# baseline (mirrors APPROVED_RESOLVERS). Correct a poisoned warmup by listing the real EWS/HMI here.
AUTHORIZED_MASTERS = set(x for x in os.environ.get("OT_AUTHORIZED_MASTERS", "").split(",") if x)
ALLOW_PORTS = set(int(x) for x in os.environ.get("OT_ALLOW_PORTS", "").split(",") if x.strip().isdigit())
GROUP_ID = os.environ.get("NDR_GROUP_ID", "ndr-ot-detectors")
STATE_BACKEND = os.environ.get("NDR_STATE_BACKEND", "memory")
REDIS_URL = os.environ.get("NDR_REDIS_URL", "redis://ndr-redis:6379/0")
MASTER_WARMUP = int(os.environ.get("OT_MASTER_WARMUP", "5"))     # masters to learn before novelty fires
MASTER_TTL = float(os.environ.get("OT_MASTER_TTL", "604800"))   # baseline retention (7 days)
WINDOW = float(os.environ.get("OT_WINDOW_SECS", "600"))         # enumeration / error window
FC_ENUM_MIN = int(os.environ.get("OT_FC_ENUM_MIN", "6"))
UNIT_ENUM_MIN = int(os.environ.get("OT_UNIT_ENUM_MIN", "4"))
ERROR_SPIKE_MIN = int(os.environ.get("OT_ERROR_SPIKE_MIN", "5"))
CAND = "ndr.finding.candidate.v1"

_store = store_mod.make_store(STATE_BACKEND, REDIS_URL)
_running = True


def _stop(*_):
    global _running
    _running = False


def _stable(s):
    return int(hashlib.sha1(s.encode()).hexdigest()[:15], 16)


def _emit(producer, detector, sev, conf, entities, mitre=None):
    """Emit one ics_control candidate, shared-Redis deduped per hour bucket so N replicas
    never double-emit (STABLE hash — Python hash() is per-process seeded)."""
    bucket = int(time.time() // 3600)
    if not _store.dedup_seen(f"emit:{TENANT}:{detector}:{_stable(entities) % 10**12}:{bucket}", 3600):
        return
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    cand = {"finding_id": f"{detector}-{_stable(entities) % 10**10}-{bucket}",
            "tenant_id": TENANT, "detector_id": detector, "detector_version": "1.0",
            "category": "ics_control", "severity": sev, "confidence": conf,
            "first_seen": now, "last_seen": now, "entities": entities, "state": "CANDIDATE"}
    if mitre:
        cand["mitre"] = mitre                                   # precise ICS technique; finding-service prefers it
    producer.send(CAND, cand)
    log.info("%s %s", detector.upper(), entities[:120])


def _known_master(src, dst):
    """Is `src` an authorized master for outstation `dst`? True if config-pinned, or the
    per-outstation baseline is not yet warmed (can't judge authorization before a baseline
    exists — suppress firing, exactly like rare_ja4's pre-warmup no-fire), or the learned set
    already contains it. Learns `src` on every observation (check-then-add) so the warmup
    captures the normal fleet; a poisoned baseline is corrected via OT_AUTHORIZED_MASTERS.
    Fleet-wide shared set so a master is "new" only if the WHOLE fleet has not seen it."""
    if src in AUTHORIZED_MASTERS:
        return True
    key = f"otmaster:{TENANT}:{dst}"
    warmed = _store.set_len(key) >= MASTER_WARMUP
    known = _store.set_contains(key, src)
    _store.set_add(key, src, MASTER_TTL)
    return (not warmed) or known


def _ent(src, dst, extra):
    return json.dumps([{"type": "ip", "role": "src", "value": src},
                       {"type": "ip", "role": "dst", "value": dst}] + extra)


def _handle(e, producer):
    modbus = e.get("modbus")
    src, dst, dport = e.get("src_ip"), e.get("dest_ip"), e.get("dest_port")
    # A record is Modbus if it says so or carries a modbus object; otherwise ignore (the
    # consumer subscribes suricata.modbus.v1, but stay defensive for mixed/raw fallback).
    if e.get("event_type") != "modbus" and modbus is None:
        return
    if not src or not dst:
        return

    # R3.5 — Modbus on an unexpected port (T0885). Independent of the modbus payload fields.
    pa, pa_why = ot.modbus_port_anomaly(dport, ALLOW_PORTS)
    if pa:
        _emit(producer, "modbus_port_anomaly", 6, 0.6, _ent(src, dst, [{"type": "why", "value": pa_why}]),
              mitre=["T0885"])

    f = ot.mb_fields(modbus)
    fc, access = f["fc"], f["access"]
    authorized = _known_master(src, dst)

    # R3.2 — new master->outstation pairing (novelty), any operation. Reuse rare-dest logic:
    # warmed up + this src never seen for this outstation. T0842 / T0859.
    if not authorized:
        _emit(producer, "new_master_pairing", 5, 0.5,
              _ent(src, dst, [{"type": "why", "value": "master never seen for this outstation"}]),
              mitre=["T0842", "T0859"])

    # R3.1 — unauthorized write/control from a non-authorized master. T0855 / T0831.
    uw, uw_why = ot.unauthorized_write(fc, access, authorized)
    if uw:
        _emit(producer, "unauthorized_write", 8, 0.7, _ent(src, dst, [{"type": "why", "value": uw_why},
              {"type": "modbus_fc", "value": fc}]), mitre=["T0855", "T0831"])

    # R3.6 — program-download / operating-mode change from a non-EWS source. T0858 / T0843.
    pd, pd_why = ot.program_download(fc, authorized)
    if pd:
        _emit(producer, "program_download", 9, 0.8, _ent(src, dst, [{"type": "why", "value": pd_why},
              {"type": "modbus_fc", "value": fc}]), mitre=["T0858", "T0843"])

    # R3.3 — function-code / unit-id enumeration (recon), per source over a window. T0846.
    if fc is not None:
        _store.set_add(f"otfc:{TENANT}:{src}", str(fc), WINDOW)
    if f["unit_id"] is not None:
        _store.set_add(f"otunit:{TENANT}:{src}", str(f["unit_id"]), WINDOW)
    en, en_why = ot.enumeration_hit(_store.set_len(f"otfc:{TENANT}:{src}"),
                                    _store.set_len(f"otunit:{TENANT}:{src}"), FC_ENUM_MIN, UNIT_ENUM_MIN)
    if en:
        _emit(producer, "fc_enumeration", 6, 0.6, _ent(src, dst, [{"type": "why", "value": en_why}]),
              mitre=["T0846"])

    # R3.4 — illegal-function / error-flag burst from a source over a window (probing/misconfig).
    if f["is_error"]:
        n = _store.counter_add(f"oterr:{TENANT}:{src}", "c", 1, WINDOW)
        es, es_why = ot.error_spike_hit(int(n), ERROR_SPIKE_MIN)
        if es:
            _emit(producer, "error_flag_spike", 5, 0.5, _ent(src, dst, [{"type": "why", "value": es_why}]))


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    producer = ndr_runtime.make_producer()
    consumer = ndr_runtime.make_consumer("suricata.modbus.v1", group_id=GROUP_ID, auto_offset_reset="latest")
    m = ndr_runtime.metrics
    m.start(int(os.environ.get("NDR_METRICS_PORT", "9108")))
    m.set_ready("store", False)
    m.set_ready("consumer")
    log.info("ot-detectors up (state=%s, modbus: unauthorized-write/novelty/enumeration/error-spike/port/program)", STATE_BACKEND)
    while _running:
        if not m.is_ready():
            try:
                _store.dedup_seen("readyprobe", 1); m.set_ready("store")
            except Exception:
                pass
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=1000).items():
            for rec in records:
                try:
                    _handle(rec.value, producer)
                except Exception as ex:
                    m.dropped("handler"); log.debug("skip record: %s", ex)
        producer.flush()
    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
