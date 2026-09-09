"""DNS-detector service (Tier-1 detection-gap fill). Consumes suricata.dns.v1 and
emits ndr.finding.candidate.v1 for DGA-looking domains and per-client NXDOMAIN
bursts. Detection logic is covered by test_dns_detect.py; this is the I/O shell.

State (per-client NXDOMAIN windows) is externalized to a WindowStore (Redis in
production, in-memory for tests), so it survives crash and consumer-group
rebalance and N replicas never double-emit: emission is gated by a shared-Redis
dedup keyed with a STABLE cross-process hash (Python's hash() is per-process
seeded, so the old in-process dedup + hash() finding_id would double-emit across
replicas). Keys are partition-tagged and enumerated via a per-partition index, so
each replica evaluates only its assigned partitions' clients (plan 005; HA parity
with behavioral-detectors).
"""
import hashlib
import json
import logging
import os
import signal
import time

import ndr_runtime                      # shared tuned consumer/producer + metrics
import store as store_mod
import dns_detect as dd

log = logging.getLogger("dns-detector")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

TENANT = os.environ.get("NDR_TENANT", "default")
DGA_THRESHOLD = float(os.environ.get("DGA_THRESHOLD", "0.72"))
NXDOMAIN_THRESHOLD = int(os.environ.get("NXDOMAIN_THRESHOLD", "20"))
WINDOW = float(os.environ.get("NXDOMAIN_WINDOW_SECS", "300"))
EVAL_EVERY = float(os.environ.get("EVAL_SECS", "30"))
GROUP_ID = os.environ.get("NDR_GROUP_ID", "ndr-dns-detector")
STATE_BACKEND = os.environ.get("NDR_STATE_BACKEND", "memory")
REDIS_URL = os.environ.get("NDR_REDIS_URL", "redis://ndr-redis:6379/0")
ENUM_INDEX = os.environ.get("NDR_ENUM_INDEX", "1") not in ("0", "false", "False", "")
CAND = "ndr.finding.candidate.v1"

_store = store_mod.make_store(STATE_BACKEND, REDIS_URL)
_running = True


def _stop(*_):
    global _running
    _running = False


def _stable(s):
    """Stable cross-process hash (SHA1) so N replicas compute the same dedup key
    and finding_id; Python's hash() is PYTHONHASHSEED-randomized per process."""
    return int(hashlib.sha1(s.encode()).hexdigest()[:15], 16)


def _index_key(prefix, part):
    return f"idx:{prefix}{part}"


def _part_of(key):
    return key.split(":", 2)[1]


def _scoped_keys(prefix, parts):
    """Client keys on this replica's assigned partitions (via the per-partition
    index), or all under prefix when parts is None (single-process/tests)."""
    if parts is None:
        return _store.keys_matching(prefix)
    if ENUM_INDEX:
        out = []
        for p in parts:
            out += _store.set_members(_index_key(prefix, p))
        return out
    return [k for k in _store.keys_matching(prefix)
            if (seg := k.split(":", 2)[1]).isdigit() and int(seg) in parts]


def _prune_index(key):
    if ENUM_INDEX:
        _store.set_remove(_index_key(key.split(":", 1)[0] + ":", _part_of(key)), key)


def _nx_add(part, client):
    key = f"nx:{part}:{TENANT}:{client}"
    if ENUM_INDEX:
        _store.window_add_indexed(key, _index_key("nx:", part), time.time(), 1, WINDOW)
    else:
        _store.window_add(key, time.time(), 1, WINDOW)


def _emit(producer, detector, category, sev, conf, entities, dedup):
    bucket = int(time.time() // 600)
    if not _store.dedup_seen(f"emit:{TENANT}:{detector}:{_stable(dedup) % 10**12}:{bucket}", 600):
        return                                       # already emitted (shared across replicas)
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    producer.send(CAND, {"finding_id": f"{detector}-{_stable(dedup) % 10**10}-{bucket}",
                         "tenant_id": TENANT, "detector_id": detector, "detector_version": "1.0",
                         "category": category, "severity": sev, "confidence": conf,
                         "first_seen": now, "last_seen": now, "entities": entities, "state": "CANDIDATE"})
    log.info("%s sev=%s %s", detector.upper(), sev, entities[:140])


def evaluate(producer, parts=None):
    cutoff = time.time() - WINDOW
    for key in _scoped_keys("nx:", parts):
        rng = _store.window_range(key, cutoff)
        if not rng:
            _prune_index(key)                        # self-clean expired client
            continue
        client = key.split(":", 3)[3]                # nx:part:tenant:client (IPv6-safe)
        if dd.nxdomain_burst(len(rng), NXDOMAIN_THRESHOLD):
            ent = json.dumps([{"type": "ip", "role": "src", "value": client},
                              {"type": "nxdomain_count", "value": len(rng)},
                              {"type": "window_secs", "value": int(WINDOW)}])
            _emit(producer, "nxdomain_burst", "c2", 6, 0.6, ent, client)


def _handle(e, producer, part):
    src = e.get("src_ip")
    qname = dd.query_name(e)
    if qname:
        hit, score, label = dd.is_dga(qname, DGA_THRESHOLD)
        if hit:
            ent = json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "domain", "value": qname},
                              {"type": "dga_label", "value": label},
                              {"type": "dga_score", "value": score}])
            _emit(producer, "dga_domain", "c2", 6, score, ent, qname)
    if dd.rcode(e) == "NXDOMAIN" and src:
        _nx_add(part, src)


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    producer = ndr_runtime.make_producer()
    consumer = ndr_runtime.make_consumer("suricata.dns.v1", group_id=GROUP_ID, auto_offset_reset="latest")
    m = ndr_runtime.metrics
    m.start(int(os.environ.get("NDR_METRICS_PORT", "9108")))
    m.set_ready("store", False)                      # /readyz waits for Redis (store-backed now)
    m.set_ready("consumer")
    log.info("dns-detector up (state=%s, dga / nxdomain-burst)", STATE_BACKEND)
    last = time.time()
    while _running:
        if not m.is_ready():                         # lazy store-readiness re-probe
            try:
                _store.dedup_seen("readyprobe", 1); m.set_ready("store")
            except Exception:
                pass
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=1000).items():
            for rec in records:
                try:
                    _handle(rec.value, producer, _tp.partition)
                except Exception as ex:
                    m.dropped("handler"); log.debug("skip record: %s", ex)
        if time.time() - last >= EVAL_EVERY:
            try:
                dp = ndr_runtime.assigned_partitions(consumer, "suricata.dns.v1")
                evaluate(producer, dp); producer.flush()
            except Exception as ex:
                m.dropped("evaluate"); log.warning("evaluate failed: %s", ex)
            last = time.time()
    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
