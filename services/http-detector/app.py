"""HTTP-detector service (Tier-1 detection-gap fill). Consumes suricata.http.v1
and emits ndr.finding.candidate.v1 for webshell / injection / traversal /
credential-in-URL / risky-method requests. Logic covered by test_http_detect.py.

Detection is stateless per request; the only shared state is emission dedup, which
is externalized to the shared Redis (dedup_seen) with a STABLE cross-process
finding hash, so N replicas never double-emit (Python's hash() is per-process
seeded -- the old in-process _emitted + hash() finding_id double-emitted across
replicas / on rebalance). This makes http-detector horizontally scalable (plan 006).
"""
import hashlib
import json
import logging
import os
import signal
import time

import ndr_runtime                      # shared tuned consumer/producer + metrics
import store as store_mod
import http_detect as hd

log = ndr_runtime.setup_logging("http-detector")

TENANT = os.environ.get("NDR_TENANT", "default")
GROUP_ID = os.environ.get("NDR_GROUP_ID", "ndr-http-detector")
STATE_BACKEND = os.environ.get("NDR_STATE_BACKEND", "memory")
REDIS_URL = os.environ.get("NDR_REDIS_URL", "redis://ndr-redis:6379/0")
CAND = "ndr.finding.candidate.v1"

_store = store_mod.make_store(STATE_BACKEND, REDIS_URL)
_running = True


def _stop(*_):
    global _running
    _running = False


def _stable(s):
    return int(hashlib.sha1(s.encode()).hexdigest()[:15], 16)


def _handle(e, producer):
    h = e.get("http", {}) or {}
    src, dst = e.get("src_ip"), e.get("dest_ip")
    url = h.get("url") or ""
    for det, cat, sev, why in hd.http_findings(
            h.get("http_method"), url, h.get("hostname"), h.get("http_content_type")):
        bucket = int(time.time() // 600)
        dk = f"{det}:{src}:{dst}:{url}"
        if not _store.dedup_seen(f"emit:{TENANT}:{det}:{_stable(dk) % 10**12}:{bucket}", 600):
            continue                                     # already emitted (shared across replicas)
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        ent = json.dumps([{"type": "ip", "role": "src", "value": src},
                          {"type": "ip", "role": "dst", "value": dst},
                          {"type": "host", "value": h.get("hostname")},
                          {"type": "uri", "value": url[:256]},
                          {"type": "why", "value": why}])
        producer.send(CAND, {"finding_id": f"{det}-{_stable(dk) % 10**10}-{bucket}",
                             "tenant_id": TENANT, "detector_id": det, "detector_version": "1.0",
                             "category": cat, "severity": sev, "confidence": 0.7,
                             "first_seen": now, "last_seen": now, "entities": ent,
                             "state": "CANDIDATE"})
        log.info("%s sev=%s %s %s", det.upper(), sev, h.get("hostname"), url[:100])


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    producer = ndr_runtime.make_producer()
    consumer = ndr_runtime.make_consumer("suricata.http.v1", group_id=GROUP_ID, auto_offset_reset="latest")
    m = ndr_runtime.metrics
    m.start(int(os.environ.get("NDR_METRICS_PORT", "9108")))
    m.set_ready("store", False)
    m.set_ready("consumer")
    log.info("http-detector up (state=%s, webshell/sqli/cmdi/traversal/cred/method)", STATE_BACKEND)
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
