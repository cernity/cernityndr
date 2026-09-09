"""File-threat service (re-eval gap G2). Consumes suricata.file.v1, loads the
abuse.ch MalwareBazaar recent-hash feed (refreshed periodically) + EICAR + any
NDR_MALWARE_HASHES, and emits ndr.finding.candidate.v1 for known-bad file hashes
or risky executable delivery. Matching is covered by test_filematch.py."""
import json
import logging
import os
import signal
import ssl
import threading
import time
import urllib.request

import ndr_runtime                      # shared tuned consumer/producer (plan 003 U6 rollout)
import filematch

log = logging.getLogger("file-threat")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
TENANT = os.environ.get("NDR_TENANT", "default")
WINDOW = float(os.environ.get("WINDOW_SECS", "600"))
REFRESH_SECS = float(os.environ.get("REFRESH_SECS", "21600"))   # 6h
FEED = os.environ.get("MALWAREBAZAAR_FEED", "https://bazaar.abuse.ch/export/txt/sha256/recent/")
CANDIDATE_TOPIC = "ndr.finding.candidate.v1"
CTX = ssl.create_default_context()

_hashes: set = {filematch.EICAR_SHA256} | {h.strip().lower() for h in os.environ.get("NDR_MALWARE_HASHES", "").split(",") if h.strip()}
_emitted: set = set()
_running = True


def _stop(*_):
    global _running
    _running = False


def _refresh():
    while _running:
        try:
            req = urllib.request.Request(FEED, headers={"User-Agent": "ndr-file-threat"})
            with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
                new = {ln.strip().lower() for ln in r.read().decode(errors="ignore").splitlines()
                       if ln and not ln.startswith("#") and len(ln.strip()) == 64}
            if new:
                _hashes.update(new)
                log.info("malware-hash feed: %d hashes loaded (total %d)", len(new), len(_hashes))
        except Exception as e:                       # noqa: BLE001 - best-effort feed
            log.warning("feed refresh failed: %s", e)
        for _ in range(int(REFRESH_SECS)):
            if not _running:
                return
            time.sleep(1)


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    threading.Thread(target=_refresh, daemon=True).start()
    producer = ndr_runtime.make_producer()
    consumer = ndr_runtime.make_consumer("suricata.file.v1", group_id="ndr-file-threat", auto_offset_reset="latest")
    ndr_runtime.start_health()          # /healthz /readyz /metrics (plan 003 obs)
    log.info("file-threat up: malware-hash + risky-delivery on suricata.file.v1")
    while _running:
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=1000).items():
            for rec in records:
                cand = filematch.to_candidate(rec.value, _hashes, TENANT)
                if cand is None:
                    continue
                key = f"{cand['finding_id']}-{int(time.time() // WINDOW)}"
                if key in _emitted:
                    continue
                _emitted.add(key)
                producer.send(CANDIDATE_TOPIC, cand)
                log.info("FILE_THREAT %s sev=%s %s", cand["detector_id"], cand["severity"], cand["entities"][:140])
        producer.flush()
    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
