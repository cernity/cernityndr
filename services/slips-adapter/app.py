"""SLIPS -> Cernity adapter. Tails SLIPS' alerts.json (IDEA0) and maps each
per-host alert to a candidate (slips_map.alert_to_candidate), producing it to
ndr.finding.candidate.v1 -- the same topic every heuristic detector emits to, so
a SLIPS verdict flows through the normal finding lifecycle (dedup, severity gate,
MITRE, forwarding) with no special path.

SLIPS runs as its own upstream container; this adapter only reads its output file
and speaks Kafka. Nothing here runs on the sensor. The exact alerts.json framing
(json-lines vs a growing array) is tolerated by _parse and validated at
integration time.
"""
import json
import os
import signal
import time

import ndr_runtime
import slips_map

log = ndr_runtime.setup_logging("slips-adapter")

TENANT = os.environ.get("NDR_TENANT", "default")
ALERTS_FILE = os.environ.get("SLIPS_ALERTS_FILE", "/slips-output/alerts.json")
POLL_SECS = float(os.environ.get("SLIPS_POLL_SECS", "2"))
CAND = "ndr.finding.candidate.v1"

_running = True


def _stop(*_):
    global _running
    _running = False


def _parse(line):
    """One IDEA0 alert per line; tolerate array brackets and trailing commas."""
    s = line.strip().rstrip(",")
    if not s or s in ("[", "]"):
        return None
    try:
        return json.loads(s)
    except ValueError:
        return None


def follow(path):
    """Yield lines appended to path, tolerating it not existing yet and being
    rotated/truncated (reopen when it shrinks)."""
    while _running:
        try:
            f = open(path, "r")
        except FileNotFoundError:
            time.sleep(POLL_SECS)
            continue
        f.seek(0, os.SEEK_END)
        while _running:
            pos = f.tell()
            line = f.readline()
            if line:
                yield line
                continue
            try:
                if os.path.getsize(path) < pos:
                    break                      # rotated -> reopen
            except OSError:
                break
            time.sleep(POLL_SECS)
        f.close()


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    producer = ndr_runtime.make_producer()
    m = ndr_runtime.metrics
    m.start(int(os.environ.get("NDR_METRICS_PORT", "9108")))
    m.set_ready("consumer")
    log.info("slips-adapter up (alerts=%s)", ALERTS_FILE)
    n = 0
    for line in follow(ALERTS_FILE):
        alert = _parse(line)
        if not alert:
            continue
        try:
            c = slips_map.alert_to_candidate(alert, TENANT)
        except Exception as ex:
            m.dropped("map")
            log.debug("map skip: %s", ex)
            continue
        if c:
            producer.send(CAND, c)
            n += 1
            if n % 20 == 0:
                producer.flush()
            log.info("SLIPS %s sev=%s -> candidate %s", c["category"], c["severity"], c["finding_id"])
    producer.flush()
    producer.close()


if __name__ == "__main__":
    main()
