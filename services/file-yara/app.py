"""file-yara service (plan U6, Track A1): consume ndr.file.extracted.v1,
download the carved file from MinIO, scan it with YARA, and emit a malware
finding on a content match. scan.py owns the pure logic; rules_refresh.py keeps
the ruleset current. This catches novel malware a hash blocklist cannot, which
is the one packet-only capability worth having regardless of the bake-off.
"""
import json
import logging
import os
import re
import signal
import tempfile
import threading
import time

from kafka import KafkaConsumer, KafkaProducer
import boto3

import scan as sc
import rules_refresh as rr

log = logging.getLogger("file-yara")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
ENDPOINT = os.environ.get("MINIO_ENDPOINT", "http://minio:9000")
TENANT = os.environ.get("NDR_TENANT", "default")
MAX_BYTES = int(os.environ.get("MAX_SCAN_BYTES", "67108864"))     # 64 MiB
REFRESH = float(os.environ.get("REFRESH_SECS", "21600"))          # 6h
IN_TOPIC = "ndr.file.extracted.v1"
OUT_TOPIC = "ndr.finding.candidate.v1"

_compiled = [None]      # single-element holder, swapped by the refresh thread
_running = True


def _stop(*_):
    global _running
    _running = False


def _refresh_loop():
    while _running:
        try:
            srcs = rr.ensure_rules()
            compiled = sc.compile_rules(srcs)
            if compiled is None:
                # keep the last-good ruleset rather than swapping in an empty one
                # (which would silently disable all scanning)
                log.warning("no yara rules compiled (sources=%d); keeping previous ruleset", len(srcs))
            else:
                _compiled[0] = compiled
                log.info("compiled %d yara rule file(s)", len(srcs))
        except Exception as e:
            log.error("yara compile failed: %s", e)
        for _ in range(int(REFRESH)):
            if not _running:
                return
            time.sleep(1)


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    s3 = boto3.client("s3", endpoint_url=ENDPOINT,
                      aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
                      aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"])
    threading.Thread(target=_refresh_loop, daemon=True).start()
    producer = KafkaProducer(bootstrap_servers=BOOTSTRAP,
                             value_serializer=lambda v: json.dumps(v).encode())
    consumer = KafkaConsumer(IN_TOPIC, bootstrap_servers=BOOTSTRAP, group_id="ndr-file-yara",
                             auto_offset_reset="latest", enable_auto_commit=True,
                             value_deserializer=lambda b: json.loads(b.decode()))
    log.info("file-yara up (max_scan_bytes=%d)", MAX_BYTES)
    while _running:
        for _tp, recs in consumer.poll(timeout_ms=1000, max_records=50).items():
            for rec in recs:
                ev = rec.value
                if not sc.should_scan(ev, MAX_BYTES):
                    continue
                bucket, _, key = ev.get("object_ref", "").partition("/")
                if not bucket or not key:
                    continue
                # defense-in-depth: the object key is the file's sha256; reject
                # anything else even though capture-agent already validates it.
                if not re.fullmatch(r"[0-9a-f]{64}", key):
                    log.warning("skipping non-sha object_ref %s", ev.get("object_ref"))
                    continue
                try:
                    with tempfile.NamedTemporaryFile() as tmp:
                        s3.download_fileobj(bucket, key, tmp)
                        tmp.seek(0)
                        data = tmp.read()
                except Exception as e:
                    log.error("download %s failed: %s", ev.get("object_ref"), e)
                    continue
                matched = sc.scan_bytes(_compiled[0], data)
                finding = sc.finding_from_matches(ev, matched, TENANT)
                if finding:
                    producer.send(OUT_TOPIC, finding)
                    log.info("FILE_YARA %s rules=%s", ev.get("sha256", "")[:12], matched)
        producer.flush()
    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
