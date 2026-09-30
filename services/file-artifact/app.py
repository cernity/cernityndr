"""file-artifact service (Increment 3, U2): I/O shell around store.py.

Consumes the EXISTING carved-file stream (ndr.file.extracted.v1), downloads the
carved bytes from MinIO, stores them under a tenant-scoped key (U2 re-key), and emits
an ndr.file.artifact.v1 linkage record so the file-observation plane can set the
bytes_available observation's file_artifact_id. Also serves authenticated + audited
retrieval (loopback, behind the TLS gateway) enforcing caller-tenant == key-tenant.

Pure storage/policy logic lives in store.py; boto3/kafka are imported here.
"""
import json
import os
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote, urlsplit

import ndr_runtime

import store

log = ndr_runtime.setup_logging("file-artifact")

ENDPOINT = os.environ.get("MINIO_ENDPOINT", "http://minio:9000")
IN_TOPIC = "ndr.file.extracted.v1"
OUT_TOPIC = "ndr.file.artifact.v1"          # bytes_available linkage for the observation plane
READ_PORT = int(os.environ.get("FILE_READER_PORT", "8094"))
# Seconds to wait for the linkage publish to be ACKed before an offset may commit. A
# stored artifact whose observation link is not durably published must NOT be committed.
PUBLISH_TIMEOUT = float(os.environ.get("FILE_ARTIFACT_PUBLISH_TIMEOUT", "30"))

_running = True


def _stop(*_):
    global _running
    _running = False


def _audit(event):
    ndr_runtime.log_event(log, "audit", timestamp=time.time(), **event)


def _linkage(record: dict) -> dict:
    """The ndr.file.artifact.v1 bytes_available linkage the observation plane applies to
    set the corresponding file observation's file_artifact_id (keyed on tenant + sha256)."""
    return {"state": "bytes_available",
            "file_artifact_id": record["artifact_id"],
            "object_ref": record["object_ref"],
            "sha256": record["sha256"],
            "tenant_segment": record["tenant_segment"],
            "sensor_id": record["sensor_id"],
            "mime": record["mime"], "size": record["size"]}


def process_one(ev, fetch, s3, producer, audit, *, publish_timeout=PUBLISH_TIMEOUT):
    """Store one carved-file event and, on a real store, publish its linkage. Returns the
    stored record (or None when there are no bytes / the event is permanently rejected).

    A PERMANENT store.PolicyError (bad archive, oversize, non-tenant-scoped key) is
    swallowed — the event can never succeed, so the caller may commit past it. Any OTHER
    exception PROPAGATES: a transient fetch/S3 error, or a linkage publish that is not
    ACKed within `publish_timeout`. The caller must then leave the offset UNCOMMITTED so
    the event replays (store is content-addressed/idempotent, so replay is safe). The
    linkage is confirmed published BEFORE the offset is eligible to commit, so a stored
    artifact never loses its bytes_available observation link."""
    try:
        record = store.store(ev, fetch, s3, audit)
    except store.PolicyError as e:                      # permanent: safe to skip and commit past
        log.warning("policy-rejected %s: %s",
                    ev.get("object_ref") if isinstance(ev, dict) else ev, e)
        return None
    if record is not None:
        producer.send(OUT_TOPIC, _linkage(record)).get(timeout=publish_timeout)  # ACK before commit
        log.info("STORED %s -> %s", (record["sha256"] or "")[:12], record["object_ref"])
    return record


def _make_handler(s3, tokens):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            ref = unquote(urlsplit(self.path).path.removeprefix("/artifact/"))
            try:
                data = store.retrieve(ref, self.headers.get("Authorization"), tokens, s3, _audit)
                code = 200
            except PermissionError:
                code, data = 403, b"file artifact access denied"
            except Exception:                       # noqa: BLE001
                code, data = 503, b"file artifact unavailable"
            self.send_response(code)
            self.send_header("Content-Type",
                             "application/octet-stream" if code == 200 else "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
    return Handler


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    import boto3                                     # lazy: keep the module import-light for tests
    s3 = boto3.client("s3", endpoint_url=ENDPOINT,
                      aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
                      aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"])
    # Fail closed at startup unless the bucket carries the configured expiry lifecycle:
    # retrieval promises a bounded window, so refuse to serve if the sweep is not real.
    store.verify_retention(s3)

    def fetch(ref):
        bucket, _, key = ref.partition("/")
        obj = s3.get_object(Bucket=bucket, Key=key)
        try:
            return obj["Body"].read(store.MAX_FILE_SIZE + 1)
        finally:
            obj["Body"].close()

    producer = ndr_runtime.make_producer()
    # Manual commits: an offset advances ONLY after its record was stored AND its linkage
    # ACK-published (or permanently rejected). enable_auto_commit=True would advance the
    # offset on a timer regardless of outcome, silently losing a transiently-failed event.
    consumer = ndr_runtime.make_consumer(IN_TOPIC, group_id="ndr-file-artifact",
                                         auto_offset_reset="latest", enable_auto_commit=False)
    if os.environ.get("FILE_READER_TOKENS"):
        tokens = json.loads(os.environ["FILE_READER_TOKENS"])
        threading.Thread(
            target=lambda: HTTPServer(("127.0.0.1", READ_PORT), _make_handler(s3, tokens)).serve_forever(),
            daemon=True).start()
    ndr_runtime.start_health()
    log.info("file-artifact up (max_file_size=%d max_archive_depth=%d)",
             store.MAX_FILE_SIZE, store.MAX_ARCHIVE_DEPTH)
    while _running:
        batch = consumer.poll(timeout_ms=1000, max_records=50)
        # Process the whole poll, then commit ONCE. process_one swallows permanent
        # rejections (committable) and RAISES on a transient failure: that propagates out
        # of the loop and crashes the service WITHOUT committing, so a restart replays from
        # the last committed offset (crash-and-replay, matching file-observer). A stored
        # record's linkage is ACK-published inside process_one before we ever reach commit.
        for _tp, recs in batch.items():
            for rec in recs:
                process_one(rec.value, fetch, s3, producer, _audit)
        consumer.commit()
    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
