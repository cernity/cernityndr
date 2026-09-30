"""file-yara service (plan U6, Track A1): consume ndr.file.extracted.v1,
download the carved file from MinIO, scan it with YARA, and emit a malware
finding on a content match. scan.py owns the pure logic; rules_refresh.py keeps
the ruleset current. This catches novel malware a hash blocklist cannot, which
is the one packet-only capability worth having regardless of the bake-off.
"""
import json
import os
import ndr_runtime
import re
import signal
import tempfile
import threading
import time

import fileforensics
import scan as sc
import rules_refresh as rr
import registry as reg_mod

log = ndr_runtime.setup_logging("file-yara")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
ENDPOINT = os.environ.get("MINIO_ENDPOINT", "http://minio:9000")
TENANT = os.environ.get("NDR_TENANT", "default")
MAX_BYTES = int(os.environ.get("MAX_SCAN_BYTES", "67108864"))     # 64 MiB
REFRESH = float(os.environ.get("REFRESH_SECS", "21600"))          # 6h
# Control-plane store for the ruleset lifecycle; must persist so promotions,
# staged drafts, and retirements survive a restart (a :memory: default would
# silently lose them). /var/lib/file-yara is a named volume owned by the service
# user (nobody) — see the Dockerfile chown and deploy/overlays/forensics.yml.
REGISTRY_DB = os.environ.get("YARA_REGISTRY_DB", "/var/lib/file-yara/registry.db")
IN_TOPIC = "ndr.file.extracted.v1"
OUT_TOPIC = "ndr.finding.candidate.v1"

_compiled = [None]      # single-element holder, swapped by the refresh thread
_registry = None        # RulesetRegistry, initialised in main()
_running = True


def _stop(*_):
    global _running
    _running = False


def _stage_remote():
    """Best-effort staging of REMOTE rulesets as DRAFTS for operator review. Runs on
    EVERY refresh (not only at startup) so changed upstream content becomes a fresh
    draft and an initial fetch that failed is retried on the next cycle. Idempotent
    by content sha256 (refresh_to_registry dedups), so unchanged content re-fetched
    is a no-op and nothing remote is ever auto-served — it reaches the scanner only
    via an authorized promotion. A staging failure (remote down) is logged, never
    raised: the compile below still runs off already-staged/promoted rules."""
    try:
        staged = rr.refresh_to_registry(_registry)
        if staged:
            log.info("staged %d new remote ruleset draft(s) for review", len(staged))
    except Exception as e:
        log.error("ruleset staging failed: %s; will retry next refresh", e)


def _refresh_once():
    """One refresh step, swapping the live compiled snapshot. First STAGES any new/
    changed remote rules as drafts (see _stage_remote), then compiles ONLY the
    bundled baseline + registry-promoted (active/shadow) rulesets; remote drafts
    never enter the compile path until an authorized promotion. Returns the eligible
    source count.

    An EMPTY eligible set — e.g. the last active/shadow ruleset was retired —
    CLEARS the snapshot: a retired ruleset must stop matching, not keep running off
    the previously compiled copy. A compile/ensure ERROR is raised to the caller,
    which keeps the last-good snapshot (a stale ruleset beats none)."""
    _stage_remote()
    srcs = rr.ensure_rules(_registry)
    if not srcs:
        if _compiled[0] is not None:
            log.warning("no eligible yara rules; cleared compiled ruleset (scans now match nothing)")
        _compiled[0] = None
        return 0
    _compiled[0] = sc.compile_rules(srcs)     # non-empty srcs -> never None
    log.info("compiled %d yara rule file(s)", len(srcs))
    return len(srcs)


def _refresh_loop():
    while _running:
        try:
            _refresh_once()
        except Exception as e:
            # keep the last-good ruleset rather than swapping in an empty one
            log.error("yara refresh failed: %s; keeping previous ruleset", e)
        for _ in range(int(REFRESH)):
            if not _running:
                return
            time.sleep(1)


def main():
    global _registry
    # Imported here, not at module load, so the registry/refresh logic is importable
    # (and unit-testable) without kafka/boto3 or a running broker present.
    from kafka import KafkaConsumer, KafkaProducer
    import boto3
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    os.makedirs(os.path.dirname(REGISTRY_DB) or ".", exist_ok=True)
    _registry = reg_mod.RulesetRegistry(REGISTRY_DB)
    # Remote rules are staged as DRAFTS on every refresh cycle (_stage_remote inside
    # _refresh_once), so the refresh thread below both stages and compiles — nothing
    # remote is served until an authorized promotion. The bundled in-repo baseline is
    # served directly by ensure_rules (and honors the registry lifecycle there).
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
                    finding["file_forensics"] = fileforensics.forensics(data)  # entropy + PE imphash
                    producer.send(OUT_TOPIC, finding)
                    log.info("FILE_YARA %s rules=%s", ev.get("sha256", "")[:12], matched)
        producer.flush()
    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
