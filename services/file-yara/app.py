"""Registry-backed YARA scanner for U2 accepted artifact announcements.

U2 consumes the extraction stream and emits accepted links. Consuming that link
avoids racing promotion or retrying forever on an artifact U2 rejected.
"""
import json
import os
import ndr_runtime
import hashlib
from datetime import datetime, timezone
from pathlib import Path
import signal
import time

import object_keys
import workers
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
IN_TOPIC = "ndr.file.artifact.v1"
OUT_TOPIC = "ndr.finding.candidate.v1"

_registry = None
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
    """Remote content remains draft; scans select the current registry per event."""
    _stage_remote()
    return len(_registry.active_for_scan())


def _bootstrap_baseline(registry, directory):
    # Only image-owned baseline bytes receive this service authority. Remote
    # drafts are never promoted here. Existing non-draft decisions win.
    for path in sorted(Path(directory).glob("*.yar")):
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if any(r["sha256"] == digest and r["status"] != "draft"
               for r in registry.list_rulesets()):
            continue
        rid = "bundled-" + digest
        if registry.get(rid) is None:
            registry.register_draft(path.stem, digest, data, "bundled-image", ruleset_id=rid)
        # Refuse an id collision with bytes registered by another source.
        row = registry.get(rid)
        if row["sha256"] != digest or row["source"] != "bundled-image":
            raise ValueError("bundled registry identity collision")
        if row["status"] == "draft":
            auth = reg_mod.allow_actors("file-yara-baseline")
            registry.promote(rid, "shadow", "file-yara-baseline", auth)
            registry.promote(rid, "active", "file-yara-baseline", auth)


def observation(event, result, *, tenant, topic, partition, offset, ingested_at):
    """One canonical observation per ruleset, detailed scan evidence in raw_record.

    U1's closed scan_verdict supports a single digest and rule-name list. Shadow
    hits and errors stay in the referenced source record, never in acted verdicts.
    """
    raw = json.dumps({"event": event, "yara_result": result}, sort_keys=True,
                     separators=(",", ":"), allow_nan=False)
    identity = [tenant, event["sensor_id"], topic, partition, offset,
                result.get("ruleset_id"), result.get("ruleset_sha256")]
    oid = "obs:" + hashlib.sha256(json.dumps(identity).encode()).hexdigest()
    file = {"state": "bytes_available", "first_seen": ingested_at,
            "last_seen": ingested_at, "mime": result.get("mime"),
            "size": event["size"], "filename": None, "transfer_ref": None,
            "session_ref": None, "source_obs_ref": event.get("source_obs_ref"),
            "file_artifact_id": event["sha256"], "sha256": event["sha256"]}
    if result.get("status") == "active" and not result.get("scan_error"):
        file["scan_verdict"] = {
            "engine": "yara/" + result["engine_version"],
            "ruleset_sha256": result["ruleset_sha256"],
            "matched_rules": sorted({m["rule"] for m in result["matches"]}),
            "scanned_at": result["scanned_at"]}
    doc = {"schema": "cernity.observation.v1", "obs_id": oid, "tenant": tenant,
           "sensor_id": event["sensor_id"], "type": "file", "entities": [],
           "ts": {"sensor": ingested_at, "normalized": ingested_at,
                  "ingested": ingested_at, "method": "ingest-fallback", "clock_offset_ms": None},
           "fields": {"file": file}, "capabilities": [],
           "source_ref": {"kind": "clickhouse-row", "table": "ndr.file_observation",
                          "tenant": tenant, "obs_id": oid,
                          "sha256": hashlib.sha256(raw.encode()).hexdigest(),
                          "topic": topic, "partition": partition, "offset": offset}}
    return doc, raw


def _validator():
    import jsonschema
    from referencing import Registry, Resource
    base = Path(__file__).resolve().parent
    if not (base / "observation.schema.json").exists():
        base = base.parents[1] / "contracts"
    canonical = json.loads((base / "observation.schema.json").read_text())
    return jsonschema.Draft202012Validator(
        json.loads((base / "file_observation.schema.json").read_text()),
        registry=Registry().with_resource(canonical["$id"], Resource.from_contents(canonical)))


def process_one(event, registry, s3, producer, ch, validator, *, topic, partition,
                offset, ingested_at, tenant=TENANT, limits=None):
    """Use U2's accepted bytes, tenant authorization, retention and digest checks."""
    ref = event.get("object_ref")
    digest = event.get("sha256")
    tseg = object_keys.tenant_segment(tenant)
    expected = object_keys.accepted_key(tseg, digest, workers.artifact_store.FILES_BUCKET)
    import re
    if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or ref != expected or not object_keys.valid_key(ref)):
        raise ValueError("invalid tenant-scoped accepted artifact reference")
    grants = {"internal": {"actor": "file-yara", "tenant_id": tenant, "file_read": True}}
    data = workers.artifact_store.retrieve(
        ref, "Bearer internal", grants, s3,
        lambda audit: ndr_runtime.log_event(log, "audit", **audit), max_size=MAX_BYTES)
    event = {**event, "object_ref": ref, "size": len(data)}
    results = sc.scan_bytes(registry, data, pcap_evidence_id=event.get("pcap_evidence_id"),
                            limits=limits)
    # Available bytes with no configured rules remain explicitly unscanned.
    for result in results or [{"scan_error": "no_rules", "acted": False}]:
        doc, raw = observation(event, result, tenant=tenant, topic=topic,
                               partition=partition, offset=offset, ingested_at=ingested_at)
        validator.validate(doc)
        ch.insert("ndr.file_observation", [[json.dumps(doc), raw]],
                  column_names=["observation", "raw_record"])
        producer.send("ndr.observation.normalized.v1", doc).get(timeout=30)
    finding = sc.finding_from_results(event, results, tenant)
    if finding:
        producer.send(OUT_TOPIC, finding).get(timeout=30)
    return results


def main():
    global _registry
    # Imported here, not at module load, so the registry/refresh logic is importable
    # (and unit-testable) without kafka/boto3 or a running broker present.
    import boto3
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    os.makedirs(os.path.dirname(REGISTRY_DB) or ".", exist_ok=True)
    _registry = reg_mod.RulesetRegistry(REGISTRY_DB)
    _bootstrap_baseline(_registry, Path(__file__).resolve().parent / "rules")
    _refresh_once()
    s3 = boto3.client("s3", endpoint_url=ENDPOINT,
                      aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
                      aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"])
    import clickhouse_connect
    ch = clickhouse_connect.get_client(host=os.environ.get("CLICKHOUSE_HOST", "clickhouse"),
                                       username=os.environ.get("CLICKHOUSE_USER", "ndr"),
                                       password=os.environ["CLICKHOUSE_PASSWORD"])
    validator = _validator()
    workers.artifact_store.verify_retention(s3)
    refreshed = time.monotonic()
    producer = ndr_runtime.make_producer()
    consumer = ndr_runtime.make_consumer(IN_TOPIC, group_id="ndr-file-yara",
                                         auto_offset_reset="latest", enable_auto_commit=False)
    log.info("file-yara up (max_scan_bytes=%d)", MAX_BYTES)
    while _running:
        for _tp, recs in consumer.poll(timeout_ms=1000, max_records=50).items():
            for rec in recs:
                if rec.timestamp_type != 1 or rec.timestamp is None or rec.timestamp < 0:
                    raise RuntimeError("file-yara requires LogAppendTime")
                try:
                    process_one(rec.value, _registry, s3, producer, ch, validator,
                                topic=rec.topic, partition=rec.partition, offset=rec.offset,
                                ingested_at=datetime.fromtimestamp(rec.timestamp / 1000, timezone.utc).isoformat())
                except (ValueError, PermissionError):
                    # Invalid/foreign-tenant links and expired/corrupt artifacts
                    # are permanent rejections. Infrastructure and ACK errors
                    # propagate, leaving the batch uncommitted for replay.
                    log.warning("rejected artifact link at %s[%s]@%s",
                                rec.topic, rec.partition, rec.offset)
        consumer.commit()
        if time.monotonic() - refreshed >= REFRESH:
            _refresh_once()
            refreshed = time.monotonic()
    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
