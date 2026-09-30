"""file-observer (Increment 3, U1b): suricata.file.v1 fileinfo -> canonical file
observations for ndr.file_observation.

Pure transform, no I/O — app.py is the Kafka consumer + ClickHouse writer. Every
row VALIDATES against contracts/file_observation.schema.json (the observation.v1
envelope + timestamp contract). State is `hashes_only` ONLY when the sensor fully
captured the file (filematch.hash_is_complete); anything else is `metadata_only`,
fail-closed with no hash at all. bytes_available and scan_verdict are NEVER emitted
here — available bytes and rule verdicts are U4's plane, not the wire producer's.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

# Reuse (never fork) the file-threat capture-completeness rule. In the container the
# Dockerfile COPYs filematch.py beside this module; in the repo/test gate it is lifted
# by path from services/file-threat. ponytail: one import bridge, not a vendored copy.
try:
    from filematch import hash_is_complete
except ModuleNotFoundError:                          # repo layout: lift from the sibling service
    import importlib.util
    _src = Path(__file__).resolve().parents[1] / "file-threat" / "filematch.py"
    _spec = importlib.util.spec_from_file_location("filematch", _src)
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    hash_is_complete = _mod.hash_is_complete

FILE_TOPIC = "suricata.file.v1"
TABLE = "ndr.file_observation"

# hash_is_complete attests capture COMPLETENESS, not digest SYNTAX. A produced
# hashes_only row must carry a well-formed lower-hex digest, so validate shape here.
_HASH_RE = {"sha256": re.compile(r"^[a-f0-9]{64}$"),
            "sha1": re.compile(r"^[a-f0-9]{40}$"),
            "md5": re.compile(r"^[a-f0-9]{32}$")}


def _load_contract_validator():
    """Validate every produced observation against the pinned contract before it is
    handed to the writer — 06-file-observation.sql requires writers to validate. One
    validator built once: file_observation.schema.json $refs the canonical
    observation.v1, so the registry resolves that $ref. Schemas live in contracts/ in
    the repo and are COPYd beside this module in the container. ponytail: the schema's
    pattern keywords enforce timestamp/hash syntax, so no optional date-time format dep."""
    here = Path(__file__).resolve().parent
    # Adjacent (flat /app container) FIRST, then contracts/ at the repo root for the test
    # gate. Only reach for a repo-root sibling when this module actually has one: under
    # WORKDIR /app, here == /app has a single ancestor, so here.parents[1] would IndexError
    # — build the fallback lazily instead of indexing a nonexistent ancestor.
    bases = [here] + ([here.parents[1] / "contracts"] if len(here.parents) >= 2 else [])
    for base in bases:
        canonical, file_schema = base / "observation.schema.json", base / "file_observation.schema.json"
        if canonical.exists() and file_schema.exists():
            canon = json.loads(canonical.read_text())
            registry = Registry().with_resource(canon["$id"], Resource.from_contents(canon))
            return jsonschema.Draft202012Validator(
                json.loads(file_schema.read_text()), registry=registry)
    raise RuntimeError("file_observation contract schemas not found beside module or in contracts/")


_VALIDATOR = _load_contract_validator()


class QuarantineError(ValueError):
    """A record that cannot be trusted to the pinned schema is dropped, not coerced."""


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _datetime(value):
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError("timezone required")
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError) as exc:
        raise QuarantineError("invalid or missing observation timestamp") from exc


def _str(value):
    """Schema strings are minLength 1; empty/non-str collapses to null."""
    return value if isinstance(value, str) and value else None


def _u64(value):
    """Schema size is a UInt64 or null; anything else (float, bool, negative) -> null."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= 18446744073709551615 else None


def inject_identity(eve, cfg_tenant, cfg_sensor):
    """Trusted-ingress identity: config-driven tenant (never from the wire); the
    edge-stamped sensor if present, else the configured one. Mirrors normalizer."""
    sensor = eve.get("host") or eve.get("sensor_id") or cfg_sensor
    return cfg_tenant, sensor


def file_fields(eve, fi, sensor_ts, state):
    flow_id = eve.get("flow_id")
    tx_id = fi.get("tx_id", eve.get("tx_id"))
    file = {
        "state": state,
        "first_seen": sensor_ts,               # single fileinfo event -> first == last
        "last_seen": sensor_ts,
        "mime": _str(fi.get("mime_type")),
        "size": _u64(fi.get("size")),
        "filename": _str(fi.get("filename")),
        "transfer_ref": f"tx:{tx_id}" if tx_id is not None else None,
        "session_ref": f"flow:{flow_id}" if flow_id else _str(eve.get("community_id")),
        "source_obs_ref": None,                # no linked upstream observation at capture time
        "file_artifact_id": None,              # bytes-on-disk is U4's plane, never asserted here
    }
    # Hashes attach ONLY to a fully-captured file; a partial/gapped hash would be a
    # false whole-file identity, so metadata_only carries no hash at all (fail closed).
    if state == "hashes_only":
        for alg in ("sha256", "sha1", "md5"):
            digest = fi.get(alg)
            if not digest:                     # absent/empty/false -> no digest for this alg
                continue
            # A completed capture whose digest is the wrong TYPE (e.g. a JSON number) or
            # the wrong SHAPE is a corrupt record. Fail closed: reject it (never emit a bad
            # whole-file identity, never crash on a non-str .lower()), don't coerce or drop.
            if not isinstance(digest, str) or not _HASH_RE[alg].fullmatch(digest.lower()):
                raise QuarantineError(f"malformed {alg} digest on a completed capture")
            file[alg] = digest.lower()
    return file


def file_observation(eve, tenant, sensor, *, topic, partition, offset,
                     ingested_at, clock_offset_ms=None):
    """Return (table, row, observation) for a fileinfo EVE, or None if not a fileinfo.

    Coordinates (topic, partition, offset) identify one bus occurrence and derive a
    replay-stable obs_id. Timestamps follow the canonical contract: normalized =
    sensor - measured clock_offset_ms when a TRUSTED offset is supplied (never read
    from EVE), else the ingest time labelled ingest-fallback.
    """
    if not isinstance(eve, dict):
        # A decoded record that is not a JSON object (null, array, scalar) cannot be a
        # fileinfo EVE. Quarantine it (never .get() a non-dict) so the consumer commits
        # past it instead of crashing and replaying it forever. Fail closed.
        raise QuarantineError("record is not a JSON object")
    if eve.get("event_type") != "fileinfo":
        return None
    fi = eve.get("fileinfo")
    if not isinstance(fi, dict) or not fi:
        raise QuarantineError("missing fileinfo evidence")
    tenant, sensor = inject_identity(eve, tenant, sensor)
    if not tenant or not isinstance(sensor, str) or not sensor:
        raise QuarantineError("observation identity required")

    sensor_time = _datetime(eve.get("timestamp"))
    ingest_time = _datetime(ingested_at)
    if clock_offset_ms is not None:
        if isinstance(clock_offset_ms, bool) or not math.isfinite(clock_offset_ms):
            raise QuarantineError("invalid trusted clock offset")
        normalized, method = sensor_time - timedelta(milliseconds=clock_offset_ms), "clock-offset"
    else:
        normalized, method = ingest_time, "ingest-fallback"

    state = "hashes_only" if hash_is_complete(fi) else "metadata_only"
    # Serialize the PARSED sensor time into the canonical format for every canonical
    # field (ts.sensor + fields.file.first_seen/last_seen). The wire form (e.g. a
    # Suricata compact "+0000" offset) fails the schema's Z/[+-]HH:MM pattern; the
    # untouched original is still preserved verbatim in raw_record.
    sensor_ts = sensor_time.isoformat()
    raw = canonical_json(eve)
    identity = [tenant, sensor, topic, partition, offset]
    obs_id = "obs:" + hashlib.sha256(canonical_json(identity).encode()).hexdigest()
    entities = [{"type": "ip", "role": role, "value": eve[key]}
                for key, role in (("src_ip", "src"), ("dest_ip", "dst"))
                if isinstance(eve.get(key), str) and eve[key]]
    doc = {"schema": "cernity.observation.v1", "obs_id": obs_id,
           "tenant": tenant, "sensor_id": sensor,
           "ts": {"sensor": sensor_ts, "normalized": normalized.isoformat(),
                  "ingested": ingest_time.isoformat(), "method": method,
                  "clock_offset_ms": clock_offset_ms},
           "entities": entities, "type": "file",
           "fields": {"file": file_fields(eve, fi, sensor_ts, state)},
           "capabilities": [],
           "source_ref": {"kind": "clickhouse-row", "table": TABLE,
                          "tenant": tenant, "obs_id": obs_id,
                          "sha256": hashlib.sha256(raw.encode()).hexdigest(),
                          "topic": topic, "partition": partition, "offset": offset}}
    # Validate the completed observation against the pinned contract BEFORE it reaches
    # the writer (06-file-observation.sql's rule). A row that violates the envelope,
    # timestamp or file-field contract is quarantined, never inserted (fail closed).
    try:
        _VALIDATOR.validate(doc)
    except jsonschema.ValidationError as exc:
        raise QuarantineError(f"observation violates the pinned contract: {exc.message}") from exc
    row = {"observation": canonical_json(doc), "raw_record": raw}
    return TABLE, row, doc
