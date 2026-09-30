"""file-observer (U1b) tests: the pure transform produces canonical file
observations that VALIDATE against file_observation.schema.json (envelope +
timestamp contract), derives state fail-closed via the lifted hash_is_complete,
and NEVER emits a scan verdict or available bytes (that is U4's plane).

Path-loaded (not `import`) because several services share the module name `app`,
and observe.py lifts file-threat/filematch.py by path in this repo layout.
"""
import hashlib
import importlib.util
import json
import re
from datetime import datetime
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


observe = _load("file_observer_observe", HERE / "observe.py")

CANONICAL = json.loads((ROOT / "contracts/observation.schema.json").read_text())
FILE_SCHEMA = json.loads((ROOT / "contracts/file_observation.schema.json").read_text())
REGISTRY = Registry().with_resource(CANONICAL["$id"], Resource.from_contents(CANONICAL))
FORMATS = jsonschema.FormatChecker()


@FORMATS.checks("date-time", raises=ValueError)
def _date_time(value):
    # Keep calendar validation active even without jsonschema's optional RFC3339 dep;
    # the canonical pattern enforces wire syntax (matches the U1a contract gate).
    if not isinstance(value, str):
        return True
    return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None


VALIDATORS = [jsonschema.Draft202012Validator(s, registry=REGISTRY, format_checker=FORMATS)
              for s in (FILE_SCHEMA, CANONICAL)]

STAMP = "2026-09-29T12:00:00Z"
CLOSED = dict(state="CLOSED", gaps=False, start=0, sha256="a" * 64)   # fully-captured file


def _eve(**fi):
    base = {"filename": "invoice.exe", "mime_type": "application/x-dosexec",
            "size": 4096, "tx_id": 7}
    base.update(fi)
    return {"event_type": "fileinfo", "timestamp": STAMP, "flow_id": 42,
            "src_ip": "10.0.0.5", "dest_ip": "45.9.1.2", "community_id": "1:abc",
            "fileinfo": base}


def _emit(eve, **kw):
    kw.setdefault("topic", observe.FILE_TOPIC)
    kw.setdefault("partition", 0)
    kw.setdefault("offset", 1)
    kw.setdefault("ingested_at", "2026-09-29T12:00:01Z")
    return observe.file_observation(eve, "tenant-a", "sensor-a", **kw)


def _validate(doc):
    for v in VALIDATORS:
        v.validate(doc)


# ── scenario 1: capture-completeness -> hashes_only vs metadata_only (fail closed) ──

def test_fully_captured_file_is_hashes_only_and_validates():
    _table, row, doc = _emit(_eve(**CLOSED))
    f = doc["fields"]["file"]
    assert f["state"] == "hashes_only" and f["sha256"] == "a" * 64
    _validate(doc)
    assert json.loads(row["observation"]) == doc          # the persisted row IS the validated doc


def test_incomplete_capture_is_metadata_only_fail_closed():
    for fi in ({"sha256": "a" * 64},                                   # missing state + gaps
               dict(CLOSED, gaps=True),                                # gapped
               dict(CLOSED, state="TRUNCATED"),                        # not CLOSED
               dict(CLOSED, start=5)):                                 # mid-stream capture
        _table, _row, doc = _emit(_eve(**fi))
        f = doc["fields"]["file"]
        assert f["state"] == "metadata_only"
        assert not any(k in f for k in ("sha256", "sha1", "md5"))      # no hash leaks
        _validate(doc)


def test_metadata_only_drops_partial_secondary_hashes():
    # A gapped file that still carried sha1/md5 -> fail closed, no hash at all.
    _t, _r, doc = _emit(_eve(state="CLOSED", gaps=True,
                             sha256="a" * 64, sha1="b" * 40, md5="c" * 32))
    f = doc["fields"]["file"]
    assert f["state"] == "metadata_only"
    assert not any(k in f for k in ("sha256", "sha1", "md5"))
    _validate(doc)


def test_malformed_primary_hash_on_complete_capture_is_quarantined():
    # hash_is_complete keys on sha256 PRESENCE, not syntax: a complete capture whose
    # sha256 is garbage must be rejected, not emitted as a bad whole-file identity.
    try:
        _emit(_eve(state="CLOSED", gaps=False, start=0, sha256="not-a-real-sha256"))
        raise AssertionError("expected QuarantineError for malformed sha256")
    except observe.QuarantineError:
        pass


def test_malformed_secondary_hash_on_complete_capture_is_quarantined():
    # A well-formed sha256 does not license a malformed sibling digest through.
    try:
        _emit(_eve(state="CLOSED", gaps=False, start=0, sha256="a" * 64, sha1="zz"))
        raise AssertionError("expected QuarantineError for malformed sha1")
    except observe.QuarantineError:
        pass


# ── scenario 2: canonical envelope + timestamp contract ───────────────────────

def test_source_ref_and_obs_id_are_canonical():
    _t, _r, doc = _emit(_eve(**CLOSED))
    assert doc["type"] == "file"
    assert re.fullmatch(r"obs:[a-f0-9]{64}", doc["obs_id"])
    assert doc["source_ref"]["obs_id"] == doc["obs_id"]
    assert doc["source_ref"]["tenant"] == doc["tenant"] == "tenant-a"
    assert doc["source_ref"]["table"] == "ndr.file_observation"
    assert doc["source_ref"]["sha256"] != doc["fields"]["file"].get("sha256")  # raw_record, not file bytes


def test_timestamp_contract_ingest_fallback_and_clock_offset():
    _t, _r, doc = _emit(_eve(**CLOSED))                    # no offset -> ingest-fallback
    ts = doc["ts"]
    assert ts["method"] == "ingest-fallback" and ts["clock_offset_ms"] is None
    # STAMP is Z-form; the canonical field is the parsed instant re-serialized.
    assert ts["sensor"] == "2026-09-29T12:00:00+00:00"
    f = doc["fields"]["file"]
    assert f["first_seen"] == f["last_seen"] == ts["sensor"]     # single event -> first == last
    assert ts["normalized"].startswith("2026-09-29T12:00:01")   # == ingest time
    _validate(doc)
    _t, _r, doc = _emit(_eve(**CLOSED), clock_offset_ms=1000)   # trusted offset -> clock-offset
    assert doc["ts"]["method"] == "clock-offset" and doc["ts"]["clock_offset_ms"] == 1000
    assert doc["ts"]["normalized"].startswith("2026-09-29T11:59:59")  # sensor - 1000ms
    _validate(doc)


def test_suricata_compact_offset_is_serialized_to_canonical_format():
    # Suricata EVE stamps a compact "+0000" offset (no colon), which fails the schema's
    # Z/[+-]HH:MM pattern. Every canonical timestamp field must be re-serialized; the
    # untouched wire form stays only in raw_record.
    pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
    wire = "2026-09-29T12:00:00.123456+0000"
    eve = _eve(**CLOSED)
    eve["timestamp"] = wire
    _t, row, doc = _emit(eve)
    f = doc["fields"]["file"]
    for field in (doc["ts"]["sensor"], f["first_seen"], f["last_seen"]):
        assert pattern.fullmatch(field), field
    assert wire in row["raw_record"]                            # original preserved verbatim
    _validate(doc)


# ── scenario 4: never a scan verdict / available bytes (U4 territory) ──────────

def test_never_emits_scan_verdict_or_available_bytes():
    for fi in (CLOSED, {"sha256": "a" * 64}):
        _t, _r, doc = _emit(_eve(**fi))
        f = doc["fields"]["file"]
        assert f["state"] in ("hashes_only", "metadata_only")   # never bytes_available
        assert "scan_verdict" not in f                          # verdicts are U4
        assert f["file_artifact_id"] is None                    # bytes are U4
        _validate(doc)


# ── ingress hygiene ───────────────────────────────────────────────────────────

def test_non_fileinfo_ignored_and_missing_fileinfo_quarantined():
    assert _emit({"event_type": "flow", "timestamp": STAMP}) is None
    try:
        _emit({"event_type": "fileinfo", "timestamp": STAMP})
        raise AssertionError("expected QuarantineError for missing fileinfo")
    except observe.QuarantineError:
        pass


def test_non_object_record_is_quarantined_not_crashed():
    # A decoded record that is not a JSON object (null, array, scalar) must convert to a
    # QuarantineError, never an AttributeError on .get() — the consumer skips and commits.
    for rec in (None, [1, 2, 3], "fileinfo", 7):
        try:
            _emit(rec)
            raise AssertionError(f"expected QuarantineError for non-object record {rec!r}")
        except observe.QuarantineError:
            pass


def test_non_string_digest_on_complete_capture_is_quarantined():
    # hash_is_complete keys on sha256 PRESENCE: a completed capture whose sha256 is a
    # JSON number is truthy-but-unusable -> fail closed, never .lower() a non-str.
    try:
        _emit(_eve(state="CLOSED", gaps=False, start=0, sha256=123))
        raise AssertionError("expected QuarantineError for non-string sha256")
    except observe.QuarantineError:
        pass


# ── contract loader: flat /app container layout ───────────────────────────────

def test_contract_loader_survives_single_ancestor_app_layout():
    # WORKDIR /app: __file__ == '/app/observe.py', so here == /app has ONE ancestor and
    # here.parents[1] does not exist. The loader must reach the adjacent-schema check
    # WITHOUT indexing that missing ancestor. Point __file__ at /app (no schemas there):
    # the fix yields the clean "schemas not found" RuntimeError; the old eager
    # here.parents[1] raised IndexError before any adjacent check ran.
    saved = observe.__file__
    observe.__file__ = "/app/observe.py"
    try:
        observe._load_contract_validator()
        raise AssertionError("expected RuntimeError: no schemas at /app")
    except IndexError:                        # the exact pre-fix regression
        raise AssertionError("loader indexed a nonexistent ancestor under /app")
    except RuntimeError:
        pass                                  # adjacent check ran and found nothing — correct
    finally:
        observe.__file__ = saved


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f()
            print("ok  " + _n)
    print("\nall file-observer tests passed")
