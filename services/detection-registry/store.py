"""Detection-registry store (plan 025 U1). CRUD over per-detection registry entries
(contracts/detection-registry.schema.json), with two invariants the schema can't carry:

  * manifest_ref must resolve to a REAL file under detections/manifest/ — a dangling or
    escaping ref is rejected on every write (the backing Detection Capability Manifest must
    actually exist).
  * change_history is APPEND-ONLY and prior entries are IMMUTABLE — an update may only extend
    the log; it can never rewrite, reorder, or drop an existing record. This is the audit
    guarantee the registry rests on, so it is enforced structurally here, not left to callers.

Lifecycle/promotion (which status transitions are legal, auto-stamping transitions) is U2 and
deliberately NOT here: update() takes a fully-formed entry and only polices schema + the two
invariants above; it does not police the transition graph.

In-memory, single-process. Reads/writes return deep copies, so a caller mutating what it got
back cannot reach into stored state (reinforcing change_history immutability). One registry
writer is the expected shape; if HA/throughput ever demands it, swap this seam for a DB —
callers only touch RegistryStore. ponytail: in-memory dict; persist only when there's a reader
that outlives the process.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator

_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA = json.loads((_ROOT / "contracts" / "detection-registry.schema.json").read_text())
_VALIDATOR = Draft202012Validator(_SCHEMA)
_MANIFEST_DIR = (_ROOT / "detections" / "manifest").resolve()


def manifest_resolves(manifest_ref: str, root: Path = _ROOT) -> bool:
    """True iff manifest_ref points at a real file UNDER detections/manifest/ (no escaping)."""
    target = (root / manifest_ref).resolve()
    manifest_dir = (root / "detections" / "manifest").resolve()
    return target.is_file() and manifest_dir in target.parents


class RegistryStore:
    def __init__(self, root: Path = _ROOT):
        self._root = root
        self._entries: dict[str, dict] = {}        # detection_id -> stored entry

    def _validate(self, entry: dict) -> None:
        _VALIDATOR.validate(entry)                  # raises jsonschema.ValidationError
        if not manifest_resolves(entry["manifest_ref"], self._root):
            raise ValueError(f"manifest_ref does not resolve to a real file: {entry['manifest_ref']!r}")

    def create(self, entry: dict) -> dict:
        """Add a new entry. Rejects a duplicate detection_id, a schema-invalid entry, or a
        dangling manifest_ref. Returns a copy of the stored entry."""
        self._validate(entry)
        did = entry["detection_id"]
        if did in self._entries:
            raise ValueError(f"detection_id already exists: {did!r}")
        self._entries[did] = copy.deepcopy(entry)
        return copy.deepcopy(self._entries[did])

    def get(self, detection_id: str) -> dict | None:
        stored = self._entries.get(detection_id)
        return copy.deepcopy(stored) if stored is not None else None

    def list(self) -> list[dict]:
        return [copy.deepcopy(self._entries[k]) for k in sorted(self._entries)]

    def update(self, entry: dict) -> dict:
        """Replace an existing entry. The detection_id must exist, the entry must be
        schema-valid with a resolving manifest_ref, and — the core invariant — change_history
        must be APPEND-ONLY: the stored history must be an exact prefix of the incoming one, so
        no prior record can be edited, reordered, or dropped (appending zero or more new records
        is allowed). Returns a copy of the stored entry."""
        self._validate(entry)
        did = entry["detection_id"]
        prior = self._entries.get(did)
        if prior is None:
            raise ValueError(f"unknown detection_id: {did!r}")
        old_hist, new_hist = prior["change_history"], entry["change_history"]
        if new_hist[: len(old_hist)] != old_hist:
            raise ValueError("change_history is append-only: prior records are immutable")
        self._entries[did] = copy.deepcopy(entry)
        return copy.deepcopy(self._entries[did])

    def delete(self, detection_id: str) -> bool:
        """Remove an entry. Returns True if it existed, False otherwise."""
        return self._entries.pop(detection_id, None) is not None
