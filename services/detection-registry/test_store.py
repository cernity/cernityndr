"""U1 unit tests for the detection-registry store. In-memory, no fixtures/framework beyond
pytest. Runs under `PYTHONPATH=shared` like the gate; `import store` resolves via pytest's
rootdir insertion (this dir has no __init__.py), matching services/file-artifact/test_store.py.

Covers CRUD plus the two store invariants: manifest_ref must resolve to a real backing manifest,
and change_history is append-only with prior records immutable (test scenario 4).
"""
import copy

import pytest
from jsonschema import ValidationError

import store


def _entry(detection_id="dns-tunnel-entropy", **over):
    e = {
        "detection_id": detection_id,
        "source": "dns",
        "status": "draft",
        "version": "1.0.0",
        "manifest_ref": "detections/manifest/dns-detector.manifest.json",
        "change_history": [
            {"ts": "2026-09-01T00:00:00Z", "actor": "carter", "from": None, "to": "draft"},
        ],
    }
    e.update(over)
    return e


# ── CRUD roundtrip ──────────────────────────────────────────────────────────────

def test_create_get_list_roundtrip():
    s = store.RegistryStore()
    assert s.list() == []
    created = s.create(_entry())
    assert created == _entry()
    assert s.get("dns-tunnel-entropy") == _entry()
    assert s.get("nope") is None
    s.create(_entry("yara-cs", source="yara", manifest_ref="detections/manifest/threat-intel.manifest.json"))
    assert [e["detection_id"] for e in s.list()] == ["dns-tunnel-entropy", "yara-cs"]  # sorted


def test_delete():
    s = store.RegistryStore()
    s.create(_entry())
    assert s.delete("dns-tunnel-entropy") is True
    assert s.get("dns-tunnel-entropy") is None
    assert s.delete("dns-tunnel-entropy") is False       # idempotent, no raise


# ── create: validation ──────────────────────────────────────────────────────────

def test_create_rejects_duplicate_id():
    s = store.RegistryStore()
    s.create(_entry())
    with pytest.raises(ValueError, match="already exists"):
        s.create(_entry())


def test_create_rejects_schema_invalid():
    s = store.RegistryStore()
    with pytest.raises(ValidationError):
        s.create(_entry(source="sigma"))                 # not in the source enum
    with pytest.raises(ValidationError):
        s.create(_entry(status="promoted"))              # not in the status enum


def test_create_rejects_dangling_manifest_ref():
    s = store.RegistryStore()
    with pytest.raises(ValueError, match="manifest_ref"):
        s.create(_entry(manifest_ref="detections/manifest/does-not-exist.manifest.json"))


# ── change_history: append-only, prior entries immutable (scenario 4) ────────────

def test_update_may_append_history():
    s = store.RegistryStore()
    s.create(_entry())
    extended = _entry()
    extended["status"] = "shadow"
    extended["change_history"].append(
        {"ts": "2026-09-10T00:00:00Z", "actor": "carter", "from": "draft", "to": "shadow"})
    updated = s.update(extended)
    assert len(updated["change_history"]) == 2
    assert s.get("dns-tunnel-entropy")["status"] == "shadow"


def test_update_rejects_rewriting_a_prior_record():
    s = store.RegistryStore()
    s.create(_entry())
    tampered = _entry()
    tampered["change_history"][0]["actor"] = "mallory"    # edit an existing record
    tampered["change_history"].append(
        {"ts": "2026-09-10T00:00:00Z", "actor": "carter", "from": "draft", "to": "shadow"})
    with pytest.raises(ValueError, match="append-only"):
        s.update(tampered)


def test_update_rejects_dropping_a_prior_record():
    s = store.RegistryStore()
    seed = _entry()
    seed["change_history"].append(
        {"ts": "2026-09-10T00:00:00Z", "actor": "carter", "from": "draft", "to": "shadow"})
    seed["status"] = "shadow"
    s.create(seed)
    truncated = _entry()                                  # back to one (first) record only
    with pytest.raises(ValueError, match="append-only"):
        s.update(truncated)


def test_update_rejects_reordering_prior_records():
    s = store.RegistryStore()
    seed = _entry()
    seed["change_history"].append(
        {"ts": "2026-09-10T00:00:00Z", "actor": "carter", "from": "draft", "to": "shadow"})
    seed["status"] = "shadow"
    s.create(seed)
    reordered = copy.deepcopy(seed)
    reordered["change_history"].reverse()
    with pytest.raises(ValueError, match="append-only"):
        s.update(reordered)


def test_update_rejects_unknown_id():
    s = store.RegistryStore()
    with pytest.raises(ValueError, match="unknown detection_id"):
        s.update(_entry("never-created"))


def test_stored_entries_are_isolated_from_caller_mutation():
    # prior records stay immutable even if the caller mutates what create()/get() returned —
    # the store holds its own copies.
    s = store.RegistryStore()
    created = s.create(_entry())
    created["change_history"][0]["actor"] = "mallory"
    created["change_history"].append({"ts": "x", "actor": "y", "from": "draft", "to": "active"})
    got = s.get("dns-tunnel-entropy")
    assert got["change_history"] == [
        {"ts": "2026-09-01T00:00:00Z", "actor": "carter", "from": None, "to": "draft"}]
    got["status"] = "active"
    assert s.get("dns-tunnel-entropy")["status"] == "draft"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} detection-registry store tests passed")
