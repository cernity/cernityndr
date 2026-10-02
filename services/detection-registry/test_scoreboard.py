"""U3 scoreboard tests (plan 025 U3). pytest, PYTHONPATH=shared like the gate;
`import scoreboard`/`import store` resolve via pytest's rootdir dir-insertion (no
__init__.py), matching test_store.py / test_lifecycle.py.

Proof-first over a 2-detection fixture whose registry detection_id deliberately differs
from the manifest detector_id (dns-tunnel-entropy -> dns-detector): one detection's
detector HAS dispositions (so its MEASURED precision/fp are computed by the SHIPPED
feedback-service quality.report), one has NONE (so the honesty gate must emit
measured:false, never a number). The measured report is produced by actually running the
generator's own generation path — services/feedback-service/quality.py over a committed-
shaped disposition snapshot — proving the numbers are REFERENCED from feedback-service,
not hand-written in the scoreboard.
"""
import json
from pathlib import Path

import pytest

from scoreboard import (GENERATED_DIR, INSUFFICIENT, MANIFEST_DIR, QUALITY_SNAPSHOT,
                        REGISTRY_DIR, SCOREBOARD_NAME, build_scoreboard, check,
                        generation_quality_report, load_registry, manifests_by_ref,
                        render, write)

ROOT = Path(__file__).resolve().parents[2]
WINDOW = ("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")

# Two registry entries. detection_id (registry identity) != detector_id (manifest): the
# join MUST resolve through manifest_ref, never assume the two ids are equal. build_scoreboard
# reads only detection_id/source/manifest_ref off each entry.
ENTRIES = [
    {"detection_id": "dns-tunnel-entropy", "source": "dns",
     "manifest_ref": "detections/manifest/dns-detector.manifest.json"},
    {"detection_id": "beacon-watch", "source": "behavioral",
     "manifest_ref": "detections/manifest/beacon-detector.manifest.json"},
]
# manifest_ref -> manifest (only the fields build_scoreboard reads; full schema lives in
# contracts/test_detection_capability.py).
MANIFESTS = {
    "detections/manifest/dns-detector.manifest.json":
        {"detector_id": "dns-detector", "status": "shipped", "attack_techniques": ["T1071"]},
    "detections/manifest/beacon-detector.manifest.json":
        {"detector_id": "beacon-detector", "status": "experimental",
         "attack_techniques": ["T1071.001"]},
}


def _snapshot(path, dispositions, findings, tenant="a", window=WINDOW):
    path.write_text(json.dumps(
        {"tenant": tenant, "window": {"from": window[0], "to": window[1]},
         "findings": findings, "dispositions": dispositions}), encoding="utf-8")
    return path


@pytest.fixture
def report(tmp_path):
    """A real feedback-service quality.v1 report produced by the generator's OWN generation
    path (generation_quality_report over a snapshot): dns-detector has 2 TP + 1 FP
    dispositions; beacon-detector has none (absent from the report)."""
    snap = _snapshot(
        tmp_path / "snap.json",
        dispositions=[
            {"finding_id": "f1", "verdict": "true_positive", "source_ts": "2026-01-01T12:00:00Z"},
            {"finding_id": "f2", "verdict": "true_positive", "source_ts": "2026-01-01T12:00:00Z"},
            {"finding_id": "f3", "verdict": "false_positive", "source_ts": "2026-01-01T12:00:00Z"}],
        findings={"f1": "dns-detector", "f2": "dns-detector", "f3": "dns-detector"})
    return generation_quality_report(snapshot_path=snap)


def _by_id(rows):
    return {r["detection_id"]: r for r in rows}


# (1) detector with dispositions shows MEASURED precision/FP (numerator/denominator).
def test_detection_with_dispositions_shows_measured_precision_and_fp(report):
    q = _by_id(build_scoreboard(ENTRIES, MANIFESTS, report))["dns-tunnel-entropy"]["quality"]
    assert q["measured"] is True
    assert (q["precision"]["numerator"], q["precision"]["denominator"]) == (2, 3)
    assert q["precision"]["value"] == pytest.approx(2 / 3)
    assert (q["fp_rate"]["numerator"], q["fp_rate"]["denominator"]) == (1, 3)
    assert q["fp_rate"]["value"] == pytest.approx(1 / 3)


# (2) detector without dispositions: measured:false, insufficient dispositions, NEVER a
# number. Exact-equality to a number-free object proves no measured value leaked in.
def test_detection_without_dispositions_is_measured_false_never_a_number(report):
    q = _by_id(build_scoreboard(ENTRIES, MANIFESTS, report))["beacon-watch"]["quality"]
    assert q == {"measured": False, "reason": "insufficient dispositions"}
    assert q == INSUFFICIENT


# Blocking-issue #2: the row's identity is the registry detection_id, its status/ATT&CK come
# from the manifest the manifest_ref RESOLVES to, and measured quality attaches by the
# manifest detector_id — even though detection_id != detector_id.
def test_registry_and_manifest_ids_differ_and_join_resolves(report):
    row = _by_id(build_scoreboard(ENTRIES, MANIFESTS, report))["dns-tunnel-entropy"]
    assert row["detection_id"] == "dns-tunnel-entropy"
    assert row["detector_id"] == "dns-detector"          # differs from detection_id
    assert row["source"] == "dns"
    assert row["status"] == "shipped"                     # from the manifest, not the registry
    assert row["attack_techniques"] == ["T1071"]
    assert row["quality"]["measured"] is True             # measured keyed by detector_id


# (5) status distinguished — each row carries its own manifest status.
def test_status_distinguished(report):
    byid = _by_id(build_scoreboard(ENTRIES, MANIFESTS, report))
    assert byid["dns-tunnel-entropy"]["status"] == "shipped"
    assert byid["beacon-watch"]["status"] == "experimental"


# Blocking-issue #1: the actual generation path consumes real dispositions. A populated
# detector yields counts; an empty one is simply absent (-> measured:false downstream).
def test_generation_path_consumes_dispositions_populated_and_empty(tmp_path):
    snap = _snapshot(
        tmp_path / "snap.json",
        dispositions=[
            {"finding_id": "f1", "verdict": "true_positive", "source_ts": "2026-01-01T12:00:00Z"},
            {"finding_id": "f2", "verdict": "false_positive", "source_ts": "2026-01-01T12:00:00Z"}],
        findings={"f1": "dns-detector", "f2": "dns-detector"})
    rep = generation_quality_report(snapshot_path=snap)
    detectors = {d["detector_id"]: d for d in rep["detectors"]}
    assert detectors["dns-detector"]["counts"] == {"true_positive": 1, "false_positive": 1, "benign": 0}
    assert "beacon-detector" not in detectors            # empty detector never fabricated
    rows = _by_id(build_scoreboard(ENTRIES, MANIFESTS, rep))
    assert rows["dns-tunnel-entropy"]["quality"]["measured"] is True
    assert rows["beacon-watch"]["quality"] == INSUFFICIENT


# An EMPTY snapshot yields zero measured detectors — every detection falls to measured:false.
def test_generation_path_empty_snapshot_all_measured_false(tmp_path):
    snap = _snapshot(tmp_path / "snap.json", dispositions=[], findings={})
    rep = generation_quality_report(snapshot_path=snap)
    assert rep["detectors"] == []
    rows = build_scoreboard(ENTRIES, MANIFESTS, rep)
    assert all(r["quality"] == INSUFFICIENT for r in rows)


# (4) deterministic — two renders over the committed registry are byte-identical.
def test_deterministic_two_runs_byte_identical(report):
    assert render(REGISTRY_DIR, report)[SCOREBOARD_NAME] == render(REGISTRY_DIR, report)[SCOREBOARD_NAME]


# The full render over the committed registry produces one row per committed entry, resolved.
def test_render_over_committed_registry(report):
    rows = json.loads(render(REGISTRY_DIR, report)[SCOREBOARD_NAME])
    entries = load_registry(REGISTRY_DIR)
    assert [r["detection_id"] for r in rows] == sorted(e["detection_id"] for e in entries)
    mbr = manifests_by_ref(entries)
    for r in rows:                                        # every row's status came from its manifest
        assert r["status"] in {"experimental", "shipped", "verified_e2e"}
        assert r["detector_id"] in {m["detector_id"] for m in mbr.values()}


# (3) --check drift gate: clean when committed matches, fails on a stale byte.
def test_check_drift_gate_fails_on_stale_output(tmp_path, report):
    committed = tmp_path / "_generated"
    write(committed, render(REGISTRY_DIR, report))
    assert check(REGISTRY_DIR, committed, report) == []
    p = committed / SCOREBOARD_NAME
    p.write_bytes(p.read_bytes() + b" ")
    assert check(REGISTRY_DIR, committed, report) == [SCOREBOARD_NAME]


# Blocking-issue #3: an UNEXPECTED file in the committed dir fails --check, but a sibling-
# owned payload (generate.py's) is excluded and does NOT trip the gate.
def test_check_drift_gate_flags_unexpected_file_but_not_sibling(tmp_path, report):
    committed = tmp_path / "_generated"
    write(committed, render(REGISTRY_DIR, report))
    (committed / "detection-table.json").write_text("{}")   # sibling-owned: must be ignored
    assert check(REGISTRY_DIR, committed, report) == []
    (committed / "stray.json").write_text("{}")             # orphan: must be flagged
    assert check(REGISTRY_DIR, committed, report) == ["stray.json"]


# The committed published scoreboard must be in sync with the registry + manifests + the
# measured source feedback-service yields at generation time (this is `scoreboard.py --check`).
def test_committed_scoreboard_in_sync():
    assert check(REGISTRY_DIR, GENERATED_DIR, generation_quality_report()) == []


# Reviewer blocking issue: the PUBLISHED scoreboard must never carry a fabricated measured
# number. No attributable production feedback-service export is committed, so the published
# snapshot holds NO dispositions and every published row is honestly measured:false; synthetic
# dispositions live only in the fixtures above, never in the committed published artifact.
def test_published_snapshot_commits_no_fabricated_dispositions():
    snap = json.loads(QUALITY_SNAPSHOT.read_text(encoding="utf-8"))
    assert snap["dispositions"] == []
    assert snap["findings"] == {}


def test_committed_published_scoreboard_is_all_measured_false():
    rows = json.loads((GENERATED_DIR / SCOREBOARD_NAME).read_text(encoding="utf-8"))
    assert rows, "committed scoreboard must have rows"
    assert all(r["quality"] == INSUFFICIENT for r in rows)


# Reviewer blocking issue: a registry detection must resolve to its OWN backing manifest's
# detector, never an unrelated one (the yara-cobaltstrike-beacon -> protocol-detectors
# mismatch). A token-overlap heuristic would false-positive on the legitimate
# suricata-sig -> ids-alerts and ti-policy -> threat-intel mappings, so the committed
# detection_id -> detector_id join is pinned to this reviewed table: repointing a detection
# at an unrelated manifest, or committing an entry with no backing manifest, fails here.
EXPECTED_DETECTOR_BY_DETECTION = {
    "anomaly-flow-volume": "anomaly-detector",
    "behavioral-beacon": "behavioral-detectors",
    "dns-tunnel-entropy": "dns-detector",
    "suricata-sig-et-malware-c2": "ids-alerts",
    "ti-policy-blocklist-match": "threat-intel",
}


def test_committed_registry_maps_only_to_reviewed_backing_detectors():
    entries = load_registry(REGISTRY_DIR)
    rows = build_scoreboard(entries, manifests_by_ref(entries), {"detectors": []})
    assert {r["detection_id"]: r["detector_id"] for r in rows} == EXPECTED_DETECTOR_BY_DETECTION


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
