"""U3 generator + drift-gate tests (plan 021 U3).

Written proof-first: these fail (ImportError) until generate.py exists. They pin
the three surface payloads over a self-contained 2-detector fixture set so they
do not drift when the real manifests change, and they prove the --check drift
gate and byte-level determinism.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate  # noqa: E402


def _manifest(detector_id, status, techniques, *, version="1.0.0",
              required_capabilities=(), input_records=("ndr.flow",)):
    return {
        "detector_id": detector_id,
        "version": version,
        "status": status,
        "required_capabilities": list(required_capabilities),
        "attack_techniques": list(techniques),
        "input_records": list(input_records),
        "features_used": [],
        "config_params": [],
        "evidence_produced": {"record": "contracts/finding.schema.json", "fields": []},
        "known_limitations": [],
        "backing_tests": {"golden_pcap": [], "benign_control": [], "performance": []},
        "first_supported_version": "0.0.1",
    }


def _write_manifests(manifest_dir, manifests):
    manifest_dir.mkdir(parents=True, exist_ok=True)
    for m in manifests:
        (manifest_dir / f"{m['detector_id']}.manifest.json").write_text(
            json.dumps(m), encoding="utf-8")


@pytest.fixture
def two_detectors(tmp_path):
    """alpha (shipped, T1046+T1071) + zeta (experimental, T1071) — overlap on T1071."""
    manifest_dir = tmp_path / "manifest"
    _write_manifests(manifest_dir, [
        _manifest("alpha-detector", "shipped", ["T1071", "T1046"],
                  input_records=["ndr.flow"]),
        _manifest("zeta-detector", "experimental", ["T1071"], version="0.1.0",
                  required_capabilities=["ja4"], input_records=["ndr.dns"]),
    ])
    return manifest_dir


# Scenario 1 — expected table rows, ATT&CK cells, release-notes lines.
def test_detection_table_rows(two_detectors):
    rendered = generate.render(two_detectors)
    rows = json.loads(rendered["detection-table.json"])
    assert rows == [
        {
            "detector_id": "alpha-detector",
            "status": "shipped",
            "version": "1.0.0",
            "first_supported_version": "0.0.1",
            "attack_techniques": ["T1046", "T1071"],
            "required_capabilities": [],
            "input_records": ["ndr.flow"],
        },
        {
            "detector_id": "zeta-detector",
            "status": "experimental",
            "version": "0.1.0",
            "first_supported_version": "0.0.1",
            "attack_techniques": ["T1071"],
            "required_capabilities": ["ja4"],
            "input_records": ["ndr.dns"],
        },
    ]


def test_attack_screen_cells(two_detectors):
    rendered = generate.render(two_detectors)
    cells = json.loads(rendered["attack-screen.json"])
    assert cells == [
        {
            "technique": "T1046",
            "status": "shipped",
            "detectors": [{"detector_id": "alpha-detector", "status": "shipped"}],
        },
        {
            "technique": "T1071",
            "status": "shipped",  # roll-up: max(shipped, experimental)
            "detectors": [
                {"detector_id": "alpha-detector", "status": "shipped"},
                {"detector_id": "zeta-detector", "status": "experimental"},
            ],
        },
    ]


def test_release_notes_lines(two_detectors):
    rendered = generate.render(two_detectors)
    notes = rendered["release-notes.md"]
    assert notes == (
        "# Detection capability — generated release notes\n"
        "\n"
        "## experimental\n"
        "\n"
        "- **zeta-detector** v0.1.0 — ATT&CK: T1071\n"
        "\n"
        "## shipped\n"
        "\n"
        "- **alpha-detector** v1.0.0 — ATT&CK: T1046, T1071\n"
        "\n"
        "## verified_e2e\n"
        "\n"
        "_none_\n"
    )


# Scenario 2 — changing a manifest status changes the generated payload.
def test_status_change_changes_payload(two_detectors):
    before = generate.render(two_detectors)
    path = two_detectors / "zeta-detector.manifest.json"
    doc = json.loads(path.read_text())
    doc["status"] = "verified_e2e"
    path.write_text(json.dumps(doc), encoding="utf-8")
    after = generate.render(two_detectors)

    assert after != before
    row = next(r for r in json.loads(after["detection-table.json"])
               if r["detector_id"] == "zeta-detector")
    assert row["status"] == "verified_e2e"
    cell = next(c for c in json.loads(after["attack-screen.json"])
                if c["technique"] == "T1071")
    assert cell["status"] == "verified_e2e"  # roll-up now promoted
    assert "## verified_e2e\n\n- **zeta-detector**" in after["release-notes.md"]


# Scenario 3 — drift gate fails when committed _generated/* is stale, passes when fresh.
def test_check_drift_gate(two_detectors, tmp_path):
    generated = tmp_path / "_generated"
    generate.write(generated, generate.render(two_detectors))
    assert generate.check(two_detectors, generated) == []  # fresh → no drift

    path = two_detectors / "alpha-detector.manifest.json"
    doc = json.loads(path.read_text())
    doc["status"] = "verified_e2e"
    path.write_text(json.dumps(doc), encoding="utf-8")
    drift = generate.check(two_detectors, generated)  # committed now stale
    assert drift  # non-empty → gate fails
    assert set(drift) <= set(generate.render(two_detectors))


def test_check_missing_generated_is_drift(two_detectors, tmp_path):
    empty = tmp_path / "_generated"  # nothing written yet
    assert generate.check(two_detectors, empty) != []


# Byte-exactness: a committed file with the same logical text but CRLF line endings
# is drift. Guards against text-mode reads normalizing newlines and hiding it.
def test_check_is_byte_exact_crlf(two_detectors, tmp_path):
    generated = tmp_path / "_generated"
    generate.write(generated, generate.render(two_detectors))
    assert generate.check(two_detectors, generated) == []  # LF baseline → no drift

    notes = generated / "release-notes.md"
    notes.write_bytes(notes.read_bytes().replace(b"\n", b"\r\n"))  # LF → CRLF, same text
    assert generate.check(two_detectors, generated) == ["release-notes.md"]


# File-set: a stale/orphaned file in the committed dir (not an output) is drift.
def test_check_unexpected_file_is_drift(two_detectors, tmp_path):
    generated = tmp_path / "_generated"
    generate.write(generated, generate.render(two_detectors))
    (generated / "orphan.json").write_bytes(b"{}\n")
    assert generate.check(two_detectors, generated) == ["orphan.json"]


# CLI contract: `--check` exits 0 when fresh, 1 when stale; bare run (write) exits 0.
def test_cli_exit_codes(two_detectors, tmp_path, monkeypatch):
    generated = tmp_path / "_generated"
    monkeypatch.setattr(generate, "MANIFEST_DIR", two_detectors)
    monkeypatch.setattr(generate, "GENERATED_DIR", generated)

    assert generate.main([]) == 0                 # write mode
    assert generate.main(["--check"]) == 0        # fresh → pass

    path = two_detectors / "alpha-detector.manifest.json"
    doc = json.loads(path.read_text())
    doc["status"] = "verified_e2e"
    path.write_text(json.dumps(doc), encoding="utf-8")
    assert generate.main(["--check"]) == 1        # stale → fail


# Scenario 4 — two runs are byte-identical (determinism).
def test_determinism(two_detectors):
    assert generate.render(two_detectors) == generate.render(two_detectors)


# Determinism must not depend on manifest file read order.
def test_determinism_independent_of_insertion_order(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    ms = [
        _manifest("alpha-detector", "shipped", ["T1071"]),
        _manifest("zeta-detector", "experimental", ["T1071"]),
    ]
    _write_manifests(a, ms)
    _write_manifests(b, list(reversed(ms)))
    assert generate.render(a) == generate.render(b)


# Scenario 5 — experimental/shipped/verified_e2e are distinguishable in each payload.
def test_status_distinguishable_in_each_payload(tmp_path):
    manifest_dir = tmp_path / "manifest"
    _write_manifests(manifest_dir, [
        _manifest("exp-detector", "experimental", ["T1001"]),
        _manifest("ship-detector", "shipped", ["T1002"]),
        _manifest("e2e-detector", "verified_e2e", ["T1003"]),
    ])
    rendered = generate.render(manifest_dir)

    table = {r["detector_id"]: r["status"] for r in json.loads(rendered["detection-table.json"])}
    assert table == {
        "exp-detector": "experimental",
        "ship-detector": "shipped",
        "e2e-detector": "verified_e2e",
    }

    screen = {c["technique"]: c["status"] for c in json.loads(rendered["attack-screen.json"])}
    assert screen == {"T1001": "experimental", "T1002": "shipped", "T1003": "verified_e2e"}

    notes = rendered["release-notes.md"]
    for status in ("experimental", "shipped", "verified_e2e"):
        assert f"## {status}\n" in notes


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
