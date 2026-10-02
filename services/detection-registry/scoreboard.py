#!/usr/bin/env python3
"""Generate the PUBLISHED detection-quality scoreboard (plan 025 U3).

Joins, per DETECTION (one registry entry), three shipped sources:

  * the detection registry (detections/registry/*.json, loaded + validated through the
    U1 services/detection-registry/store.py RegistryStore) — supplies the detection's
    identity (detection_id) and source family, and the manifest_ref that points each
    entry at its backing manifest;
  * the Detection Capability Manifest the entry's manifest_ref RESOLVES to
    (detections/manifest/*.manifest.json, contracts/detection-capability.schema.json) —
    supplies the maturity STATUS (experimental|shipped|verified_e2e) and the ATT&CK
    techniques claimed, plus the manifest detector_id used to key measured quality;
  * the SHIPPED feedback-service quality computation
    (services/feedback-service/quality.py) — MEASURED precision/fp_rate, with
    numerator/denominator, for each detector that has dispositions.

The registry's detection_id deliberately differs from the manifest's detector_id (e.g.
dns-tunnel-entropy -> dns-detector): the join resolves through manifest_ref, never by
assuming the two ids are equal.

HONESTY GATE (the lead of this task): a detection's measured block is emitted ONLY where
feedback-service actually reports dispositions for its detector — the precision/fp_rate
rate-dicts are copied verbatim from that report, never computed or hand-written here. A
detection whose detector has no dispositions emits {"measured": false, "reason":
"insufficient dispositions"} — never a fabricated or frozen number. The measured source
is a committed, deterministic snapshot (published-quality.json) that this generator feeds
through feedback-service's OWN computation at generation time; the numbers are derived by
quality.report(), not written into the scoreboard.

Like detections/manifest/generate.py the output is deterministic and byte-stable (sorted
keys, LF), so `scoreboard.py --check` is a real CI drift gate: it regenerates into a temp
dir and fails on any byte or file-set difference vs the committed output (changed, missing,
or unexpected files), excluding the sibling generator's co-tenant payloads (docs/decisions/008).
"""
import argparse
import importlib.util
import json
import sqlite3
import sys
import tempfile
from pathlib import Path

import store  # U1 RegistryStore — validates entries + proves manifest_ref resolves on load

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parents[1]
REGISTRY_DIR = _ROOT / "detections" / "registry"
MANIFEST_DIR = _ROOT / "detections" / "manifest"
GENERATED_DIR = MANIFEST_DIR / "_generated"
QUALITY_SNAPSHOT = _HERE / "published-quality.json"
SCOREBOARD_NAME = "detection-quality-scoreboard.json"

# Emitted for every detection whose detector feedback-service does not report dispositions for.
INSUFFICIENT = {"measured": False, "reason": "insufficient dispositions"}


def load_registry(registry_dir, root=_ROOT):
    """Committed published registry entries, loaded through the U1 RegistryStore so each is
    schema-validated and its manifest_ref is proven to resolve to a real manifest. Returned
    sorted by detection_id (RegistryStore.list() sorts)."""
    s = store.RegistryStore(root)
    for p in sorted(registry_dir.glob("*.json")):
        s.create(json.loads(p.read_text(encoding="utf-8")))
    return s.list()


def manifests_by_ref(entries, root=_ROOT):
    """manifest_ref -> parsed manifest, for every distinct ref the entries reference. Refs are
    repo-relative paths (detections/manifest/*.manifest.json) resolved against root."""
    refs = sorted({e["manifest_ref"] for e in entries})
    return {ref: json.loads((root / ref).read_text(encoding="utf-8")) for ref in refs}


def _measured_block(detector):
    """Copy a feedback-service quality report entry's precision/fp_rate rate-dicts
    (numerator/denominator/value/confidence_interval/low_confidence) verbatim — the
    scoreboard never computes or writes a measured number itself."""
    return {"measured": True,
            "precision": detector["precision"],
            "fp_rate": detector["fp_rate"]}


def build_scoreboard(entries, manifests, quality_report):
    """One row per registry entry, joined to the manifest its manifest_ref resolves to and to
    the measured quality for that manifest's detector_id. ``manifests`` is a manifest_ref ->
    manifest dict. Status + ATT&CK come from the manifest; measured quality from the
    feedback-service report where dispositions exist for the detector, else the honest
    insufficient-dispositions block. A detector appears in the report only with >=1 counted
    disposition, so presence <=> dispositions exist."""
    measured = {d["detector_id"]: d for d in quality_report.get("detectors", [])}
    rows = []
    for e in sorted(entries, key=lambda e: e["detection_id"]):
        m = manifests[e["manifest_ref"]]
        detector_id = m["detector_id"]
        detector = measured.get(detector_id)
        rows.append({
            "detection_id": e["detection_id"],
            "source": e["source"],
            "detector_id": detector_id,
            "status": m["status"],
            "attack_techniques": sorted(m["attack_techniques"]),
            "quality": _measured_block(detector) if detector else dict(INSUFFICIENT),
        })
    return rows


def _dump_json(obj):
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render(registry_dir, quality_report, root=_ROOT):
    """{filename: text} for the whole payload set (one file here), in memory."""
    entries = load_registry(registry_dir, root)
    scoreboard = build_scoreboard(entries, manifests_by_ref(entries, root), quality_report)
    return {SCOREBOARD_NAME: _dump_json(scoreboard)}


def write(out_dir, rendered):
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, text in rendered.items():
        # write_bytes, not write_text: text mode would translate "\n" to os.linesep
        # and break byte-stability (and the drift gate). The payload is LF by
        # construction; keep it LF on disk. (Mirrors generate.py.)
        (out_dir / name).write_bytes(text.encode("utf-8"))


def _sibling_output_names():
    """The co-tenant generator's committed filenames in the shared _generated/ dir, read
    from detections/manifest/generate.py itself so the two lists cannot drift. These are
    excluded from this gate's orphan check (docs/decisions/008): each generator polices only
    the files it owns, but must still recognise the sibling's files as legitimate."""
    spec = importlib.util.spec_from_file_location(
        "scoreboard_sibling_generate", MANIFEST_DIR / "generate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return set(module.OUTPUTS)


def check(registry_dir, generated_dir, quality_report, root=_ROOT):
    """Byte-exact drift over the scoreboard's OWN committed output(s). Regenerates into a temp
    dir and compares the committed dir against it by file SET and by BYTES. A name is drift if
    it is changed (bytes differ), missing (in fresh, not committed), or UNEXPECTED (in
    committed, not fresh) — the last catches an orphan file nobody regenerates. The sibling
    generator's co-tenant payloads are excluded from the committed set so they are not flagged
    as orphans (docs/decisions/008). Bytes — not read_text — because text-mode reads normalize
    CRLF/CR to "\\n" and would hide a non-LF committed file."""
    rendered = render(registry_dir, quality_report, root)
    sibling = _sibling_output_names()
    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp)
        write(fresh, rendered)
        fresh_names = set(rendered)
        committed_names = ({p.name for p in generated_dir.iterdir()
                            if p.is_file() and p.name not in sibling}
                           if generated_dir.exists() else set())
        drift = fresh_names ^ committed_names                 # missing or unexpected
        for name in fresh_names & committed_names:            # changed (byte-exact)
            if (generated_dir / name).read_bytes() != (fresh / name).read_bytes():
                drift.add(name)
    return sorted(drift)


def _load_quality():
    spec = importlib.util.spec_from_file_location(
        "scoreboard_quality", _ROOT / "services" / "feedback-service" / "quality.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _SnapshotFindings:
    """Stand-in for feedback-service's ClickHouse finding_id -> detector_id join, backed by the
    committed snapshot's static mapping. Matches the .detectors(tenant, ids) shape quality.report
    calls (tenant is irrelevant for a single-tenant committed snapshot)."""
    def __init__(self, mapping):
        self._mapping = mapping

    def detectors(self, tenant, finding_ids):
        return {fid: self._mapping[fid] for fid in finding_ids if fid in self._mapping}


def generation_quality_report(snapshot_path=QUALITY_SNAPSHOT):
    """The measured source for the COMMITTED scoreboard, produced by running feedback-service's
    OWN computation over a committed, deterministic disposition+findings snapshot.

    A published artifact behind a drift gate must be a pure function of committed inputs, so the
    attributable feedback-service export (an explicit tenant + window + provenance, plus the
    dispositions and the finding->detector join) lives in published-quality.json. This loads it,
    materialises the feedback-service feedback table in a temp sqlite db, and calls
    quality.report() — so measured numbers, where they exist, are DERIVED by the shipped
    computation and only ever copied from this report, NEVER hand-written. No attributable
    production export is committed to this dev repo, so the snapshot's dispositions are empty and
    every detector is absent from the report and falls to the honest measured:false downstream;
    synthetic dispositions that exercise the measured path live only in test_scoreboard.py.
    """
    quality = _load_quality()
    snap = json.loads(Path(snapshot_path).read_text(encoding="utf-8"))
    start, end = quality.parse_window(snap["window"]["from"], snap["window"]["to"])
    findings = _SnapshotFindings(snap["findings"])
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "feedback.sqlite3"
        con = sqlite3.connect(db)
        # Mirror services/feedback-service/router.py's feedback table (source of truth).
        con.execute("CREATE TABLE feedback (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, "
                    "sink TEXT NOT NULL, record TEXT NOT NULL)")
        for i, record in enumerate(snap["dispositions"]):
            con.execute("INSERT INTO feedback VALUES (?, ?, ?, ?)",
                        (str(i), snap["tenant"], "published-snapshot", json.dumps(record)))
        con.commit()
        con.close()
        return quality.report(str(db), findings, snap["tenant"], start, end)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate the published detection-quality scoreboard from the registry + "
                    "manifests + feedback-service.")
    parser.add_argument("--check", action="store_true",
                        help="drift gate: fail (exit 1) if the committed scoreboard is stale")
    args = parser.parse_args(argv)

    report = generation_quality_report()
    if args.check:
        drift = check(REGISTRY_DIR, GENERATED_DIR, report)
        if drift:
            print("DRIFT: committed detection-quality-scoreboard.json is stale; re-run "
                  "services/detection-registry/scoreboard.py and commit:", file=sys.stderr)
            for name in drift:
                print(f"  - {name}", file=sys.stderr)
            return 1
        print("ok: scoreboard matches registry + manifests + feedback-service")
        return 0

    write(GENERATED_DIR, render(REGISTRY_DIR, report))
    print(f"wrote _generated/{SCOREBOARD_NAME}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
