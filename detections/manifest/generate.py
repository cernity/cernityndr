#!/usr/bin/env python3
"""Generate the three detection surface payloads from per-detector manifests (plan 021 U3).

Pure and deterministic: no network, no clock, stable ordering. Reads every
``detections/manifest/*.manifest.json`` and writes, into ``_generated/``:

  * ``detection-table.json`` — one row per detector for the website table
  * ``attack-screen.json``   — one cell per ATT&CK technique for the Vantage screen
  * ``release-notes.md``     — a markdown fragment grouped by maturity status

Each payload carries the experimental|shipped|verified_e2e status so the three are
distinguishable. Output is byte-stable (sorted keys, fixed ordering) so ``--check``
is a meaningful CI drift gate: it regenerates into a temp dir and fails on any
byte or file-set difference vs the committed ``_generated/*`` (changed, missing, or
unexpected files). These vendored outputs feed U4/U5.
"""
import argparse
import json
import sys
import tempfile
from pathlib import Path

MANIFEST_DIR = Path(__file__).resolve().parent
GENERATED_DIR = MANIFEST_DIR / "_generated"

# Maturity ladder, low → high. Fixes release-notes section order and the
# attack-screen roll-up (a technique's cell takes the most-mature covering detector).
STATUS_ORDER = ("experimental", "shipped", "verified_e2e")


def load_manifests(manifest_dir):
    """All manifests in the dir, sorted by detector_id for a stable order."""
    manifests = [json.loads(p.read_text(encoding="utf-8"))
                 for p in sorted(manifest_dir.glob("*.manifest.json"))]
    manifests.sort(key=lambda m: m["detector_id"])
    return manifests


def build_detection_table(manifests):
    return [
        {
            "detector_id": m["detector_id"],
            "status": m["status"],
            "version": m["version"],
            "first_supported_version": m["first_supported_version"],
            "attack_techniques": sorted(m["attack_techniques"]),
            "required_capabilities": sorted(m["required_capabilities"]),
            "input_records": sorted(m["input_records"]),
        }
        for m in manifests
    ]


def build_attack_screen(manifests):
    """One cell per technique → covering detectors + roll-up status (most mature)."""
    by_technique = {}
    for m in manifests:
        for technique in m["attack_techniques"]:
            by_technique.setdefault(technique, []).append(
                {"detector_id": m["detector_id"], "status": m["status"]})
    cells = []
    for technique in sorted(by_technique):
        detectors = sorted(by_technique[technique], key=lambda d: d["detector_id"])
        rollup = max((d["status"] for d in detectors), key=STATUS_ORDER.index)
        cells.append({"technique": technique, "status": rollup, "detectors": detectors})
    return cells


def build_release_notes(manifests):
    lines = ["# Detection capability — generated release notes", ""]
    for status in STATUS_ORDER:
        lines += [f"## {status}", ""]
        group = [m for m in manifests if m["status"] == status]
        if not group:
            lines += ["_none_", ""]
            continue
        for m in group:  # already detector_id-sorted by load_manifests
            techniques = ", ".join(sorted(m["attack_techniques"])) or "—"
            lines.append(f"- **{m['detector_id']}** v{m['version']} — ATT&CK: {techniques}")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def _dump_json(obj):
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


# name → (manifests → file text). Single source of truth for the output set.
OUTPUTS = {
    "detection-table.json": lambda ms: _dump_json(build_detection_table(ms)),
    "attack-screen.json": lambda ms: _dump_json(build_attack_screen(ms)),
    "release-notes.md": build_release_notes,
}


def render(manifest_dir):
    """{filename: text} for every output — the whole payload set, in memory."""
    manifests = load_manifests(manifest_dir)
    return {name: build(manifests) for name, build in OUTPUTS.items()}


def write(out_dir, rendered):
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, text in rendered.items():
        # write_bytes, not write_text: text mode translates "\n" to os.linesep,
        # which would make output non-byte-stable across platforms and defeat the
        # drift gate. The payloads are LF by construction; keep them LF on disk.
        (out_dir / name).write_bytes(text.encode("utf-8"))


def check(manifest_dir, generated_dir):
    """Byte-exact drift: filenames that differ between a fresh render and the committed dir.

    Regenerates into a temp dir (per the spec) and compares the committed
    ``_generated/`` against it by file SET and by BYTES. A name is drift if it is
    changed (bytes differ), missing (in fresh, not committed), or unexpected (in
    committed, not fresh). Bytes — not ``read_text`` — because text-mode reads
    normalize CRLF/CR to "\\n" and would hide a non-LF committed file.
    """
    rendered = render(manifest_dir)
    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp)
        write(fresh, rendered)
        fresh_names = {p.name for p in fresh.iterdir()}
        # _generated/ is shared: services/detection-registry/scoreboard.py writes its
        # own file here too and polices it separately (docs/decisions/008). Ignore
        # sibling-owned outputs so this gate flags only genuine orphans among OUR set.
        foreign = {"detection-quality-scoreboard.json"}
        committed_names = ({p.name for p in generated_dir.iterdir() if p.name not in foreign}
                           if generated_dir.exists() else set())
        drift = set(fresh_names) ^ set(committed_names)  # missing or unexpected
        for name in fresh_names & committed_names:        # changed (byte-exact)
            if (fresh / name).read_bytes() != (generated_dir / name).read_bytes():
                drift.add(name)
    return sorted(drift)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate detection surface payloads from manifests.")
    parser.add_argument("--check", action="store_true",
                        help="drift gate: fail (exit 1) if committed _generated/* is stale vs manifests")
    args = parser.parse_args(argv)

    if args.check:
        drift = check(MANIFEST_DIR, GENERATED_DIR)
        if drift:
            print("DRIFT: committed _generated/ is stale vs manifests; re-run "
                  "detections/manifest/generate.py and commit:", file=sys.stderr)
            for name in drift:
                print(f"  - {name}", file=sys.stderr)
            return 1
        print("ok: _generated/ matches manifests")
        return 0

    write(GENERATED_DIR, render(MANIFEST_DIR))
    for name in OUTPUTS:
        print(f"wrote _generated/{name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
