# U3: detections/manifest/_generated/ is a shared, multi-owner output dir

Status: implemented, pending independent review.

Plan 025 U3 ships `services/detection-registry/scoreboard.py`, whose committed
output is `detections/manifest/_generated/detection-quality-scoreboard.json` —
the same directory `detections/manifest/generate.py` already writes its three
payloads into. The dir now has two independent generators.

`generate.py`'s drift gate was written for a sole owner: it treats any file in
`_generated/` not in its own output set as an orphan (drift). With a second
owner that whole-dir orphan rule would wrongly flag the sibling's file.

Decision: in a shared `_generated/`, each generator's `--check` polices ONLY the
files it produces, and each excludes the other's known filenames from its orphan
check so a genuine stray file is still caught while the co-tenant is not. The
exclusion is symmetric:

- `generate.py --check` keeps its orphan detection but excludes known
  sibling-owned filenames (currently the scoreboard) from the committed set.
- `scoreboard.py --check` compares its own file set byte-exact against the
  committed copy (changed, missing, or unexpected = drift). It too compares the
  committed dir's file SET — excluding `generate.py`'s payloads — so an orphan
  file nobody regenerates fails the gate. It reads the sibling's filenames from
  `generate.py`'s own `OUTPUTS` (via import) rather than hard-coding them, so the
  two exclusion lists cannot drift apart.

Both gates remain regenerate-to-temp and byte-exact (LF, sorted keys), so the
determinism and CI value is unchanged. The alternative — a shared registry of
every generator's outputs — is more machinery than two generators warrant; the
small explicit exclusion in `generate.py` is revisited if a third owner appears.
