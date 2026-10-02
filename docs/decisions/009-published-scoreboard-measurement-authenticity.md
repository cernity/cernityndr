# U3: the published scoreboard publishes only attributable measurements

Status: implemented, pending independent review.

Plan 025 U3's honesty gate says a detection emits MEASURED precision/FP only
where feedback-service reports dispositions, else `{"measured": false, "reason":
"insufficient dispositions"}` — never a fabricated or frozen number, and measured
values are REFERENCED from feedback-service at generation time.

An earlier revision satisfied the *letter* of this (numbers were computed by
`quality.report()`, not hand-typed) while violating its *intent*: the input
`dispositions` in `published-quality.json` were eight invented `dns-f*` records.
Running real arithmetic over fabricated inputs still publishes a fabricated
measurement — the committed scoreboard claimed `dns-detector` precision 0.625 /
FP 0.375 with no backing findings. Measurement *authenticity* is not the same as
arithmetic *correctness*; the gate is about the former.

Decision: the committed `published-quality.json` is an ATTRIBUTABLE
feedback-service export (explicit tenant + window + `provenance`). No attributable
production disposition export exists for this dev repo, so its `dispositions` and
`findings` are EMPTY and every published detection honestly falls to
`measured:false`. Measured numbers appear in the published artifact only when a
real export with provenance is committed, and then only for the detectors it
covers. Synthetic dispositions that exercise the measured code path live ONLY in
`services/detection-registry/test_scoreboard.py` fixtures, never in the published
input. Two tests pin this: the committed snapshot carries no dispositions, and
every committed row is `measured:false`.

Related: a published registry entry must resolve to its OWN backing manifest's
detector, not an unrelated one. `yara-cobaltstrike-beacon` had no backing manifest
(no YARA detector manifest exists) and borrowed `protocol-detectors`, publishing
that detector's TLS/DoH maturity and ATT&CK under a YARA detection. It is removed
until a real YARA manifest exists; authoring one is out of U3 scope. A golden
`detection_id -> detector_id` table test guards the committed registry against
unrelated mappings. A token-overlap heuristic was rejected: it would false-positive
on the legitimate `suricata-sig -> ids-alerts` and `ti-policy -> threat-intel`
mappings. (The U1 `contracts/fixtures/detection-registry/valid_yara.json` schema
fixture still references `protocol-detectors` purely to exercise schema+resolution
for the `yara` source enum value; it is not a published claim and is left to U1.)
