# benchmarks/dashboards — paired SIEM views (M3 / §10)

The **numerical source of truth is the export**, not a dashboard: `benchmarks/run.py` writes the
complete raw arm docs + the shared source EVE to `out/<scenario>/output/*.jsonl`
(`suricata-alerts.jsonl`, `cernity-findings.jsonl`, `zeek-notices.jsonl`, `source-eve.jsonl`) via
refresh + `search_after` (no 10k cap). Any precision/recall or volume claim is computed from those
files and `report.json` — a screenshot alone is insufficient (§8/§20).

This directory is the **human-facing view layer** on top of that data:

- `mappings/arm-index-template.json` — an OpenSearch index template (`arm-a-suricata*`,
  `arm-b-findings*`, `arm-c-zeek*`) so fields are typed (`src_ip`/`dest_ip` ip, `*_seen`/timestamp
  date, `detector_id`/`category`/`finding_id`/`state` keyword, `severity` int). `run.py` applies it
  best-effort before ingestion; apply manually with
  `curl -XPUT $OS/_index_template/cernity-bench-arms -H 'Content-Type: application/json' \
     --data-binary @mappings/arm-index-template.json` (strip the `_comment`).
- **Dashboards service** — brought up by the benchmark compose as `dashboards`, bound to
  `127.0.0.1:5601` (loopback, §3), pointed at the bench OpenSearch. Open it after a run.

## The three views to build/import (§10)

Create index patterns `arm-a-suricata*`, `arm-b-findings*`, `arm-c-zeek*` (time field
`@timestamp`/`timestamp`), then:

- **View A — Suricata baseline:** all-events Discover (timestamp, event_type, src/dest, proto,
  flow id); an alert-only view (`event_type:alert` — signature, SID, severity, endpoints); cards
  for stored telemetry vs actual alerts vs unique episodes vs duplicates. Add the A2 alert-only and
  A3 SIEM-rule views for the professional-SOC evaluation.
- **View B — Cernity findings:** analyst queue (finding id/revision, detector, category,
  severity/confidence, entities, first/last seen, evidence status); finding detail (detection math,
  MITRE, evidence links); cards for logical findings vs delivered revisions vs suppression vs
  delivery failures.
- **View C — side-by-side:** each preregistered scenario with A2 alerts, A3 items, B findings,
  detection outcome, duplicate count, evidence completeness, latency — native queue behaviour as
  well as logical counts; do not put Suricata severity and Cernity score on one scale without a
  documented mapping.

## Status / honesty

The export, index template, and Dashboards service are shipped and (export + template) validated
headlessly. **The saved objects (index patterns + View A/B/C) and the paired screenshots require
the running Dashboards and a browser — a human step.** Export saved objects from the running
Dashboards into `saved-objects.ndjson` here so the views become importable and reproducible; pair
each showcase screenshot with the exported JSON, the query, the source EVE excerpt, and the truth
episode (§10). Until then M3's "paired screenshots" exit item is not met headlessly; the auditable
JSON side of it is.
