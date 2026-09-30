# Cernity NDR — SIEM content packs (B-U8)

Buildable, versioned content packs that let an analyst complete a triage in **their own** SIEM —
Splunk, Elastic, or OpenSearch — without hand-querying ClickHouse. These are **data/config
artifacts**, not a live SIEM integration: nothing here connects to a SIEM, and the gate
(`test_packs.py`) is template-parse + field-reference validation only.

Every dashboard, pivot, and drilldown keys **only** on the stable pivot fields in
[`contracts/siem_pivot.schema.json`](../../contracts/siem_pivot.schema.json), renamed to each
platform's schema by [`services/findings-forwarder/mappings.py`](../../services/findings-forwarder/mappings.py)
(`to_cim` for Splunk CIM, `to_ecs` for Elastic/OpenSearch ECS). A drilldown never keys on an
unstable field, so it is always either a working link or a documented gap
(`file_artifact_id`/`investigation_id` are null until Track A / U9 produce them).

## Packs & versions

Versions are pinned in [`MANIFEST.json`](MANIFEST.json) (one per pack) and echoed in each pack's
native descriptor:

| Pack | Version | Descriptor |
|------|---------|-----------|
| Splunk (`cernity_ndr_ta`) | 0.1.0 | `splunk/cernity_ndr_ta/default/app.conf` |
| Elastic (`cernity_ndr`)   | 0.1.0 | `elastic/manifest.yml` |
| OpenSearch (`cernity_ndr`) | 0.1.0 | `opensearch/index_templates/ndr-ecs-pivots.json` |

## Layout

- `splunk/cernity_ndr_ta/` — TA/add-on: `app.conf`, CIM `props.conf`/`transforms.conf`, `macros.conf`,
  `savedsearches.conf`, `metadata/default.meta`, and `findings_index_template.json` (kept consistent
  with the Elastic `ndr-findings` template — see below).
- `splunk/dashboards/` — Entity Timeline, Evidence, Findings. Portable view definitions: each panel
  carries its SPL, and each input/drilldown names the CIM field it keys on plus its canonical
  siem_pivot field.
- `elastic/` — integration `manifest.yml`, ECS `index_templates/ndr-ecs-pivots.json`, dashboards,
  and `detection_rules/`.
- `opensearch/` — ECS `index_templates/`, dashboards, `saved_searches/`.

The dashboards/pivots use one small portable JSON schema across all three platforms (`inputs`,
`panels[].query`, `panels[].drilldowns[]`, each drilldown carrying `canonical` + `pivot_field`), so
the field-reference contract is machine-checkable and the same triage flow renders on every
platform. `build.py` renders them to native import artifacts (see **Build** below); the packs are
deployment input, not a running integration.

### Findings index consistency

`splunk/cernity_ndr_ta/default/findings_index_template.json` declares the same core findings fields,
with compatible types, as the Elastic template
[`deploy/central/es/ndr-findings-index-template.json`](../central/es/ndr-findings-index-template.json)
(validated by `contracts/test_ndr_findings_template.py`). `test_packs.py` asserts the two stay in
step so `finding_id`, `severity`, the date fields, etc. sort/aggregate the same way in either SIEM.

## Build

The dashboards and saved searches are authored once as **portable JSON** (`inputs`,
`panels[].drilldowns[]`, each pivot carrying `canonical` + `pivot_field` + `bind`) — the
machine-checkable field-reference contract, identical in shape across all three platforms.
`build.py` renders that source into each platform's native import format (ADR
[004](../../docs/decisions/004-siem-packs-portable-source-native-build.md)):

```sh
PYTHONPATH=shared .venv/bin/python -m deploy.siem.build     # writes deploy/siem/dist/
# equivalently: .venv/bin/python deploy/siem/build.py --out deploy/siem/dist
```

The render is pure and offline (no live SIEM, no network). `dist/` is a build output — regenerated
by `build.py`, validated by `test_packs.py`, git-ignored, never hand-edited. It contains:

- `dist/splunk/dashboards/*.xml` — Simple XML `<form>` dashboards. In-SIEM drilldowns URL-encode the
  clicked value with the native `|u` token modifier; the two evidence drilldowns open the in-search
  `pcap_href`/`file_href` the macros compute with `isnull` guards.
- `dist/splunk/cernity_ndr_ta/` — the TA, copied verbatim (conf, metadata, lookups, findings template).
- `dist/{elastic,opensearch}/saved_objects/*.ndjson` — Kibana / OpenSearch Dashboards saved objects
  (a Discover `search` per view + URL drilldowns). External evidence links target `MANIFEST.json`
  `evidence.base_url` with the id URL-encoded via the `encodeURIComponent` handlebars helper; a null
  id yields no navigable link.
- `dist/{elastic,opensearch}/index_templates/` — the ECS index templates, copied.
- `dist/elastic/detection_rules/beaconing_by_entity.json` — the native Kibana Security threshold rule.
- `dist/elastic/cernity_ndr/` — the same Elastic assets in a Fleet integration package layout
  (`manifest.yml`, `changelog.yml`, `docs/`, `kibana/`, `elasticsearch/`).

The two drilldowns that leave the SIEM (pcap, extracted file) point at the deployer's evidence
gateway. `MANIFEST.json` `evidence.base_url` / `external_destinations` describe the target and are
the single source of truth: `build.py` renders it into the Elastic/OpenSearch URL drilldowns **and**
into the Splunk `cernity_evidence_base` macro (`splunk/cernity_ndr_ta/default/macros.conf`), so one
manifest edit retargets all three platforms.

## Install

Build first (above), then load each rendered artifact through its platform's normal mechanism:

- **Splunk** — install `dist/splunk/cernity_ndr_ta/` as an app and import `dist/splunk/dashboards/*.xml`
  as Simple XML dashboards. Retarget the evidence gateway by setting `MANIFEST.json` `evidence.base_url`
  before building — `build.py` renders it into the `cernity_evidence_base` macro (editing the source
  macro directly is overwritten on the next build).
- **Elastic** — `PUT` `dist/elastic/index_templates/ndr-ecs-pivots.json`, import
  `dist/elastic/saved_objects/*.ndjson` as saved objects, and import the detection rule — or install
  `dist/elastic/cernity_ndr/` as a Fleet integration package.
- **OpenSearch** — `PUT` `dist/opensearch/index_templates/ndr-ecs-pivots.json` and import
  `dist/opensearch/saved_objects/*.ndjson`.

No credentials or endpoints are baked in; supply them at install time.

## §26 — source note

These packs are **independently authored** from the public Splunk Common Information Model, Elastic
Common Schema, and OpenSearch documentation. The public capability they take inspiration from
(cross-SIEM triage content for an NDR) is common to the category; the **implementation here is
Cernity's own**. No Corelight TAs, dashboards, saved searches, wording, trademarked feature
names, or other vendor assets are used or copied. The CIM/ECS field homes are chosen from the open
standards; pivots with no standard home use the sanctioned `vendor_*` (CIM) / `cernity.*` (ECS)
extension namespaces.
