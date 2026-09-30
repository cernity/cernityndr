"""B-U8: deterministic native renderer for the SIEM content packs (ADR 004).

The portable defs under `deploy/siem/<platform>/…` are the single source of truth (one edit
covers all three platforms and stays machine-checkable against contracts/siem_pivot.schema.json).
This module renders them into platform-native artifacts under `deploy/siem/dist/`:

  * Splunk dashboards  -> Simple XML `<form>` (drilldowns use the native `|u` URL-encode token
    modifier; evidence links ride the in-search pcap_href/file_href the macros compute with
    isnull guards).
  * Elastic / OpenSearch dashboards + saved searches -> saved-object NDJSON (a Discover `search`
    object + URL drilldowns; external evidence links use the `encodeURIComponent` handlebars helper
    on the configured evidence.base_url).
  * Elastic detection rule -> the native Kibana Security threshold rule, copied as-is.
  * Elastic assets are also emitted in a Fleet integration package layout
    (`dist/elastic/cernity_ndr/{manifest.yml,changelog.yml,docs,kibana,elasticsearch}`).

`dist/` is a build OUTPUT: regenerated here, validated by deploy/siem/test_packs.py, never
hand-edited. No live SIEM, no network — pure rendering, so the gate can validate it offline.

Run: `.venv/bin/python -m deploy.siem.build` (or `python deploy/siem/build.py`) — writes dist/.
"""
import argparse
import glob
import json
import os
import shutil
import sys
import xml.etree.ElementTree as ET

import yaml

_SIEM = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_SIEM))
sys.path.insert(0, os.path.join(_ROOT, "services", "findings-forwarder"))
import mappings  # noqa: E402

SCHEMA = json.load(open(os.path.join(_ROOT, "contracts", "siem_pivot.schema.json")))
SCHEMA_FIELDS = set(SCHEMA["properties"])
PLATFORM_MAP = {"splunk": mappings.CIM_MAP, "elastic": mappings.ECS_MAP, "opensearch": mappings.ECS_MAP}
# Discover app id per platform (used in in-SIEM URL drilldown templates).
_DISCOVER = {"elastic": "discover", "opensearch": "data-explorer/discover"}
_INDEX_PATTERN_ID = "ndr-ecs"
# opens targets that stay inside the SIEM as another dashboard/saved object.
_DASHBOARD_TARGETS = {"entity_timeline", "evidence", "findings"}


# --------------------------------------------------------------------------- loading

def _load_defs(platform):
    """All portable dashboard/saved-search defs for a platform, keyed by their `id`."""
    defs = {}
    for sub in ("dashboards", "saved_searches"):
        for p in sorted(glob.glob(os.path.join(_SIEM, platform, sub, "*.json"))):
            d = json.load(open(p))
            defs[d["id"]] = d
    return defs


def _manifest():
    return json.load(open(os.path.join(_SIEM, "MANIFEST.json")))


# --------------------------------------------------------------------------- validation

def validate_defn(defn, cmap):
    """Reject a portable def the native build cannot honour — the negative cases ADR 004 pins:
    an unknown pivot field, a CIM/ECS name that disagrees with mappings.py, or a drilldown that
    binds a field its panel never produces (an occurrence id dropped by aggregation)."""
    for inp in defn.get("inputs", []):
        _check_pivot(defn, inp, cmap)
    for panel in defn["panels"]:
        produced = set(panel.get("produces", []))
        for d in panel.get("drilldowns", []):
            _check_pivot(defn, d, cmap)
            if d["bind"] not in produced:
                raise ValueError(
                    f"{defn['id']}: drilldown bind {d['bind']!r} not produced by panel "
                    f"{panel['id']!r} {sorted(produced)}")


def _check_pivot(defn, node, cmap):
    canon, field = node["canonical"], node["pivot_field"]
    if canon not in SCHEMA_FIELDS:
        raise ValueError(f"{defn['id']}: canonical {canon!r} not in siem_pivot.schema.json")
    if cmap[canon] != field:
        raise ValueError(f"{defn['id']}: {canon} -> {field!r}, mappings.py says {cmap[canon]!r}")


def _destination(defn, drill, manifest):
    """Resolve a drilldown's destination or raise. External (pcap/file_artifact) must be a
    MANIFEST external_destinations entry; an in-SIEM dashboard target must exist and expose an
    input for the drilldown's canonical; `search` stays in place."""
    opens = drill["opens"]
    if opens in manifest["external_destinations"]:
        return ("external", manifest["external_destinations"][opens])
    if opens == "search":
        return ("search", None)
    if opens not in _DASHBOARD_TARGETS:
        raise ValueError(f"{defn['id']}: drilldown opens {opens!r} has no known destination")
    return ("dashboard", opens)


def _target_input(defs, target_id, canonical):
    """The target dashboard's input pivot_field for this canonical (raises if the target has none —
    a drilldown pointing at a dashboard that cannot receive the value is a broken pivot)."""
    for inp in defs[target_id]["inputs"]:
        if inp["canonical"] == canonical:
            return inp
    raise ValueError(f"{target_id}: no input for canonical {canonical!r}")


# --------------------------------------------------------------------------- Splunk Simple XML

def render_splunk_dashboard(defn, defs, manifest):
    cmap = mappings.CIM_MAP
    validate_defn(defn, cmap)
    form = ET.Element("form", version="1.1")
    ET.SubElement(form, "label").text = defn["title"]
    fs = ET.SubElement(form, "fieldset", submitButton="false")
    for inp in defn["inputs"]:
        el = ET.SubElement(fs, "input", type="text", token=inp["token"])
        ET.SubElement(el, "label").text = inp["label"]
    for panel in defn["panels"]:
        pnl = ET.SubElement(ET.SubElement(form, "row"), "panel")
        ET.SubElement(pnl, "title").text = panel["title"]
        table_like = panel["viz"] == "table"
        viz = ET.SubElement(pnl, "table" if table_like else "chart")
        ET.SubElement(ET.SubElement(viz, "search"), "query").text = panel["search"]
        drills = panel.get("drilldowns", [])
        if not drills:
            continue
        dd = ET.SubElement(viz, "drilldown")
        for d in drills:
            cond = ET.SubElement(dd, "condition", field=d["bind"])
            ET.SubElement(cond, "link", target="_blank").text = _splunk_link(
                defn, d, defs, manifest, table_like)
    ET.indent(form, space="  ")
    return ET.tostring(form, encoding="unicode") + "\n"


def _splunk_link(defn, drill, defs, manifest, table_like):
    kind, dest = _destination(defn, drill, manifest)
    # Chart click: filter by the clicked SERIES name ($click.name2$ = the pivot field value, e.g. the
    # signature), NOT $click.value2$ which is the Y-axis measure (the count).
    raw = f"$row.{drill['bind']}$" if table_like else "$click.name2$"
    enc = raw[:-1] + "|u$"  # native URL-encode token modifier: $row.x$ -> $row.x|u$
    if kind == "external":
        # bind is the in-search href (base_url + urlencode(id), null-guarded) — open it directly.
        return raw
    if kind == "search":
        return f'search?q=`cernity_ndr_findings` {drill["pivot_field"]}="{enc}"'
    tok = _target_input(defs, dest, drill["canonical"])["token"]
    return f"{dest}?form.{tok}={enc}"


# --------------------------------------------------------------- Kibana/OpenSearch saved objects

def render_saved_objects(defn, platform, defs, manifest):
    validate_defn(defn, mappings.ECS_MAP)
    objs = [_index_pattern_obj(defn["index_pattern"]), _search_obj(defn, platform, defs, manifest)]
    return "".join(json.dumps(o, sort_keys=True) + "\n" for o in objs)


def _index_pattern_obj(index_pattern):
    return {"id": _INDEX_PATTERN_ID, "type": "index-pattern", "managed": False,
            "attributes": {"title": index_pattern}, "references": []}


def _resolve_query(defn, search):
    """A Kibana Discover saved search stores a literal query — it has no dashboard-style runtime
    input tokens. So resolve each `{{token}}` input to `field : *` (sensible initial state: every
    matching document); the concrete pivot value arrives at open time via the incoming URL drilldown
    (`_url_drilldown`), which rewrites Discover's `_a` query. Raises if a token is left unresolved."""
    q = search
    for inp in defn.get("inputs", []):
        q = q.replace('"{{' + inp["token"] + '}}"', "*")
    if "{{" in q:
        raise ValueError(f"{defn['id']}: unresolved input token in query {q!r}")
    return q


def _search_obj(defn, platform, defs, manifest):
    # A Discover saved search is one query + one document table (its built-in @timestamp histogram is
    # the "over time" view). So the view's panels share one base filter, and the rendered columns are
    # the UNION of every panel's produces — every drilldown binds a clicked cell, so its bind field
    # must be a rendered column (the occurrence ids the histogram panel drops are kept here).
    queries = {p["search"] for p in defn["panels"]}
    if len(queries) != 1:
        raise ValueError(f"{defn['id']}: ECS render needs one shared panel query, got {sorted(queries)}")
    columns = list(dict.fromkeys(c for p in defn["panels"] for c in p["produces"]))
    search_source = {"query": {"language": "kuery", "query": _resolve_query(defn, defn["panels"][0]["search"])},
                     "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"}
    events = []
    for panel in defn["panels"]:
        for d in panel.get("drilldowns", []):
            if d["bind"] not in columns:  # defensive: validate_defn already pins bind in produces
                raise ValueError(f"{defn['id']}: drilldown bind {d['bind']!r} not a rendered column")
            events.append(_url_drilldown(defn, d, platform, defs, manifest))
    return {
        "id": _obj_id(platform, defn["id"]),
        "type": "search",
        "managed": False,
        "attributes": {
            "title": defn["title"],
            "columns": columns,
            "sort": [],
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(search_source, sort_keys=True)},
            "enhancements": {"dynamicActions": {"events": events}},
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern", "id": _INDEX_PATTERN_ID}],
    }


def _obj_id(platform, dash_id):
    return f"cernity-ndr-{platform}-{dash_id}"


def _url_drilldown(defn, drill, platform, defs, manifest):
    kind, dest = _destination(defn, drill, manifest)
    disc = _DISCOVER[platform]
    if kind == "external":
        base = manifest["evidence"]["base_url"]
        # encodeURIComponent handlebars helper on the clicked value; a null id yields no value.
        path = dest["path"].replace("{id}", "{{encodeURIComponent event.value}}")
        template, name = base + path, dest["label"]
    elif kind == "search":
        template = f"app/{disc}#/?_a=(query:(language:kuery,query:'{drill['pivot_field']}: \"{{{{encodeURIComponent event.value}}}}\"'))"
        name = f"Filter by {drill['pivot_field']}"
    else:
        tok_field = _target_input(defs, dest, drill["canonical"])["pivot_field"]
        template = (f"app/{disc}#/view/{_obj_id(platform, dest)}"
                    f"?_a=(query:(language:kuery,query:'{tok_field}: \"{{{{encodeURIComponent event.value}}}}\"'))")
        name = f"Open {dest}"
    return {"eventId": f"dd-{drill['opens']}-{drill['bind']}", "triggers": ["VALUE_CLICK_TRIGGER"],
            "action": {"factoryId": "URL_DRILLDOWN", "name": name,
                       "config": {"openInNewTab": True, "encodeUrl": False,
                                  "url": {"template": template}}}}


# --------------------------------------------------------------------------- assembly

def _copy_tree(rel):
    """Source files under `deploy/siem/<rel>/` as {dist-relpath: text}, copied verbatim."""
    out = {}
    base = os.path.join(_SIEM, rel)
    for p in sorted(glob.glob(os.path.join(base, "**", "*"), recursive=True)):
        if os.path.isfile(p):
            out[os.path.relpath(p, _SIEM)] = open(p).read()
    return out


def _render_evidence_macro(text, base_url):
    """Rewrite the `[cernity_evidence_base]` macro definition from MANIFEST.json evidence.base_url so
    one manifest edit retargets the evidence gateway on ALL three platforms (Elastic/OpenSearch read
    the same base_url in `_url_drilldown`). The macro is `iseval=1`, so the definition is a quoted
    string eval expression. Everything else in macros.conf is copied verbatim."""
    lines = text.splitlines(keepends=True)
    in_stanza = False
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            in_stanza = s == "[cernity_evidence_base]"
        elif in_stanza and s.startswith("definition"):
            lines[i] = f'definition = "{base_url}"' + ("\n" if line.endswith("\n") else "")
            break
    return "".join(lines)


def build_all(manifest=None):
    """Render every native artifact into an in-memory {dist-relpath: text} tree (no disk writes),
    so the gate can validate the rendered output offline and deterministically. `manifest` defaults
    to MANIFEST.json; callers pass an override to build against a different evidence gateway."""
    manifest = manifest or _manifest()
    out = {}

    # Splunk: copy the TA, render dashboards to Simple XML. The evidence macro is rendered from the
    # manifest (not copied verbatim) so MANIFEST.json evidence.base_url is the single source of truth.
    out.update({os.path.join("splunk", k[len("splunk/"):]): v
                for k, v in _copy_tree("splunk/cernity_ndr_ta").items()})
    _macros = "splunk/cernity_ndr_ta/default/macros.conf"
    out[_macros] = _render_evidence_macro(out[_macros], manifest["evidence"]["base_url"])
    sp_defs = _load_defs("splunk")
    for d in sp_defs.values():
        out[f"splunk/dashboards/{d['id']}.xml"] = render_splunk_dashboard(d, sp_defs, manifest)

    # Elastic / OpenSearch: saved-object NDJSON + copied index templates.
    for platform in ("elastic", "opensearch"):
        defs = _load_defs(platform)
        for d in defs.values():
            out[f"{platform}/saved_objects/{d['id']}.ndjson"] = render_saved_objects(
                d, platform, defs, manifest)
        out.update(_copy_tree(f"{platform}/index_templates"))

    # Elastic detection rule: native Kibana Security rule, copied as-is.
    out.update(_copy_tree("elastic/detection_rules"))

    out.update(_fleet_package(manifest, out))
    return out


def _fleet_package(manifest, rendered):
    """Elastic Fleet integration package layout (ADR 004): manifest, changelog, docs, kibana
    (saved objects + rule), elasticsearch (index template)."""
    pkg = "elastic/cernity_ndr"
    ver = manifest["packs"]["elastic"]["version"]
    out = {f"{pkg}/manifest.yml": open(os.path.join(_SIEM, "elastic", "manifest.yml")).read()}
    out[f"{pkg}/changelog.yml"] = yaml.safe_dump(
        [{"version": ver, "changes": [{"description": "Cernity NDR SIEM content pack",
                                       "type": "enhancement", "link": "N/A"}]}], sort_keys=False)
    out[f"{pkg}/docs/README.md"] = (
        "# Cernity NDR (Elastic integration package)\n\n"
        "Rendered by `deploy/siem/build.py` from the portable pack source. Contains ECS index "
        "templates, triage saved searches (entity timeline, evidence, findings) with URL "
        "drilldowns, and a native detection rule.\n")
    for k, v in rendered.items():
        if k.startswith("elastic/saved_objects/"):
            out[f"{pkg}/kibana/search/{os.path.basename(k)}"] = v
        elif k.startswith("elastic/detection_rules/"):
            out[f"{pkg}/kibana/security_rule/{os.path.basename(k)}"] = v
        elif k.startswith("elastic/index_templates/"):
            out[f"{pkg}/elasticsearch/index_template/{os.path.basename(k)}"] = v
    return out


def write_dist(out_dir):
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    for rel, text in build_all().items():
        dest = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w") as fh:
            fh.write(text)
    return out_dir


def main(argv=None):
    ap = argparse.ArgumentParser(description="Render SIEM content packs to native artifacts (ADR 004).")
    ap.add_argument("--out", default=os.path.join(_SIEM, "dist"), help="output dir (default: deploy/siem/dist)")
    args = ap.parse_args(argv)
    write_dist(args.out)
    print(f"rendered {len(build_all())} artifacts -> {args.out}")


if __name__ == "__main__":
    main()
