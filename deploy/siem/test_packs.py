"""B-U8: validate the SIEM content packs without a live SIEM.

Template-parse + field-reference validation only (the unit's gate). Asserts:
  1. every index/mapping/dashboard template parses (valid JSON / YAML);
  2. every dashboard/pivot drilldown keys on a Splunk-CIM / ECS field that maps back to a stable
     field in contracts/siem_pivot.schema.json (no unstable-field drilldown), consistent with
     services/findings-forwarder/mappings.py;
  3. the Splunk findings index template stays consistent with the Elastic ndr-findings template
     (contracts/test_ndr_findings_template.py);
  4. each pack is versioned (MANIFEST.json + the pack's native descriptor) and the README carries
     the §26 source note;
  5. a representative exported finding populates the entity-timeline + evidence + PCAP pivots the
     dashboards drill on (against the mapping helpers, no live SIEM).
"""
import configparser
import copy
import glob
import json
import os
import sys
import xml.etree.ElementTree as ET

import pytest
import yaml

_SIEM = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_SIEM))
sys.path.insert(0, os.path.join(_ROOT, "services", "findings-forwarder"))
import mappings  # noqa: E402
sys.path.insert(0, _SIEM)
import build  # noqa: E402  (ADR 004: the gate validates build.py's rendered native artifacts)

SCHEMA = json.load(open(os.path.join(_ROOT, "contracts", "siem_pivot.schema.json")))
SCHEMA_FIELDS = set(SCHEMA["properties"])
# Splunk keys on CIM names; Elastic and OpenSearch both key on ECS names.
PLATFORM_MAP = {"splunk": mappings.CIM_MAP, "elastic": mappings.ECS_MAP, "opensearch": mappings.ECS_MAP}

_JSON = sorted(glob.glob(os.path.join(_SIEM, "**", "*.json"), recursive=True))
_YAML = sorted(glob.glob(os.path.join(_SIEM, "**", "*.yml"), recursive=True) +
               glob.glob(os.path.join(_SIEM, "**", "*.yaml"), recursive=True))


def _platform(path):
    return os.path.relpath(path, _SIEM).split(os.sep)[0]


def _walk(obj):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)


def _pivots(obj):
    """Every input/drilldown object — the ones that name a pivot field (`canonical` + `pivot_field`)."""
    return [d for d in _walk(obj) if isinstance(d, dict) and "canonical" in d and "pivot_field" in d]


def _flatten_props(props, prefix=""):
    """ES/OpenSearch mapping properties -> set of dotted leaf field names."""
    out = set()
    for name, node in props.items():
        dotted = f"{prefix}{name}"
        if isinstance(node, dict) and "properties" in node:
            out |= _flatten_props(node["properties"], dotted + ".")
        else:
            out.add(dotted)
    return out


# ---------------------------------------------------------------------------- scenario 1

def test_every_json_template_parses():
    assert _JSON, "no JSON pack files found"
    for p in _JSON:
        with open(p) as fh:
            json.load(fh)  # raises on malformed JSON


def test_every_yaml_template_parses():
    assert _YAML, "no YAML pack files found"
    for p in _YAML:
        with open(p) as fh:
            assert yaml.safe_load(fh) is not None, p


# ---------------------------------------------------------------------------- scenario 2

def test_drilldowns_key_only_on_schema_fields():
    seen = 0
    for p in _JSON:
        cmap = PLATFORM_MAP.get(_platform(p))
        if cmap is None:
            continue
        for d in _pivots(json.load(open(p))):
            canon, field = d["canonical"], d["pivot_field"]
            assert canon in SCHEMA_FIELDS, f"{p}: canonical {canon!r} not in siem_pivot.schema.json"
            assert cmap[canon] == field, f"{p}: {canon} -> {field!r}, mappings.py says {cmap[canon]!r}"
            seen += 1
    assert seen, "no drilldown/pivot references found to validate"


def test_drilldown_binds_are_produced_by_their_panel():
    """Every drilldown's `bind` must be a field the owning panel's query actually produces — a
    drilldown that binds a field the panel never emits is a broken pivot. (The Splunk dashboards'
    comments promise this check.)"""
    seen = 0
    for p in _JSON:
        for node in _walk(json.load(open(p))):
            if not (isinstance(node, dict) and "produces" in node and "drilldowns" in node):
                continue
            produced = set(node["produces"])
            for d in node["drilldowns"]:
                bind = d.get("bind")
                assert bind in produced, f"{p}: drilldown bind {bind!r} not in panel produces {sorted(produced)}"
                seen += 1
    assert seen, "no drilldown binds found to validate"


def test_props_conf_cim_aliases_match_mappings():
    cp = configparser.ConfigParser(strict=False)
    cp.read(os.path.join(_SIEM, "splunk", "cernity_ndr_ta", "default", "props.conf"))
    targets = set()
    for _stanza in cp.sections():
        for key, val in cp[_stanza].items():
            if key.startswith("fieldalias-"):
                targets.add(val.split(" AS ")[-1].strip())  # RHS of `<src> AS <cim>`
    assert targets == set(mappings.CIM_MAP.values()), targets ^ set(mappings.CIM_MAP.values())


def test_ecs_index_templates_type_every_pivot_field():
    want = set(mappings.ECS_MAP.values())
    for platform in ("elastic", "opensearch"):
        tmpl = json.load(open(os.path.join(_SIEM, platform, "index_templates", "ndr-ecs-pivots.json")))
        fields = _flatten_props(tmpl["template"]["mappings"]["properties"])
        assert want <= fields, f"{platform}: missing {want - fields}"


# ---------------------------------------------------------------------------- scenario 3

def test_splunk_findings_template_consistent_with_es():
    es = json.load(open(os.path.join(_ROOT, "deploy", "central", "es", "ndr-findings-index-template.json")))
    es_props = es["template"]["mappings"]["properties"]
    sp = json.load(open(os.path.join(_SIEM, "splunk", "cernity_ndr_ta", "default", "findings_index_template.json")))
    sp_fields = sp["fields"]
    # The queryable core that contracts/test_ndr_findings_template.py pins, with the Splunk type family.
    family = {"keyword": "string", "integer": "number", "long": "number", "float": "number", "date": "time"}
    core = ("finding_id", "tenant_id", "detector_id", "detector_version", "category", "state",
            "severity", "revision", "@timestamp", "first_seen", "last_seen", "emitted_at")
    for f in core:
        assert f in sp_fields, f"Splunk findings template missing core field {f}"
        assert sp_fields[f] == family[es_props[f]["type"]], f"{f}: Splunk {sp_fields[f]} vs ES {es_props[f]['type']}"


# ---------------------------------------------------------------------------- scenario 4

def test_each_pack_is_versioned():
    manifest = json.load(open(os.path.join(_SIEM, "MANIFEST.json")))
    packs = manifest["packs"]
    assert set(packs) == {"splunk", "elastic", "opensearch"}
    for name, pack in packs.items():
        assert pack["version"], f"{name} pack has no version"
    # Native descriptors echo the same version.
    app = configparser.ConfigParser(strict=False)
    app.read(os.path.join(_SIEM, "splunk", "cernity_ndr_ta", "default", "app.conf"))
    assert app["launcher"]["version"] == packs["splunk"]["version"]
    el = yaml.safe_load(open(os.path.join(_SIEM, "elastic", "manifest.yml")))
    assert el["version"] == packs["elastic"]["version"]


def test_readme_carries_section26_note():
    txt = open(os.path.join(_SIEM, "README.md")).read()
    assert "§26" in txt
    assert "independently authored" in txt.lower()
    assert "Corelight" in txt  # explicit no-Corelight-assets statement


# ---------------------------------------------------------------------------- scenario 5

# Representative exported finding: an entity + asset, a flow with a community_id and an observation,
# a sensor, and a captured-packet evidence object.
FINDING = {
    "finding_id": "F-500", "detector_id": "slips_ml", "detector_version": "2.0",
    "model_version": "slips-2026.09", "revision": 1, "incident_id": "inc-1",
    "sensor_ids": ["sensor-a"],
    "entities": [{"type": "entity", "value": "default|asset:h7"}, {"type": "asset", "value": "asset:h7"}],
    "source_events": [{"community_id": "1:abc=", "obs_id": "obs:" + "a" * 64}],
    "evidence_refs": ["minio://ndr-pcap/f500.pcap"],
}
# file_artifact_id / investigation_id are null until Track A / U9 — a documented gap, not a broken pivot.
_NULL_UNTIL_LATER = {"file_artifact_id", "investigation_id"}


def test_representative_finding_populates_dashboard_pivots():
    p = mappings.pivot(FINDING)
    cim, ecs = mappings.to_cim(FINDING), mappings.to_ecs(FINDING)
    # entity-timeline: entity, asset, observation point.
    for canon in ("entity_id", "asset_key", "observation_point"):
        assert p[canon] is not None
    # evidence + PCAP: observation, flow, captured packets.
    for canon in ("observation_id", "community_id", "pcap_evidence_id"):
        assert p[canon] is not None
    # and they resolve through both renamers.
    assert cim["risk_object"] and cim["dvc"] and cim["vendor_pcap_evidence_id"]
    assert ecs["cernity.entity_id"] and ecs["observer.name"] and ecs["cernity.pcap_evidence_id"]

    # Every pivot the entity-timeline + evidence dashboards actually drill on is populated for this
    # finding (except the documented null-until-later ones) — the dashboards' contract, not a fixed list.
    for platform in ("splunk", "elastic", "opensearch"):
        for view in ("entity_timeline", "evidence"):
            for sub in ("dashboards", "saved_searches"):
                path = os.path.join(_SIEM, platform, sub, view + ".json")
                if not os.path.exists(path):
                    continue
                for d in _pivots(json.load(open(path))):
                    canon = d["canonical"]
                    if canon not in _NULL_UNTIL_LATER:
                        assert p[canon] is not None, f"{path}: {canon} null for representative finding"


# ---------------------------------------------------------------------------- scenario 6
# ADR 004: build.py renders the portable source to platform-native artifacts. The gate validates
# the RENDERED output parses to its platform schema and its pivot destinations resolve, offline.

_DIST = build.build_all()


def test_build_is_deterministic():
    assert build.build_all() == _DIST  # same input -> byte-identical output (dist is a CI artifact)


def test_splunk_dashboards_render_valid_simple_xml():
    seen = 0
    for rel, text in _DIST.items():
        if not (rel.startswith("splunk/dashboards/") and rel.endswith(".xml")):
            continue
        form = ET.fromstring(text)  # raises on malformed XML; input is build.py's own output (trusted, no XXE surface)
        assert form.tag == "form", rel
        tokens = {i.get("token") for i in form.iter("input")}
        assert tokens, rel
        for cond in form.iter("condition"):
            bind = cond.get("field")
            link = cond.find("link").text
            assert bind in link, f"{rel}: link {link!r} does not carry its bind {bind!r}"
            # A navigation target (dashboard/search) URL-encodes its dynamic value with |u; an
            # external href is the in-search pcap_href/file_href (already encoded by the macro).
            if "?" in link:
                assert "|u$" in link, f"{rel}: navigation link {link!r} missing |u URL-encode"
            seen += 1
    assert seen, "no rendered Splunk drilldowns validated"


def test_saved_objects_render_valid_ndjson():
    seen = 0
    for rel, text in _DIST.items():
        if not rel.endswith(".ndjson"):
            continue
        objs = [json.loads(l) for l in text.splitlines() if l.strip()]
        assert objs, rel
        ids = {o["id"] for o in objs}
        for o in objs:
            assert {"id", "type", "attributes", "references"} <= o.keys(), rel
            for ref in o["references"]:
                assert ref["id"] in ids, f"{rel}: dangling reference {ref['id']!r}"
        seen += 1
    assert seen, "no rendered saved-object NDJSON validated"


def test_build_evidence_destinations_resolve_offline():
    manifest = build._manifest()
    base = manifest["evidence"]["base_url"]
    for platform in ("elastic", "opensearch"):
        text = _DIST[f"{platform}/saved_objects/evidence.ndjson"]
        templates = [e["action"]["config"]["url"]["template"]
                     for o in (json.loads(l) for l in text.splitlines() if l.strip())
                     if o["type"] == "search"
                     for e in o["attributes"]["enhancements"]["dynamicActions"]["events"]]
        for name, dest in manifest["external_destinations"].items():
            prefix = base + dest["path"].split("{id}")[0]
            hits = [t for t in templates if t.startswith(prefix)]
            assert hits, f"{platform}: no evidence link to {name} ({prefix})"
            assert all("encodeURIComponent" in t for t in hits), f"{platform}: {name} id not URL-encoded"
    # Splunk opens the in-search href (base_url wiring lives in the macro).
    for href in ("$row.pcap_href$", "$row.file_href$"):
        assert href in _DIST["splunk/dashboards/evidence.xml"]


def test_detection_rule_is_native_threshold():
    rule = json.loads(_DIST["elastic/detection_rules/beaconing_by_entity.json"])
    assert rule["type"] == "threshold"
    assert set(rule["threshold"]["field"]) <= set(mappings.ECS_MAP.values())


def test_fleet_package_layout():
    pkg = "elastic/cernity_ndr"
    for required in (f"{pkg}/manifest.yml", f"{pkg}/changelog.yml", f"{pkg}/docs/README.md"):
        assert required in _DIST, f"missing Fleet artifact {required}"
    assert any(k.startswith(f"{pkg}/kibana/search/") for k in _DIST)
    assert any(k.startswith(f"{pkg}/kibana/security_rule/") for k in _DIST)
    assert any(k.startswith(f"{pkg}/elasticsearch/index_template/") for k in _DIST)


def _search_object(text):
    """The single Discover `search` saved object out of a rendered saved-object NDJSON file."""
    objs = [json.loads(l) for l in text.splitlines() if l.strip()]
    return next(o for o in objs if o["type"] == "search")


def test_saved_search_query_has_no_unresolved_input_tokens():
    """A Discover saved search stores a literal query — an unresolved `{{entity}}` would search for
    that literal string. build.py resolves inputs to a `field : *` initial state instead."""
    seen = 0
    for platform in ("elastic", "opensearch"):
        for view in build._load_defs(platform):
            obj = _search_object(_DIST[f"{platform}/saved_objects/{view}.ndjson"])
            q = json.loads(obj["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])["query"]["query"]
            assert "{{" not in q, f"{platform}/{view}: unresolved input token in query {q!r}"
            seen += 1
    assert seen, "no rendered saved searches validated"


def test_saved_search_columns_expose_every_drilldown_bind():
    """Rendered field availability + action bindings (not just the portable `produces`): a URL
    drilldown fires on a clicked cell, so every drilldown bind must be a column the rendered object
    actually shows — including the occurrence ids the histogram panel drops (event.id,
    cernity.observation_id on entity_timeline). One dynamic action per drilldown."""
    for platform in ("elastic", "opensearch"):
        for view, defn in build._load_defs(platform).items():
            obj = _search_object(_DIST[f"{platform}/saved_objects/{view}.ndjson"])
            cols = set(obj["attributes"]["columns"])
            drills = [d for p in defn["panels"] for d in p.get("drilldowns", [])]
            binds = {d["bind"] for d in drills}
            assert binds <= cols, f"{platform}/{view}: binds {binds - cols} not in rendered columns {sorted(cols)}"
            events = obj["attributes"]["enhancements"]["dynamicActions"]["events"]
            assert len(events) == len(drills), f"{platform}/{view}: {len(events)} actions for {len(drills)} drilldowns"
            # entity_timeline keeps both views: the histogram split field AND the occurrence detail ids.
            if view == "entity_timeline":
                assert {"event.id", "cernity.observation_id", "rule.id"} <= cols, sorted(cols)


def test_representative_pivot_reaches_destination_query():
    """A representative finding's ECS entity value flows through the findings->entity_timeline URL
    drilldown into the destination Discover query — substituting Kibana's {{event.value}} runtime
    var yields a query keyed on the entity_timeline entity field carrying that value."""
    ecs = mappings.to_ecs(FINDING)
    entity = ecs["cernity.entity_id"]
    assert entity  # representative finding has an entity
    for platform in ("elastic", "opensearch"):
        obj = _search_object(_DIST[f"{platform}/saved_objects/findings.ndjson"])
        events = obj["attributes"]["enhancements"]["dynamicActions"]["events"]
        tmpl = next(e["action"]["config"]["url"]["template"] for e in events
                    if e["eventId"] == "dd-entity_timeline-cernity.entity_id")
        # event.value is escaped via the encodeURIComponent handlebars helper (see injection guard);
        # a plain entity value is unchanged by it, so substitute the encoded token form.
        resolved = tmpl.replace("{{encodeURIComponent event.value}}", entity).replace("{{event.value}}", entity)
        assert "cernity.entity_id" in resolved and entity in resolved, resolved


def test_insiem_kql_drilldowns_escape_event_value():
    """Injection guard: an in-SIEM (search/view) Discover drilldown interpolates the clicked value into
    a double-quoted KQL string inside the RISON `_a` state with encodeUrl:false, so a raw {{event.value}}
    lets a value containing a quote break out and inject query state. Every event.value in a KQL template
    must go through the encodeURIComponent helper (as the external evidence links already do)."""
    seen = 0
    for platform in ("elastic", "opensearch"):
        for view, defn in build._load_defs(platform).items():
            obj = _search_object(_DIST[f"{platform}/saved_objects/{view}.ndjson"])
            for e in obj["attributes"]["enhancements"]["dynamicActions"]["events"]:
                tmpl = e["action"]["config"]["url"]["template"]
                assert "{{event.value}}" not in tmpl, (
                    f"{platform}/{view}: raw unescaped event.value in drilldown {tmpl!r}")
                if "event.value" in tmpl:
                    assert "encodeURIComponent event.value" in tmpl, f"{platform}/{view}: {tmpl!r}"
                    seen += 1
    assert seen, "no in-SIEM drilldowns validated"


def test_splunk_chart_drilldown_keys_on_series_not_count():
    """A chart-panel drilldown must filter by the clicked SERIES name ($click.name2$ = the pivot field
    value, e.g. the signature), never $click.value2$ which is the Y-axis measure (the count). Keying on
    the count produces a nonsensical drilldown search."""
    seen = 0
    for rel, text in _DIST.items():
        if not (rel.startswith("splunk/dashboards/") and rel.endswith(".xml")):
            continue
        form = ET.fromstring(text)
        for cond in form.iter("condition"):
            link = cond.find("link").text
            if "$click." in link:
                # tokens may carry the |u URL-encode modifier ($click.name2|u$), so match the prefix.
                assert "$click.value2" not in link, f"{rel}: chart drilldown keys on the count: {link!r}"
                assert "$click.name2" in link, f"{rel}: chart drilldown missing series token: {link!r}"
                seen += 1
    assert seen, "no Splunk chart drilldowns validated"


def test_manifest_evidence_base_url_flows_to_all_platforms():
    """Regression (the supported config path): setting MANIFEST.json evidence.base_url before
    building retargets the evidence gateway on ALL three platforms — the Splunk macro and the
    Elastic/OpenSearch URL drilldowns — not just Elastic/OpenSearch."""
    m = copy.deepcopy(build._manifest())
    m["evidence"]["base_url"] = "https://configured.example"
    out = build.build_all(m)
    macros = out["splunk/cernity_ndr_ta/default/macros.conf"]
    assert 'definition = "https://configured.example"' in macros
    assert "evidence.example.invalid" not in macros
    for platform in ("elastic", "opensearch"):
        text = out[f"{platform}/saved_objects/evidence.ndjson"]
        assert "https://configured.example/pcap/" in text
        assert "evidence.example.invalid" not in text


# --- negative cases (ADR 004): the build rejects an unknown field, a missing destination, and an
# occurrence id dropped by aggregation.

def _elastic_defn():
    return copy.deepcopy(build._load_defs("elastic")["evidence"])


def test_build_rejects_unknown_field():
    d = _elastic_defn()
    d["panels"][0]["drilldowns"][0]["canonical"] = "not_a_pivot_field"
    with pytest.raises(ValueError, match="siem_pivot"):
        build.validate_defn(d, mappings.ECS_MAP)


def test_build_rejects_field_dropped_by_aggregation():
    d = _elastic_defn()
    d["panels"][0]["produces"].remove(d["panels"][0]["drilldowns"][0]["bind"])
    with pytest.raises(ValueError, match="not produced"):
        build.validate_defn(d, mappings.ECS_MAP)


def test_build_rejects_missing_destination():
    manifest = build._manifest()
    manifest["external_destinations"] = {}  # pcap/file_artifact no longer resolve anywhere
    with pytest.raises(ValueError, match="no known destination"):
        build.render_saved_objects(_elastic_defn(), "elastic", build._load_defs("elastic"), manifest)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"all {len(fns)} pack tests passed")
