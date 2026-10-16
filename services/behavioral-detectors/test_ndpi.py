"""nDPI risk-set normalization: Suricata emits `flow_risk` (dict or list); the
detector must read it (not just fall back to breed), and a risk is an OBJECT —
{id: {risk, risk_score, severity}} — so it must arrive as queryable fields, not as
a Python repr of the dict."""
import os
import json
import time
from pathlib import Path

os.environ["NDR_TENANT"] = "default"

import app
import detectors as det
import ndpi_policy as ndpi_pol
import store


def _names(risks):
    return [r.get("name") for r in risks]


def test_flow_risk_dict_id_to_name():
    risks = app._ndpi_risks({"flow_risk": {"7": "Self-signed Certificate", "0": "Malicious JA3"}})
    assert _names(risks) == ["Self-signed Certificate", "Malicious JA3"]
    assert [r["id"] for r in risks] == ["7", "0"]


def test_flow_risk_dict_name_to_bool():
    risks = app._ndpi_risks({"flow_risk": {"Malicious JA3 Fingerprint": True}})
    assert _names(risks) == ["Malicious JA3 Fingerprint"]
    # a false membership flag is not a risk, and no id/severity is invented
    assert app._ndpi_risks({"flow_risk": {"Malicious JA3 Fingerprint": False}}) == []
    assert risks[0] == {"name": "Malicious JA3 Fingerprint"}


def test_flow_risk_list_passthrough():
    assert app._ndpi_risks({"flow_risk": ["Suspicious DGA Domain"]}) == [{"name": "Suspicious DGA Domain"}]


def test_legacy_risk_field_still_works():
    assert app._ndpi_risks({"risk": ["Cleartext Credentials"]}) == [{"name": "Cleartext Credentials"}]


def test_bare_string_and_absent_risk():
    assert app._ndpi_risks({"risk": "Malformed Packet"}) == [{"name": "Malformed Packet"}]
    assert app._ndpi_risks({"flow_risk": None}) == []
    assert app._ndpi_risks({"breed": "Safe"}) == []


def test_empty_when_no_ndpi():
    assert app._ndpi_risks({}) == []


def test_risk_feeds_the_detector():
    # a real Suricata flow_risk name must trip the ndpi risk detector
    risks = app._ndpi_risks({"flow_risk": {"1": "Malicious JA3 Fingerprint"}})
    hit, matched = det.ndpi_risk_hit(risks)
    assert hit and matched == ["Malicious JA3 Fingerprint"]


# --- the structured flow_risk object (the defect this file's header names) --------
# Verbatim from the repo's published evidence, where this whole object was delivered
# as the ndpi_risk entity's value, stringified.
_EVIDENCE = {"flow_risk": {"188": {"risk": "Susp DNS Traffic",
                                   "risk_score": {"client": 350, "server": 110, "total": 460},
                                   "severity": "Medium"}}}


def test_structured_risk_parses_into_fields():
    risks = app._ndpi_risks(_EVIDENCE)
    assert len(risks) == 1
    r = risks[0]
    assert r["id"] == "188" and r["name"] == "Susp DNS Traffic" and r["severity"] == "Medium"
    assert r["score"] == {"total": 460, "client": 350, "server": 110}


def test_structured_risk_is_never_a_python_repr():
    # "{'" is the signature of str() on a risk object -> the headline regression test
    assert "{'" not in json.dumps(app._ndpi_risks(_EVIDENCE))


def test_structured_risk_still_hits_on_its_name():
    hit, matched = det.ndpi_risk_hit(app._ndpi_risks(_EVIDENCE))
    assert hit and matched == ["Susp DNS Traffic"]       # the name, not the object


def test_both_modes_read_the_same_parse():
    # legacy consumes the projection, structured consumes ndpi_policy's full entries;
    # one parser means the two modes can never disagree about a risk's fields.
    legacy = app._ndpi_risks(_EVIDENCE)[0]
    structured = ndpi_pol.parse_ndpi_risks(_EVIDENCE)[0]
    assert all(legacy[k] == structured[k] for k in legacy)
    assert set(legacy) == {"id", "name", "severity", "score"}
    fnd = ndpi_pol.ndpi_findings(_EVIDENCE, "10.0.0.1", "203.0.113.1", "default")[0]
    assert "{'" not in json.dumps(fnd["entities"])


def test_multiple_risks_all_parsed_in_order():
    risks = app._ndpi_risks({"flow_risk": {
        "188": {"risk": "Susp DNS Traffic", "severity": "Medium"},
        "7": {"risk": "Self-signed Certificate", "severity": "Low",
              "risk_score": {"total": 50}},
        "99": {"risk": "HTTP Numeric IP Address", "severity": "Low"},
    }})
    assert _names(risks) == ["Susp DNS Traffic", "Self-signed Certificate", "HTTP Numeric IP Address"]
    hit, matched = det.ndpi_risk_hit(risks)
    assert hit and matched == ["Susp DNS Traffic", "Self-signed Certificate"]   # the third is not high


def test_partial_risks_degrade_to_the_fields_present():
    no_sev = app._ndpi_risks({"flow_risk": {"1": {"risk": "Susp Entropy",
                                                  "risk_score": {"total": 10}}}})[0]
    assert no_sev == {"id": "1", "name": "Susp Entropy", "score": {"total": 10}}
    no_score = app._ndpi_risks({"flow_risk": {"2": {"risk": "Susp Entropy", "severity": "Low"}}})[0]
    assert no_score == {"id": "2", "name": "Susp Entropy", "severity": "Low"}


def test_malformed_risk_sets_do_not_raise():
    cases = [
        {"flow_risk": {"1": ["not", "a", "risk"]}},            # value is a list
        {"flow_risk": {"1": 42}},                              # value is an int
        {"flow_risk": {"1": {"severity": "High"}}},            # nested dict, no risk name
        {"flow_risk": {"1": {"risk": "Susp Entropy", "risk_score": "460"}}},   # score not a dict
        {"flow_risk": {7: {"risk": "Susp Entropy"}}},          # non-string key
        {"flow_risk": 3.5},                                    # container is a scalar
        {"flow_risk": [None, True, {"risk": None}]},
    ]
    for c in cases:
        risks = app._ndpi_risks(c)
        assert isinstance(risks, list)
        det.ndpi_risk_hit(risks)                               # matching must survive it too
        assert "{'" not in json.dumps(risks)
    # a nameless risk keeps its id as evidence, invents no name, and cannot score as high
    assert app._ndpi_risks({"flow_risk": {"1": {"severity": "High"}}}) == [{"id": "1"}]
    assert det.ndpi_risk_hit([{"id": "1"}]) == (False, [])
    # a risk_score that is not an object contributes no scores rather than failing
    assert app._ndpi_risks(
        {"flow_risk": {"1": {"risk": "Susp Entropy", "risk_score": "460"}}}
    ) == [{"id": "1", "name": "Susp Entropy"}]


def test_huge_risk_set_is_bounded():
    big = {"flow_risk": {str(i): {"risk": f"Risk {i}", "severity": "Low"} for i in range(500)}}
    assert len(app._ndpi_risks(big)) == ndpi_pol.MAX_RISKS     # bound applied, not unbounded


class _CountingDict(dict):
    """Counts how many entries the parser actually pulls, so the bound can be shown to
    stop the traversal rather than only trimming the result."""
    seen = 0

    def items(self):
        for kv in dict.items(self):
            self.seen += 1
            yield kv


class _CountingList(list):
    seen = 0

    def __iter__(self):
        for v in list.__iter__(self):
            self.seen += 1
            yield v


def test_huge_risk_set_bounds_the_traversal_not_just_the_output():
    m = _CountingDict((str(i), {"risk": f"Risk {i}", "severity": "Low"}) for i in range(10000))
    assert len(app._ndpi_risks({"flow_risk": m})) == ndpi_pol.MAX_RISKS
    assert m.seen == ndpi_pol.MAX_RISKS            # stopped AT the bound; 10k entries never built
    lst = _CountingList(f"Risk {i}" for i in range(10000))
    assert len(ndpi_pol.parse_ndpi_risks({"risk": lst})) == ndpi_pol.MAX_RISKS
    assert lst.seen == ndpi_pol.MAX_RISKS


def test_bound_counts_entries_that_produce_no_output():
    # entries that yield nothing — false membership flags, bools in a list — still cost
    # a traversal step, so the bound has to cap what is INSPECTED, not what is kept.
    m = _CountingDict((f"Risk {i}", False) for i in range(10000))
    assert app._ndpi_risks({"flow_risk": m}) == []
    assert m.seen == ndpi_pol.MAX_RISKS
    lst = _CountingList(False for _ in range(10000))
    assert ndpi_pol.parse_ndpi_risks({"risk": lst}) == []
    assert lst.seen == ndpi_pol.MAX_RISKS
    # mixed: the kept entries come from the first MAX_RISKS inspected, not from a scan
    # that walks the whole container looking for MAX_RISKS keepers.
    mixed = _CountingDict((str(i), {"risk": f"Risk {i}"} if i % 2 else False) for i in range(10000))
    assert len(app._ndpi_risks({"flow_risk": mixed})) == ndpi_pol.MAX_RISKS // 2
    assert mixed.seen == ndpi_pol.MAX_RISKS


# --- legacy behaviour that must be byte-identical to the pre-fix implementation ----
# The old reader was `n.get("risk") or n.get("flow_risk")`, i.e. `risk` wins whenever
# it is truthy. The structured classifier deliberately does the opposite (canonical
# flow_risk first), so the two precedences are kept apart; only parsing is shared.
def test_legacy_risk_field_keeps_precedence_over_flow_risk():
    both = {"risk": ["Susp DNS Traffic"], "flow_risk": ["Benign"]}
    assert det.ndpi_risk_hit(app._ndpi_risks(both)) == (True, ["Susp DNS Traffic"])
    empty_canonical = {"risk": ["Susp DNS Traffic"], "flow_risk": None}
    assert det.ndpi_risk_hit(app._ndpi_risks(empty_canonical)) == (True, ["Susp DNS Traffic"])
    # a falsy `risk` still falls back to flow_risk, exactly as `or` always did
    assert _names(app._ndpi_risks({"risk": [], "flow_risk": {"188": {"risk": "Susp DNS Traffic"}}})) \
        == ["Susp DNS Traffic"]
    # unchanged on the structured side: a legacy value never overrides the canonical one
    assert ndpi_pol.parse_ndpi_risks(both)[0]["name"] == "Benign"


def test_long_legacy_risk_name_still_matches_in_full():
    long = "x" * 5000 + " Susp DNS Traffic"          # the match lives past MAX_NAME
    assert det.ndpi_risk_hit(app._ndpi_risks({"risk": [long]})) == (True, [long])
    # the structured classifier still bounds the name it stores — unchanged
    assert len(ndpi_pol.parse_ndpi_risks({"flow_risk": [long]})[0]["name"]) == ndpi_pol.MAX_NAME


def test_hostile_score_degrades_instead_of_raising():
    nd = {"flow_risk": {"1": {"risk": "Susp DNS Traffic", "severity": "Medium",
                              "risk_score": {"total": 10 ** 400, "client": 350}},
                        "2": {"risk": "Self-signed Certificate", "severity": "Low"}}}
    risks = app._ndpi_risks(nd)                       # legacy path (the default mode)
    assert risks[0] == {"id": "1", "name": "Susp DNS Traffic", "severity": "Medium",
                        "score": {"client": 350}}     # unrepresentable total dropped, sibling kept
    assert _names(risks)[1] == "Self-signed Certificate"        # and the other risk survives
    assert ndpi_pol.parse_ndpi_risks(nd)[0]["score"] == {"client": 350}      # structured path too


# --- the finding carries the structure (point 3) ---------------------------------
def _emit(ndpi, src, dst):
    app._store = store.make_store("memory")
    p = type("P", (), {"sent": [], "send": lambda self, t, m: self.sent.append(m),
                       "flush": lambda self: None})()
    app._handle({"event_type": "flow", "src_ip": src, "dest_ip": dst, "ndpi": ndpi,
                 "flow": {"bytes_toserver": 10, "bytes_toclient": 10, "age": 1}},
                p, time.time())
    return [m for m in p.sent if m["detector_id"] == "ndpi_risk"]


def test_finding_entity_carries_the_parsed_risk():
    cands = _emit(_EVIDENCE, "10.0.0.41", "203.0.113.41")
    assert len(cands) == 1
    assert "{'" not in cands[0]["entities"]
    ent = [e for e in json.loads(cands[0]["entities"]) if e["type"] == "ndpi_risk"][0]
    assert ent["value"] == ["Susp DNS Traffic"]               # legacy names preserved
    assert ent["risks"][0]["severity"] == "Medium"
    assert ent["risks"][0]["score"]["total"] == 460


def test_finding_keeps_distinct_risks_that_share_a_name():
    # nDPI can flag the same risk NAME under two ids with different scores/severities;
    # keying the emitted records by name dropped all but the last.
    nd = {"flow_risk": {"1": {"risk": "Susp DNS Traffic", "severity": "Medium",
                              "risk_score": {"total": 460}},
                        "2": {"risk": "Susp DNS Traffic", "severity": "High",
                              "risk_score": {"total": 800}}}}
    cands = _emit(nd, "10.0.0.43", "203.0.113.43")
    ent = [e for e in json.loads(cands[0]["entities"]) if e["type"] == "ndpi_risk"][0]
    assert ent["value"] == ["Susp DNS Traffic", "Susp DNS Traffic"]   # legacy names, unchanged
    assert [r["id"] for r in ent["risks"]] == ["1", "2"]              # emission order, both kept
    assert [r["severity"] for r in ent["risks"]] == ["Medium", "High"]
    assert [r["score"]["total"] for r in ent["risks"]] == [460, 800]


# --- U3/R15: emitted candidates must conform to the strict finding schema ---
def _load_schema():
    # locate the finding schema across layouts: repo (a parent has contracts/), a flat image
    # (/app), or not bundled -> None (schema tests then skip; R15 is also covered by
    # contracts/test_contracts.py and the behavioral image does not validate at runtime).
    here = Path(__file__).resolve()
    for base in list(here.parents) + [Path("/app")]:
        for rel in ("contracts/finding.schema.json", "finding.schema.json"):
            p = base / rel
            if p.exists():
                return json.loads(p.read_text())
    return None


_SCHEMA = _load_schema()
_PROPS = set(_SCHEMA["properties"]) if _SCHEMA else set()
_REQ = set(_SCHEMA["required"]) if _SCHEMA else set()


def _conforms(cand):
    # finding.schema.json is additionalProperties:false -> every key must be declared, required present
    assert cand is not None, "candidate was dedup-suppressed; use a unique identity/entities per test"
    extra = set(cand) - _PROPS
    assert not extra, f"undeclared fields (schema additionalProperties:false): {extra}"
    assert _REQ <= set(cand), f"missing required: {_REQ - set(cand)}"


def test_legacy_candidate_conforms_to_schema():
    if _SCHEMA is None:
        return       # schema not bundled in this image
    ent = json.dumps([{"type": "ip", "role": "src", "value": "10.0.0.9"}])
    _conforms(app._candidate("ndpi_risk", "malware", 6, 0.6, ent, "schema-legacy"))


def test_structured_candidate_conforms_to_schema():
    if _SCHEMA is None:
        return       # schema not bundled in this image
    fnds = ndpi_pol.ndpi_findings({"flow_risk": {"35": {"risk": "Susp Entropy", "severity": "Low"}}},
                                  "10.0.0.1", "10.0.0.2", "schema-structured")
    assert len(fnds) == 1
    fnd = fnds[0]
    c = app._candidate("ndpi_risk", fnd["category"], fnd["severity"], fnd["confidence"],
                       json.dumps(fnd["entities"]), "schema-structured",
                       detector_version=ndpi_pol.DETECTOR_VERSION, identity=fnd["identity"])
    _conforms(c)
    assert c["detector_version"] == "2.0" and c["category"] == "observation" and c["severity"] == 2


def test_structured_risk_finding_conforms_to_schema():
    if _SCHEMA is None:
        return       # schema not bundled in this image
    cands = _emit(_EVIDENCE, "10.0.0.42", "203.0.113.42")
    _conforms(cands[0])
    # `entities` is typed array|string with unconstrained object items, so the nested
    # risk objects need no schema change — assert that, so a tightening breaks here.
    items = _SCHEMA["properties"]["entities"]["items"]
    assert items == {"type": "object"}, f"entity items constrained: {items}"


def test_r15_fields_are_declared_in_schema():
    if _SCHEMA is None:
        return       # schema not bundled in this image
    # the fields the emitter actually sets, previously rejected by additionalProperties:false
    assert {"observed", "emitted_at", "revision"} <= _PROPS


def test_structured_mode_default_is_legacy():
    assert app.NDPI_MODE == "legacy"       # inert until explicitly enabled (plan 008 KTD6)


if __name__ == "__main__":
    import inspect
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    ran = 0
    for fn in fns:
        if inspect.getfullargspec(fn).args:
            continue
        fn(); print(f"ok  {fn.__name__}"); ran += 1
    print(f"\nall {ran} nDPI tests passed")


def test_reordered_identical_risk_set_is_one_finding_not_two():
    """Reviewer finding: the structured `risks` list rode on the finding in EMISSION
    order while the sibling `value` was sorted, so the same risk set arriving in a
    different order serialized differently and deduped as a SECOND finding. Identity
    inputs must be order-stable; evidence order must not invent a new finding."""
    a = [{"id": 2, "name": "Susp DNS Traffic", "severity": "Medium"},
         {"id": 7, "name": "Obfuscated", "severity": "Low"}]
    b = list(reversed(a))
    assert det.sorted_risks(a) == det.sorted_risks(b)
    # Same name, different score, must both survive and order stably (a name key would
    # collapse one of them).
    dup = [{"id": 1, "name": "Susp DNS Traffic", "score": {"total": 460}},
           {"id": 9, "name": "Susp DNS Traffic", "score": {"total": 120}}]
    assert len(det.sorted_risks(dup)) == 2
    assert det.sorted_risks(dup) == det.sorted_risks(list(reversed(dup)))
    assert det.sorted_risks([]) == []


_EXTRA_TESTS = [test_reordered_identical_risk_set_is_one_finding_not_two]
for _t in _EXTRA_TESTS:
    _t()
    print("ok ", _t.__name__)
