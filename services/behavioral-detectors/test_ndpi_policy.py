"""nDPI structured-parser tests (plan 008 U1; pure)."""
import copy

import ndpi_policy as p


def test_canonical_nested_flow_risk():
    # the real deployed shape (U0 manifest): flow_risk keyed by enum id
    ndpi = {"flow_risk": {"46": {"risk": "Unidirectional Traffic", "severity": "Low",
                                 "risk_score": {"total": 500, "client": 430, "server": 70}}},
            "breed": "Safe", "proto": "TLS"}
    e = p.parse_ndpi_risks(ndpi)
    assert len(e) == 1
    r = e[0]
    assert r["id"] == "46" and r["name"] == "Unidirectional Traffic"
    assert r["severity"] == "Low" and r["severity_known"] is True
    assert r["score"] == {"total": 500, "client": 430, "server": 70}
    assert r["score_scope"] == "unverified" and r["source"] == "flow_risk"
    assert "malformed" not in r


def test_prefers_flow_risk_over_legacy_risk():
    ndpi = {"flow_risk": {"35": {"risk": "Susp Entropy", "severity": "Low"}},
            "risk": {"99": {"risk": "Should Be Ignored", "severity": "Critical"}}}
    e = p.parse_ndpi_risks(ndpi)
    assert [r["name"] for r in e] == ["Susp Entropy"]
    assert all(r["source"] == "flow_risk" for r in e)


def test_legacy_risk_fallback_when_no_flow_risk():
    e = p.parse_ndpi_risks({"risk": {"5": {"risk": "Known Proto on Non Std Port", "severity": "Medium"}}})
    assert len(e) == 1 and e[0]["source"] == "risk" and e[0]["severity"] == "Medium"


def test_id_name_mapping_shape():
    e = p.parse_ndpi_risks({"flow_risk": {"12": "Some Risk"}})
    assert len(e) == 1 and e[0]["id"] == "12" and e[0]["name"] == "Some Risk"
    assert e[0]["severity"] is None and e[0]["severity_known"] is False


def test_name_true_membership_flags():
    e = p.parse_ndpi_risks({"flow_risk": {"Susp Entropy": True, "Not Present": False}})
    assert [r["name"] for r in e] == ["Susp Entropy"]        # false membership contributes nothing


def test_bool_is_not_a_score_component():
    ndpi = {"flow_risk": {"1": {"risk": "X", "severity": "Low",
                                "risk_score": {"total": True, "client": 5, "server": -3}}}}
    r = p.parse_ndpi_risks(ndpi)[0]
    assert r["score"] == {"client": 5}                        # bool total + negative server dropped


def test_nan_and_inf_scores_dropped():
    ndpi = {"flow_risk": {"1": {"risk": "X", "severity": "Low",
                                "risk_score": {"total": float("nan"), "client": float("inf"), "server": 7}}}}
    assert p.parse_ndpi_risks(ndpi)[0]["score"] == {"server": 7}


def test_unknown_tier_preserved_but_flagged():
    r = p.parse_ndpi_risks({"flow_risk": {"1": {"risk": "X", "severity": "Spicy"}}})[0]
    assert r["severity"] == "Spicy" and r["severity_known"] is False
    assert "unknown severity tier" in r["malformed"]


def test_missing_name_is_malformed_but_keeps_siblings():
    ndpi = {"flow_risk": {"1": {"severity": "Low"},                       # no risk name
                          "2": {"risk": "Good", "severity": "Low"}}}
    e = p.parse_ndpi_risks(ndpi)
    assert len(e) == 2
    bad = [r for r in e if r["id"] == "1"][0]
    good = [r for r in e if r["id"] == "2"][0]
    assert "malformed" in bad and good["name"] == "Good" and "malformed" not in good


def test_non_dict_ndpi_and_no_risk_field_yield_empty():
    assert p.parse_ndpi_risks(None) == []
    assert p.parse_ndpi_risks("nope") == []
    assert p.parse_ndpi_risks([1, 2]) == []
    assert p.parse_ndpi_risks({"breed": "Safe", "proto": "TLS"}) == []
    assert p.parse_ndpi_risks({"flow_risk": {}}) == []          # canonical-but-empty is not a risk


def test_legacy_stringified_dict_is_opaque_never_evaled():
    # a historical entities-style string must be treated as an opaque name, not parsed
    s = "{'risk': 'Susp Entropy', 'severity': 'Low'}"
    e = p.parse_ndpi_risks({"risk": [s]})
    assert len(e) == 1 and e[0]["name"] == s and e[0]["severity"] is None


def test_input_is_not_mutated():
    ndpi = {"flow_risk": {"46": {"risk": "Unidirectional Traffic", "severity": "Low",
                                 "risk_score": {"total": 500}}}}
    before = copy.deepcopy(ndpi)
    p.parse_ndpi_risks(ndpi)
    assert ndpi == before


def test_oversized_risk_set_is_capped():
    big = {"flow_risk": {str(i): {"risk": f"R{i}", "severity": "Low"} for i in range(500)}}
    assert len(p.parse_ndpi_risks(big)) == p.MAX_RISKS


def test_name_length_bounded():
    r = p.parse_ndpi_risks({"flow_risk": {"1": {"risk": "z" * 5000, "severity": "Low"}}})[0]
    assert len(r["name"]) == p.MAX_NAME




# --- U2: classification tests (plan 008 KTD1-KTD3) ---
def _e(name, sev=None):
    return {"name": name, "severity": sev, "severity_known": sev in p.TIERS}


def test_classify_all_observed_are_observation_low():
    for name in ("Known Proto on Non Std Port", "HTTP Susp User-Agent",
                 "TLS (probably) Not Carrying HTTPS", "Missing SNI TLS Extn",
                 "TLS Fatal Alert", "Susp Entropy", "Unidirectional Traffic", "Minor Issues"):
        v = p.classify_ndpi_risk(_e(name, "Low"))
        assert v["category"] == "observation" and v["severity"] == 2
        assert v["disposition"] == "emit_low" and v["confidence"] == 0.20 and v["verified"] is True


def test_high_tier_heuristic_still_observation_2():
    # id=11 HTTP Susp User-Agent is nDPI High, but a heuristic UA -> observation/2 (per decision)
    v = p.classify_ndpi_risk(_e("HTTP Susp User-Agent", "High"))
    assert v["category"] == "observation" and v["severity"] == 2


def test_unknown_name_is_unclassified_not_malware():
    v = p.classify_ndpi_risk(_e("Totally New Risk Name", "Critical"))
    assert v["category"] == "unclassified" and v["severity"] == 1 and v["verified"] is False


def test_no_substring_matching():
    # a name containing an exact rule as a substring must NOT match it
    v = p.classify_ndpi_risk(_e("Susp Entropy And Then Some", "Low"))
    assert v["category"] == "unclassified"


def test_policy_band_maps_and_clamps_native_tier():
    # clear-text credentials band (2,5): High tier -> 6 clamped to 5
    v = p.classify_ndpi_risk(_e("Clear-Text Credentials", "High"))
    assert v["category"] == "policy" and v["severity"] == 5 and v["severity_basis"] == "native_tier"
    # Low tier -> 2 (band floor)
    assert p.classify_ndpi_risk(_e("Clear-Text Credentials", "Low"))["severity"] == 2


def test_severity_is_derived_not_constant():
    lo = p.classify_ndpi_risk(_e("Malicious JA3 Fingerprint", "Low"))["severity"]   # band (3,7) floor 3
    hi = p.classify_ndpi_risk(_e("Malicious JA3 Fingerprint", "Severe"))["severity"] # tier 7 -> 7
    assert lo == 3 and hi == 7 and lo != hi


def test_confidence_weights_by_category():
    assert p.classify_ndpi_risk(_e("Clear-Text Credentials", "Low"))["confidence"] == 0.80
    assert p.classify_ndpi_risk(_e("Malicious JA3 Fingerprint", "Low"))["confidence"] == 0.50
    assert p.classify_ndpi_risk(_e("Susp Entropy", "Low"))["confidence"] == 0.20
    assert all(p.classify_ndpi_risk(_e(n, "Low"))["calibrated"] is False
               for n in ("Susp Entropy", "Clear-Text Credentials"))


def test_breed_smbv1_is_policy_3():
    v = p.classify_breed("Dangerous", "NetBIOS.SMBv1")
    assert v["category"] == "policy" and v["severity"] == 3 and v["rule"] == "breed:smbv1"


def test_generic_dangerous_breed_is_observation():
    v = p.classify_breed("Unsafe", "SomeProto")
    assert v["category"] == "observation" and v["severity"] == 2


def test_safe_breed_is_not_a_finding():
    assert p.classify_breed("Safe", "TLS") is None
    assert p.classify_breed("Acceptable", "TLS") is None
    assert p.classify_breed("", "") is None


# --- U3: ndpi_findings assembly tests (plan 008 KTD4/KTD5) ---
def test_findings_entropy_is_one_observation():
    nd = {"flow_risk": {"35": {"risk": "Susp Entropy", "severity": "Low",
                               "risk_score": {"total": 210}}}, "breed": "Safe", "proto": "TLS"}
    fs = p.ndpi_findings(nd, "10.0.0.1", "10.0.0.2", "t1")
    assert len(fs) == 1
    f0 = fs[0]
    assert f0["category"] == "observation" and f0["severity"] == 2 and f0["disposition"] == "emit_low"
    roles = {e.get("role"): e.get("value") for e in f0["entities"] if e.get("type") == "ip"}
    assert roles == {"src": "10.0.0.1", "dst": "10.0.0.2"}
    ev = [e for e in f0["entities"] if e["type"] == "ndpi_evidence"][0]["value"]
    assert ev["category"] == "observation" and ev["calibrated"] is False
    assert ev["risks"][0]["native_severity"] == "Low" and ev["risks"][0]["score_scope"] == "unverified"
    assert "observation" in f0["identity"] and "t1" in f0["identity"]


def test_findings_mixed_categories_split():
    nd = {"flow_risk": {"35": {"risk": "Susp Entropy", "severity": "Low"},
                        "3": {"risk": "Clear-Text Credentials", "severity": "High"}}}
    fs = p.ndpi_findings(nd, "a", "b", "t1")
    cats = {f["category"]: f["severity"] for f in fs}
    assert cats == {"observation": 2, "policy": 5}          # separate findings, distinct severities
    assert len({f["identity"] for f in fs}) == 2


def test_findings_smbv1_breed_is_policy_3():
    fs = p.ndpi_findings({"breed": "Dangerous", "proto": "NetBIOS.SMBv1"}, "a", "b", "t1")
    assert len(fs) == 1 and fs[0]["category"] == "policy" and fs[0]["severity"] == 3


def test_findings_identity_stable_across_score_and_order():
    a = {"flow_risk": {"35": {"risk": "Susp Entropy", "severity": "Low", "risk_score": {"total": 210}},
                       "46": {"risk": "Unidirectional Traffic", "severity": "Low"}}}
    b = {"flow_risk": {"46": {"risk": "Unidirectional Traffic", "severity": "Low"},
                       "35": {"risk": "Susp Entropy", "severity": "Low", "risk_score": {"total": 999}}}}
    ia = p.ndpi_findings(a, "s", "d", "t1")[0]["identity"]
    ib = p.ndpi_findings(b, "s", "d", "t1")[0]["identity"]
    assert ia == ib                                          # score + key order do not change identity


def test_findings_identity_separates_endpoints_and_category():
    base = {"flow_risk": {"35": {"risk": "Susp Entropy", "severity": "Low"}}}
    i1 = p.ndpi_findings(base, "s", "d1", "t1")[0]["identity"]
    i2 = p.ndpi_findings(base, "s", "d2", "t1")[0]["identity"]
    i3 = p.ndpi_findings(base, "s", "d1", "t2")[0]["identity"]
    assert i1 != i2 and i1 != i3                             # dst and tenant are in identity


def test_findings_empty_when_no_risk_and_safe_breed():
    assert p.ndpi_findings({"breed": "Safe", "proto": "TLS"}, "a", "b", "t1") == []
    assert p.ndpi_findings({}, "a", "b", "t1") == []


def test_findings_unknown_risk_is_unclassified():
    fs = p.ndpi_findings({"flow_risk": {"99": {"risk": "Brand New Risk", "severity": "Critical"}}}, "a", "b", "t1")
    assert len(fs) == 1 and fs[0]["category"] == "unclassified" and fs[0]["severity"] == 1



if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} ndpi_policy tests passed")
