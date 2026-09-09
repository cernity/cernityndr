"""U8 correlation logic tests (pure, stdlib only)."""
import correlate as c


def _f(fid, det, cat, sev, ts, mitre=None):
    return {"finding_id": fid, "detector_id": det, "category": cat,
            "severity": sev, "ts": ts, "mitre": mitre or []}


def test_single_finding_below_threshold_no_incident():
    fire, reason = c.should_incident([_f("a", "beacon", "c2", 7, 1000)], now=1000)
    assert not fire, reason


def test_multi_tactic_ordered_chain_incident():
    fs = [
        _f("s", "horizontal_scan", "recon", 5, 1000, ["T1046"]),
        _f("i", "ids_signature", "malware", 9, 1100, ["T1071"]),
        _f("b", "beacon", "c2", 7, 1200, ["T1071"]),
        _f("l", "lateral_movement", "lateral", 7, 1300, ["T1021"]),
    ]
    fire, reason = c.should_incident(fs, now=1300)
    assert fire and reason == "kill-chain", reason
    inc = c.build_incident("10.0.0.5", fs, now=1300)
    assert inc["detector_id"] == "correlation_incident"
    assert inc["severity"] >= 9
    assert set(inc["evidence_refs"]) == {"s", "i", "b", "l"}
    assert inc["mitre"] == ["T1021", "T1046", "T1071"]
    assert "reconnaissance -> " in inc["entities"]


def test_dedup_same_detector_no_inflation():
    many = [_f(f"n{i}", "ndpi_risk", "malware", 6, 1000 + i) for i in range(10)]
    one = [_f("n0", "ndpi_risk", "malware", 6, 1009)]
    assert c.entity_risk(many, now=1010) == c.entity_risk(one, now=1010)


def test_risk_threshold_trips_without_chain():
    # three distinct high-sev detectors in the SAME stage: risk trips it, not a chain
    fs = [_f(f"x{i}", f"det{i}", "c2", 8, 1000) for i in range(3)]
    fire, reason = c.should_incident(fs, now=1000, params={"risk_threshold": 12.0})
    assert fire and reason == "risk-threshold", reason


def test_risk_decays():
    fresh = [_f("a", "beacon", "c2", 8, 1000)]
    assert c.entity_risk(fresh, now=1000) > c.entity_risk(fresh, now=1000 + 3600)


def test_incident_input_ignored():
    fs = [_f("inc", "correlation_incident", "incident", 9, 1000),
          _f("b", "beacon", "c2", 7, 1000)]
    fire, _ = c.should_incident(fs, now=1000)
    assert not fire  # only the single beacon counts, incident is filtered out


def test_single_stage_is_not_a_chain():
    fs = [_f("a", "beacon", "c2", 7, 1000), _f("b", "long_connection", "c2", 5, 1100)]
    assert not c.is_ordered_chain(fs)  # both are stage 2


def test_unrelated_categories_do_not_forge_a_chain_without_order():
    # exfil then recon (backwards) is two stages but never a forward progression
    fs = [_f("e", "exfil", "exfil", 8, 1000), _f("r", "scan", "recon", 5, 1100)]
    assert not c.is_ordered_chain(fs)


def test_multi_tactic_fires_regardless_of_order():
    # intent: two distinct kill-chain stages on one entity is worth an incident
    # even when forward order cannot be proven (an ordered chain just scores
    # higher). The same backwards pair above is a chain=no but multi-tactic=yes.
    fs = [_f("e", "exfil", "exfil", 8, 1000), _f("r", "scan", "recon", 5, 1100)]
    fire, reason = c.should_incident(fs, now=1100)
    assert fire and reason == "multi-tactic", reason


def test_elevated_risk_narrative_when_no_stage():
    # a category with no kill-chain stage still builds an incident via risk,
    # with the fallback narrative.
    fs = [_f(f"x{i}", f"d{i}", "unknown", 8, 1000) for i in range(2)]
    fire, reason = c.should_incident(fs, now=1000, params={"risk_threshold": 12.0})
    assert fire and reason == "risk-threshold", reason
    inc = c.build_incident("host1", fs, now=1000, reason=reason)
    assert "elevated risk" in inc["entities"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("ok ", fn.__name__)
    print(f"\nall {len(fns)} correlation tests passed")
