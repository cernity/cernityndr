"""Managed-config tests (plan U4)."""
import config_source as cs


def test_bootstrap_defaults_match_constants():
    snap = cs.current()
    assert snap["beacon_threshold"] == 0.80
    assert snap["exfil_bytes"] == 50_000_000
    assert snap["strobe_min_conns"] == 90


def test_valid_override_merges_onto_defaults():
    m = cs._validate_and_merge({"beacon_threshold": 0.7, "exfil_bytes": 1000})
    assert m["beacon_threshold"] == 0.7 and m["exfil_bytes"] == 1000
    assert m["strobe_min_conns"] == 90            # untouched key keeps default


def test_unknown_and_bad_type_values_dropped():
    m = cs._validate_and_merge({"bogus_key": 1, "beacon_threshold": "not-a-number"})
    assert "bogus_key" not in m
    assert m["beacon_threshold"] == 0.80          # bad type rejected, default kept


def test_empty_or_malformed_doc_yields_defaults():
    assert cs._validate_and_merge({}) == cs.DEFAULTS
    assert cs._validate_and_merge(None) == cs.DEFAULTS


def test_allowlists_fold_into_detector_module():
    class D:
        _BEACON_ALLOW = {"8.8.8.8"}
        _EXFIL_ALLOW = ("160.79.104.",)
    cs.apply_allowlists(D, {"beacon_allowlist": ["1.1.1.1"], "exfil_allowlist": ["203.0.113."]})
    assert "1.1.1.1" in D._BEACON_ALLOW and "8.8.8.8" in D._BEACON_ALLOW
    assert "203.0.113." in D._EXFIL_ALLOW and "160.79.104." in D._EXFIL_ALLOW


if __name__ == "__main__":
    import inspect
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        if inspect.getfullargspec(fn).args:
            continue
        fn(); print(f"ok  {fn.__name__}")
    print("all config-source tests passed")
