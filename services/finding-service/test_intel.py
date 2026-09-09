"""intel (Tier-2) tests — pure, via injected resolver/fetch hooks. No network."""
import json
import os
import tempfile

# Enable the toggles for the test process BEFORE importing the module.
os.environ["INTEL_RDNS"] = "1"
os.environ["INTEL_RDAP"] = "1"
os.environ["INTEL_NRD_DAYS"] = "30"
os.environ["GREYNOISE_API_KEY"] = "test-key"
os.environ["VIRUSTOTAL_API_KEY"] = "test-key"

import intel


def _finding(entities):
    return {"finding_id": "x", "entities": json.dumps(entities)}


def test_registrable():
    assert intel.registrable("a.b.evil.com") == "evil.com"
    assert intel.registrable("evil.com") == "evil.com"
    assert intel.registrable("localhost") == "localhost"


def test_registration_date_parse():
    rdap = {"events": [{"eventAction": "last changed", "eventDate": "2020-01-01T00:00:00Z"},
                       {"eventAction": "registration", "eventDate": "2021-06-15T00:00:00Z"}]}
    d = intel._registration_date(rdap)
    assert d is not None and d.year == 2021 and d.month == 6


def test_domain_age_and_nrd():
    from datetime import datetime, timezone, timedelta
    recent = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    fetch = lambda dom: {"events": [{"eventAction": "registration", "eventDate": recent}]}
    f = _finding([{"type": "sni", "value": "brand-new.evil.com"}])
    intel.enrich(f, hooks={"rdap": fetch})
    dom = f["intel"]["domains"]["brand-new.evil.com"]
    assert dom["age_days"] in (2, 3) and dom["nrd"] is True


def test_old_domain_not_nrd():
    fetch = lambda dom: {"events": [{"eventAction": "registration", "eventDate": "2005-01-01T00:00:00Z"}]}
    f = _finding([{"type": "domain", "value": "old.example.com"}])
    intel.enrich(f, hooks={"rdap": fetch})
    assert f["intel"]["domains"]["old.example.com"]["nrd"] is False


def test_reverse_dns_and_greynoise():
    f = _finding([{"type": "ip", "role": "dst", "value": "8.8.8.8"}])
    intel.enrich(f, hooks={"resolver": lambda ip: "dns.google",
                           "greynoise": lambda ip: {"noise": True, "riot": False,
                                                    "classification": "benign", "name": "Shodan.io"},
                           "virustotal": lambda ip: {}})   # no-op VT fetch (avoid real network)
    assert f["intel"]["rdns"]["8.8.8.8"] == "dns.google"
    rep = f["intel"]["reputation"]["8.8.8.8"]
    assert rep["classification"] == "benign" and rep["name"] == "Shodan.io" and rep["noise"] is True


def test_greynoise_unobserved_still_reports_noise_riot():
    f = _finding([{"type": "ip", "role": "dst", "value": "9.9.9.9"}])   # unique IP (cache is per-IP)
    intel.enrich(f, hooks={"resolver": lambda ip: None, "virustotal": lambda ip: {},
                           "greynoise": lambda ip: {"noise": False, "riot": False,
                                                    "message": "IP not observed"}})
    assert f["intel"]["reputation"]["9.9.9.9"] == {"noise": False, "riot": False}


def test_virustotal_stats():
    vt_json = {"data": {"attributes": {"last_analysis_stats":
               {"malicious": 3, "suspicious": 1, "harmless": 60, "undetected": 25}}}}
    f = _finding([{"type": "ip", "role": "dst", "value": "1.2.3.4"}])   # routable (external)
    intel.enrich(f, hooks={"virustotal": lambda ip: vt_json})
    assert f["intel"]["virustotal"]["1.2.3.4"] == {"malicious": 3, "suspicious": 1, "harmless": 60}


def test_fingerprint_name_from_map():
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({"abc123": "Cobalt Strike (default)"}, fh)
        path = fh.name
    intel.FP_MAP_PATH = path
    intel._FP_MAP = None                              # reset cache to pick up the override
    assert intel.fingerprint_name("ABC123") == "Cobalt Strike (default)"
    assert intel.fingerprint_name("nope") is None
    os.unlink(path)


def test_reputation_skips_internal_ips():
    # Internal IPs must never be sent to VT/GreyNoise (privacy + pointlessness).
    called = []
    f = _finding([{"type": "ip", "role": "src", "value": "10.0.0.5"},
                  {"type": "ip", "role": "dst", "value": "192.168.1.9"}])
    intel.enrich(f, hooks={"resolver": lambda ip: None,
                           "virustotal": lambda ip: called.append(ip) or {},
                           "greynoise": lambda ip: called.append(ip) or {}})
    assert called == [], f"reputation APIs were queried for internal IPs: {called}"
    assert "virustotal" not in f.get("intel", {})


def test_no_entities_no_intel():
    f = {"finding_id": "x", "entities": ""}
    intel.enrich(f)
    assert "intel" not in f


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print("ok ", fn.__name__)
    print("all %d intel tests passed" % len(fns))
