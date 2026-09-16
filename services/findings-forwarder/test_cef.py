import cef

FINDING = {
    "finding_id": "beacon-1", "detector_id": "beacon", "category": "c2",
    "severity": 8, "tenant_id": "default", "mitre": ["T1071"],
    "entities": [{"type": "ip", "role": "src", "value": "10.0.0.5"},
                 {"type": "ip", "role": "dst", "value": "203.0.113.10"}],
}


def test_cef_header_and_fields():
    line = cef.to_cef(FINDING)
    assert line.startswith("CEF:0|Cernity|NDR|1.0|beacon|c2|8|")
    assert "src=10.0.0.5" in line
    assert "dst=203.0.113.10" in line
    assert "cs1=beacon-1" in line
    assert "cs2=T1071" in line


def test_cef_entities_from_json_string():
    f = dict(FINDING, entities='[{"role":"src","value":"1.1.1.1"},{"role":"dst","value":"2.2.2.2"}]')
    line = cef.to_cef(f)
    assert "src=1.1.1.1" in line and "dst=2.2.2.2" in line


def test_cef_escapes_pipe_in_header():
    line = cef.to_cef(dict(FINDING, detector_id="a|b"))
    assert "a\\|b" in line


def test_cef_maps_slips_attacker_victim_roles():
    # handoff §4: SLIPS entities use attacker/victim, not src/dst — the reviewed extractor
    # produced no src/dst for every SLIPS finding. attacker->src, victim->dst.
    f = {"finding_id": "slips-1", "detector_id": "slips_ml", "category": "c2", "severity": 8,
         "tenant_id": "t",
         "entities": [{"type": "ip", "role": "attacker", "value": "10.0.0.9"},
                      {"type": "ip", "role": "victim", "value": "8.8.8.8"}]}
    line = cef.to_cef(f)
    assert "src=10.0.0.9" in line and "dst=8.8.8.8" in line


def test_cef_carries_revision_and_evidence_link():
    f = dict(FINDING, revision=3, evidence_refs=["minio://ndr-pcap/x.pcap", "minio://ndr-pcap/y"])
    line = cef.to_cef(f)
    assert "cs4=3" in line and "cs4Label=revision" in line
    assert "flexString1=minio://ndr-pcap/x.pcap" in line     # first evidence pointer (companion path)


def test_cef_carries_reverse_dns_domains():
    # §6.5: reverse-DNS enrichment must reach the transport, mapped to CEF's DNS-domain keys.
    f = dict(FINDING, intel={"rdns": {"10.0.0.5": "host.internal", "203.0.113.10": "evil.example"}})
    line = cef.to_cef(f)
    assert "sourceDnsDomain=host.internal" in line
    assert "destinationDnsDomain=evil.example" in line


def test_cef_carries_community_id_from_source_events():
    # U5: CEF carries the community_id pivot from source_events; the full EVE rides the JSON sink.
    f = dict(FINDING, source_events=[{"event_type": "quic", "community_id": "1:abc=",
                                      "record": {"quic": {"ja4": "q13d.."}}}])
    line = cef.to_cef(f)
    # CEF ext-value escaping turns '=' into '\=', so match the label + the escaped value.
    assert "cs5Label=communityId" in line and "cs5=1:abc" in line


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"all {len(fns)} cef tests passed")
