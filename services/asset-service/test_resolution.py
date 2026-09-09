"""U17 asset resolution tests (pure)."""
import resolution as r

FLOW = {"event_type": "flow", "src_ip": "10.0.0.5", "dest_ip": "1.1.1.1"}
ARP = {"event_type": "arp", "arp": {"src_ip": "10.0.0.5", "src_mac": "AA:BB:CC:00:11:22"}}
DHCP = {"event_type": "dhcp", "dhcp": {"assigned_ip": "10.0.0.5",
        "client_mac": "aa:bb:cc:00:11:22", "hostname": "laptop-1"}}


def test_flow_yields_two_ip_only_observations():
    obs = r.extract_evidence(FLOW)
    assert len(obs) == 2 and all(o["mac"] is None for o in obs)


def test_arp_yields_ip_and_mac():
    o = r.extract_evidence(ARP)[0]
    assert o["ip"] == "10.0.0.5" and o["mac"] == "AA:BB:CC:00:11:22"


def test_dhcp_yields_ip_mac_hostname():
    o = r.extract_evidence(DHCP)[0]
    assert o["hostname"] == "laptop-1" and o["mac"].endswith("11:22")


def test_mac_first_asset_key():
    o = r.extract_evidence(ARP)[0]
    assert r.asset_key(o, {}) == "mac:aa:bb:cc:00:11:22"


def test_ip_only_resolves_via_known_binding():
    # once ARP taught us 10.0.0.5 -> MAC, an IP-only flow obs resolves to the MAC.
    ip_to_mac = {"10.0.0.5": "aa:bb:cc:00:11:22"}
    flow_obs = r.extract_evidence(FLOW)[0]           # 10.0.0.5, no mac
    assert r.asset_key(flow_obs, ip_to_mac) == "mac:aa:bb:cc:00:11:22"


def test_unknown_ip_keys_on_ip():
    assert r.asset_key({"ip": "9.9.9.9", "mac": None}, {}) == "ip:9.9.9.9"


def test_cross_sensor_same_mac_same_key():
    # same device, two sensors, different-cased MAC -> one asset_key.
    o1 = r.asset_key({"ip": "10.0.0.5", "mac": "AA:BB:CC:00:11:22"}, {})
    o2 = r.asset_key({"ip": "10.0.0.99", "mac": "aa:bb:cc:00:11:22"}, {})
    assert o1 == o2


def test_merge_accumulates_and_raises_confidence():
    a = r.merge(None, r.extract_evidence(ARP)[0], "t1")
    a = r.merge(a, r.extract_evidence(DHCP)[0], "t2")
    assert "laptop-1" in a["hostname_set"]
    assert "aa:bb:cc:00:11:22" in a["mac_set"]      # normalized lower, deduped
    assert a["confidence"] > 0.5 and a["last_seen"] == "t2"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} resolution tests passed")
