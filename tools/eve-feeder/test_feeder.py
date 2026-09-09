from feeder import route


def test_route_flow():
    assert route({"event_type": "flow", "src_ip": "10.0.0.5"}) == ("suricata.flow.v1", b"10.0.0.5")


def test_route_dns():
    assert route({"event_type": "dns", "src_ip": "10.0.0.9"}) == ("suricata.dns.v1", b"10.0.0.9")


def test_route_unkeyed():
    assert route({"event_type": "flow"}) == ("suricata.flow.v1", b"unkeyed")


def test_route_unknown_type():
    assert route({"event_type": "smtp", "src_ip": "10.0.0.1"}) == ("suricata.raw.v1", b"10.0.0.1")


if __name__ == "__main__":
    test_route_flow()
    test_route_dns()
    test_route_unkeyed()
    test_route_unknown_type()
    print("ok test_feeder")
