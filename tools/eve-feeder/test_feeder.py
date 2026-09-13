from feeder import route, _security_kwargs


def test_security_none_is_plaintext():
    assert _security_kwargs({}) == {}                       # no mechanism -> local/insecure bus
    assert _security_kwargs({"NDR_BUS_SASL_MECHANISM": ""}) == {}  # empty toggle (insecure recipe)


def test_security_sasl_plaintext_internal():
    env = {"NDR_BUS_SASL_MECHANISM": "SCRAM-SHA-512",
           "NDR_BUS_SASL_USER": "cernity-sensor", "NDR_BUS_SASL_PASSWORD": "pw"}
    assert _security_kwargs(env) == {"security_protocol": "SASL_PLAINTEXT",
                                     "sasl_mechanism": "SCRAM-SHA-512",
                                     "sasl_plain_username": "cernity-sensor",
                                     "sasl_plain_password": "pw"}


def test_security_sasl_ssl_with_ca():
    env = {"NDR_BUS_SASL_MECHANISM": "SCRAM-SHA-512", "NDR_BUS_SASL_USER": "u",
           "NDR_BUS_SASL_PASSWORD": "p", "NDR_BUS_TLS_CA": "/certs/ca.crt"}
    k = _security_kwargs(env)
    assert k["security_protocol"] == "SASL_SSL" and k["ssl_cafile"] == "/certs/ca.crt"


def test_security_partial_raises():
    try:
        _security_kwargs({"NDR_BUS_SASL_MECHANISM": "SCRAM-SHA-512"})   # user/pass missing
        assert False, "half-configured SASL must fail loudly"
    except SystemExit:
        pass


def test_route_flow():
    assert route({"event_type": "flow", "src_ip": "10.0.0.5"}) == ("suricata.flow.v1", b"10.0.0.5")


def test_route_dns():
    assert route({"event_type": "dns", "src_ip": "10.0.0.9"}) == ("suricata.dns.v1", b"10.0.0.9")


def test_route_unkeyed():
    assert route({"event_type": "flow"}) == ("suricata.flow.v1", b"unkeyed")


def test_route_unknown_type():
    assert route({"event_type": "smtp", "src_ip": "10.0.0.1"}) == ("suricata.raw.v1", b"10.0.0.1")


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok", _n)
    print("ok test_feeder")
