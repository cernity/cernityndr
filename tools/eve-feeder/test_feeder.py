from datetime import datetime, timezone

from feeder import route, _security_kwargs, paced_offsets, reanchor, _parse


def test_paced_offsets_honours_interarrival():
    evs = [{"timestamp": "2026-01-01T00:00:00+00:00"},
           {"timestamp": "2026-01-01T00:00:05+00:00"},
           {"timestamp": "2026-01-01T00:00:10+00:00"}]
    assert paced_offsets(evs) == [0.0, 5.0, 10.0]
    assert paced_offsets(evs, speed=2) == [0.0, 2.5, 5.0]        # labelled acceleration


def test_paced_offsets_untimestamped_inherits_previous():
    evs = [{"timestamp": "2026-01-01T00:00:00+00:00"}, {"no": "ts"},
           {"timestamp": "2026-01-01T00:00:04+00:00"}]
    assert paced_offsets(evs) == [0.0, 0.0, 4.0]


def test_paced_offsets_max_gap_caps_idle_but_default_is_true_timing():
    evs = [{"timestamp": "2026-01-01T00:00:00+00:00"},
           {"timestamp": "2026-01-01T00:01:00+00:00"},   # 60s gap
           {"timestamp": "2026-01-01T00:01:05+00:00"}]   # +5s
    assert paced_offsets(evs) == [0.0, 60.0, 65.0]                 # default: true timing, no cap
    assert paced_offsets(evs, max_gap=10) == [0.0, 10.0, 15.0]     # labelled idle-gap compression


def test_paced_offsets_clamps_out_of_order_delta():
    evs = [{"timestamp": "2026-01-01T00:00:10+00:00"},
           {"timestamp": "2026-01-01T00:00:05+00:00"}]   # earlier than previous
    assert paced_offsets(evs) == [0.0, 0.0]                        # negative delta clamps to 0


def test_reanchor_anchor_start_vs_end():
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    def mk():
        return [{"timestamp": "2026-01-01T00:00:00+00:00"},
                {"timestamp": "2026-01-01T00:01:00+00:00"}]     # 60s apart
    end = reanchor(mk(), now=now, anchor="end")
    assert _parse(end[-1]["timestamp"]) == now                  # newest at now (burst)
    start = reanchor(mk(), now=now, anchor="start")
    assert _parse(start[0]["timestamp"]) == now                 # oldest at now (paced)
    assert (_parse(end[-1]["timestamp"]) - _parse(end[0]["timestamp"])).total_seconds() == 60


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
