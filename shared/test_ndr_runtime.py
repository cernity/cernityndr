"""Broker-free tests for the shared runtime (plan 003 U1): config defaults +
override precedence + the partition-assignment helper. No KafkaConsumer is
constructed (the kafka import in ndr_runtime is lazy), so this runs in the build
gate without a broker."""
import os

import ndr_runtime as rt


class _FakeTP:
    def __init__(self, topic, partition):
        self.topic, self.partition = topic, partition


class _FakeConsumer:
    def __init__(self, tps):
        self._tps = set(tps)

    def assignment(self):
        return self._tps


def test_consumer_defaults():
    c = rt._consumer_config("g")
    assert c["group_id"] == "g"
    assert c["max_poll_records"] == 1000
    assert c["enable_auto_commit"] is True
    assert c["fetch_max_bytes"] == 52428800


def test_env_and_explicit_override_precedence():
    os.environ["NDR_MAX_POLL_RECORDS"] = "250"
    try:
        assert rt._consumer_config("g")["max_poll_records"] == 250          # env wins over default
        assert rt._consumer_config("g", max_poll_records=7)["max_poll_records"] == 7  # explicit wins over env
    finally:
        del os.environ["NDR_MAX_POLL_RECORDS"]


def test_malformed_env_falls_back_to_default():
    os.environ["NDR_MAX_POLL_RECORDS"] = "notanint"
    try:
        assert rt._consumer_config("g")["max_poll_records"] == 1000
    finally:
        del os.environ["NDR_MAX_POLL_RECORDS"]


def test_producer_tuning():
    p = rt._producer_config()
    assert p["linger_ms"] == 10 and p["batch_size"] == 65536 and p["compression_type"] == "lz4"
    assert rt._producer_config(compression_type="zstd")["compression_type"] == "zstd"


def test_security_unset_is_empty_and_configs_unchanged():
    # default internal path: no SASL keys leak into the configs
    assert rt._security_config() == {}
    c = rt._consumer_config("g")
    assert "security_protocol" not in c and "sasl_mechanism" not in c
    assert "security_protocol" not in rt._producer_config()


def test_security_full_sasl_env_populates_both_configs():
    env = {"NDR_BUS_SASL_MECHANISM": "SCRAM-SHA-512", "NDR_BUS_SASL_USER": "sensor",
           "NDR_BUS_SASL_PASSWORD": "pw", "NDR_BUS_TLS_CA": "/certs/ca.crt"}
    os.environ.update(env)
    try:
        assert rt._security_config() == {
            "security_protocol": "SASL_SSL", "sasl_mechanism": "SCRAM-SHA-512",
            "sasl_plain_username": "sensor", "sasl_plain_password": "pw",
            "ssl_cafile": "/certs/ca.crt"}
        assert rt._consumer_config("g")["security_protocol"] == "SASL_SSL"
        assert rt._producer_config()["sasl_mechanism"] == "SCRAM-SHA-512"
    finally:
        for k in env:
            del os.environ[k]


def test_security_no_ca_is_sasl_plaintext():
    # No CA -> SASL over plaintext, for the central pipeline authenticating to the
    # internal listener on the private docker network (not reachable off-box). A
    # remote sensor sets NDR_BUS_TLS_CA and gets SASL_SSL (test above).
    env = {"NDR_BUS_SASL_MECHANISM": "SCRAM-SHA-512", "NDR_BUS_SASL_USER": "u",
           "NDR_BUS_SASL_PASSWORD": "p"}
    os.environ.update(env)
    try:
        s = rt._security_config()
        assert "ssl_cafile" not in s and s["security_protocol"] == "SASL_PLAINTEXT"
        assert rt._consumer_config("g")["security_protocol"] == "SASL_PLAINTEXT"
    finally:
        for k in env:
            del os.environ[k]


def test_security_partial_env_raises():
    os.environ["NDR_BUS_SASL_MECHANISM"] = "SCRAM-SHA-512"       # user/pass missing
    try:
        try:
            rt._security_config()
            assert False, "missing user/pass must raise"
        except ValueError:
            pass
    finally:
        del os.environ["NDR_BUS_SASL_MECHANISM"]


def test_explicit_security_override_wins_over_env():
    env = {"NDR_BUS_SASL_MECHANISM": "SCRAM-SHA-512", "NDR_BUS_SASL_USER": "u",
           "NDR_BUS_SASL_PASSWORD": "p"}
    os.environ.update(env)
    try:
        c = rt._consumer_config("g", security_protocol="PLAINTEXT")
        assert c["security_protocol"] == "PLAINTEXT"            # explicit wins over env
    finally:
        for k in env:
            del os.environ[k]


def test_assigned_partitions_scopes_by_topic():
    c = _FakeConsumer([_FakeTP("suricata.flow.v1", 0), _FakeTP("suricata.flow.v1", 3),
                       _FakeTP("suricata.dns.v1", 1)])
    assert rt.assigned_partitions(c) == {0, 1, 3}
    assert rt.assigned_partitions(c, "suricata.flow.v1") == {0, 3}


def test_assigned_partitions_empty_before_rebalance():
    assert rt.assigned_partitions(_FakeConsumer([])) == set()


def test_metrics_attribute_resolves_lazily():
    # Services that run their own metrics server reach it as ndr_runtime.metrics;
    # the lazy PEP 562 __getattr__ must resolve it (regression: it once raised
    # AttributeError after metrics became a lazy import, crash-looping 4 detectors).
    assert rt.metrics.__name__ == "metrics"
    try:
        rt.definitely_not_an_attribute
        assert False, "unknown attribute should raise"
    except AttributeError:
        pass


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f()
            print("ok", _n)
    print("all ndr_runtime tests passed")
