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


def test_assigned_partitions_scopes_by_topic():
    c = _FakeConsumer([_FakeTP("suricata.flow.v1", 0), _FakeTP("suricata.flow.v1", 3),
                       _FakeTP("suricata.dns.v1", 1)])
    assert rt.assigned_partitions(c) == {0, 1, 3}
    assert rt.assigned_partitions(c, "suricata.flow.v1") == {0, 3}


def test_assigned_partitions_empty_before_rebalance():
    assert rt.assigned_partitions(_FakeConsumer([])) == set()


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f()
            print("ok", _n)
    print("all ndr_runtime tests passed")
