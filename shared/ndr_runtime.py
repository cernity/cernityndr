"""Shared consumer runtime for the central NDR detection tier (plan 003 U1).

One throughput-tuned KafkaConsumer/KafkaProducer factory + a partition-assignment
helper + the metrics/health server, vendored into every docker/ndr/* consumer
image through the shared build context (COPY _shared/ndr_runtime.py). Python's GIL
means the tier scales by running N consumer PROCESSES in one group on one box
(one per core), so what matters per process is: tuned fetch/poll sizing so the
bus is not the bottleneck, one uniform metrics/health surface, and knowing which
partitions THIS process owns so it can evaluate only its own entities
(`assigned_partitions`, the seam plan 003 U4 uses).

Every tunable is env-overridable; explicit kwargs win over env, env wins over the
default. The kafka import is lazy so the config helpers and `assigned_partitions` stay
unit-testable without a broker (test_ndr_runtime.py).
"""
import json
import os

import metrics  # lives beside this file in _shared/ and is COPYed into every
                # image; available as ndr_runtime.metrics, though behavioral-
                # detectors imports it directly. Imported here so the runtime can
                # wire health/readiness uniformly later.


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _bootstrap():
    return os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")


def _consumer_config(group_id, **overrides):
    """Throughput-tuned KafkaConsumer kwargs for one single-box replica. Larger
    fetch/poll sizing keeps the bus from becoming the ceiling when many replicas
    read many partitions; all env-overridable, explicit overrides win."""
    conf = dict(
        bootstrap_servers=_bootstrap(),
        group_id=group_id,
        auto_offset_reset=os.environ.get("NDR_OFFSET_RESET", "latest"),
        enable_auto_commit=True,
        max_poll_records=_int("NDR_MAX_POLL_RECORDS", 1000),
        fetch_max_bytes=_int("NDR_FETCH_MAX_BYTES", 52428800),          # 50 MiB
        max_partition_fetch_bytes=_int("NDR_MAX_PARTITION_FETCH_BYTES", 10485760),  # 10 MiB
        fetch_min_bytes=_int("NDR_FETCH_MIN_BYTES", 1),
        fetch_max_wait_ms=_int("NDR_FETCH_MAX_WAIT_MS", 500),
        value_deserializer=lambda b: json.loads(b.decode()),
    )
    conf.update(overrides)
    return conf


def _producer_config(**overrides):
    """Tuned KafkaProducer kwargs: small linger + batch + compression. Findings
    are rare events (one per detection, not a stream), so linger is kept low --
    just enough to coalesce a burst without adding visible latency to an emit.
    All env-overridable."""
    conf = dict(
        bootstrap_servers=_bootstrap(),
        value_serializer=lambda v: json.dumps(v).encode(),
        linger_ms=_int("NDR_LINGER_MS", 10),
        batch_size=_int("NDR_BATCH_SIZE", 65536),
        compression_type=os.environ.get("NDR_COMPRESSION", "lz4"),
    )
    conf.update(overrides)
    return conf


def make_consumer(*topics, group_id, **overrides):
    from kafka import KafkaConsumer                 # lazy: keeps this module import-light
    return KafkaConsumer(*topics, **_consumer_config(group_id, **overrides))


def make_producer(**overrides):
    from kafka import KafkaProducer
    return KafkaProducer(**_producer_config(**overrides))


def assigned_partitions(consumer, topic=None):
    """Partition numbers this replica currently owns, read from the live consumer
    assignment. This is the seam partition-scoped evaluate() uses so each replica
    evaluates only its own entities (plan 003 U4): iterate keys tagged with a
    partition in this set. `topic=None` spans all assigned topics. Returns an
    empty set before the first poll/rebalance settles the assignment."""
    return {tp.partition for tp in consumer.assignment()
            if topic is None or tp.topic == topic}


def start_health(port=None, ready=("consumer",)):
    """Start the /healthz /readyz /metrics server and mark the given readiness
    components ready (plan 003 observability). A stateless consumer uses the
    default ('consumer',); a service with external state declares that component
    not-ready first and flips it when reachable."""
    metrics.start(port if port is not None else int(os.environ.get("NDR_METRICS_PORT", "9108")))
    for c in ready:
        metrics.set_ready(c)
