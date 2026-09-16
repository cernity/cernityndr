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
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone

# `metrics` (which needs prometheus_client) is imported lazily so that setup_logging —
# the piece every service uses — has zero heavy deps and works even in the light,
# self-contained service images. Services that manage their own metrics server reach it
# as `ndr_runtime.metrics`; PEP 562 module __getattr__ resolves that on first access
# (still lazy — prometheus_client is only imported when a service actually touches it).


def __getattr__(name):
    if name == "metrics":
        import metrics                              # lazy: only imported when a service uses it
        return metrics
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _bootstrap():
    return os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")


def _security_config():
    """SASL kwargs for a client pointed at a secured broker. Returns {} when
    NDR_BUS_SASL_MECHANISM is unset, so the fully-insecure demo path (no auth) is
    byte-identical to before. TLS is used when a CA is provided (a remote sensor over
    the external listener); without one, SASL runs over plaintext on the private
    docker network (the central pipeline authenticating to the internal listener,
    which is not reachable off-box). Env:
      NDR_BUS_SASL_MECHANISM  e.g. SCRAM-SHA-512 -- presence gates the whole block
      NDR_BUS_SASL_USER / NDR_BUS_SASL_PASSWORD   required when the mechanism is set
      NDR_BUS_TLS_CA          CA cert path -> SASL_SSL; omit -> SASL_PLAINTEXT
    """
    mech = os.environ.get("NDR_BUS_SASL_MECHANISM")
    if not mech:
        return {}
    user = os.environ.get("NDR_BUS_SASL_USER")
    pw = os.environ.get("NDR_BUS_SASL_PASSWORD")
    if not user or not pw:
        raise ValueError("NDR_BUS_SASL_MECHANISM is set but NDR_BUS_SASL_USER/"
                         "NDR_BUS_SASL_PASSWORD is missing")
    ca = os.environ.get("NDR_BUS_TLS_CA")
    conf = {"security_protocol": "SASL_SSL" if ca else "SASL_PLAINTEXT",
            "sasl_mechanism": mech,
            "sasl_plain_username": user, "sasl_plain_password": pw}
    if ca:
        conf["ssl_cafile"] = ca
    return conf


def _consumer_config(group_id, **overrides):
    """Throughput-tuned KafkaConsumer kwargs for one single-box replica. Larger
    fetch/poll sizing keeps the bus from becoming the ceiling when many replicas
    read many partitions; all env-overridable, explicit overrides win.

    auto_offset_reset precedence (documented): an explicitly-set NDR_OFFSET_RESET wins
    over everything, including a service's hard-coded default. This lets offline replay
    position EVERY consumer deterministically (a service that hard-codes 'latest' would
    otherwise silently skip a burst produced before it joined). Unset in production, each
    service keeps its own code default; the base default is 'latest'."""
    conf = dict(
        bootstrap_servers=_bootstrap(),
        group_id=group_id,
        auto_offset_reset="latest",
        enable_auto_commit=True,
        max_poll_records=_int("NDR_MAX_POLL_RECORDS", 1000),
        fetch_max_bytes=_int("NDR_FETCH_MAX_BYTES", 52428800),          # 50 MiB
        max_partition_fetch_bytes=_int("NDR_MAX_PARTITION_FETCH_BYTES", 10485760),  # 10 MiB
        fetch_min_bytes=_int("NDR_FETCH_MIN_BYTES", 1),
        fetch_max_wait_ms=_int("NDR_FETCH_MAX_WAIT_MS", 500),
        value_deserializer=lambda b: json.loads(b.decode()),
        **_security_config(),                                  # SASL_SSL when env-set, else {}
    )
    conf.update(overrides)                       # a service's explicit default wins over base
    env_reset = os.environ.get("NDR_OFFSET_RESET")
    if env_reset:                                # ...but an explicit env setting wins over that
        conf["auto_offset_reset"] = env_reset
    # §57.6: treat an EMPTY value and an INVALID-EXPLICIT value differently.
    #  - Empty/unset (the `${NDR_OFFSET_RESET-}` compose passthrough, or a service override that read it)
    #    is a benign "not configured" -> fall back to the base default. Left as "" it is an INVALID reset
    #    policy that crash-loops the consumer on NoOffsetForPartitionError (silent zero output).
    #  - A NON-EMPTY typo (e.g. "earliest " / "erliest") is a real misconfiguration. Do NOT silently
    #    coerce it to `latest` — that would quietly skip existing history for a new group. Fail LOUDLY at
    #    construction with a clear message so the operator fixes it, not an opaque partition error later.
    reset = conf.get("auto_offset_reset")
    if reset in ("", None):
        conf["auto_offset_reset"] = "latest"
    elif reset not in ("latest", "earliest", "none"):
        raise ValueError(f"invalid auto_offset_reset {reset!r}: expected latest|earliest|none "
                         "(check NDR_OFFSET_RESET; leave it empty to default to latest)")
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
        **_security_config(),                                  # SASL_SSL when env-set, else {}
    )
    conf.update(overrides)
    return conf


def make_consumer(*topics, group_id, **overrides):
    from kafka import KafkaConsumer                 # lazy: keeps this module import-light
    return KafkaConsumer(*topics, **_consumer_config(group_id, **overrides))


def make_producer(**overrides):
    from kafka import KafkaProducer
    return KafkaProducer(**_producer_config(**overrides))


EVAL_ACK_TOPIC = "ndr.eval.ack.v1"


def emit_eval_ack(producer, svc, group, partitions, evaluated_wall, records_seen,
                  horizon_secs, worker=None, topic=EVAL_ACK_TOPIC):
    """Publish an evaluation-completion ack per assigned partition (§handoff stage 3): a detector's
    producer exit + consumer offset progress prove input was CONSUMED, not that its TIMER-DRIVEN
    windows were evaluated through the observation horizon. After an evaluate() pass a detector
    emits, per partition it owns, {svc, group, partition, evaluated_wall, records_seen, horizon_secs,
    worker}. A reader confirms an ack exists with evaluated_wall >= (last input time + horizon) for
    every expected detector/partition — i.e. the detector had, and completed, a post-drain evaluation
    covering the horizon. Best-effort: an ack failure must never disrupt detection."""
    if producer is None:
        return
    for p in sorted(partitions or []):
        try:
            producer.send(topic, value={"svc": svc, "group": group, "partition": p,
                                        "evaluated_wall": evaluated_wall, "records_seen": records_seen,
                                        "horizon_secs": horizon_secs, "worker": worker})
        except Exception:                            # noqa: BLE001 (acks are evidence, not the workload)
            pass


class EvalAckEmitter:
    """Uniform evaluation-completion acks for any timer-driven consumer (§handoff stage 3 rollout).
    Call `.seen(n)` as records are handled and `.beat(consumer)` once per loop iteration: it emits a
    per-partition ack to ndr.eval.ack.v1 at most every `every` seconds (and on `force`), stamped with
    a stable worker epoch. A post-drain beat proves the detector's loop ran — and thus its periodic
    evaluate() executed — past the input, not merely that offsets advanced. Emission never disrupts
    the loop (best-effort)."""

    def __init__(self, producer, svc, group, horizon_secs, every=None):
        import time as _t
        import uuid as _u
        self._producer, self._svc, self._group = producer, svc, group
        self._horizon = horizon_secs
        self._every = float(every if every is not None else _int("NDR_EVAL_ACK_EVERY", 15))
        self._worker = _u.uuid4().hex
        self._records = 0
        self._last = 0.0
        self._t = _t

    def seen(self, n=1):
        self._records += n

    def beat(self, consumer, force=False):
        now = self._t.time()
        if not force and (now - self._last) < self._every:
            return
        self._last = now
        emit_eval_ack(self._producer, self._svc, self._group, assigned_partitions(consumer),
                      now, self._records, self._horizon, worker=self._worker)


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
    import metrics  # lazy: only services that expose /metrics need prometheus_client
    metrics.start(port if port is not None else int(os.environ.get("NDR_METRICS_PORT", "9108")))
    for c in ready:
        metrics.set_ready(c)


# ── Logging ───────────────────────────────────────────────────────────────────
# One shared setup so every service logs identically. LOG_FORMAT=json (default)
# emits one JSON object per line with standard fields (ts, level, svc, tenant,
# event); LOG_FORMAT=text is human-readable for `docker logs` / the quickstart.
# LOG_LEVEL sets the threshold (INFO default). setup_logging also starts a
# low-frequency liveness heartbeat so a deployer can see the service is alive.

class _JsonFormatter(logging.Formatter):
    def __init__(self, service):
        super().__init__()
        self.service = service

    def format(self, record):
        d = {"ts": datetime.now(timezone.utc).isoformat(),
             "level": record.levelname,
             "svc": self.service,
             "tenant": os.environ.get("NDR_TENANT", "default"),
             "msg": record.getMessage()}
        ev = getattr(record, "cernity_event", None)
        if ev:
            d["event"] = ev
        for k, v in getattr(record, "cernity_fields", {}).items():
            d[k] = v
        if record.exc_info:
            d["exc"] = self.formatException(record.exc_info)
        return json.dumps(d, default=str)


def setup_logging(service):
    """Configure root logging for a service and return its logger. Reads
    LOG_LEVEL (INFO) and LOG_FORMAT (json|text, json default). Also starts a
    daemon liveness heartbeat every HEARTBEAT_SECS (default 300s)."""
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    fmt = os.environ.get("LOG_FORMAT", "json").lower()
    handler = logging.StreamHandler(sys.stdout)
    if fmt == "text":
        handler.setFormatter(logging.Formatter(
            f"%(asctime)s %(levelname)s [{service}] %(message)s"))
    else:
        handler.setFormatter(_JsonFormatter(service))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    log = logging.getLogger(service)
    _start_heartbeat(log)
    return log


def log_event(logger, event, level=logging.INFO, **fields):
    """Emit a structured event: clean JSON fields in json mode, `event k=v k=v`
    inline in text mode."""
    msg = event
    if fields:
        msg = event + " " + " ".join(f"{k}={v}" for k, v in fields.items())
    logger.log(level, msg, extra={"cernity_event": event, "cernity_fields": fields})


_HEARTBEAT_STARTED = False


def _start_heartbeat(logger):
    global _HEARTBEAT_STARTED
    if _HEARTBEAT_STARTED:
        return
    _HEARTBEAT_STARTED = True
    secs = _int("HEARTBEAT_SECS", 300)

    def beat():
        while True:
            time.sleep(secs)
            log_event(logger, "heartbeat", uptime_s=secs)

    threading.Thread(target=beat, name="cernity-heartbeat", daemon=True).start()
