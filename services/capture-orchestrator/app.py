"""Capture orchestrator (plan U10 + closed-loop follow-up). Consumes
ndr.capture.request.v1, applies the safety gates (gates.py), and — when armed —
emits an ARM DIRECTIVE to ndr.capture.arm.v1 for the sensor's capture-agent to
actuate (suricatasc dataset-add on the LOCAL socket + bounded PCAP + MinIO +
enrichment request). It also consumes ndr.capture.status.v1 completions from the
agent to FREE the per-sensor budget — closing the loop that previously leaked
jobs and eventually refused every capture with max_concurrent_jobs.

No SSH, no central key-holding: the orchestrator only produces gated directives
onto the authenticated bus; each sensor's agent owns local actuation. Gate logic
is covered by test_gates.py.
"""
import hashlib
import json
import os
import re
import ndr_runtime
import signal

from kafka import KafkaConsumer, KafkaProducer
import gates

log = ndr_runtime.setup_logging("capture-orchestrator")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
REQUEST_TOPIC = "ndr.capture.request.v1"
STATUS_TOPIC = "ndr.capture.status.v1"
ARM_TOPIC = "ndr.capture.arm.v1"

MANIFEST = {"capture_profiles": {p: {"available": True} for p in ("ip", "ja4", "sni", "dns")}}
THR = {"max_loss_pct": float(os.environ.get("MAX_LOSS_PCT", "1.0")),
       "max_cpu_pct": float(os.environ.get("MAX_CPU_PCT", "85.0"))}
LIMITS = {"max_jobs": int(os.environ.get("MAX_JOBS", "3")),
          "max_bytes": int(os.environ.get("MAX_BYTES", "500000000"))}

_running = True
_budget: dict = {}   # sensor_id -> {active_jobs, bytes_captured}


def _stop(*_):
    global _running
    _running = False


# Absent/empty tenant -> this explicit, documented segment (never the literal
# str(None) = 'None', which would silently pool every untenanted capture together).
DEFAULT_TENANT_SEGMENT = "_no-tenant"


def tenant_segment(tenant) -> str:
    """Collision-free, path-safe tenant namespace for a PCAP object key. The FULL
    SHA-256 digest of the raw tenant id is the collision-free part — distinct tenant
    ids never map to the same segment, so one tenant can never overwrite another's
    PCAP. The truncated, sanitized prefix is only a human-readable label and is
    allowed to collide (e.g. two ids sharing the first 32 chars); a truncated digest
    would leave only ~48 bits and a feasible birthday collision, so we keep all 256.
    An absent/empty tenant uses DEFAULT_TENANT_SEGMENT, never str(None)."""
    if tenant is None or not str(tenant).strip():
        return DEFAULT_TENANT_SEGMENT
    raw = str(tenant)
    safe = re.sub(r"[^A-Za-z0-9._-]", "", raw).replace("..", "").strip(".")[:32] or "t"
    return f"{safe}-{hashlib.sha256(raw.encode()).hexdigest()}"


def object_key(tenant, fid, value, profile) -> str:
    """Tenant-namespaced MinIO object key for a preserved PCAP. The tenant segment
    keys the object per-tenant, so an identical flow tuple in two tenants resolves to
    two distinct objects (no cross-tenant overwrite)."""
    return f"ndr-pcap/{tenant_segment(tenant)}/{fid or value}-{profile}.pcap"


def probe_health(sensor_id: str) -> dict:
    # B-U8/R12: no real sensor-health signal is wired yet, so report state UNMEASURED rather than
    # fabricating a perfectly-healthy 0.0 (which made the gate treat every sensor as known-good).
    # `measured=False` lets consumers distinguish "unknown" from a real zero; the numeric fields keep
    # the gate contract until the agent publishes suricatasc kernel_drops to a health topic.
    return {"packet_loss_pct": 0.0, "cpu_pct": 0.0, "measured": False}


def _handle_request(req, producer):
    sensor_id = req.get("sensor_id", "sensor-1")
    profile = req.get("capture_profile", "ip")
    value = req.get("value", "")
    fid = req.get("finding_id", "")
    armed, reason = gates.decide_arm(
        {"sensor_id": sensor_id, "capture_profile": profile, "value": value},
        MANIFEST, probe_health(sensor_id), _budget, THR, LIMITS)
    producer.send(STATUS_TOPIC, {"finding_id": fid, "sensor_id": sensor_id, "profile": profile,
                                 "value": value, "armed": armed, "reason": reason})
    if not armed:
        log.info("REFUSED %s %s=%s: %s", sensor_id, profile, value, reason)
        return
    s = _budget.setdefault(sensor_id, {"active_jobs": 0, "bytes_captured": 0})
    s["active_jobs"] += 1
    pcap_ref = object_key(req.get("tenant_id"), fid, value, profile)
    producer.send(ARM_TOPIC, {
        "finding_id": fid, "sensor_id": sensor_id, "capture_profile": profile,
        "value": value, "pcap_ref": pcap_ref, "tenant_id": req.get("tenant_id"),
        "ttl_secs": req.get("ttl_secs"), "max_bytes": req.get("max_bytes"),
    })
    log.info("ARM DIRECTIVE %s %s=%s -> %s (active=%d)",
             sensor_id, profile, value, pcap_ref, s["active_jobs"])


def _handle_completion(status):
    """Agent terminal status frees the central budget. Agent messages carry a
    'state'; the orchestrator's own decision status does not — so we only act on
    the agent's."""
    state = status.get("state")
    if state not in ("completed", "failed", "rejected", "refused"):
        return
    sensor_id = status.get("sensor_id", "sensor-1")
    s = _budget.setdefault(sensor_id, {"active_jobs": 0, "bytes_captured": 0})
    if s["active_jobs"] > 0:
        s["active_jobs"] -= 1
    s["bytes_captured"] += int(status.get("bytes", 0) or 0)
    log.info("FREED %s on %s (active=%d, bytes=%d)",
             sensor_id, state, s["active_jobs"], s["bytes_captured"])


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    producer = KafkaProducer(bootstrap_servers=BOOTSTRAP,
                             value_serializer=lambda v: json.dumps(v).encode())
    consumer = KafkaConsumer(
        REQUEST_TOPIC, STATUS_TOPIC, bootstrap_servers=BOOTSTRAP,
        group_id="ndr-capture-orchestrator", auto_offset_reset="earliest",
        enable_auto_commit=True, value_deserializer=lambda b: json.loads(b.decode()))
    log.info("capture-orchestrator up: %s + %s", REQUEST_TOPIC, STATUS_TOPIC)

    while _running:
        batch = consumer.poll(timeout_ms=1000, max_records=100)
        for tp, records in batch.items():
            for rec in records:
                if tp.topic == REQUEST_TOPIC:
                    _handle_request(rec.value, producer)
                elif tp.topic == STATUS_TOPIC:
                    _handle_completion(rec.value)
        producer.flush()

    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
