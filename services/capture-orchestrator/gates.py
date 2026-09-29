"""Capture-orchestration safety gates (plan U10; v2 §18, §21; v6 §14).

The origin's highest-risk component: never arm capture on a sensor that can't do
it, is unhealthy, or is over budget. Pure logic — app.py wires it to the capture
request topic, the sensor socket, and MinIO. Refusal paths are tested first.
"""
from __future__ import annotations


def capability_gate(manifest: dict, profile: str) -> tuple[bool, str]:
    """Refuse if the sensor's capability manifest doesn't offer the profile
    (v6 §14 — no capture job acceptance if capability unavailable)."""
    prof = (manifest.get("capture_profiles") or {}).get(profile) or {}
    if prof.get("available") is True:
        return True, "ok"
    return False, "capability_unavailable"


def health_gate(health: dict, thr: dict) -> tuple[bool, str]:
    """Refuse when arming would risk packet fidelity (v2 §21.4)."""
    if float(health.get("packet_loss_pct", 0) or 0) > thr["max_loss_pct"]:
        return False, "packet_loss_over_threshold"
    if float(health.get("cpu_pct", 0) or 0) > thr["max_cpu_pct"]:
        return False, "cpu_over_threshold"
    return True, "ok"


def budget_gate(sensor_id: str, budget: dict, limits: dict) -> tuple[bool, str]:
    """Per-sensor local capture budget (v2 §21.3)."""
    s = budget.get(sensor_id, {})
    if int(s.get("active_jobs", 0)) >= limits["max_jobs"]:
        return False, "max_concurrent_jobs"
    if int(s.get("bytes_captured", 0)) >= limits["max_bytes"]:
        return False, "byte_budget_exhausted"
    return True, "ok"


def decide_arm(request: dict, manifest: dict, health: dict,
               budget: dict, thr: dict, limits: dict) -> tuple[bool, str]:
    """All gates must pass, in order, before arming. Returns (arm, reason).
    Capability first (cheapest + hardest no), then health, then budget."""
    sensor_id = request.get("sensor_id", "")
    profile = request.get("capture_profile", "ip")
    for ok_fn, args in (
        (capability_gate, (manifest, profile)),
        (health_gate, (health, thr)),
        (budget_gate, (sensor_id, budget, limits)),
    ):
        ok, reason = ok_fn(*args)
        if not ok:
            return False, reason
    return True, "armed"


# Suricata arming command for a given profile + value (v2 §18.2). Returned as a
# suricatasc command string; app.py runs it on the sensor. Disarm is the paired
# dataset-remove; the tag TTL also auto-expires the capture window.
PROFILE_DATASET = {
    "ip": ("ndr-capture-ip", "ip"),
    "ja4": ("ndr-capture-ja4", "string"),
    "sni": ("ndr-capture-sni", "string"),
    "dns": ("ndr-capture-dns", "string"),
}


def arm_command(profile: str, value: str) -> str:
    ds, typ = PROFILE_DATASET[profile]
    return f"dataset-add {ds} {typ} {value}"


def disarm_command(profile: str, value: str) -> str:
    ds, typ = PROFILE_DATASET[profile]
    return f"dataset-remove {ds} {typ} {value}"


def decide_preserve(request, policy, health, budget, now):
    """Upgrade a v1 IP capture intent only under a local, explicit sensor policy.

    The incoming request carries no authorization authority. Policy identity,
    ceilings and the MAC are supplied here, never copied from caller fields.
    """
    import capture_v2
    import hashlib
    if (health.get('measured') is not True
            or any(type(health.get(k)) not in (int, float) or not 0 <= health[k] <= 100
                   for k in ('cpu_pct', 'packet_loss_pct'))):
        raise PermissionError('sensor health unmeasured')
    ok, reason = health_gate(health, {'max_loss_pct': policy['max_loss_pct'],
                                     'max_cpu_pct': policy['max_cpu_pct']})
    if not ok:
        raise PermissionError(reason)
    trigger = request.get('trigger_ts', now)
    doc = {
        'schema_version': 'capture-request.v2', 'mode': 'preserve',
        'tenant_id': request.get('tenant_id'), 'sensor_id': request.get('sensor_id'),
        'finding_id': request.get('finding_id'), 'capture_profile': request.get('capture_profile', 'ip'),
        'value': request.get('value'), 'reason': 'finding capture intent',
        'policy_id': policy.get('policy_id'),
        'window': {'start': trigger - policy['lookback_s'], 'end': trigger},
        'limits': {k: policy[k] for k in ('max_bytes', 'max_duration_s', 'retention_s')},
        'expires_at': min(trigger + 300, now + 60),
    }
    # Stable for duplicate intents even if the orchestrator's receive time changes.
    doc['request_id'] = hashlib.sha256(capture_v2.canonical([
        doc['tenant_id'], doc['sensor_id'], doc['finding_id'], policy['policy_id']])).hexdigest()
    capture_v2.authorize(doc, policy, now, verify=False)
    doc['authorization'] = capture_v2.sign(doc, policy.get('signing_key'))
    budget.reserve(doc, policy)
    return doc
