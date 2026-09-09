"""Correlation logic (plan U8, Track B): per-entity risk accumulation and
MITRE ATT&CK tactic-chain sequencing. Pure functions only, no I/O — the
service shell (app.py) does Kafka and ClickHouse. Tested by test_correlate.py.

An incident fires when one entity's findings either accumulate enough risk or
line up into a multi-stage kill chain. Incidents are themselves findings
(detector_id=correlation_incident) so they reuse the whole finding path; the
shell filters those back out on input so an incident never re-correlates into
another incident.
"""
from __future__ import annotations

import json
import time

INCIDENT_DETECTOR = "correlation_incident"

# Finding category -> (kill-chain stage index, tactic label). Stages are
# ordered so a sequence that advances through them over time is a chain.
STAGE = {
    "recon": (0, "reconnaissance"),
    "malware": (1, "initial-access"),
    "bruteforce": (1, "credential-access"),
    "anomaly": (1, "execution"),
    "c2": (2, "command-and-control"),
    "dns_tunnel": (2, "command-and-control"),
    "lateral": (3, "lateral-movement"),
    "exfil": (4, "exfiltration"),
}

# Defaults; the shell overrides these from env.
DEFAULTS = {
    "risk_threshold": 12.0,    # decayed severity-sum that alone trips an incident
    "min_tactics": 2,          # distinct kill-chain stages that trip an incident
    "half_life_secs": 3600.0,  # risk halves every hour
}


def is_incident(finding: dict) -> bool:
    """Incidents are findings too; the shell must not re-correlate them."""
    return finding.get("detector_id") == INCIDENT_DETECTOR


def _severity(f: dict) -> float:
    try:
        return float(f.get("severity", 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def _ts(f: dict, default: float) -> float:
    ts = f.get("ts")
    if ts is None:
        return default
    try:
        return float(ts)
    except (TypeError, ValueError):
        return default


def entity_risk(findings, now, half_life_secs=DEFAULTS["half_life_secs"]):
    """Severity-weighted, time-decayed risk for one entity, deduped per
    detector_id so one chatty detector cannot inflate the score. Each detector
    contributes only its single strongest (tie-broken by most recent) finding.
    """
    strongest = {}  # detector_id -> (severity, ts)
    for f in findings:
        det = f.get("detector_id", "")
        sev, ts = _severity(f), _ts(f, now)
        cur = strongest.get(det)
        if cur is None or sev > cur[0] or (sev == cur[0] and ts > cur[1]):
            strongest[det] = (sev, ts)
    risk = 0.0
    for sev, ts in strongest.values():
        age = max(0.0, now - ts)
        risk += sev * 0.5 ** (age / half_life_secs)
    return round(risk, 3)


def tactic_stages(findings):
    """List of (stage_index, ts, label) for findings whose category maps to a
    kill-chain stage. Used for chain detection and the incident narrative."""
    out = []
    for f in findings:
        st = STAGE.get(f.get("category", ""))
        if st is not None:
            out.append((st[0], _ts(f, 0.0), st[1]))
    return out


def is_ordered_chain(findings):
    """True if the entity's stages advance in kill-chain order over time: at
    least two distinct stages, and the peak stage seen never regresses as time
    advances (a real progression, not a random mix within one stage)."""
    stages = sorted((ts, idx) for idx, ts, _ in tactic_stages(findings))
    if len({idx for _, idx in stages}) < 2:
        return False
    peak, advanced = -1, 0
    for _, idx in stages:
        if idx > peak:
            advanced += 1
            peak = idx
    return advanced >= 2


def should_incident(findings, now, params=None):
    """Decide whether an entity's findings warrant an incident. Ignores
    incident-typed inputs. Returns (bool, reason)."""
    p = {**DEFAULTS, **(params or {})}
    active = [f for f in findings if not is_incident(f)]
    if not active:
        return False, "no findings"
    distinct = {STAGE[f["category"]][0] for f in active if f.get("category") in STAGE}
    if is_ordered_chain(active) and len(distinct) >= p["min_tactics"]:
        return True, "kill-chain"
    # multi-tactic fires on >= min_tactics distinct stages regardless of order:
    # two different attacker tactics on one entity warrant an incident even when
    # forward progression cannot be proven (the ordered chain above scores higher).
    if len(distinct) >= p["min_tactics"] and len(active) >= 2:
        return True, "multi-tactic"
    if entity_risk(active, now, p["half_life_secs"]) >= p["risk_threshold"]:
        return True, "risk-threshold"
    return False, "below threshold"


def build_incident(entity, findings, now, tenant="homelab", reason="", params=None):
    """Shape the incident finding: detector_id=correlation_incident, high
    confidence so finding-service finalizes it without a capture, constituent
    finding_ids in evidence_refs, union of MITRE techniques in mitre, and a
    readable kill-chain narrative in entities. Correlation raises severity
    above the strongest constituent finding."""
    p = {**DEFAULTS, **(params or {})}
    active = [f for f in findings if not is_incident(f)]
    risk = entity_risk(active, now, p["half_life_secs"])
    by_stage = {}
    for idx, _ts_, label in tactic_stages(active):
        by_stage.setdefault(idx, label)
    chain = [by_stage[i] for i in sorted(by_stage)]
    ordered = is_ordered_chain(active)
    max_sev = max((int(_severity(f)) for f in active), default=1)
    severity = max(1, min(10, max_sev + (2 if ordered else 1)))
    finding_ids = [f.get("finding_id") for f in active if f.get("finding_id")]
    mitre = sorted({t for f in active for t in (f.get("mitre") or [])})
    narrative = f"{entity}: " + " -> ".join(chain) if chain else f"{entity}: elevated risk"
    entities = json.dumps([
        {"type": "entity", "role": "subject", "value": entity},
        {"type": "narrative", "value": narrative},
        {"type": "tactic_chain", "value": chain},
        {"type": "risk_score", "value": risk},
        {"type": "trigger", "value": reason},
    ])
    return {
        "finding_id": f"incident-{entity}-{int(now)}",
        "tenant_id": tenant,
        "detector_id": INCIDENT_DETECTOR,
        "detector_version": "1.0",
        "category": "incident",
        "severity": severity,
        "confidence": 0.95,
        "first_seen": _fmt(min((_ts(f, now) for f in active), default=now)),
        "last_seen": _fmt(now),
        "entities": entities,
        "evidence_refs": finding_ids,
        "mitre": mitre,
        "state": "CANDIDATE",
    }


def _fmt(epoch: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(epoch))
