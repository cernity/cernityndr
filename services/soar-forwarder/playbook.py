"""SOAR playbook logic (plan U13). Pure + testable. Given a FINAL finding,
decide the SOC actions and build the notification. app.py runs the effects
(ntfy notify, optional POST to a real SOAR — Shuffle/n8n/TheHive).

Homelab-safe: containment is SIMULATED (labelled, never touches the network).
"""
from __future__ import annotations
import json

# ntfy priority per severity (1-5).
def _priority(sev: int) -> int:
    if sev >= 9:
        return 5
    if sev >= 7:
        return 4
    if sev >= 4:
        return 3
    return 2


def actions_for(f: dict) -> list[str]:
    """Which playbook actions fire for this finding."""
    acts = ["notify"]
    if f.get("detector_id") == "correlation_incident":
        acts.append("escalate_incident")    # correlated multi-stage incident (plan U10): top priority
    if int(f.get("severity", 0) or 0) >= 7:
        acts.append("contain_sim")          # simulated containment (homelab-safe)
    if f.get("enrichment_state") == "ENRICHMENT_FAILED":
        acts.append("flag_review")          # analyst should look — enrichment didn't land
    if f.get("category") == "recon":
        acts.append("watchlist_source")     # add scanner to a watchlist
    return acts


def notification(f: dict) -> dict:
    ents = f.get("entities", "")
    try:
        parsed = json.loads(ents) if isinstance(ents, str) else ents
        who = ", ".join(e.get("value", "?") for e in (parsed or []) if isinstance(e, dict))
    except (ValueError, TypeError):
        who = "?"
    sev = int(f.get("severity", 0) or 0)
    return {
        "title": f"NDR {f.get('category', '?')}: {f.get('detector_id', '?')}",
        "priority": _priority(sev),
        "tags": (f.get("mitre") or []) + [f.get("category", "")],
        "message": (f"finding {f.get('finding_id')} sev={sev} "
                    f"conf={f.get('confidence')} entities=[{who}] "
                    f"state={f.get('state')}/{f.get('enrichment_state')}"),
    }


def playbook(f: dict) -> dict:
    """Full playbook result for a finding — actions + notification payload."""
    return {"finding_id": f.get("finding_id"),
            "actions": actions_for(f),
            "notification": notification(f)}
