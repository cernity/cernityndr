"""Incident/role-aware scoring for the benchmark (M2 / §7). Pure, stdlib only; unit-gated by
test_episodes.py.

Set-vs-truth scoring (extract.flagged_from_*) counted a benign peer — or the attack's own C2
target — as a false positive whenever a detection named it. This module instead matches each
DETECTION to a labelled EPISODE by:

  * behaviour compatibility (detection category vs the episode's behaviour class),
  * ENTITY + ROLE (the detection must implicate one of the episode's entities in a role the
    episode assigns — flagging the target of a matched episode is not an unrelated FP), and
  * time-interval overlap (only when both sides carry a reliable interval; offline replay
    reanchors timestamps, so a missing/soft interval is not over-constrained), and
  * tenant (the same IP in two tenants is two different entities).

Recall counts each malicious episode ONCE (duplicate detections and same-id revisions are
workload, not extra incidents). Precision is over analyst items: relevant = matched a malicious
episode; false = matched none; items that match only an `unknown` episode are UNSCORED (§7).
"""
from __future__ import annotations

# Behaviour classes a detection category may satisfy for an episode. Unmapped -> exact match.
_COMPAT = {
    "c2": {"c2", "beacon", "beaconing", "malware", "trojan"},
    "recon": {"recon", "scan", "portscan"},
    "exfil": {"exfil", "exfiltration"},
    "lateral": {"lateral", "lateral_movement"},
    "malware": {"malware", "c2", "trojan"},
}


# Detections and truth use different role vocabularies (Suricata/findings say src/dst; truth
# says initiator/target). Normalise both to the same two canonical roles before comparing.
_ROLE_ALIAS = {
    "src": "initiator", "source": "initiator", "initiator": "initiator", "client": "initiator",
    "dst": "target", "dest": "target", "destination": "target", "target": "target",
    "server": "target", "responder": "target",
}


def _norm_role(r):
    r = (r or "").lower()
    return _ROLE_ALIAS.get(r, r or None)


def _entity_roles(obj):
    """value -> canonical role for an episode/detection (role may be None)."""
    out = {}
    for e in obj.get("entities", []):
        v = e.get("value")
        if v:
            out[v] = _norm_role(e.get("role"))
    return out


def _behavior_ok(det, ep):
    d = (det.get("behavior") or det.get("category") or "").lower()
    t = (ep.get("behavior") or "").lower()
    if not d or not t:                 # evidence-agnostic on either side
        return True
    return d == t or d in _COMPAT.get(t, {t})


def _interval_ok(det, ep, tol=0.0):
    di, ei = det.get("interval"), ep.get("interval")
    if not di or not ei:               # soft: reanchored/absent times must not over-constrain
        return True
    return di["start"] <= ei["end"] + tol and ei["start"] <= di["end"] + tol


def _role_compatible(det_roles, ep_roles, shared):
    """>=1 shared entity carried in a role the episode assigns (a detection with no role for
    that entity is allowed — many detections do not label roles)."""
    return any(det_roles.get(v) in (None, ep_roles.get(v)) for v in shared)


def matches(det, ep, tol=0.0):
    if (det.get("tenant") or "default") != (ep.get("tenant") or "default"):
        return False
    ep_roles = _entity_roles(ep)
    shared = set(_entity_roles(det)) & set(ep_roles)
    if not shared:
        return False
    return (_role_compatible(_entity_roles(det), ep_roles, shared)
            and _behavior_ok(det, ep) and _interval_ok(det, ep, tol))


def _dedup(detections):
    """Collapse same-logical-finding revisions (by finding_id) to one analyst item; keep every
    item that has no id. Preserves order."""
    seen, out = set(), []
    for d in detections:
        fid = d.get("finding_id")
        if fid is not None:
            if fid in seen:
                continue
            seen.add(fid)
        out.append(d)
    return out


def score(detections, episodes, tol=0.0):
    """Episode-level recall + analyst-item precision (§7). `detections` and `episodes` are dicts
    with `entities`(+role), optional `behavior`/`category`, `interval`, `tenant`, `finding_id`."""
    detections = _dedup(detections)
    mal = [e for e in episodes if e.get("label") == "malicious"]
    unknown = [e for e in episodes if e.get("label") == "unknown"]

    surfaced = [ep.get("id") for ep in mal if any(matches(d, ep, tol) for d in detections)]
    tp_ep, fn_ep = len(surfaced), len(mal) - len(surfaced)
    recall = tp_ep / len(mal) if mal else 0.0

    relevant, unscored, false = [], [], []
    for d in detections:
        if any(matches(d, ep, tol) for ep in mal):
            relevant.append(d)
        elif any(matches(d, ep, tol) for ep in unknown):
            unscored.append(d)                        # matched only unknown -> unscored (§7)
        else:
            false.append(d)
    adjudicated = len(relevant) + len(false)
    precision = len(relevant) / adjudicated if adjudicated else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "malicious_episodes": len(mal),
        "episodes_surfaced": tp_ep, "episodes_missed": fn_ep,
        "episode_recall": round(recall, 4),
        "analyst_items": len(relevant) + len(false) + len(unscored),
        "relevant_items": len(relevant), "false_items": len(false), "unscored_items": len(unscored),
        "analyst_precision": round(precision, 4), "f1": round(f1, 4),
        "surfaced_ids": surfaced,
        "missed_ids": [ep.get("id") for ep in mal if ep.get("id") not in surfaced],
    }
