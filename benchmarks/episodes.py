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

# Behaviour CLASS (episode) -> the detector CATEGORIES that satisfy it (a taxonomy, not tuning:
# a class is the analyst-level behaviour, the categories are the specific detector techniques).
# Unmapped class -> exact match. Reconciled against the categories the detectors actually emit.
_COMPAT = {
    "c2": {"c2", "beacon", "beaconing", "malware", "trojan"},
    "recon": {"recon", "scan", "portscan", "strobe", "discovery", "internal_scan"},
    "exfil": {"exfil", "exfiltration", "dns_tunnel", "dns_exploded", "large_transfer"},
    "lateral": {"lateral", "lateral_movement", "rdp_fanout", "smb_fanout"},
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


def _temporal(det, ep, tol=0.0):
    """Three-way temporal verdict (§24.3 repair). Timestamps are aligned to ONE clock upstream:
    the feeder records the replay-clock mapping and both detections and episode truth are expressed
    on it, so overlap is meaningful.
      untimed — the episode is not time-bounded (no interval): time does not constrain the match.
      in      — both carry an interval and they overlap.
      out     — both carry an interval and they are disjoint (a real time exclusion).
      unknown — the episode IS time-bounded but the detection carries no time: temporally
                UNVERIFIABLE. This must NOT silently match (the prior soft rule over-credited);
                the caller records it as ambiguous, distinct from an in-window match and from a miss."""
    ei = ep.get("interval")
    if not ei:
        return "untimed"
    di = det.get("interval")
    if not di:
        return "unknown"
    inside = di["start"] <= ei["end"] + tol and ei["start"] <= di["end"] + tol
    return "in" if inside else "out"


def _required_values(ep):
    """The entity values a detection MUST implicate to surface this episode (R3/§21.3). Default:
    ALL of the episode's entities — a peer-specific beacon needs BOTH the initiator and the
    target/domain; one shared IP is insufficient (that was the §20.1 over-credit: two episodes
    sharing a source were both credited by a detection naming only that source). An episode may
    narrow the requirement with `match_requires` (a list of values) for a family whose
    discriminator is a subset (e.g. a scan keyed on the initiator + target-set evidence)."""
    mr = ep.get("match_requires")
    return set(mr) if mr else set(_entity_roles(ep))


def _identity_match(det, ep):
    """Entity+role+behavior+tenant match — the discriminating relationship, WITHOUT the temporal
    check. Recall/precision layer the temporal verdict on top of this (§24.3)."""
    if (det.get("tenant") or "default") != (ep.get("tenant") or "default"):
        return False
    det_roles = _entity_roles(det)
    required = _required_values(ep)
    ep_roles = _entity_roles(ep)
    # every discriminating entity must be implicated (subset), each in a compatible role
    # (a detection that does not label the role is allowed — many detections do not).
    if not required or not required.issubset(set(det_roles)):
        return False
    if not all(det_roles.get(v) in (None, ep_roles.get(v)) for v in required):
        return False
    return _behavior_ok(det, ep)


def match_verdict(det, ep, tol=0.0):
    """Per-(detection, episode) verdict combining identity + the three-way temporal check:
      'match'     — identity holds and time is untimed/in-window (credits recall, relevant item).
      'ambiguous' — identity holds but the time-bounded episode's window is unverifiable for this
                    detection (no invented credit; recorded as ambiguous, not a miss, not an FP).
      'no'        — identity fails, or the detection is provably out of the episode's window."""
    if not _identity_match(det, ep):
        return "no"
    t = _temporal(det, ep, tol)
    if t in ("untimed", "in"):
        return "match"
    return "ambiguous" if t == "unknown" else "no"


def matches(det, ep, tol=0.0):
    """Boolean surface match: a detection surfaces an episode only on a hard 'match' (identity +
    time). Ambiguous/out-of-window is not a surface (§24.3)."""
    return match_verdict(det, ep, tol) == "match"


def _dedup(detections):
    """Collapse same-logical-finding revisions (by finding_id) to one analyst item; keep every
    item that has no id. Preserves order."""
    seen, out = set(), []
    for d in detections:
        fid = d.get("finding_id")
        if fid is not None:
            key = (d.get("tenant") or "default", fid)     # scope identity by tenant (§20.1)
            if key in seen:
                continue
            seen.add(key)
        out.append(d)
    return out


def shift_interval(interval, offset):
    """Map an interval onto the replay clock by `offset` seconds (§25.3). The offline feeder
    reanchors every event by a single recorded shift; episode truth is authored in the ORIGINAL
    clock, so mapping it forward by that same shift makes overlap with delivered detection times
    meaningful. None-safe (untimed truth stays untimed)."""
    if not interval or not offset:
        return interval
    return {"start": interval["start"] + offset, "end": interval["end"] + offset}


def score(detections, episodes, tol=0.0, replay_offset=0.0):
    """Episode-level recall + analyst-item precision (§7). `detections` and `episodes` are dicts
    with `entities`(+role), optional `behavior`/`category`, `interval`, `tenant`, `finding_id`.
    `replay_offset` maps each episode's ORIGINAL-clock interval onto the replay clock the delivered
    detections carry (§25.3); the original bounds are retained on the input, only a shifted copy is
    compared."""
    detections = _dedup(detections)
    if replay_offset:
        episodes = [dict(e, interval=shift_interval(e.get("interval"), replay_offset)) for e in episodes]
    mal = [e for e in episodes if e.get("label") == "malicious"]
    unknown = [e for e in episodes if e.get("label") == "unknown"]

    # A malicious episode is SURFACED only by a hard match (identity + in-window/untimed). An
    # episode whose only identity-matching detections are temporally unverifiable is AMBIGUOUS —
    # reported separately from a true miss so a missing timestamp is visible, not silently credited.
    surfaced, ambiguous_eps = [], []
    for ep in mal:
        verdicts = [match_verdict(d, ep, tol) for d in detections]
        if "match" in verdicts:
            surfaced.append(ep.get("id"))
        elif "ambiguous" in verdicts:
            ambiguous_eps.append(ep.get("id"))
    missed = [ep.get("id") for ep in mal
              if ep.get("id") not in surfaced and ep.get("id") not in ambiguous_eps]
    tp_ep = len(surfaced)
    recall = tp_ep / len(mal) if mal else 0.0        # surfaced+ambiguous+missed == total

    relevant, ambiguous, unscored, false = [], [], [], []
    for d in detections:
        mal_verdicts = [match_verdict(d, ep, tol) for ep in mal]
        if "match" in mal_verdicts:
            relevant.append(d)
        elif "ambiguous" in mal_verdicts:
            ambiguous.append(d)                       # right identity, unverifiable time (§24.3)
        elif any(matches(d, ep, tol) for ep in unknown):
            unscored.append(d)                        # matched only unknown -> unscored (§7)
        else:
            false.append(d)
    # Precision is over ADJUDICABLE items only: ambiguous/unscored cannot be adjudicated for/against
    # an incident, so they are excluded from the ratio rather than counted as relevant or false.
    adjudicated = len(relevant) + len(false)
    precision = len(relevant) / adjudicated if adjudicated else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "malicious_episodes": len(mal),
        "episodes_surfaced": tp_ep, "episodes_missed": len(missed),
        "episodes_ambiguous": len(ambiguous_eps), "ambiguous_ids": ambiguous_eps,
        "episode_recall": round(recall, 4),
        "analyst_items": len(relevant) + len(false) + len(ambiguous) + len(unscored),
        "relevant_items": len(relevant), "false_items": len(false),
        "ambiguous_items": len(ambiguous), "unscored_items": len(unscored),
        "analyst_precision": round(precision, 4), "f1": round(f1, 4),
        "surfaced_ids": surfaced,
        "missed_ids": missed,
    }
