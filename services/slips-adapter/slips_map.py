"""Pure mapping: a SLIPS alert (IDEA0 JSON) -> a Cernity candidate finding.

SLIPS emits an alert only after accumulated evidence for a (profile, timewindow)
crosses its threshold, so every alert here is already a high-fidelity, per-host
verdict -- the fidelity level Cernity wants (alerts, not raw evidence). We
translate that verdict into the candidate contract (contracts/finding.schema.json)
tagged detector_id=slips_ml and let finding-service run it through the same
lifecycle as any heuristic candidate. ML-only alerts become their own findings;
correlating a SLIPS verdict with an agreeing heuristic finding (merge & boost) is
a separate concern that needs cross-detector state -- not done here.

The mapping tables (SLIPS threat level -> severity, IDEA0 category -> Cernity
category + ATT&CK) are DEFAULTS meant to be tuned against real traffic. They are
deliberately simple and honest: an ML hit we can't defensibly pin to a technique
gets category "anomaly" and no MITRE, never a fabricated one.
"""
import hashlib
import json
import time

# SLIPS threat levels -> Cernity severity (1-10). A SLIPS *alert* (not raw
# evidence) is already significant, so even "low" maps mid-scale. Tunable.
_THREAT_SEV = {"info": 3, "low": 4, "medium": 6, "high": 8, "critical": 9}
_DEFAULT_TL = "critical"   # SLIPS' own default alert threat level

# IDEA0 top-level taxonomy segment -> (cernity category, precise ATT&CK). Prefix
# match on the first segment of the first IDEA0 Category. Unknown -> anomaly/[]:
# an honest "ML behavioral hit, no defensible technique".
_CAT = {
    "Recon":        ("recon", ["T1046"]),
    "Attempt":      ("bruteforce", ["T1110"]),
    "Intrusion":    ("c2", ["T1071"]),
    "Malware":      ("c2", ["T1071"]),
    "Exfiltration": ("exfil", ["TA0010"]),
    "Anomaly":      ("anomaly", []),
}


def _first_ip(idea_nodes):
    """IDEA0 Source/Target is a list of nodes; pull the first IPv4/IPv6."""
    for node in idea_nodes or []:
        for k in ("IP4", "IP6"):
            v = node.get(k)
            if v:
                return v[0]
    return None


def _threat_level(alert):
    tl = str(alert.get("threat_level") or "").lower()
    return tl if tl in _THREAT_SEV else _DEFAULT_TL


def _category(alert):
    cats = alert.get("Category") or []
    first = (cats[0] if cats else "").split(".")[0]
    return _CAT.get(first, ("anomaly", []))


def _idea_time(alert):
    """IDEA0 DetectTime is ISO8601; Cernity findings use "%Y-%m-%d %H:%M:%S"."""
    t = alert.get("DetectTime") or alert.get("CreateTime")
    if not t:
        return None
    return str(t).replace("T", " ").replace("Z", "").split(".")[0][:19]


def _stable(s):
    return int(hashlib.sha1(s.encode()).hexdigest()[:15], 16)


def alert_to_candidate(alert, tenant, version="1.0"):
    """Return a candidate dict, or None if the alert has no usable attacker IP."""
    attacker = _first_ip(alert.get("Source"))
    if not attacker:
        return None
    victim = _first_ip(alert.get("Target"))
    tl = _threat_level(alert)
    category, mitre = _category(alert)
    conf = min(max(float(alert.get("Confidence", 0.7) or 0.7), 0.0), 1.0)
    desc = alert.get("Description") or alert.get("Note") or "SLIPS behavioral alert"
    aid = str(alert.get("ID") or _stable(f"{attacker}:{alert.get('DetectTime', '')}:{desc}"))

    ents = [{"type": "ip", "role": "attacker", "value": attacker}]
    if victim:
        ents.append({"type": "ip", "role": "victim", "value": victim})
    ents.append({"type": "ml", "source": "slips", "threat_level": tl, "description": desc})

    now = _idea_time(alert) or time.strftime("%Y-%m-%d %H:%M:%S")
    c = {"finding_id": f"slips-{aid}",
         "tenant_id": tenant, "detector_id": "slips_ml", "detector_version": version,
         "category": category, "severity": _THREAT_SEV[tl], "confidence": conf,
         "first_seen": now, "last_seen": now,
         "entities": json.dumps(ents), "state": "CANDIDATE"}
    if mitre:
        c["mitre"] = mitre     # precise technique(s); finding-service prefers this
    return c
