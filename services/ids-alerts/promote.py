"""Promote Suricata IDS signature alerts to NDR finding candidates (re-eval gap G1).

Suricata's signature engine is the platform's highest-confidence "this is a known
attack" verdict, but its alerts (on suricata.raw.v1) were never turned into
findings. This promotes the THREAT-relevant ones — filtering out the decoder/info
noise that dominates the alert stream (~99% of it) — into finding candidates.

Pure and testable; app.py is the Kafka I/O shell. Threat filter: keep Suricata
severity <= 2 (ET assigns 1-2 to malware/trojan/exploit/known-bad; 3 is
policy/info/protocol-decode), or an explicit Major/Critical signature_severity,
and always drop engine/decoder + ET INFO/POLICY signatures.
"""
from __future__ import annotations
import json

THREAT_SEVERITY_MAX = 2

# Engine/decoder + pure-informational signatures — never a threat finding.
_NOISE_PREFIXES = (
    "SURICATA STREAM", "SURICATA Ethertype", "SURICATA UDP", "SURICATA TCP",
    "SURICATA IP", "SURICATA ICMP", "SURICATA zero", "SURICATA DNS",
    "ET INFO", "ET POLICY", "GPL POLICY",
)

# Suricata alert category -> our finding category (drives MITRE in finding-service).
# Unmapped threat alerts still promote, as generic 'malware'.
_CATEGORY_MAP = {
    "a network trojan was detected": "c2",
    "malware command and control activity detected": "c2",
    "misc attack": "c2",                      # incl. Spamhaus / known-bad-IP hits
    "attempted denial of service": "c2",
    "attempted information leak": "recon",
    "detection of a network scan": "recon",
    "potential corporate privacy violation": "exfil",
    "exfiltration": "exfil",
    "successful administrator privilege gain": "lateral",
    "attempted administrator privilege gain": "lateral",
    "attempted user privilege gain": "lateral",
    "web application attack": "malware",
    "exploit kit activity detected": "malware",
    "targeted malicious activity was detected": "malware",
}


def _sig_severity(md: dict) -> str:
    v = (md or {}).get("signature_severity")
    if isinstance(v, list):
        return " ".join(str(x) for x in v).lower()
    return str(v or "").lower()


def is_threat_alert(alert: dict) -> bool:
    """A promotable, threat-relevant Suricata alert (not decoder/info noise)."""
    if not alert:
        return False
    sig = str(alert.get("signature", ""))
    if sig.startswith(_NOISE_PREFIXES):
        return False
    try:
        sev = int(alert.get("severity"))
    except (TypeError, ValueError):
        return False
    ss = _sig_severity(alert.get("metadata") or {})
    return sev <= THREAT_SEVERITY_MAX or "major" in ss or "critical" in ss


def category_for(alert: dict) -> str:
    return _CATEGORY_MAP.get(str(alert.get("category", "")).strip().lower(), "malware")


def join_key_entities(eve: dict) -> list[dict]:
    """community_id/flow_id join a finding back to the exact connection's
    flow/tls/dns telemetry in ClickHouse (metadata enrichment, no capture).
    Only added when the source event carries them. Keep in sync with the same
    helper in file-threat/filematch.py and threat-intel/app.py."""
    out = []
    if eve.get("community_id"):
        out.append({"type": "community_id", "value": eve["community_id"]})
    if eve.get("flow_id"):
        out.append({"type": "flow_id", "value": eve["flow_id"]})
    return out


def to_candidate(eve: dict, tenant: str = "homelab") -> dict | None:
    """Map a Suricata alert EVE record to an ndr.finding.candidate.v1, or None."""
    if eve.get("event_type") != "alert":
        return None
    alert = eve.get("alert") or {}
    if not is_threat_alert(alert):
        return None
    sev = int(alert.get("severity", 2) or 2)
    our_sev = 9 if sev <= 1 else 8            # Suricata sev1 -> 9, sev2 -> 8
    sid = alert.get("signature_id")
    src, dst = eve.get("src_ip"), eve.get("dest_ip")
    ents = [
        {"type": "ip", "role": "src", "value": src},
        {"type": "ip", "role": "dst", "value": dst},
        {"type": "signature", "value": alert.get("signature")},
        {"type": "signature_id", "value": sid},
    ]
    ents += join_key_entities(eve)
    entities = json.dumps(ents)
    return {
        "finding_id": f"idsig-{sid}-{abs(hash((sid, src, dst))) % 10**10}",
        "tenant_id": tenant, "detector_id": "ids_signature", "detector_version": "1.0",
        "category": category_for(alert), "severity": our_sev, "confidence": 0.9,
        "entities": entities, "state": "CANDIDATE",
    }
