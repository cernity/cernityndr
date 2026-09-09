"""Asset / identity resolution (plan U17; v2 §15.5). Pure logic — app.py wires it
to the topics + ClickHouse. The entity spine: resolve every observation to a
stable asset_key within a tenant so the SAME host seen by different sensors (same
MAC) folds into one entity, even as its IP changes (NAT/DHCP).

Keys are always (tenant_id, asset_key). MAC is the strongest identity; fall back
to a currently-known IP->MAC binding; else key on the IP itself.
"""
from __future__ import annotations


def extract_evidence(eve: dict) -> list[dict]:
    """Pull (ip, mac, hostname) observations from a Suricata EVE record.
    Different event types carry different identity strength."""
    et = eve.get("event_type")
    out: list[dict] = []
    if et == "flow":
        # flows give IP activity only (no L2 on most sensors).
        for ip in (eve.get("src_ip"), eve.get("dest_ip")):
            if ip:
                out.append({"ip": ip, "mac": None, "hostname": None, "src": "flow"})
    elif et == "arp":
        a = eve.get("arp", {}) or {}
        if a.get("src_ip"):
            out.append({"ip": a.get("src_ip"), "mac": a.get("src_mac"),
                        "hostname": None, "src": "arp"})
    elif et == "dhcp":
        d = eve.get("dhcp", {}) or {}
        ip = d.get("assigned_ip") or d.get("client_ip")
        if ip:
            out.append({"ip": ip, "mac": d.get("client_mac"),
                        "hostname": d.get("hostname"), "src": "dhcp"})
    return out


def asset_key(obs: dict, ip_to_mac: dict) -> str:
    """Resolve an observation to a stable asset_key. MAC-first identity."""
    mac = obs.get("mac")
    if mac:
        return f"mac:{mac.lower()}"
    ip = obs.get("ip")
    known = ip_to_mac.get(ip)
    if known:
        return f"mac:{known.lower()}"     # cross-sensor unification via IP->MAC
    return f"ip:{ip}"


def merge(asset: dict | None, obs: dict, ts: str) -> dict:
    """Merge an observation into an asset record (accumulate sets, advance seen)."""
    a = asset or {"ip_set": [], "mac_set": [], "hostname_set": [],
                  "evidence_sources": [], "first_seen": ts, "confidence": 0.5,
                  "role_if_known": ""}
    for field, val in (("ip_set", obs.get("ip")), ("mac_set", obs.get("mac")),
                       ("hostname_set", obs.get("hostname")),
                       ("evidence_sources", obs.get("src"))):
        v = (val or "").lower() if field == "mac_set" and val else val
        if v and v not in a[field]:
            a[field] = a[field] + [v]
    a["last_seen"] = ts
    # confidence rises with corroborating evidence types.
    a["confidence"] = min(1.0, 0.5 + 0.1 * len(set(a["evidence_sources"])))
    return a
