"""East-west / lateral-movement detector logic (plan U8 Tier 2; v2 §16.6).
Pure functions — app.py keeps per-source state. BLUEPRINT: validatable only with
Windows/AD/SMB traffic on the monitored segment (this homelab has none), but this
is the highest-value NDR tier for an enterprise and fires the moment east-west
traffic appears.
"""
from __future__ import annotations

PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")


def is_internal(ip: str) -> bool:
    return bool(ip) and any(ip.startswith(p) for p in PRIVATE_PREFIXES)


# admin / remote-exec ports that carry lateral movement (T1021).
ADMIN_PORTS = {445, 3389, 5985, 5986, 135, 139, 22, 23, 1433, 3306, 5432, 5900}

# DCERPC interfaces used by lateral tooling (PsExec/schtasks/WMI). T1021.002/T1569.
LATERAL_DCERPC_UUIDS = {
    "367abb81-9844-35f1-ad32-98f038001003": "svcctl (service create/start — PsExec)",
    "1ff70682-0a51-30e8-076d-740be8cee98b": "atsvc (scheduled task)",
    "86d35949-83c9-4044-b424-db363231fd0c": "ITaskSchedulerService",
    "4b324fc8-1670-01d3-1278-5a47bf6ee188": "srvsvc (share enum)",
    "8a885d04-1ceb-11c9-9fe8-08002b104860": "IWbemServices (WMI/DCOM exec)",
}


def lateral_fanout(internal_admin_targets: set, min_targets: int = 5) -> tuple[bool, int]:
    """One source touching many distinct internal hosts on admin ports."""
    dsts = {d for (d, _p) in internal_admin_targets}
    return (len(dsts) >= min_targets, len(dsts))


def rdp_fanout(rdp_targets: set, min_targets: int = 3) -> tuple[bool, int]:
    """One source RDP-ing to many internal hosts."""
    return (len(rdp_targets) >= min_targets, len(rdp_targets))


def kerberoast_score(tgs_reqs: list[dict], min_spns: int = 8) -> tuple[bool, int, bool]:
    """Kerberoasting (T1558.003): one host requesting service tickets for many
    distinct SPNs, especially with RC4 (etype 23) downgrade. tgs_reqs is a list of
    {sname, encryption}. Returns (hit, distinct_spns, rc4_seen)."""
    spns = {t.get("sname") for t in tgs_reqs if t.get("sname")}
    rc4 = any(str(t.get("encryption", "")).lower() in ("23", "rc4", "rc4-hmac", "0x17")
              for t in tgs_reqs)
    return (len(spns) >= min_spns or (rc4 and len(spns) >= 3), len(spns), rc4)


def dcerpc_lateral(interface_uuid: str) -> tuple[bool, str]:
    """DCERPC call to a lateral-movement interface."""
    u = (interface_uuid or "").lower()
    if u in LATERAL_DCERPC_UUIDS:
        return True, LATERAL_DCERPC_UUIDS[u]
    return False, ""
