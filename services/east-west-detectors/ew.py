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


def scan_score(dst_port_pairs: set, min_dsts: int = 25, min_ports: int = 15) -> tuple[bool, str, int]:
    """Internal scanning (T1046): one source touching many distinct internal hosts
    (horizontal) or many distinct ports on one host (vertical). `dst_port_pairs` is a
    set of (dst, port). Returns (hit, kind, n)."""
    dsts = {d for (d, _p) in dst_port_pairs}
    if len(dsts) >= min_dsts:
        return True, "horizontal", len(dsts)
    ports_by_dst: dict[str, set] = {}
    for d, p in dst_port_pairs:
        ports_by_dst.setdefault(d, set()).add(p)
    mx = max((len(s) for s in ports_by_dst.values()), default=0)
    if mx >= min_ports:
        return True, "vertical", mx
    return False, "", 0


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


def spray_score(distinct_failed_principals: set, min_principals: int = 10) -> tuple[bool, int]:
    """Password spraying (T1110.003): one source failing auth against many DISTINCT
    accounts (a few tries each) — the inverse of brute force (many tries, one
    account). `distinct_failed_principals` is the set of accounts this source failed
    against in the window. Returns (hit, n)."""
    n = len({p for p in distinct_failed_principals if p})
    return (n >= min_principals, n)


def asrep_roast_score(preauthless_principals: set, min_accounts: int = 3) -> tuple[bool, int]:
    """AS-REP roasting (T1558.004): AS-REQs for accounts with Kerberos
    pre-authentication disabled (the KDC returns an AS-REP an attacker cracks
    offline). `preauthless_principals` = distinct accounts seen in AS-REQs with no
    pre-auth. Sits alongside kerberoast_score (T1558.003, the TGS side). Returns
    (hit, n)."""
    n = len({p for p in preauthless_principals if p})
    return (n >= min_accounts, n)


def ransomware_smb_score(distinct_files: int, writes: int, reads: int,
                         min_files: int = 100, min_writes: int = 100,
                         min_write_ratio: float = 0.7) -> tuple[bool, int]:
    """Ransomware over SMB (T1486): one source writing/renaming a flood of DISTINCT
    files in a short window, write-heavy (encryption rewrites every file). Read-only
    enumeration (writes==0) never fires; a busy read-mostly file server stays below
    the write ratio. Returns (hit, writes)."""
    total = writes + reads
    if total == 0:
        return (False, 0)
    ratio = writes / total
    return (distinct_files >= min_files and writes >= min_writes and ratio >= min_write_ratio, writes)


# SMB named pipes used by remote-exec tooling (PsExec/schtasks/registry/SAM). T1021.002.
LATERAL_EXEC_PIPES = {
    "svcctl": "service control (PsExec)",
    "atsvc": "scheduled task (at)",
    "winreg": "remote registry",
    "samr": "SAM remote",
    "lsarpc": "LSA remote",
}


def _pipe_key(name: str) -> str:
    """Normalise an SMB pipe name: strip leading \\, PIPE\\, and casing."""
    k = (name or "").lower().replace("\\", "/").rsplit("/", 1)[-1]
    return k


def lateral_exec_score(pipe_names, dcerpc_ifaces, winrm_targets,
                       min_signals: int = 1) -> tuple[bool, list]:
    """Remote code execution across hosts (PsExec / WMI / scheduled-task / WinRM;
    T1021.002 / T1047 / T1569.002). Matches known exec SMB named pipes, DCERPC exec
    interfaces, and WinRM (5985/5986) access. Benign RPC that hits none of these
    stays quiet. Returns (hit, matched_descriptions)."""
    matched = []
    for pn in pipe_names or []:
        k = _pipe_key(pn)
        if k in LATERAL_EXEC_PIPES:
            matched.append(f"pipe:{k} ({LATERAL_EXEC_PIPES[k]})")
    for uuid in dcerpc_ifaces or []:
        hit, desc = dcerpc_lateral(uuid)
        if hit:
            matched.append(f"dcerpc:{desc}")
    if winrm_targets:
        matched.append(f"winrm:{len({t for t in winrm_targets if t})} target(s)")
    return (len(matched) >= min_signals, matched)


def llmnr_poison_score(answered_names: set, min_names: int = 5) -> tuple[bool, int]:
    """LLMNR / NBT-NS / mDNS poisoning (T1557.001): a host answering many DISTINCT
    name queries it does not own (Responder-style), versus a legitimate host that
    answers only for its own name. `answered_names` = distinct query names this host
    answered. TELEMETRY NOTE: Suricata surfaces LLMNR (udp/5355) as dns events but
    does NOT decode NBT-NS (udp/137), so coverage is LLMNR/mDNS-leaning; see
    docs/suricata-config.md.

    ROADMAP / NOT YET WIRED: this scoring is unit-tested but is not yet consumed by
    app.py — east-west subscribes to flow/raw, not the dns stream. Wiring it to
    per-responder dns-answer state is tracked; until then it does not emit findings.

    Returns (hit, n)."""
    n = len({x for x in answered_names if x})
    return (n >= min_names, n)
