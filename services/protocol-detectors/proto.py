"""Protocol detectors (plan U8 Tier 3/4). Pure scoring — app.py keeps state and
consumes tls/http/ssh/dns/flow. Covers JA4 novelty, cloud-staging, DoH, TLS cert
anomalies, suspicious user-agents, SSH brute-force, and ICMP exfil.
"""
from __future__ import annotations
import ipaddress
import os
import re

_EXTRA = tuple(p.strip() for p in os.environ.get("NDR_INTERNAL_PREFIXES", "").split(",") if p.strip())
PRIVATE = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
           "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
           "172.28.", "172.29.", "172.30.", "172.31.", "127.", "169.254.", "fe80:") + _EXTRA


def is_multicast(ip: str) -> bool:
    if not ip:
        return False
    if ip[:2].lower() == "ff":
        return True
    try:
        o = int(ip.split(".")[0])
        return 224 <= o <= 239 or o == 255
    except (ValueError, IndexError):
        return False


def is_external(ip: str) -> bool:
    if not ip or is_multicast(ip):
        return False
    if any(ip.startswith(p) for p in PRIVATE):     # IPv4 private + operator extras + fe80:
        return False
    if ":" in ip:                                   # IPv6: ULA (fc00::/7) / link-local = internal (F06)
        try:
            a = ipaddress.ip_address(ip)
            return not (a.is_private or a.is_link_local)
        except ValueError:
            return False
    return True


# --- D01: novelty is entity-relative; fleet popularity is context, not trust. ---
def ja4_valid(fp) -> bool:
    # Validate before exposing even partial features; flattened hashes have no AC.
    return isinstance(fp, str) and re.fullmatch(
        r"[tqd](?:1[0-3]|s[23]|d[12]|00)[di][0-9]{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}", fp) is not None


def ja4_parts(fp):
    return tuple(fp.split("_")) if ja4_valid(fp) else None


def ja4_ac(fp):
    parts = ja4_parts(fp)
    return f"{parts[0]}_{parts[2]}" if parts else ""


def baseline_maturity(observations, distinct, first_seen_ts, now,
                      min_observations=100, min_span_secs=86400):
    # D01 requires both traffic and coverage: elapsed idle time alone cannot warm a host.
    if observations < min_observations or distinct < 1 or first_seen_ts is None:
        return "cold"
    return "ready" if now - first_seen_ts >= min_span_secs else "warming"


def ja4_novelty(fp, entity_seen, entity_ac_seen, fleet_count, maturity,
                rare_max_entities=2, corroborated=False):
    if not ja4_valid(fp) or maturity != "ready" or fp in entity_seen:
        return False, [], 0.0, 0
    reasons = ["JA4_NEW_TO_ENTITY"]
    rare = fleet_count <= rare_max_entities
    if rare:
        reasons.append("JA4_RARE_IN_FLEET")
    severity, confidence = (5, 0.5) if rare or corroborated else (2, 0.3)
    if ja4_ac(fp) in entity_ac_seen:
        reasons.append("JA4_AC_SIMILARITY")
        # AC is supporting evidence of a benign variant only, never a malicious verdict.
        severity, confidence = max(1, severity - 1), confidence * 0.5
    return True, reasons, confidence, severity


def ja4_transition_burst(fp_times, window_secs=600, min_distinct=5):
    # Anchor to the latest observation, independent of wall clock for replay/tests.
    if not fp_times:
        return False, 0
    now = max(ts for ts, _ in fp_times)
    count = len({fp for ts, fp in fp_times
                 if now - window_secs <= ts <= now and ja4_valid(fp)})
    return count >= min_distinct, count


# Retain fingerprints for a week; maturity expires after a week of INACTIVITY, not
# on a tumbling deadline that would periodically disable a mature detector.
JA4_BASELINE_TTL_SECS = 604800.0


# --- Cloud-staging exfil (TA0010): TLS SNI to a data-sharing/cloud-storage host --
CLOUD_STAGING_SNIS = (
    "dropbox.com", "dropboxusercontent", "drive.google", "docs.google",
    "storage.googleapis", "onedrive", "1drv.ms", "mega.nz", "mega.io",
    "wetransfer", "pastebin.com", "transfer.sh", "anonfiles", "gofile.io",
    "s3.amazonaws", "backblazeb2", "sendspace", "file.io",
)


def cloud_staging_hit(sni: str) -> tuple[bool, str]:
    s = (sni or "").lower()
    for c in CLOUD_STAGING_SNIS:
        if c in s:
            return True, c
    return False, ""


# --- DoH / DoT to a non-approved resolver (defense evasion) ---------------------
DOH_SNIS = ("cloudflare-dns.com", "dns.google", "dns.quad9.net", "doh.opendns",
            "mozilla.cloudflare-dns", "dns.adguard", "doh.cleanbrowsing",
            "dns.nextdns", "chrome.cloudflare-dns")


# Well-known port -> the Suricata app_proto expected on it. A detected app that
# contradicts this (ssh on 443, cleartext http on a TLS port) is an evasion signal.
_PORT_PROTO = {22: "ssh", 21: "ftp", 25: "smtp", 587: "smtp", 465: "smtp",
               53: "dns", 80: "http", 8080: "http", 443: "tls", 8443: "tls",
               110: "pop3", 995: "pop3", 143: "imap", 993: "imap",
               445: "smb", 139: "smb", 3389: "rdp", 1883: "mqtt"}


def port_proto_mismatch(app_proto: str, dst_port, allow_ports=frozenset()) -> tuple[bool, str]:
    """True + why when Suricata's detected app_proto contradicts the well-known
    service for dst_port (T1571). Skips absent/unknown app_proto, ports with no
    expectation, and allowlisted tunneling ports. tls/ssl are treated as one."""
    ap = (app_proto or "").lower()
    if not ap or ap in ("failed", "unknown"):
        return False, ""
    try:
        port = int(dst_port)
    except (TypeError, ValueError):
        return False, ""
    if port in allow_ports:
        return False, ""
    expected = _PORT_PROTO.get(port)
    if expected is None:
        return False, ""
    norm = lambda p: "tls" if p in ("tls", "ssl") else p
    if norm(ap) != norm(expected):
        return True, f"{norm(ap)} on port {port} (expected {norm(expected)})"
    return False, ""


def doh_hit(sni: str, dst_port: int, approved_resolvers: set) -> tuple[bool, str]:
    s = (sni or "").lower()
    if dst_port == 853:            # DoT is unambiguous
        return True, "dot:853"
    for d in DOH_SNIS:
        if d in s and s not in approved_resolvers:
            return True, f"doh:{d}"
    return False, ""


# --- TLS cert anomaly: self-signed or very short-lived --------------------------
def cert_anomaly(subject: str, issuer: str, not_before: str, not_after: str) -> tuple[bool, str]:
    if subject and issuer and subject.strip() == issuer.strip():
        return True, "self_signed"
    # very short validity (< 2 days) is a common malware/C2 tell (ISO dates).
    try:
        from datetime import datetime
        b = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
        a = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
        if (a - b).total_seconds() < 2 * 86400:
            return True, "short_validity"
    except (ValueError, AttributeError, TypeError):
        pass
    return False, ""


# --- Suspicious user-agent (multi-tactic): non-browser / tooling ----------------
BAD_UA_SUBSTR = ("curl/", "wget/", "python-requests", "python-urllib", "go-http-client",
                 "powershell", "certutil", "bitsadmin", "nmap", "sqlmap", "masscan",
                 "libwww-perl", "winhttp", "java/", "empire", "cobalt")


def suspicious_ua(ua: str) -> tuple[bool, str]:
    if ua is None or ua == "":
        return True, "empty_ua"
    u = ua.lower()
    for b in BAD_UA_SUBSTR:
        if b in u:
            return True, b
    return False, ""


# --- SSH brute-force (T1110): many short SSH sessions src->dst ------------------
def ssh_brute_hit(session_count: int, min_sessions: int = 15) -> bool:
    return session_count >= min_sessions


# --- ICMP exfil (TA0010): large/many ICMP to an external dst -------------------
def icmp_exfil_hit(proto: str, total_bytes: int, dst_ip: str,
                   threshold: int = 1_000_000) -> bool:
    return (str(proto).upper() in ("ICMP", "IPV6-ICMP", "ICMPV6")
            and is_external(dst_ip) and total_bytes >= threshold)


# --- Reframed domain fronting (T1090.004): ECH, or cleartext Host != TLS SNI -----
def _strip_www(h: str) -> str:
    h = (h or "").lower().strip().split(":")[0]
    return h[4:] if h.startswith("www.") else h


def ech_present(tls_evt: dict) -> bool:
    """TLS ClientHello carrying Encrypted Client Hello (ECH), which hides the real
    SNI. Suricata exposes this only in recent builds; an absent field means no fire
    (dormant, documented in docs/suricata-config.md). ECH extension type is 0xfe0d."""
    if not tls_evt:
        return False
    if tls_evt.get("ech") or "encrypted_client_hello" in tls_evt:
        return True
    exts = tls_evt.get("extensions") or tls_evt.get("client_extensions") or []
    return any(str(e).lower() in ("ech", "encrypted_client_hello", "65037", "0xfe0d", "fe0d")
               for e in exts)


def host_sni_mismatch(sni: str, http_host: str) -> bool:
    """Cleartext HTTP Host that does not match the TLS SNI seen on the same flow — a
    domain-fronting tell. Both must be present (www-insensitive)."""
    if not sni or not http_host:
        return False
    return _strip_www(sni) != _strip_www(http_host)


def ech_or_host_sni_mismatch(tls_evt: dict, sni: str, http_host: str) -> tuple[bool, str]:
    """Reframed domain fronting (T1090.004): ECH usage, or a cleartext Host that
    disagrees with the flow's TLS SNI. Classic HTTPS fronting (fully encrypted, no
    visible Host) is out of scope and explicitly does NOT fire — there is nothing to
    compare. Returns (hit, reason)."""
    if ech_present(tls_evt):
        return True, "ech"
    if host_sni_mismatch(sni, http_host):
        return True, f"host_sni_mismatch:{http_host}!={sni}"
    return False, ""
