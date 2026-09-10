"""Threat-intel feed parsing + matching (plan U8 Tier 1; RITA's 4th pillar).
Pure logic — app.py fetches the feeds and consumes the topics. Matches observed
dst IPs / JA3 / TLS cert SHA1 / domains against abuse.ch blocklists.
"""
from __future__ import annotations
import re

_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HEX = re.compile(r"^[0-9a-f]{32,64}$")


def parse_feodo(text: str) -> set[str]:
    """Feodo Tracker ipblocklist.txt: one C2 IP per line, '#' comments."""
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tok = line.split(",")[0].strip()
        if _IP.match(tok):
            out.add(tok)
    return out


def parse_hash_csv(text: str) -> set[str]:
    """SSLBL sslblacklist.csv / ja3_fingerprints.csv: extract the hash column
    (SHA1 40-hex or JA3 32-hex md5), tolerating either column layout."""
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for tok in line.split(","):
            t = tok.strip().lower()
            if _HEX.match(t):
                out.add(t)
                break
    return out


def norm(v: str) -> str:
    return (v or "").strip().lower()


def match(dst_ip: str, ja3: str, cert_sha1: str,
          feodo: set, ja3_bl: set, cert_bl: set) -> tuple[bool, str, str]:
    """Return (hit, feed, ioc) for the strongest match on an observation."""
    if dst_ip and dst_ip in feodo:
        return True, "feodo_c2", dst_ip
    j = norm(ja3)
    if j and j in ja3_bl:
        return True, "sslbl_ja3", j
    c = norm(cert_sha1)
    if c and c in cert_bl:
        return True, "sslbl_cert", c
    return False, "", ""


def parse_fp_list(text: str) -> set[str]:
    """Operator-supplied known-C2 server-fingerprint blocklist: one JA3S/JA4S/JARM
    per line, '#' comments, optional trailing ',reason' column. Case-insensitive.
    This is the operator's own list of malware-tool fingerprints (Cobalt Strike,
    Sliver, etc.) — no feed is bundled."""
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tok = norm(line.split(",")[0])
        if tok:
            out.add(tok)
    return out


def match_server_fp(ja3s: str, ja4s: str, jarm: str, fp_bl: set) -> tuple[bool, str, str]:
    """Match a TLS SERVER-side fingerprint (JA3S / JA4S / JARM) against the operator
    known-C2 fingerprint blocklist. Returns (hit, fp_type, ioc). An empty blocklist
    is a no-op (feature off)."""
    for typ, val in (("ja3s", ja3s), ("ja4s", ja4s), ("jarm", jarm)):
        v = norm(val)
        if v and v in fp_bl:
            return True, f"c2fp_{typ}", v
    return False, "", ""
