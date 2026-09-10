"""Zeek-log <-> Suricata-EVE capability parity (pure, stdlib only). Encodes how far
Suricata's EVE (as Cernity configures it) covers what Zeek logs standalone, and
renders the table used in docs/suricata-zeek-parity.md. This backs the "Suricata
logging on the same level as Zeek" claim with a concrete, checkable map.
"""
from __future__ import annotations

COVERAGE = ("full", "partial", "none")

# Zeek log -> (Suricata EVE equivalent, coverage, note). Order is display order.
PARITY = {
    "conn":     ("flow (+ community-id)", "full", "connection records + flow hash"),
    "dns":      ("dns (version 3)", "full", "queries and answers"),
    "http":     ("http (extended)", "full", "method / host / user-agent / status"),
    "ssl":      ("tls (extended)", "full", "version / SNI / cipher"),
    "x509":     ("tls subject/issuer/notbefore/notafter", "partial", "cert fields, not the full DER chain"),
    "files":    ("files (force-hash)", "full", "file extraction + hashes"),
    "ssh":      ("ssh", "full", "client/server banners"),
    "smb":      ("smb", "partial", "command/filename; op granularity varies by Suricata version"),
    "kerberos": ("krb5", "partial", "sname/encryption/error_code; no pre-auth flag exposed"),
    "dce_rpc":  ("dcerpc", "full", "interface UUIDs"),
    "ntlm":     ("smb.ntlmssp", "partial", "surfaced inside smb events"),
    "ja4":      ("tls.ja4 / ja4s", "full", "client + server fingerprints"),
    "weird":    ("anomaly", "partial", "Suricata anomaly events cover some Zeek 'weird's"),
    "notice":   ("(none — Cernity findings)", "none",
                 "Zeek's scripted notices have no direct EVE analog; Cernity's detectors ARE "
                 "that behavioral layer — the point of the whole comparison"),
}


def coverage_counts() -> dict:
    out = {c: 0 for c in COVERAGE}
    for _z, (_e, cov, _n) in PARITY.items():
        out[cov] += 1
    return out


def render_table() -> str:
    lines = ["| Zeek log | Suricata EVE equivalent | Coverage | Note |",
             "|---|---|---|---|"]
    for z, (eve, cov, note) in PARITY.items():
        lines.append(f"| `{z}` | {eve} | {cov} | {note} |")
    return "\n".join(lines) + "\n"
