"""U2 live EVE matching against the local U1 intel store.
Legacy feed parsing and static matching remain available when INTEL_DB is unset.
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


def match_static(dst_ip: str, ja3: str, cert_sha1: str,
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


def dimensions(eve: dict):
    """Yield only supplied EVE values; never infer a URL scheme or a file hash."""
    from urllib.parse import urlsplit

    def obj(value):
        return value if isinstance(value, dict) else {}

    def value(kind, field, raw):
        if isinstance(raw, dict):
            raw = raw.get("hash")
        if isinstance(raw, str) and raw.strip():
            yield kind, field, raw

    for field in ("src_ip", "dest_ip"):
        yield from value("ip", field, eve.get(field))
    tls = obj(eve.get("tls"))
    yield from value("domain", "tls.sni", tls.get("sni"))
    for field, kind in (("ja3", "ja3"), ("ja3s", "ja3"), ("ja4", "ja4"),
                        ("ja4s", "ja4"), ("fingerprint", "cert")):
        yield from value(kind, "tls." + field, tls.get(field))
    dns = obj(eve.get("dns"))
    yield from value("domain", "dns.rrname", dns.get("rrname"))
    for group in ("queries", "answers"):
        entries = dns.get(group)
        if isinstance(entries, list):
            for i, entry in enumerate(entries):
                yield from value("domain", f"dns.{group}.{i}.rrname", obj(entry).get("rrname"))
    http = obj(eve.get("http"))
    yield from value("domain", "http.hostname", http.get("hostname"))
    # EVE commonly supplies only a request target (/path). It is not a full URL.
    for field, raw in (("http.url", http.get("url")), ("url", eve.get("url"))):
        if isinstance(raw, str):
            try:
                parsed = urlsplit(raw)
                if parsed.scheme and parsed.hostname:
                    yield "url", field, raw
            except ValueError:
                continue


def match(eve: dict, store, tenant: str, now: float) -> list[dict]:
    """All live U1 hits for a trusted service tenant, including labeled suppressed hits.

    Re-derive trust/score at read time. Suppressed hits are returned for local audit,
    never prioritized. Payload tenant identifiers cannot select a different store tenant.
    """
    import ipaddress
    import lifecycle

    if not tenant or (eve.get("tenant_id") is not None and eve["tenant_id"] != tenant):
        return []
    if eve.get("tenant") is not None and eve["tenant"] != tenant:
        return []
    matches = []
    seen = set()
    for kind, field, raw in dimensions(eve):
        try:
            normalized = lifecycle.norm_indicator(kind, raw)
        except ValueError:
            continue
        records = []
        exact = store.get(tenant, kind, normalized)
        if exact:
            records.append(exact)
        if kind == "ip":
            try:
                address = ipaddress.ip_address(normalized)
                for record in store.networks(tenant):
                    try:
                        if address in ipaddress.ip_network(record["indicator"], strict=False):
                            records.append(record)
                    except ValueError:
                        continue
            except ValueError:
                pass
        for record in records:
            key = (kind, record["indicator"], field, normalized)
            if key in seen:
                continue
            seen.add(key)
            lifecycle.derive(record, now)
            if not lifecycle.is_active(record, now):
                continue
            record["suppressed"] = store.is_suppressed(tenant, kind, record["indicator"], now)
            record["observed_field"] = field
            record["observed_value"] = raw
            matches.append(record)
    return matches
