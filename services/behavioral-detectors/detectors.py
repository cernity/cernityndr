"""Behavioral detector scoring (plan U8; v2 §16.3-4, §16.8). Pure functions —
app.py keeps the per-entity state and emits candidates. These are the stateful
detectors that don't fit a simple windowed count: beaconing (timing regularity),
DNS tunneling / DGA (volume + entropy), exfiltration (outbound volume).

Validate against RITA (ALTERNATIVES.md) as the FOSS oracle.
"""
from __future__ import annotations
import ipaddress
import math
import os

# Extra internal prefixes from env (e.g. the ISP-delegated IPv6 /prefix).
_EXTRA = tuple(p.strip() for p in os.environ.get("NDR_INTERNAL_PREFIXES", "").split(",") if p.strip())
PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                    "127.", "169.254.", "fe80:") + _EXTRA

# Legit-periodic destinations that look like beacons but aren't (DNS resolvers,
# NTP). Extend via NDR_BEACON_ALLOWLIST.
_BEACON_ALLOW = set(["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"]
                    + [x.strip() for x in os.environ.get("NDR_BEACON_ALLOWLIST", "").split(",") if x.strip()])

# Trusted egress destinations to exclude from exfil scoring — this site's own
# API/backup providers where large outbound volume is expected (e.g. Anthropic
# API traffic from a workstation). Prefix match. Set via NDR_EXFIL_ALLOWLIST.
# Narrow this to exfil only: unlike NDR_INTERNAL_PREFIXES it does NOT mark the
# range internal, so beacon/long-conn/rare-dest still watch it.
_EXFIL_ALLOW = tuple(p.strip() for p in os.environ.get("NDR_EXFIL_ALLOWLIST", "").split(",") if p.strip())


def is_multicast(ip: str) -> bool:
    if not ip:
        return False
    if ip[:2].lower() == "ff":            # IPv6 multicast ff00::/8
        return True
    try:
        o = int(ip.split(".")[0])
        return 224 <= o <= 239 or o == 255  # IPv4 multicast/broadcast
    except (ValueError, IndexError):
        return False


def is_external(ip: str) -> bool:
    if not ip or is_multicast(ip):
        return False
    if any(ip.startswith(p) for p in PRIVATE_PREFIXES):   # IPv4 private + operator extras + fe80:
        return False
    if ":" in ip:                                          # IPv6: ULA (fc00::/7) / link-local = internal (F06)
        try:
            a = ipaddress.ip_address(ip)
            return not (a.is_private or a.is_link_local)
        except ValueError:
            return False
    return True


# Pure content-CDN prefixes — high keepalive noise, low C2 risk. Deliberately
# NOT including cloud IaaS (AWS/Azure/DO/GCP compute) since C2 often lives there.
CDN_PREFIXES = (
    # Cloudflare
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
    "104.23.", "104.24.", "104.25.", "104.26.", "104.27.", "172.64.", "172.65.",
    "172.66.", "172.67.", "172.68.", "172.69.", "172.70.", "172.71.", "2606:4700",
    # Fastly
    "151.101.", "146.75.", "199.232.", "2a04:4e42",
    # Google (serving)
    "142.250.", "142.251.", "172.217.", "216.58.", "172.253.", "74.125.", "2607:f8b0",
    # Apple
    "17.", "2620:149",
    # Akamai
    "23.32.", "23.33.", "23.34.", "23.35.", "23.192.", "23.193.", "2.16.", "2.17.",
)


def beacon_noise_dst(ip: str) -> bool:
    """Destinations to exclude from beacon analysis: multicast, known resolvers,
    and pure content CDNs (keepalive noise). Cloud IaaS stays in scope for C2."""
    return (is_multicast(ip) or ip in _BEACON_ALLOW
            or any(ip.startswith(p) for p in CDN_PREFIXES))


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _stats(xs: list[float]) -> tuple[float, float]:
    n = len(xs)
    if n == 0:
        return 0.0, 0.0
    mean = sum(xs) / n
    var = sum((x - mean) ** 2 for x in xs) / n
    return mean, math.sqrt(var)


def _median(xs: list[float]) -> float:
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return 0.0
    m = n // 2
    return s[m] if n % 2 else (s[m - 1] + s[m]) / 2.0


def _quartiles(xs: list[float]) -> tuple[float, float, float]:
    """Q1, Q2, Q3 by splitting the sorted series at the median (Tukey's method,
    which is what RITA uses for the Bowley skew of intervals/sizes)."""
    s = sorted(xs)
    n = len(s)
    if n < 2:
        v = s[0] if s else 0.0
        return v, v, v
    m = n // 2
    lower, upper = s[:m], (s[m + 1:] if n % 2 else s[m:])
    return _median(lower), _median(s), _median(upper)


def _bowley_skew_score(xs: list[float]) -> float:
    """1 - |Bowley skewness|, in 0..1. Bowley skew = (Q3 + Q1 - 2*Q2)/(Q3 - Q1) is
    a quartile-based (outlier-robust) skewness; a perfectly regular beacon is
    symmetric (skew ~ 0 -> score ~ 1). RITA uses this instead of moment skewness
    because a few jittered intervals do not wreck it."""
    q1, q2, q3 = _quartiles(xs)
    denom = q3 - q1
    if denom == 0:
        return 1.0                      # all quartiles equal = perfectly regular
    skew = (q3 + q1 - 2 * q2) / denom
    return max(0.0, 1.0 - abs(skew))


def _madm_score(xs: list[float]) -> float:
    """1 - MADM/median, in 0..1. MADM (median absolute deviation from the median)
    is a robust dispersion measure; RITA uses it instead of std-dev/CV because it
    ignores the occasional outlier a jittering beacon injects to evade CV."""
    med = _median(xs)
    if med <= 0:
        return 0.0
    mad = _median([abs(x - med) for x in xs])
    return max(0.0, 1.0 - min(mad / med, 1.0))


def _count_score(n: int, target: int) -> float:
    """Connection-count confidence, 0..1, saturating at `target`. RITA weights a
    beacon by how many connections it saw: 6 regular callbacks is weak evidence,
    hundreds is strong. Below the target the score scales linearly."""
    return max(0.0, min(1.0, n / float(target))) if target > 0 else 1.0


def _regularity(xs: list[float]) -> float:
    """RITA's per-series regularity: mean of the outlier-robust skew and MADM
    scores. 1.0 = perfectly regular, ~0 = irregular."""
    if not xs:
        return 0.0
    return 0.5 * _bowley_skew_score(xs) + 0.5 * _madm_score(xs)


# --- Beaconing (v2 §16.3): regular callback to a destination ------------------
# Multi-signal beacon scoring, adopting RITA's method (Active Countermeasures)
# rather than deploying RITA as a separate tool: a C2 beacon is regular in BOTH
# its inter-arrival intervals AND its payload sizes. RITA scores regularity with
# OUTLIER-ROBUST statistics (Bowley skewness + median absolute deviation), not
# coefficient-of-variation, because a beacon that injects a few jittered
# intervals to evade a CV threshold barely moves the quartile-based measures.
# The score also weights by connection count (more callbacks = stronger evidence).
def beacon_score(timestamps: list[float], sizes: list[float] | None = None,
                 min_conns: int = 6, threshold: float = 0.80,
                 count_target: int = 12) -> tuple[bool, float]:
    """Return (is_beacon, score 0..1). Score = (2*regularity + count_score)/3,
    where regularity is the mean of Bowley-skew and MADM scores (interval-only,
    or averaged with payload-size regularity when `sizes` is given) and
    count_score saturates at `count_target` connections."""
    ts = sorted(timestamps)
    if len(ts) < min_conns:
        return False, 0.0
    intervals = [b - a for a, b in zip(ts, ts[1:]) if b > a]
    if not intervals or _median(intervals) <= 0:
        return False, 0.0
    reg = _regularity(intervals)
    if sizes and len(sizes) >= min_conns:
        reg = 0.5 * reg + 0.5 * _regularity(sizes)
    cnt = _count_score(len(ts), count_target)
    score = round((2.0 * reg + cnt) / 3.0, 3)
    return (score >= threshold), score


# --- FQDN / SNI beaconing (fast-flux / CDN-fronted C2) ------------------------
# The plain beacon keys on the destination IP, so C2 that rotates its IP every
# callback (fast-flux, or a CDN/domain-fronted controller) never reaches quorum on
# any one IP. Keying the beacon on the DOMAIN instead lets those callbacks
# accumulate. This only fires when the domain was seen across MULTIPLE dst IPs in
# the window (the rotation signature); a single-IP domain is already covered by
# beacon_score, so gating on min_ips avoids double-counting the stable-IP case.
def fqdn_beacon(timestamps: list[float], sizes: list[float] | None,
                n_distinct_ips: int, min_ips: int = 2,
                **kw) -> tuple[bool, float]:
    """Return (is_beacon, score). Defers to beacon_score for the regularity math;
    fires only when the domain spans >= min_ips destination IPs (IP rotation)."""
    if n_distinct_ips < min_ips:
        return False, 0.0
    return beacon_score(timestamps, sizes, **kw)


# --- Strobe (RITA): a pair with an abnormally HIGH connection count -----------
# RITA surfaces "strobes" separately from beacons: connections so numerous (and
# often so dense) that the beacon scorer filters them out, yet the sheer volume
# of separate connections to one external dst is itself anomalous. Causes: fast
# callback C2, a misconfigured/looping client, or a connection-per-request agent.
# Cheap: uses the connection count the beacon window already tracks. Kept distinct
# from a genuine beacon (regular timing) — this fires on the count alone.
def strobe_check(n_conns: int, dst_ip: str, is_beacon: bool = False,
                 min_conns: int = 90) -> tuple[bool, float]:
    """Return (is_strobe, score). Fires on a high count of separate connections to
    an external dst that did NOT already score as a beacon (so a regular beacon is
    reported as a beacon, not double-counted as a strobe)."""
    if is_beacon or not is_external(dst_ip) or n_conns < min_conns:
        return False, 0.0
    return True, round(min(1.0, n_conns / (min_conns * 4.0)), 3)


# --- DNS tunneling / DGA (v2 §16.4): high-volume, long/high-entropy queries ----
def dns_tunnel_score(qnames: list[str], min_queries: int = 50,
                     len_threshold: float = 40.0,
                     entropy_threshold: float = 3.5) -> tuple[bool, float]:
    if len(qnames) < min_queries:
        return False, 0.0
    avg_len = sum(len(q) for q in qnames) / len(qnames)
    avg_ent = sum(shannon_entropy(q) for q in qnames) / len(qnames)
    is_tunnel = avg_len > len_threshold or avg_ent > entropy_threshold
    score = round(min(1.0, (avg_len / 60.0) * 0.5 + (avg_ent / 4.5) * 0.5), 3)
    return is_tunnel, score


# Two-level public suffixes where the registered domain is the third-from-last
# label (e.g. foo.co.uk -> registered "foo.co.uk"). Small, common set — this is a
# heuristic, not a full public-suffix list, which is all the exploded-DNS grouping
# needs (misgrouping a rare ccTLD only splits one tunnel's count across parents).
_TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.au", "net.au", "org.au",
    "co.nz", "com.br", "com.cn", "com.mx", "co.za", "co.in", "co.kr",
}


def registered_parent(qname: str) -> str:
    """The registered domain of a qname (label + public suffix), used to group
    subdomains for exploded-DNS. `a.b.tunnel.evil.co.uk` -> `evil.co.uk`."""
    labels = (qname or "").rstrip(".").lower().split(".")
    if len(labels) < 2:
        return qname or ""
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# RITA's "exploded DNS": DNS tunneling/exfil encodes data in the SUBDOMAIN labels,
# so one client emits a large number of UNIQUE subdomains all under a single
# registered parent (tunnel.evil.com). The length/entropy heuristic above misses
# this when the encoded labels are short or low-entropy; counting distinct
# subdomains per parent is RITA's signature DNS check. Returns (is_tunnel, score,
# parent) for the worst parent — parent lets the finding name the tunnel domain.
def dns_exploded_score(qnames: list[str],
                       min_subdomains: int = 30) -> tuple[bool, float, str]:
    by_parent: dict[str, set[str]] = {}
    for q in qnames:
        p = registered_parent(q)
        if not p or p == (q or "").rstrip(".").lower():
            continue                      # bare parent query, no subdomain to count
        by_parent.setdefault(p, set()).add((q or "").rstrip(".").lower())
    if not by_parent:
        return False, 0.0, ""
    parent, subs = max(by_parent.items(), key=lambda kv: len(kv[1]))
    n = len(subs)
    if n < min_subdomains:
        return False, 0.0, ""
    score = round(min(1.0, n / (min_subdomains * 4)), 3)
    return True, score, parent


# --- nDPI-risk (Tier 1): Suricata already flags these; we just act on them -----
# High-severity nDPI risk substrings (matched case-insensitively). nDPI risk
# strings vary by version, so match on substrings, not exact names.
HIGH_NDPI_RISKS = (
    "malicious", "suspicious dga", "dga domain", "self-signed", "malformed",
    "clear-text credential", "cleartext", "known proto on non std port",
    "binary application transfer", "susp", "possible exploit", "obfuscated",
    "tls certificate expired", "tls suspicious", "punycode", "anonymous subscriber",
)


def ndpi_risk_hit(risk_set: list[str]) -> tuple[bool, list[str]]:
    """Return (hit, matched_high_risks) for a flow's nDPI risk set. (Active once
    the sensor emits ndpi.risk; today it emits ndpi.breed — see ndpi_breed_hit.)"""
    matched = [r for r in (risk_set or [])
               if any(h in r.lower() for h in HIGH_NDPI_RISKS)]
    return (bool(matched), matched)


# nDPI "breed" is emitted today (risk output isn't). Dangerous/Unsafe breeds flag
# risky protocols (e.g. cleartext, anonymizers, malware-associated).
RISKY_BREEDS = ("dangerous", "potentially dangerous", "unsafe")


def ndpi_breed_hit(breed: str) -> bool:
    return bool(breed) and breed.lower() in RISKY_BREEDS


# --- Long connection (Tier 1; RITA): persistent session to an external dst -----
def longconn_check(duration_secs: float, dst_ip: str,
                   threshold_secs: float = 3600.0) -> tuple[bool, float]:
    if not is_external(dst_ip) or (duration_secs or 0) < threshold_secs:
        return False, 0.0
    return True, round(min(1.0, duration_secs / (threshold_secs * 6)), 3)


# RITA's actual long-connection method: sum the duration of ALL connections
# between a (src,dst) pair over the window, not just one flow. A C2 that opens
# many short-lived connections (or reconnects on drop) never trips the
# single-flow threshold above, but its CUMULATIVE session time is the tell —
# RITA flags a pair by total time connected across the analysis window. Gate on
# a minimum connection count so a single genuinely-long flow stays with
# longconn_check and this fires on the sustained-reconnect pattern.
def longconn_cumulative_check(total_secs: float, n_conns: int, dst_ip: str,
                              threshold_secs: float = 3600.0,
                              min_conns: int = 4) -> tuple[bool, float]:
    if not is_external(dst_ip) or n_conns < min_conns or (total_secs or 0) < threshold_secs:
        return False, 0.0
    return True, round(min(1.0, total_secs / (threshold_secs * 6)), 3)


# --- Rare destination (Tier 1): new external dst for an asset with history ------
def is_rare_dest(known_dsts: set, dst_ip: str, min_history: int = 15) -> bool:
    """Fire only once the asset has a baseline of known dsts, and this external
    dst is new to it (avoids firing on cold-start / first-ever observations)."""
    return (is_external(dst_ip) and len(known_dsts) >= min_history
            and dst_ip not in known_dsts)


# --- Exfiltration (v2 §16.8): large outbound transfer to an external dst -------
def exfil_check(bytes_to_server: int, dst_ip: str,
                threshold_bytes: int = 50_000_000) -> tuple[bool, float]:
    if not is_external(dst_ip):
        return False, 0.0
    if _EXFIL_ALLOW and any(dst_ip.startswith(p) for p in _EXFIL_ALLOW):
        return False, 0.0
    if bytes_to_server < threshold_bytes:
        return False, 0.0
    # score scales with how far over threshold (capped).
    return True, round(min(1.0, bytes_to_server / (threshold_bytes * 4)), 3)


def low_slow_exfil(bytes_to_server: int, conn_count: int, dst_ip: str,
                   low_floor: int = 5_000_000, threshold_bytes: int = 50_000_000,
                   min_conns: int = 10) -> tuple[bool, float]:
    """Low-and-slow exfil (T1029/T1030): cumulative outbound that stays BELOW the burst
    ceiling (so exfil_check ignores it) but exceeds a floor spread over many connections
    — the sustained-trickle band the burst detector misses. Skips internal/allowlisted."""
    if not is_external(dst_ip):
        return False, 0.0
    if _EXFIL_ALLOW and any(dst_ip.startswith(p) for p in _EXFIL_ALLOW):
        return False, 0.0
    if bytes_to_server >= threshold_bytes:          # burst detector owns this band
        return False, 0.0
    if bytes_to_server < low_floor or conn_count < min_conns:
        return False, 0.0
    return True, round(min(1.0, conn_count / (min_conns * 5)), 3)


# --- Threat gate (G5): scale a north-south behavioral finding's severity by how
# hostile the destination looks, so beacons/exfil to safe known apps sink and
# those to suspect/dangerous dsts rise. Uses nDPI breed/risk already on the flow
# record, plus optional threat-intel / DGA signals. Never drops a finding — only
# re-prioritizes — so a real C2 hiding behind a "safe" label is not suppressed. --
_DANGEROUS_BREEDS = ("dangerous", "potentially dangerous", "unsafe")
_SAFE_BREEDS = ("safe", "acceptable")
_MALICIOUS_RISK_HINTS = ("malicious", "suspicious", "dga", "exploit", "obfuscated",
                         "anonymous", "self-signed", "clear-text", "cleartext")


def _malicious_risk(risks) -> bool:
    for r in (risks or []):
        s = str(r).lower()
        if any(h in s for h in _MALICIOUS_RISK_HINTS):
            return True
    return False


def dst_threat_score(ndpi_breed: str = "", ndpi_risks=None,
                     ti_hit: bool = False, dga: bool = False) -> int:
    """Severity delta in -2..+2 for a north-south finding based on destination
    hostility. +2 escalate (known-bad / dangerous / malicious-risk), -2
    de-prioritize (safe app, no risk), 0 unknown."""
    breed = (ndpi_breed or "").lower()
    if ti_hit or dga or _malicious_risk(ndpi_risks) or breed in _DANGEROUS_BREEDS:
        return 2
    if breed in _SAFE_BREEDS and not (ndpi_risks or []):
        return -2
    return 0


# --- Per-asset / environment-prevalence baseline (v2 §16, request #4) ----------
# The threat gate above judges a destination by its hostility (nDPI/TI). This adds
# a BASELINE judgement: how common is the destination across the fleet? A
# behavioral finding (beacon/exfil/long-conn) to a destination almost no asset
# contacts is far more suspicious than one to a destination half the fleet uses
# routinely. This is the environment-prevalence tier of per-asset baselining: the
# peer group is the whole fleet (MVP); role-based peer groups and per-asset
# history are the next increment (they need the externalized asset spine).
def env_prevalence_delta(env_assets, rare_max: int = 2, common_min: int = 8) -> int:
    """Severity delta from destination prevalence across the fleet. +1 when the
    destination is RARE (<= rare_max assets ever contacted it) — escalate; -1 when
    COMMON (>= common_min assets) — de-prioritize; 0 in between or unknown."""
    if env_assets is None:
        return 0
    if env_assets <= rare_max:
        return 1
    if env_assets >= common_min:
        return -1
    return 0


def gated_severity(base: int, ndpi_breed: str = "", ndpi_risks=None,
                   ti_hit: bool = False, dga: bool = False, env_assets=None) -> int:
    """Apply the threat gate + prevalence baseline to a base severity, clamped
    1..10. `env_assets` is how many distinct assets have contacted the dst."""
    delta = dst_threat_score(ndpi_breed, ndpi_risks, ti_hit, dga) + env_prevalence_delta(env_assets)
    return max(1, min(10, base + delta))
