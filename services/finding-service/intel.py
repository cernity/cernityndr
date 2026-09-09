"""Optional Tier-2 enrichment adapters for findings.

Everything here is OFF by default and best-effort: each adapter is gated by an env
toggle or an API key, results are TTL-cached, network calls have short timeouts, and
any failure is swallowed — a finding is enriched with whatever succeeded and nothing
in this module ever raises into the hot path.

Adapters:
  * reverse_dns(ip)        — PTR via the local resolver (toggle INTEL_RDNS). No key.
  * domain_age_days(dom)   — registration age via RDAP (toggle INTEL_RDAP); feeds the
                             newly-registered-domain (NRD) flag, a strong C2/phishing signal.
  * fingerprint_name(fp)   — JA3/JA4 -> known app/malware name from a bundled, operator-
                             overridable map (offline).
  * greynoise(ip)          — internet-scanner/benign classification (needs GREYNOISE_API_KEY).
                             The template for VirusTotal/OTX/etc.: same shape, different URL+key.

Network functions take an injectable `fetch`/`resolver` so the logic is unit-tested
without touching the network.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import ssl
import time
import urllib.request
from datetime import datetime, timezone


def _is_external(ip: str) -> bool:
    """Globally-routable? Reputation lookups (VT/GreyNoise) must never be sent an
    internal/RFC1918 address — it's pointless and leaks your internal addressing to a
    third party."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

# --- toggles / config -------------------------------------------------------
RDNS_ON = os.environ.get("INTEL_RDNS", "") not in ("", "0", "false", "False")
RDAP_ON = os.environ.get("INTEL_RDAP", "") not in ("", "0", "false", "False")
NRD_DAYS = int(os.environ.get("INTEL_NRD_DAYS", "30"))
FP_MAP_PATH = os.environ.get("INTEL_FP_MAP", "")            # override the bundled map
GREYNOISE_KEY = os.environ.get("GREYNOISE_API_KEY", "")
VT_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
HTTP_TIMEOUT = float(os.environ.get("INTEL_HTTP_TIMEOUT", "3"))
_CTX = ssl.create_default_context()

# --- tiny TTL cache (per-process; enrichment tolerates a cold cache) --------
_CACHE: dict = {}


def _cached(key, ttl, produce):
    now = time.time()
    hit = _CACHE.get(key)
    if hit and hit[0] > now:
        return hit[1]
    val = produce()
    _CACHE[key] = (now + ttl, val)
    return val


def _http_json(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, context=_CTX, timeout=HTTP_TIMEOUT) as r:
        return json.loads(r.read().decode(errors="ignore"))


# --- reverse DNS ------------------------------------------------------------
def reverse_dns(ip, resolver=None):
    resolver = resolver or (lambda a: socket.gethostbyaddr(a)[0])

    def _do():
        try:
            return resolver(ip)
        except Exception:                            # noqa: BLE001
            return None
    return _cached(f"rdns:{ip}", 3600, _do)


# --- domain age / NRD via RDAP ---------------------------------------------
def registrable(domain: str) -> str:
    """Naive eTLD+1 (last two labels). Good enough for the common gTLD case; an
    operator with ccTLD-heavy traffic can front this with their own map."""
    parts = domain.strip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _rdap_fetch(domain):
    return _http_json(f"https://rdap.org/domain/{domain}")


def _registration_date(rdap: dict):
    for ev in (rdap or {}).get("events", []) or []:
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            try:
                return datetime.fromisoformat(str(ev["eventDate"]).replace("Z", "+00:00"))
            except ValueError:
                return None
    return None


def domain_age_days(domain, fetch=None):
    """Days since registration, or None. Cached 24h (registration dates barely move)."""
    reg = registrable(domain)
    fetch = fetch or _rdap_fetch

    def _do():
        try:
            d = _registration_date(fetch(reg))
        except Exception:                            # noqa: BLE001
            return None
        if d is None:
            return None
        return (datetime.now(timezone.utc) - d).days
    return _cached(f"age:{reg}", 86400, _do)


# --- JA3/JA4 -> known tool/malware name ------------------------------------
_FP_MAP = None


def _load_fp_map():
    global _FP_MAP
    if _FP_MAP is not None:
        return _FP_MAP
    _FP_MAP = {}
    path = FP_MAP_PATH or os.path.join(os.path.dirname(__file__), "fingerprints.json")
    try:
        with open(path) as fh:
            _FP_MAP = {k.lower(): v for k, v in json.load(fh).items()}
    except Exception:                                # noqa: BLE001 - map is optional
        _FP_MAP = {}
    return _FP_MAP


def fingerprint_name(fp):
    if not fp:
        return None
    return _load_fp_map().get(str(fp).lower())


# --- GreyNoise (example reputation adapter) --------------------------------
def greynoise(ip, fetch=None):
    """GreyNoise Community verdict for an IP, or None (disabled/failed). Returns the
    useful fields the API gives: `noise` (seen scanning the internet) and `riot` (a known
    benign service) are always present and informative even when the IP is unobserved;
    `classification` ('benign'/'malicious'/'unknown') and `name` (e.g. 'Shodan.io') appear
    when GreyNoise has seen it."""
    if not GREYNOISE_KEY:
        return None

    def _do():
        try:
            data = (fetch or (lambda a: _http_json(
                f"https://api.greynoise.io/v3/community/{a}",
                headers={"key": GREYNOISE_KEY})))(ip)
        except Exception:                            # noqa: BLE001
            return None
        if not isinstance(data, dict):
            return None
        out = {"noise": bool(data.get("noise")), "riot": bool(data.get("riot"))}
        for k in ("classification", "name", "last_seen"):
            if data.get(k):
                out[k] = data[k]
        return out
    return _cached(f"gn:{ip}", 3600, _do)


# --- VirusTotal (IP reputation via last-analysis stats) --------------------
def virustotal(ip, fetch=None):
    """VT v3 last-analysis stats for an IP: {malicious, suspicious, harmless} or None
    (disabled/failed). Needs VIRUSTOTAL_API_KEY. Free tier is rate-limited (4 req/min),
    so the 1h cache matters."""
    if not VT_KEY:
        return None

    def _do():
        try:
            data = (fetch or (lambda a: _http_json(
                f"https://www.virustotal.com/api/v3/ip_addresses/{a}",
                headers={"x-apikey": VT_KEY})))(ip)
        except Exception:                            # noqa: BLE001
            return None
        stats = (((data or {}).get("data") or {}).get("attributes") or {}).get("last_analysis_stats")
        if not isinstance(stats, dict):
            return None
        return {"malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)}
    return _cached(f"vt:{ip}", 3600, _do)


# --- orchestrator -----------------------------------------------------------
def enrich(finding: dict, hooks: dict = None) -> dict:
    """Attach a Tier-2 `intel` block to the finding, in place. `hooks` lets a caller
    inject resolver/fetch for tests; production passes nothing and uses the real ones.
    Only enabled adapters run."""
    hooks = hooks or {}
    ents = finding.get("entities")
    if isinstance(ents, str):
        try:
            items = json.loads(ents)
        except (ValueError, TypeError):
            items = []
    else:
        items = ents if isinstance(ents, list) else []

    intel = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        t, val = it.get("type"), it.get("value")
        if not val:
            continue
        if t == "ip":
            if RDNS_ON:                              # local resolver; fine for internal IPs too
                name = reverse_dns(val, hooks.get("resolver"))
                if name:
                    intel.setdefault("rdns", {})[val] = name
            if _is_external(val):                    # reputation: external IPs ONLY (privacy)
                gn = greynoise(val, hooks.get("greynoise"))
                if gn:
                    intel.setdefault("reputation", {})[val] = gn
                vt = virustotal(val, hooks.get("virustotal"))
                if vt:
                    intel.setdefault("virustotal", {})[val] = vt
        elif t in ("domain", "sni"):
            if RDAP_ON:
                age = domain_age_days(val, hooks.get("rdap"))
                if age is not None:
                    dom = intel.setdefault("domains", {}).setdefault(val, {})
                    dom["age_days"] = age
                    dom["nrd"] = age <= NRD_DAYS
        elif t in ("ja3", "ja4"):
            nm = fingerprint_name(val)
            if nm:
                intel.setdefault("fingerprints", {})[val] = nm
    if intel:
        finding["intel"] = intel
    return finding
