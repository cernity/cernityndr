"""Offline GeoIP / ASN + community-id enrichment for findings (Tier-1 enrichment).

Every finding that leaves finding-service gets, for each *external* IP in its
entities, a small geo block (country, ASN, AS org) so an analyst sees "who and
where" without leaving the finding. Lookups use mounted MaxMind GeoLite2 databases;
if the DBs are not present the module is a no-op — findings pass through unchanged.

Community ID (a standard cross-tool flow hash) is lifted to the top level when a
detector attached one, so the analyst can pivot the finding into Suricata/Zeek/Arkime
by the same key.

Pure + dependency-light: `geoip2` is imported lazily inside open_readers() so this
module and its tests load without the library or the databases present.
"""
from __future__ import annotations

import ipaddress
import json
import os

# MaxMind DB paths (GeoLite2-Country.mmdb or -City.mmdb, and GeoLite2-ASN.mmdb).
# Operator mounts the DBs and points these at them; unset => enrichment disabled.
GEO_DB = os.environ.get("GEOIP_DB", "")             # Country or City DB (either works)
ASN_DB = os.environ.get("GEOIP_ASN_DB", "")


def _is_external(ip: str) -> bool:
    """True for a globally-routable IP. Private/loopback/link-local/CGNAT are skipped —
    geo/ASN on RFC1918 is noise, and this keeps internal addressing out of lookups."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def open_readers(geo_db: str = None, asn_db: str = None) -> dict:
    """Open whatever MaxMind readers are available. Returns {} if geoip2 is missing
    or no DB path resolves — callers then get pass-through behavior."""
    geo_db = GEO_DB if geo_db is None else geo_db
    asn_db = ASN_DB if asn_db is None else asn_db
    try:
        import geoip2.database as gdb
    except Exception:                                # noqa: BLE001 - optional dependency
        return {}
    readers = {}
    for name, path in (("geo", geo_db), ("asn", asn_db)):
        if path and os.path.exists(path):
            try:
                readers[name] = gdb.Reader(path)
            except Exception:                        # noqa: BLE001 - bad/absent DB is non-fatal
                pass
    return readers


def _lookup(readers: dict, ip: str) -> dict:
    """Best-effort country + ASN for one IP. Any per-field failure is swallowed so a
    partial DB set still yields what it can."""
    out = {}
    geo = readers.get("geo")
    if geo is not None:
        try:                                         # City DB
            out["country"] = geo.city(ip).country.iso_code
        except Exception:                            # noqa: BLE001
            try:                                     # Country DB
                out["country"] = geo.country(ip).country.iso_code
            except Exception:                        # noqa: BLE001
                pass
    asn = readers.get("asn")
    if asn is not None:
        try:
            r = asn.asn(ip)
            out["asn"] = r.autonomous_system_number
            out["as_org"] = r.autonomous_system_organization
        except Exception:                            # noqa: BLE001
            pass
    return {k: v for k, v in out.items() if v is not None}


def enrich_finding(finding: dict, readers: dict) -> dict:
    """Add `geo` (per external IP) and lift `community_id` onto the finding, in place.
    No-op-safe: with empty readers only community_id passthrough runs."""
    ents = finding.get("entities")
    if isinstance(ents, str):
        try:
            items = json.loads(ents)
        except (ValueError, TypeError):
            items = []
    else:
        items = ents or []
    if not isinstance(items, list):
        items = []

    geo = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        if it.get("type") == "community_id" and it.get("value") and "community_id" not in finding:
            finding["community_id"] = it.get("value")
        if it.get("type") == "ip":
            ip = it.get("value")
            if ip and ip not in geo and _is_external(ip) and readers:
                info = _lookup(readers, ip)
                if info:
                    geo[ip] = info
    if geo:
        finding["geo"] = geo
    return finding
