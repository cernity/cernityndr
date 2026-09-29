"""Intel lifecycle rules (plan U1): normalize -> dedup(merge provenance, keep best
TRUSTED currently-valid score) -> score -> expire. Pure functions over intel.v1
records + a store seam (services/threat-intel/store.py); no bus/network here so it
is unit-testable and reusable by the U2 matcher.

Trust + validity model (design §12.1, KTD5):
  * Each indicator carries provenance: one entry per (source, feed) that reported it,
    and each entry carries its OWN `expiry` (that source's assertion validity).
  * derive(record, now) recomputes the now-dependent effective fields:
      - score/source/feed/source_trust come from the entry with the HIGHEST
        source_trust among the CURRENTLY-VALID assertions (tie -> highest score). A
        low-trust feed can NEVER override a high-trust indicator's score; and an
        EXPIRED high-trust assertion no longer counts, so a still-valid lower-trust
        assertion takes over rather than keeping a stale high score alive.
      - tlp = the MOST RESTRICTIVE marking across ALL provenance. Sharing restrictions
        bind the merged content and are chosen INDEPENDENTLY of the score winner: one
        red contributor makes the whole record red (never exportable). §12.1.
      - disposition = active iff any assertion is still valid, else expired. A refresh
        that adds a fresh assertion reactivates an expired indicator.
  * Suppression is a SEPARATE, auditable, EXPIRING decision (the store's suppressions
    table), checked live at match time like the Inc-1 advisory ignore-list — never a
    silent permanent drop.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

TLP_LEVELS = ("clear", "green", "amber", "amber+strict", "red")
_TLP_RANK = {t: i for i, t in enumerate(TLP_LEVELS)}
NON_EXPORTABLE_TLP = {"red"}   # §12.1: TLP:red is never shared/exported


def _canon_host(host: str) -> str:
    """Lowercase a URL host; canonicalize an IP-literal host with ipaddress and re-bracket
    an IPv6 literal so equivalent forms collapse and the URL stays well-formed
    (https://[2001:db8::1]/ not https://2001:db8::1/). A DNS name is just lowercased."""
    host = (host or "").lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host                                # ordinary hostname
    return f"[{ip.compressed}]" if ip.version == 6 else str(ip)


def norm_indicator(itype: str, value: str) -> str:
    """Canonical store key for an indicator value, used by both the feed normalizers
    (write key) and the matcher (lookup key) so they agree.
      * ip: canonicalized with ipaddress (so 2001:0db8:0:0:0:0:0:1 == 2001:db8::1);
        a non-IP value is kept verbatim rather than dropped.
      * domain/hash/ja3/ja4/cert: wholly case-insensitive -> lowercased.
      * url: only the case-insensitive components (scheme + host) are lowercased/canonical;
        the path/query/fragment/userinfo are case-SENSITIVE (RFC 3986 §6.2.2.1) and kept
        verbatim, so /Secret?Token=ABC and /secret?token=abc stay distinct resources. An
        IPv6 host keeps its brackets.
    """
    v = (value or "").strip()
    if itype == "ip":
        try:
            return ipaddress.ip_address(v).compressed   # canonical (IPv6 lowercased/compressed)
        except ValueError:
            return v                               # not a bare IP -> keep verbatim
    if itype != "url":
        return v.lower()
    p = urlsplit(v)
    if not p.scheme or not p.hostname:
        return v                                   # unparseable -> keep verbatim, don't conflate
    netloc = _canon_host(p.hostname) + (f":{p.port}" if p.port else "")
    if p.username:
        netloc = p.username + (f":{p.password}" if p.password else "") + "@" + netloc
    return urlunsplit((p.scheme.lower(), netloc, p.path, p.query, p.fragment))


def epoch(ts: str) -> float:
    """Parse an intel.v1 date-time (…Z or +00:00) to epoch seconds. Py3.9's
    fromisoformat rejects a trailing 'Z', so normalize it first."""
    return datetime.fromisoformat((ts or "").strip().upper().replace("Z", "+00:00")).timestamp()


def iso(epoch_s: float) -> str:
    return datetime.fromtimestamp(epoch_s, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def most_restrictive_tlp(tlps):
    """The most restrictive TLP among the given markings (clear < green < amber <
    amber+strict < red). Unknown/None markings are ignored; returns None if none apply
    (caller then uses the feed default)."""
    known = [t for t in tlps if t in _TLP_RANK]
    return max(known, key=lambda t: _TLP_RANK[t]) if known else None


def _earlier(a: str, b: str) -> str:
    return a if epoch(a) <= epoch(b) else b


def _later(a: str, b: str) -> str:
    return a if epoch(a) >= epoch(b) else b


def _rank(prov: dict) -> tuple:
    # highest source_trust wins; tie broken by highest score. "keep best TRUSTED score."
    return (float(prov["source_trust"]), float(prov["score"]))


def _prov_expiry(prov: dict, record_expiry: str) -> str:
    """A provenance entry's own assertion validity; falls back to the record expiry for
    older records written before per-source expiry was tracked."""
    return prov.get("expiry") or record_expiry


def _valid_provs(provs: list, record_expiry: str, now: float) -> list:
    return [p for p in provs if epoch(_prov_expiry(p, record_expiry)) > now]


def best_provenance(provs: list, record_expiry: str, now: float) -> dict:
    """Best-trusted CURRENTLY-VALID assertion; if none are valid, the best-trusted
    overall (so a fully-expired record still reports a coherent score for history)."""
    valid = _valid_provs(provs, record_expiry, now)
    return max(valid or provs, key=_rank)


def is_exportable(record: dict) -> bool:
    """§12.1: TLP:red must not leave the platform. Everything else may be exported to
    the SIEM/onward per the operator's sharing policy. The record's tlp is the
    most-restrictive across its provenance (set by derive), so a merged record that
    absorbed any red content is itself red and not exportable."""
    return record.get("tlp") not in NON_EXPORTABLE_TLP


def is_expired(record: dict, now: float) -> bool:
    return epoch(record["expiry"]) <= now


def is_active(record: dict, now: float) -> bool:
    """An indicator matches only while active AND unexpired. Suppression is checked
    separately (store-side, expiring) by match()."""
    return record.get("disposition") == "active" and not is_expired(record, now)


def derive(record: dict, now: float) -> dict:
    """Recompute the now-dependent effective fields from provenance, in place. Called
    after every merge (ingest) and again on read (match) so validity/score/tlp reflect
    the current time even without a re-ingest. Pure w.r.t. the store."""
    provs = record["provenance"]
    record["expiry"] = max((_prov_expiry(p, record["expiry"]) for p in provs), key=epoch)
    winner = best_provenance(provs, record["expiry"], now)
    record["score"] = winner["score"]
    record["source"] = winner["source"]
    record["feed"] = winner["feed"]
    record["source_trust"] = winner["source_trust"]
    record["tlp"] = most_restrictive_tlp([p.get("tlp") for p in provs]) or record.get("tlp")
    record["disposition"] = "active" if _valid_provs(provs, record["expiry"], now) else "expired"
    return record


def merge(existing: dict, incoming: dict) -> dict:
    """Dedup two intel.v1 records for the same (tenant, type, indicator): union their
    provenance and widen first_seen (min) / last_seen (max). The effective
    score/tlp/source/expiry/disposition are (re)computed by derive() from the merged
    provenance — never copied from one contributor. `existing` may be None (first sight).

    Provenance is keyed by (source, feed): a refresh from the SAME source/feed SUPERSEDES
    that source's prior assertion (adopting its newest validity window/score/tlp) rather
    than accumulating a stale duplicate. Otherwise an updated (e.g. shortened) valid_until
    would be ignored — derive() takes max(expiry) across provenance, so a leftover older
    entry would keep an expired-but-refreshed indicator matching. Different sources coexist."""
    if existing is None:
        return dict(incoming)
    refreshed = {(p.get("source"), p.get("feed")) for p in incoming["provenance"]}
    provs = [p for p in existing["provenance"]
             if (p.get("source"), p.get("feed")) not in refreshed]
    provs += list(incoming["provenance"])
    merged = dict(existing)
    merged["provenance"] = provs
    merged["first_seen"] = _earlier(existing["first_seen"], incoming["first_seen"])
    merged["last_seen"] = _later(existing["last_seen"], incoming["last_seen"])
    return merged


def _apply_revocation(base: dict, rv: dict, now: float):
    """Drop the (source, feed) assertion named by `rv` from `base`, preserving every other
    contributor. Returns the re-derived record, or None if that was its last assertion (the
    indicator no longer has any contributor and must be removed)."""
    remaining = [p for p in base["provenance"]
                 if (p.get("source"), p.get("feed")) != (rv["source"], rv["feed"])]
    if not remaining:
        return None
    kept = dict(base)
    kept["provenance"] = remaining
    return derive(kept, now)


def ingest(store, records, now: float, revocations=()) -> list:
    """normalize (done by the feed connector) -> dedup+score+expire (merge then derive)
    -> persist. ATOMIC per refresh: the WHOLE batch is merged+validated in memory first
    (a malformed record raises here, before any write), then persisted in one transaction
    (store.upsert_many rolls back on failure). A failed refresh therefore leaves the store
    exactly as it was — never half-written. Records that share a key inside the batch merge
    with each other (not just with the store). Re-ingesting a fresh assertion for an expired
    indicator restores its active disposition (derive recomputes it).

    `revocations` (feed-supplied withdrawal markers) are applied after the merges: each
    removes that feed's assertion from the stored indicator and re-derives it, so an
    active->revoked refresh (or a validity window that has now passed) invalidates the prior
    assertion instead of leaving it silently active. Other contributors are preserved; an
    indicator whose LAST assertion is withdrawn is deleted. Applied in the same transaction
    so a revocation refresh is all-or-nothing too."""
    working: dict = {}
    for rec in records:
        key = (rec["tenant"], rec["type"], rec["indicator"])
        base = working[key] if key in working else store.get(*key)
        working[key] = derive(merge(base, rec), now)   # raises on malformed record -> no writes yet
    deletes = []
    for rv in revocations:
        key = (rv["tenant"], rv["type"], rv["indicator"])
        base = working[key] if key in working else store.get(*key)
        if base is None:
            continue                                   # nothing stored for this key -> no-op
        updated = _apply_revocation(base, rv, now)
        if updated is None:
            working.pop(key, None)
            deletes.append(key)
        else:
            working[key] = updated
    out = list(working.values())
    store.upsert_many(out, deletes)                     # single transaction; all-or-nothing
    return out


def match(store, tenant: str, itype: str, value: str, now: float):
    """Return the live indicator matching (tenant, type, value), or None. Re-derives at
    read-now so an assertion that expired since the last ingest is honored, then
    excludes expired and currently-suppressed indicators. This is the seam the U2 live
    matcher and the U3 retro-hunt call — kept here so expiry/suppression/trust are
    honored in exactly one place."""
    ind = norm_indicator(itype, value)
    rec = store.get(tenant, itype, ind)
    if rec is None:
        return None
    derive(rec, now)
    if not is_active(rec, now):
        return None
    if store.is_suppressed(tenant, itype, ind, now):
        return None
    return rec


def exportable(records):
    """Filter to the records that may be shared/exported (drops TLP:red — including any
    record that merged red content, since its effective tlp is red)."""
    return [r for r in records if is_exportable(r)]
