"""Intel feed connectors (plan U1). Each connector fetches a feed and normalizes its
records to intel.v1 (with tlp + source_trust + provenance); lifecycle.py then
dedups/scores/expires and store.py persists.

Ships this increment: STIX/TAXII 2.1, MISP, generic HTTP(S) list, and abuse.ch (the
existing ti.py blocklist parsing folded in). The connector interface leaves room for
OpenCTI + Git/GitHub/GitLab feeds (§12.2) which are DEFERRED to a later increment —
add a Connector subclass, no interface change needed.

FEED TRUST CONTROLS (§12.1, KTD5): every connector carries a per-feed `source_trust`
weight and default `tlp`; fetch() applies per-feed `auth` and TLS certificate pinning
(fail-closed) so a feed cannot be silently MITM'd or spoofed into the store.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import logging
import re
import ssl
import urllib.parse
import urllib.request
from datetime import datetime

import lifecycle
import ti   # existing abuse.ch parse primitives (folded in, not reimplemented)


_TLP_LEVELS = lifecycle.TLP_LEVELS   # ("clear","green","amber","amber+strict","red")
_INTEL_TYPES = ("ip", "domain", "url", "hash", "ja3", "ja4", "cert")  # intel.v1 enum
_DISPOSITIONS = ("active", "suppressed", "expired")

_MAX_REDIRECTS = 5
_REDIRECT_CODES = (301, 302, 303, 307, 308)

# The exact top-level / provenance property sets from contracts/intel.schema.json
# (both are additionalProperties:false) — an unknown key is a schema violation, so a
# feed cannot smuggle extra fields into a stored record.
_RECORD_KEYS = frozenset((
    "indicator", "type", "source", "feed", "score", "tlp", "source_trust",
    "first_seen", "last_seen", "expiry", "disposition", "tenant", "provenance"))
_PROV_KEYS = frozenset((
    "source", "feed", "score", "tlp", "source_trust", "first_seen", "last_seen",
    "expiry", "observed_at"))

_log = logging.getLogger("threat-intel.feeds")


class FeedTrustError(Exception):
    """A feed's TLS pin did not match, or the transport would leak credentials — refuse
    the data (fail-closed)."""


class FeedFetchIncomplete(Exception):
    """A paged feed (TAXII) could not be fetched to completion: the server said more
    pages exist but returned no usable continuation token, or the page cap was hit while
    more remained. Fail loud rather than silently ingest a partial collection."""


# --- runtime intel.v1 validation (§12.1) --------------------------------------
# Enforced at ingest so no malformed feed record reaches the store. Self-contained: the
# dep-light service image ships no jsonschema and no schema file, so this mirrors
# contracts/intel.schema.json directly; test_lifecycle keeps the two in lockstep when
# jsonschema is available (parity test).
# The intel.v1 datetime pattern verbatim from contracts/intel.schema.json $defs.datetime.
# fromisoformat alone is too lenient (it accepts a space separator and a naive value the
# schema pattern rejects), so gate on the pattern FIRST, then still parse to reject an
# impossible calendar value the pattern cannot catch (e.g. month 13).
_DT_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")


def _is_datetime(s) -> bool:
    if not isinstance(s, str) or not _DT_RE.match(s):
        return False                             # must match the schema's date-time pattern
    try:
        datetime.fromisoformat(s.strip().upper().replace("Z", "+00:00"))
    except ValueError:
        return False                             # pattern-shaped but not a real instant
    return True


def _is_str(v, lo=1, hi=256) -> bool:
    return isinstance(v, str) and lo <= len(v) <= hi


def _is_num(v, lo, hi) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and lo <= float(v) <= hi


def _valid_provenance_entry(p) -> bool:
    if not isinstance(p, dict):
        return False
    if set(p) - _PROV_KEYS:                      # additionalProperties:false
        return False
    if not (_is_str(p.get("source")) and _is_str(p.get("feed"))):
        return False
    if p.get("tlp") not in _TLP_LEVELS:
        return False
    if not (_is_num(p.get("score"), 0, 100) and _is_num(p.get("source_trust"), 0, 1)):
        return False
    if not (_is_datetime(p.get("first_seen")) and _is_datetime(p.get("last_seen"))):
        return False
    for k in ("expiry", "observed_at"):          # optional, but a datetime when present
        if k in p and not _is_datetime(p[k]):
            return False
    return True


def validate_intel(record) -> bool:
    """True iff `record` conforms to intel.v1 (contracts/intel.schema.json): required
    fields present, every value within the schema's enums/bounds, timestamps parseable
    and tz-aware. A False is quarantined by the caller (logged, never stored) so a bad
    type, out-of-range score/trust, unknown TLP, or unparseable timestamp from an
    untrusted feed can never poison the store."""
    if not isinstance(record, dict):
        return False
    if set(record) - _RECORD_KEYS:               # additionalProperties:false
        return False
    ind = record.get("indicator")
    if not (isinstance(ind, str) and 1 <= len(ind) <= 2048 and ind.strip()):
        return False
    if record.get("type") not in _INTEL_TYPES:
        return False
    if not (_is_str(record.get("source")) and _is_str(record.get("feed"))
            and _is_str(record.get("tenant"))):
        return False
    if not (_is_num(record.get("score"), 0, 100) and _is_num(record.get("source_trust"), 0, 1)):
        return False
    if record.get("tlp") not in _TLP_LEVELS:
        return False
    if record.get("disposition") not in _DISPOSITIONS:
        return False
    if not all(_is_datetime(record.get(k)) for k in ("first_seen", "last_seen", "expiry")):
        return False
    provs = record.get("provenance")
    if not isinstance(provs, list) or not provs:
        return False
    return all(_valid_provenance_entry(p) for p in provs)


def verify_pin(der_cert: bytes, pin: str) -> None:
    """Verify a leaf cert's SHA-256 fingerprint against a configured pin
    ('sha256:<hex>' or bare hex, case-insensitive). Raises FeedTrustError on mismatch.
    Pure so it is unit-testable without a live TLS handshake (the live pull is a
    real-env smoke)."""
    want = pin.split(":", 1)[1] if ":" in pin else pin
    got = hashlib.sha256(der_cert).hexdigest()
    if got.lower() != want.strip().lower():
        raise FeedTrustError(f"TLS pin mismatch: got {got}")


class Connector:
    """Base connector. Subclasses implement parse(payload) -> [raw dict]; normalize()
    and fetch() are shared. A raw dict is {indicator, type, [score], [tlp],
    [first_seen], [last_seen], [expiry]} — connector-specific extraction lives in parse."""

    default_score = 75.0

    def __init__(self, feed, source, source_trust, url=None, tlp="amber",
                 ttl_days=30.0, auth=None, tls_pin=None):
        self.feed = feed
        self.source = source
        self.source_trust = float(source_trust)
        # Enforce the feed's trust/TLP settings up front (loud config error) so a
        # misconfigured feed fails fast rather than silently quarantining every record.
        if not 0.0 <= self.source_trust <= 1.0:
            raise ValueError(f"feed source_trust must be in [0,1], got {self.source_trust}")
        if tlp not in _TLP_LEVELS:
            raise ValueError(f"unknown feed tlp {tlp!r}")
        self.url = url
        self.tlp = tlp
        self.ttl_days = float(ttl_days)
        self.auth = auth            # e.g. "Bearer <token>" / "Basic <b64>" — per-feed
        self.tls_pin = tls_pin      # 'sha256:<hex>' leaf-cert pin

    def parse(self, payload):
        raise NotImplementedError

    def normalize(self, raw, tenant, now):
        """One raw record -> a full intel.v1 record for `tenant` at epoch `now`.
        Fills defaults (score/tlp from feed config, first/last_seen=now, expiry=now+ttl)
        and builds the single-entry provenance the lifecycle merges on dedup."""
        itype = raw["type"]
        indicator = lifecycle.norm_indicator(itype, raw["indicator"])
        first_seen = raw.get("first_seen") or lifecycle.iso(now)
        last_seen = raw.get("last_seen") or lifecycle.iso(now)
        score = max(0.0, min(100.0, float(raw.get("score", self.default_score))))
        # The feed's configured tlp is a FLOOR, not merely a default: an incoming record
        # marking may make the record MORE restrictive, never less. Combine the two
        # most-restrictive-wins so a green-marked record on a tlp=red feed stays red
        # (reviewer regression: an incoming marking must not downgrade the feed's TLP).
        tlp = lifecycle.most_restrictive_tlp([self.tlp, raw.get("tlp")]) or self.tlp
        expiry = raw.get("expiry") or lifecycle.iso(now + self.ttl_days * 86400)
        # per-source assertion validity == this feed's expiry for the record; the
        # lifecycle selects scores only from currently-valid assertions (per-source expiry).
        prov = {"source": self.source, "feed": self.feed, "score": score, "tlp": tlp,
                "source_trust": self.source_trust, "first_seen": first_seen,
                "last_seen": last_seen, "expiry": expiry, "observed_at": lifecycle.iso(now)}
        return {"indicator": indicator, "type": itype, "source": self.source,
                "feed": self.feed, "score": score, "tlp": tlp,
                "source_trust": self.source_trust, "first_seen": first_seen,
                "last_seen": last_seen, "expiry": expiry, "disposition": "active",
                "tenant": tenant, "provenance": [prov]}

    def _emit(self, raw, tenant, now):
        """Normalize one raw record to intel.v1 and gate it against the schema. Returns
        the record, or None if it fails validation (quarantined: logged, never stored)."""
        rec = self.normalize(raw, tenant, now)
        if validate_intel(rec):
            return rec
        _log.warning("quarantined invalid intel record from %s/%s: type=%r indicator=%r",
                     self.source, self.feed, rec.get("type"), rec.get("indicator"))
        return None

    def records(self, payload, tenant, now):
        """Parse a fetched payload, normalize every record to intel.v1, and drop
        (quarantine) any that fail validation so no malformed record reaches the store."""
        return [r for r in (self._emit(x, tenant, now) for x in self.parse(payload))
                if r is not None]

    def revocations(self, payload, tenant, now):
        """Withdrawal markers {tenant, type, indicator, source, feed} for indicators this
        feed no longer asserts (STIX revoked / out-of-window). lifecycle.ingest removes the
        matching stored assertion. Base feeds carry no revocation channel -> none."""
        return []

    def _http(self, url, opener=None, extra_headers=None):
        """One GET with per-feed auth + TLS pinning. `opener(req)->response` is injectable
        for tests; the default uses a pin-then-auth transport (see _fetch) that verifies the
        leaf-cert pin BEFORE any credential is sent and refuses credential-leaking redirects.
        Fail-closed: a configured pin that cannot be verified raises."""
        headers = {"User-Agent": "ndr-threat-intel/2.0"}
        if extra_headers:
            headers.update(extra_headers)
        if opener is not None:                       # test seam: caller supplies the response
            req = urllib.request.Request(url, headers=headers)
            if self.auth:
                req.add_header("Authorization", self.auth)
            resp = opener(req)
            if self.tls_pin:
                der = _peer_der(resp)
                if der is None:
                    raise FeedTrustError("TLS pin configured but peer cert unavailable")
                verify_pin(der, self.tls_pin)
            body = resp.read()
            return body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else body
        return self._fetch(url, headers)

    def _fetch(self, url, headers, timeout=30):
        """Real transport. Fail-closed against credential leaks (reviewer regression):
          * credentials are NEVER sent over plaintext http;
          * for https, the configured leaf-cert pin is verified right after the handshake
            and BEFORE the request (and its Authorization header) is transmitted;
          * redirects are validated by _redirect_target — an authenticated or pinned feed
            refuses to redirect at all, and an https->http downgrade is always refused,
            so credentials can never cross an origin or a plaintext hop."""
        for _ in range(_MAX_REDIRECTS + 1):
            parts = urllib.parse.urlsplit(url)
            if self.auth and parts.scheme != "https":
                raise FeedTrustError("refusing to send credentials over non-https transport")
            if self.tls_pin and parts.scheme != "https":
                raise FeedTrustError("TLS pin configured on a non-https URL")
            conn = _open_verified(parts, timeout, self.tls_pin)
            try:
                path = parts.path or "/"
                if parts.query:
                    path += "?" + parts.query
                h = dict(headers)
                if self.auth:
                    h["Authorization"] = self.auth
                conn.request("GET", path, headers=h)
                resp = conn.getresponse()
                if resp.status in _REDIRECT_CODES:
                    loc = resp.headers.get("Location")
                    resp.read()
                    url = _redirect_target(url, loc, bool(self.auth), bool(self.tls_pin))
                    continue
                body = resp.read()
                if resp.status >= 400:
                    raise OSError(f"feed fetch {url} -> HTTP {resp.status}")
                return body.decode("utf-8", "replace")
            finally:
                conn.close()
        raise FeedTrustError(f"too many redirects fetching {self.url}")

    def fetch(self, opener=None):
        """Fetch the whole feed payload (single request for list/bundle feeds)."""
        return self._http(self.url, opener)


def _open_verified(parts, timeout, tls_pin):
    """Open an HTTP(S) connection to `parts`; for https, verify the leaf-cert pin (if any)
    right after the handshake and BEFORE the caller sends any request/credentials
    (fail-closed). Returns a connected http.client connection."""
    host, port = parts.hostname, parts.port
    if parts.scheme == "https":
        conn = http.client.HTTPSConnection(host, port, context=ssl.create_default_context(),
                                           timeout=timeout)
        conn.connect()                               # handshake only; no request bytes yet
        if tls_pin:
            der = conn.sock.getpeercert(binary_form=True)
            if not der:
                conn.close()
                raise FeedTrustError("TLS pin configured but peer cert unavailable")
            try:
                verify_pin(der, tls_pin)             # BEFORE any auth header is transmitted
            except Exception:
                conn.close()
                raise
        return conn
    if parts.scheme == "http":
        return http.client.HTTPConnection(host, port, timeout=timeout)
    raise FeedTrustError(f"unsupported scheme {parts.scheme!r}")


def _redirect_target(current_url, location, has_auth, has_pin):
    """Decide the next URL for a 3xx, or raise FeedTrustError if following it would be
    unsafe. Fail-closed: an authenticated OR pinned feed must not redirect at all — a
    redirect could carry credentials to another origin (urllib's default handler retains
    Authorization across an https->http/other-host redirect) and a pin only covers the
    configured origin. For an unauthenticated feed, follow only if the scheme is not
    downgraded from https to http. Point authenticated/pinned feeds directly at the final
    URL."""
    if not location:
        raise FeedTrustError("redirect without a Location")
    nxt = urllib.parse.urljoin(current_url, location)
    if has_auth or has_pin:
        raise FeedTrustError(f"refusing redirect on authenticated/pinned feed: "
                             f"{current_url} -> {nxt}")
    cur, new = urllib.parse.urlsplit(current_url), urllib.parse.urlsplit(nxt)
    if cur.scheme == "https" and new.scheme != "https":
        raise FeedTrustError(f"refusing https->{new.scheme or '?'} downgrade redirect: {nxt}")
    return nxt


def _peer_der(resp):
    """Best-effort DER of the peer leaf cert from a urllib response, for pin checks
    (opener/test seam only; the real transport pins in _open_verified)."""
    try:
        return resp.fp.raw._sock.getpeercert(binary_form=True)   # CPython ssl socket
    except Exception:
        return None


# --- generic HTTP(S) list -----------------------------------------------------
_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HEX = re.compile(r"^[0-9a-fA-F]{32,64}$")


def infer_type(value: str) -> str:
    """Infer an indicator type from its lexical form (generic HTTP feeds often ship a
    bare list). Explicit type columns override this."""
    v = value.strip()
    if _IP.match(v):
        return "ip"
    if v.startswith(("http://", "https://")):
        return "url"
    if _HEX.match(v):
        return "hash"
    return "domain"


class HttpConnector(Connector):
    """Generic HTTP(S) feed: one indicator per line, '#' comments, optional trailing
    ',type[,score]' columns (type inferred from the value otherwise)."""

    def parse(self, payload):
        out = []
        for line in payload.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cols = [c.strip() for c in line.split(",")]
            value = cols[0]
            itype = cols[1] if len(cols) > 1 and cols[1] else infer_type(value)
            raw = {"indicator": value, "type": itype}
            if len(cols) > 2 and cols[2]:
                try:
                    raw["score"] = float(cols[2])
                except ValueError:
                    pass
            out.append(raw)
        return out


# --- abuse.ch (existing ti.py primitives folded in) ---------------------------
class AbuseChConnector(HttpConnector):
    """abuse.ch blocklists via the existing ti.py parsers. `variant` picks the feed:
    feodo (C2 IPs), sslbl_cert (cert SHA1), sslbl_ja3 (JA3). Reuses ti.parse_* rather
    than reimplementing the blocklist formats (KTD1: reuse the match primitives)."""

    default_score = 90.0   # abuse.ch confirmed-malicious lists are high-confidence

    _PARSE = {
        "feodo": (ti.parse_feodo, "ip"),
        "sslbl_cert": (ti.parse_hash_csv, "cert"),
        "sslbl_ja3": (ti.parse_hash_csv, "ja3"),
    }

    def __init__(self, variant, source_trust=0.9, **kw):
        if variant not in self._PARSE:
            raise ValueError(f"unknown abuse.ch variant {variant!r}")
        self.variant = variant
        kw.setdefault("tlp", "green")   # abuse.ch is public/shareable
        super().__init__(feed=variant, source="abuse.ch", source_trust=source_trust, **kw)

    def parse(self, payload):
        fn, itype = self._PARSE[self.variant]
        return [{"indicator": v, "type": itype} for v in fn(payload)]


# --- STIX / TAXII 2.1 ---------------------------------------------------------
# We deliberately support ONLY simple single-comparison equality patterns of the form
# `[<obj-type>:<prop> = '<value>']`. Compound patterns (AND/OR/FOLLOWEDBY, or more than
# one comparison) are REJECTED rather than silently reduced to their first term, which
# would broaden the indicator's meaning. Non-equality operators (IN/LIKE/MATCHES/<,>…)
# are likewise unsupported.
_STIX_EQ = re.compile(r"\[?\s*([a-z0-9_-]+):([a-z0-9._'\-]+)\s*=\s*'([^']*)'\s*\]?\s*$", re.I)
_STIX_BOOL = re.compile(r"(?<![A-Za-z])(AND|OR|FOLLOWEDBY)(?![A-Za-z])", re.I)
_STIX_CMP = re.compile(
    r":[a-z0-9._'\-]+\s*(?:!=|<=|>=|=|<|>|IN|LIKE|MATCHES|ISSUPERSET|ISSUBSET)", re.I)

# Well-known static TLP marking-definition ids (TLP 2.0 + legacy 1.0) so bundles that
# reference the standard markings without embedding the definition still resolve.
_STIX_TLP_IDS = {
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487": "clear",       # TLP:CLEAR 2.0
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "clear",       # TLP:WHITE 1.0
    "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb": "green",       # TLP:GREEN 2.0
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",       # TLP:GREEN 1.0
    "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421": "amber",       # TLP:AMBER 2.0
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",       # TLP:AMBER 1.0
    "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003": "amber+strict",# TLP:AMBER+STRICT 2.0
    "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1": "red",         # TLP:RED 2.0
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",         # TLP:RED 1.0
}


def _stix_type(obj_type, prop):
    """Map a supported STIX observable property to an intel.v1 type, or None. Restricts
    file/x509 to their `hashes.*` properties — `file:name`, `file:size` etc. are NOT
    hashes and are rejected rather than mislabeled."""
    obj_type, prop = obj_type.lower(), prop.lower()
    if obj_type in ("ipv4-addr", "ipv6-addr") and prop == "value":
        return "ip"
    if obj_type == "domain-name" and prop == "value":
        return "domain"
    if obj_type == "url" and prop == "value":
        return "url"
    if obj_type == "file" and prop.startswith("hashes."):
        return "hash"
    if obj_type == "x509-certificate" and prop.startswith("hashes."):
        return "cert"
    return None


def _stix_pattern(pattern):
    """Parse a supported simple-equality STIX pattern -> (itype, value), or None.
    Rejects compound/multi-comparison/non-equality patterns and unsupported properties."""
    if not pattern:
        return None
    if _STIX_BOOL.search(pattern):
        return None                              # compound boolean -> reject, don't broaden
    if len(_STIX_CMP.findall(pattern)) != 1:
        return None                              # zero or >1 comparison -> reject
    m = _STIX_EQ.match(pattern.strip())
    if not m or not m.group(3):
        return None                              # only single equality with a value
    itype = _stix_type(m.group(1), m.group(2))
    return (itype, m.group(3)) if itype else None


def _combine_marking_refs(refs, tlp_of, known_nontlp):
    """Combine an object's marking refs into a single TLP, most-restrictive-wins. A ref
    that resolves to no known marking at all is treated conservatively as TLP:red so an
    unknown restriction can never downgrade sharing. Returns None when no ref is present
    (caller then uses the feed default).
    # ponytail: unresolved ref => red (fail-safe). A non-TLP marking present in the
    # bundle is 'no TLP', not unresolved, so legit statement/copyright markings don't
    # force red. Upgrade path: full marking-definition resolution if feeds need it."""
    if not refs:
        return None
    levels = []
    for r in refs:
        if r in tlp_of:
            levels.append(tlp_of[r])
        elif r in known_nontlp:
            continue                             # known non-TLP marking -> not a restriction we model
        else:
            levels.append("red")                 # unresolved -> conservative
    return lifecycle.most_restrictive_tlp(levels)


def _stix_within_validity(raw, now):
    """A STIX indicator's validity window is carried on the parsed raw as first_seen
    (valid_from) and expiry (valid_until). Reject it if it is not yet valid
    (valid_from > now) or already past (valid_until <= now), or if either timestamp is
    unparseable (a malformed window is quarantined here and, belt-and-braces, downstream)."""
    vf, vu = raw.get("first_seen"), raw.get("expiry")
    try:
        if vf and lifecycle.epoch(vf) > now:
            return False
        if vu and lifecycle.epoch(vu) <= now:
            return False
    except ValueError:
        return False
    return True


class StixTaxiiConnector(Connector):
    """STIX 2.1 bundle (or a TAXII 2.1 collection-objects envelope). Reads `indicator`
    SDOs with simple-equality patterns: extracts the observable value + type,
    `valid_from`/`valid_until`, and `confidence` (0-100) as the score. TLP is the
    most-restrictive of the object's applicable markings (object + granular), else the
    feed default. fetch() follows TAXII 2.1 pagination (`more`/`next`)."""

    max_pages = 100   # ponytail: bound the paging loop; raise if a feed legitimately exceeds it

    def fetch(self, opener=None):
        """Follow TAXII 2.1 pagination to COMPLETION: repeat the objects GET while the
        envelope says `more`, threading the `next` cursor, accumulating every page so
        parse() sees the whole collection. Never return a partial collection silently — if
        the server reports `more` but returns no usable `next` cursor, or the page cap is
        reached while pages remain, raise FeedFetchIncomplete instead of ingesting a
        truncated feed."""
        headers = {"Accept": "application/taxii+json;version=2.1"}
        objs, url = [], self.url
        for _ in range(self.max_pages):
            env = json.loads(self._http(url, opener, headers))
            objs.extend(env.get("objects", []) if isinstance(env, dict) else env)
            if not (isinstance(env, dict) and env.get("more")):
                return json.dumps({"objects": objs})     # server signalled the last page
            nxt = env.get("next")
            if not nxt:
                raise FeedFetchIncomplete(
                    "TAXII feed reports more=true but returned no continuation token (next)")
            sep = "&" if "?" in self.url else "?"
            url = f"{self.url}{sep}next={urllib.parse.quote(str(nxt))}"
        raise FeedFetchIncomplete(
            f"TAXII pagination exceeded max_pages={self.max_pages} with more=true still set")

    @staticmethod
    def _withdrawn(raw, now) -> bool:
        """This STIX indicator no longer asserts a live match: revoked, or currently
        outside its valid_from..valid_until window."""
        return bool(raw.get("revoked")) or not _stix_within_validity(raw, now)

    def records(self, payload, tenant, now):
        """Like the base, but first enforce STIX validity: a revoked indicator, or one
        whose valid_from is in the future / valid_until has passed, is NOT emitted (it must
        not match). Such indicators instead surface via revocations() so a refresh can
        withdraw a previously-stored assertion."""
        out = []
        for raw in self.parse(payload):
            if self._withdrawn(raw, now):
                continue
            rec = self._emit(raw, tenant, now)
            if rec is not None:
                out.append(rec)
        return out

    def revocations(self, payload, tenant, now):
        """Withdrawal markers for indicators this bundle revokes or that fell out of their
        validity window: ingest removes THIS feed's assertion from any stored indicator
        (other contributors preserved). So an active->revoked refresh, or an updated
        validity window that has now passed, invalidates the prior assertion rather than
        leaving it silently active. (reviewer regression)"""
        out = []
        for raw in self.parse(payload):
            if not self._withdrawn(raw, now):
                continue
            out.append({"tenant": tenant, "type": raw["type"],
                        "indicator": lifecycle.norm_indicator(raw["type"], raw["indicator"]),
                        "source": self.source, "feed": self.feed})
        return out

    def parse(self, payload):
        doc = json.loads(payload) if isinstance(payload, str) else payload
        objs = doc.get("objects", doc if isinstance(doc, list) else [])
        tlp_of, known_nontlp = dict(_STIX_TLP_IDS), set()
        for o in objs:
            if o.get("type") != "marking-definition":
                continue
            mid, lvl = o.get("id"), None
            if o.get("definition_type") == "tlp":
                lvl = ((o.get("definition", {}) or {}).get("tlp")
                       or o.get("name", "").replace("TLP:", "").strip()).lower() or None
            elif o.get("name", "").upper().startswith("TLP:"):
                lvl = o["name"].split(":", 1)[1].strip().lower()
            if lvl in _TLP_LEVELS:
                tlp_of[mid] = lvl
            elif mid:
                known_nontlp.add(mid)          # a real, non-TLP marking present in the bundle
        out = []
        for o in objs:
            if o.get("type") != "indicator":
                continue
            parsed = _stix_pattern(o.get("pattern", ""))
            if parsed is None:
                continue                       # unsupported/compound pattern — skip, don't broaden
            itype, value = parsed
            # Keep revoked indicators (tagged) so records() can exclude them AND
            # revocations() can withdraw a previously-stored assertion for the same key.
            raw = {"indicator": value, "type": itype, "revoked": bool(o.get("revoked"))}
            if isinstance(o.get("confidence"), (int, float)):
                raw["score"] = float(o["confidence"])
            if o.get("valid_from"):
                raw["first_seen"] = o["valid_from"]
            if o.get("valid_until"):
                raw["expiry"] = o["valid_until"]
            refs = list(o.get("object_marking_refs", []))
            refs += [g["marking_ref"] for g in o.get("granular_markings", []) if g.get("marking_ref")]
            tlp = _combine_marking_refs(refs, tlp_of, known_nontlp)
            if tlp:
                raw["tlp"] = tlp
            out.append(raw)
        return out


# --- MISP ---------------------------------------------------------------------
_MISP_TYPE = {
    "ip-src": "ip", "ip-dst": "ip", "domain": "domain", "hostname": "domain",
    "url": "url", "md5": "hash", "sha1": "hash", "sha256": "hash",
    "ja3-fingerprint-md5": "ja3", "ja4": "ja4", "x509-fingerprint-sha1": "cert",
}


def _misp_tlp_levels(tags):
    """The TLP levels named by a MISP Tag list (`tlp:red`, …), unknown tags ignored."""
    out = []
    for tag in tags or []:
        name = (tag.get("name") or "").lower()
        if name.startswith("tlp:"):
            lvl = name.split(":", 1)[1].strip()
            if lvl in _TLP_LEVELS:
                out.append(lvl)
    return out


class MispConnector(Connector):
    """MISP event JSON (a single event or {'response':[{'Event':...}]}). Maps each
    Event.Attribute to an intel.v1 indicator. TLP honors BOTH event-level and
    attribute-level `tlp:*` tags, most-restrictive-wins (an attribute tagged tlp:red in
    a tlp:green event is red), falling back to the feed default when neither is marked."""

    def parse(self, payload):
        doc = json.loads(payload) if isinstance(payload, str) else payload
        events = []
        if "response" in doc:
            events = [e.get("Event", {}) for e in doc["response"]]
        elif "Event" in doc:
            events = [doc["Event"]]
        else:
            events = [doc]
        out = []
        for ev in events:
            ev_levels = _misp_tlp_levels(ev.get("Tag"))
            for attr in ev.get("Attribute", []):
                itype = _MISP_TYPE.get(attr.get("type"))
                if itype is None or not attr.get("value"):
                    continue
                raw = {"indicator": attr["value"], "type": itype}
                tlp = lifecycle.most_restrictive_tlp(_misp_tlp_levels(attr.get("Tag")) + ev_levels)
                if tlp:
                    raw["tlp"] = tlp
                out.append(raw)
        return out
