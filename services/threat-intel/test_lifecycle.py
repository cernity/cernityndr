"""Intel lifecycle tests (plan U1): connector normalization, dedup/trust weighting,
expiry, TLP export, expiring suppression, feed-failure durability, tenant isolation.

store.py is loaded by PATH (shared/store.py owns the name `store` on PYTHONPATH=shared);
lifecycle/feeds/ti bare-import fine (no shared collision) once this dir is on sys.path.
Runs under pytest and standalone (python test_lifecycle.py) with zero non-stdlib deps;
if jsonschema is present it also validates connector output against intel.schema.json.
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import lifecycle  # noqa: E402
import feeds       # noqa: E402

_spec = importlib.util.spec_from_file_location("intel_store", os.path.join(HERE, "store.py"))
_store_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_store_mod)
IntelStore = _store_mod.IntelStore

NOW = lifecycle.epoch("2026-09-29T00:00:00Z")
FUTURE = "2026-12-01T00:00:00Z"
PAST = "2026-01-01T00:00:00Z"

# optional schema validation (present under pytest; absent in the dep-light Docker build)
try:
    import json as _json
    from jsonschema import Draft202012Validator as _V
    _SCHEMA = _json.loads(open(os.path.join(ROOT, "contracts", "intel.schema.json")).read())
    _VALIDATE = _V(_SCHEMA).validate
except Exception:
    _VALIDATE = None


def rec(indicator, itype, score, trust, feed, source="src", tlp="amber",
        tenant="t1", first="2026-09-01T00:00:00Z", last="2026-09-20T00:00:00Z", expiry=FUTURE):
    prov = {"source": source, "feed": feed, "score": score, "tlp": tlp,
            "source_trust": trust, "first_seen": first, "last_seen": last, "expiry": expiry}
    return {"indicator": lifecycle.norm_indicator(itype, indicator), "type": itype,
            "source": source, "feed": feed, "score": score, "tlp": tlp,
            "source_trust": trust, "first_seen": first, "last_seen": last,
            "expiry": expiry, "disposition": "active", "tenant": tenant,
            "provenance": [prov]}


# --- connector normalization --------------------------------------------------
def test_http_connector_normalizes():
    c = feeds.HttpConnector(feed="blocklist", source="acme", source_trust=0.6, tlp="green")
    out = c.records("# hdr\n9.9.9.9\nbad.example.com,domain,42\n", "t1", NOW)
    by_ind = {r["indicator"]: r for r in out}
    assert by_ind["9.9.9.9"]["type"] == "ip"
    assert by_ind["9.9.9.9"]["tlp"] == "green" and by_ind["9.9.9.9"]["source_trust"] == 0.6
    assert by_ind["bad.example.com"]["type"] == "domain" and by_ind["bad.example.com"]["score"] == 42
    for r in out:
        assert r["provenance"][0]["source_trust"] == 0.6 and r["provenance"][0]["tlp"] == "green"
        if _VALIDATE:
            _VALIDATE(r)


def test_abusech_connector_folds_in_ti():
    c = feeds.AbuseChConnector("feodo", source_trust=0.9)
    out = c.records("# Feodo\n185.100.87.202\n1.2.3.4,443,online\n", "t1", NOW)
    inds = {r["indicator"] for r in out}
    assert inds == {"185.100.87.202", "1.2.3.4"}
    assert all(r["type"] == "ip" and r["source"] == "abuse.ch" and r["tlp"] == "green" for r in out)
    assert all(r["source_trust"] == 0.9 and r["score"] == 90.0 for r in out)


def test_stix_taxii_connector_normalizes():
    bundle = """{"type":"bundle","objects":[
      {"type":"marking-definition","id":"marking-definition--tlp-green","definition_type":"tlp",
       "name":"TLP:GREEN","definition":{"tlp":"green"}},
      {"type":"indicator","pattern":"[ipv4-addr:value = '9.9.9.9']","confidence":80,
       "valid_from":"2026-09-01T00:00:00Z","valid_until":"2026-12-01T00:00:00Z",
       "object_marking_refs":["marking-definition--tlp-green"]},
      {"type":"indicator","pattern":"[domain-name:value = 'evil.example']","confidence":55}
    ]}"""
    # tlp="clear" floor so the parsed record markings show through (the floor guarantee
    # itself is covered by test_feed_tlp_is_a_floor_incoming_marking_cannot_downgrade).
    c = feeds.StixTaxiiConnector(feed="taxii-main", source="vendorX", source_trust=0.7, tlp="clear")
    out = {r["indicator"]: r for r in c.records(bundle, "t1", NOW)}
    assert out["9.9.9.9"]["type"] == "ip" and out["9.9.9.9"]["score"] == 80
    assert out["9.9.9.9"]["tlp"] == "green" and out["9.9.9.9"]["expiry"] == "2026-12-01T00:00:00Z"
    assert out["evil.example"]["type"] == "domain" and out["evil.example"]["source_trust"] == 0.7
    if _VALIDATE:
        for r in out.values():
            _VALIDATE(r)


def test_misp_connector_normalizes():
    event = """{"Event":{"Tag":[{"name":"tlp:amber"}],"Attribute":[
      {"type":"domain","value":"Bad.Example.COM"},
      {"type":"sha256","value":"ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD01"},
      {"type":"ja3-fingerprint-md5","value":"E7D705A3286E19EA42F587B344EE6865"},
      {"type":"comment","value":"ignored"}]}}"""
    c = feeds.MispConnector(feed="misp-org", source="orgY", source_trust=0.8)
    out = {r["type"]: r for r in c.records(event, "t1", NOW)}
    assert out["domain"]["indicator"] == "bad.example.com"          # normalized
    assert out["hash"]["indicator"].islower() and out["ja3"]["indicator"].islower()
    assert all(r["tlp"] == "amber" and r["source_trust"] == 0.8 for r in out.values())
    assert "comment" not in {r["type"] for r in out.values()}       # unmapped attr skipped


def test_misp_attribute_marking_overrides_event():
    # An attribute tagged tlp:red inside a tlp:green event must NOT come out green.
    event = """{"Event":{"Tag":[{"name":"tlp:green"}],"Attribute":[
      {"type":"ip-dst","value":"9.9.9.9","Tag":[{"name":"tlp:red"}]},
      {"type":"ip-dst","value":"8.8.8.8"}]}}"""
    # tlp="clear" floor so the event/attribute markings show through unclamped.
    c = feeds.MispConnector(feed="misp-org", source="orgY", source_trust=0.8, tlp="clear")
    out = {r["indicator"]: r for r in c.records(event, "t1", NOW)}
    assert out["9.9.9.9"]["tlp"] == "red"          # attribute marking honored (most restrictive)
    assert out["8.8.8.8"]["tlp"] == "green"        # inherits event marking


def test_stix_combines_and_conservatively_resolves_markings():
    bundle = """{"objects":[
      {"type":"marking-definition","id":"marking-definition--g","definition_type":"tlp",
       "name":"TLP:GREEN","definition":{"tlp":"green"}},
      {"type":"marking-definition","id":"marking-definition--r","definition_type":"tlp",
       "name":"TLP:RED","definition":{"tlp":"red"}},
      {"type":"indicator","pattern":"[ipv4-addr:value = '1.1.1.1']",
       "object_marking_refs":["marking-definition--g","marking-definition--r"]},
      {"type":"indicator","pattern":"[ipv4-addr:value = '2.2.2.2']",
       "object_marking_refs":["marking-definition--unknown-xyz"]}
    ]}"""
    c = feeds.StixTaxiiConnector(feed="taxii", source="vendorX", source_trust=0.7)
    out = {r["indicator"]: r for r in c.records(bundle, "t1", NOW)}
    assert out["1.1.1.1"]["tlp"] == "red"          # green+red combine -> most restrictive
    assert out["2.2.2.2"]["tlp"] == "red"          # unresolved ref -> conservative red


def test_stix_rejects_compound_and_unsupported_patterns():
    bundle = """{"objects":[
      {"type":"indicator","pattern":"[ipv4-addr:value = '1.1.1.1' AND ipv4-addr:value = '2.2.2.2']"},
      {"type":"indicator","pattern":"[file:name = 'evil.exe']"},
      {"type":"indicator","pattern":"[file:hashes.'SHA-256' = 'ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234']"}
    ]}"""
    c = feeds.StixTaxiiConnector(feed="taxii", source="vendorX", source_trust=0.7)
    out = c.records(bundle, "t1", NOW)
    assert len(out) == 1                            # compound + file:name rejected, only the hash kept
    assert out[0]["type"] == "hash"
    assert out[0]["indicator"] == "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
    assert not any("1.1.1.1" in r["indicator"] for r in out)   # compound not broadened to its first term


def test_stix_taxii_pagination_follows_more():
    page1 = _json.dumps({"more": True, "next": "PAGE2", "objects": [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '1.1.1.1']"}]})
    page2 = _json.dumps({"more": False, "objects": [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '2.2.2.2']"}]})

    class _R:
        def __init__(self, b): self._b = b
        def read(self): return self._b.encode()

    def opener(req):
        assert "application/taxii+json" in req.get_header("Accept", "")
        return _R(page2 if "next=PAGE2" in req.full_url else page1)

    c = feeds.StixTaxiiConnector(feed="taxii", source="vendorX", source_trust=0.7,
                                 url="https://taxii/collections/x/objects/")
    out = {r["indicator"] for r in c.records(c.fetch(opener=opener), "t1", NOW)}
    assert out == {"1.1.1.1", "2.2.2.2"}           # both pages ingested, not just page 1


# --- dedup / trust weighting --------------------------------------------------
def test_dedup_merges_provenance_and_keeps_best_trusted():
    s = IntelStore()
    lifecycle.ingest(s, [rec("1.1.1.1", "ip", 60, 0.5, "feedA")], NOW)
    lifecycle.ingest(s, [rec("1.1.1.1", "ip", 40, 0.8, "feedB")], NOW)   # higher trust wins
    r = s.get("t1", "ip", "1.1.1.1")
    assert len(r["provenance"]) == 2
    assert r["source_trust"] == 0.8 and r["score"] == 40 and r["feed"] == "feedB"


def test_low_trust_cannot_override_high_trust():
    s = IntelStore()
    lifecycle.ingest(s, [rec("2.2.2.2", "ip", 90, 0.9, "trusted")], NOW)
    lifecycle.ingest(s, [rec("2.2.2.2", "ip", 100, 0.3, "sketchy")], NOW)  # higher score, low trust
    r = s.get("t1", "ip", "2.2.2.2")
    assert r["source_trust"] == 0.9 and r["score"] == 90 and r["feed"] == "trusted"
    assert len(r["provenance"]) == 2                                       # still recorded


def test_merge_keeps_most_restrictive_tlp():
    # Sharing restriction binds the merged content INDEPENDENTLY of the score winner:
    # a red contributor makes the whole record red / non-exportable, even though the
    # higher-trust green source wins the effective score. (reviewer regression)
    s = IntelStore()
    lifecycle.ingest(s, [rec("1.0.0.9", "ip", 70, 0.5, "redfeed", tlp="red")], NOW)
    lifecycle.ingest(s, [rec("1.0.0.9", "ip", 40, 0.9, "greenfeed", tlp="green")], NOW)
    r = s.get("t1", "ip", "1.0.0.9")
    assert r["tlp"] == "red" and lifecycle.is_exportable(r) is False
    assert r["score"] == 40 and r["feed"] == "greenfeed"                  # score from best-trusted
    assert len(r["provenance"]) == 2
    assert lifecycle.exportable(s.list(["t1"])) == []                     # red record not exported


# --- expiry -------------------------------------------------------------------
def test_expired_indicator_stops_matching():
    s = IntelStore()
    lifecycle.ingest(s, [rec("3.3.3.3", "ip", 80, 0.9, "f", expiry=PAST)], NOW)
    lifecycle.ingest(s, [rec("4.4.4.4", "ip", 80, 0.9, "f", expiry=FUTURE)], NOW)
    assert s.get("t1", "ip", "3.3.3.3")["disposition"] == "expired"
    assert lifecycle.match(s, "t1", "ip", "3.3.3.3", NOW) is None
    assert lifecycle.match(s, "t1", "ip", "4.4.4.4", NOW)["score"] == 80


def test_expired_trusted_source_falls_to_valid_lower_trust():
    # A high-trust assertion that has EXPIRED must not keep its stale score alive; a
    # still-valid lower-trust assertion takes over. (reviewer regression: per-source expiry)
    s = IntelStore()
    lifecycle.ingest(s, [rec("10.0.0.1", "ip", 90, 0.9, "hi", expiry=PAST)], NOW)
    lifecycle.ingest(s, [rec("10.0.0.1", "ip", 50, 0.5, "lo", expiry=FUTURE)], NOW)
    m = lifecycle.match(s, "t1", "ip", "10.0.0.1", NOW)
    assert m is not None and m["score"] == 50 and m["feed"] == "lo"       # not the expired 90/hi


def test_expired_indicator_reactivates_on_refresh():
    # A fresh assertion re-activates an expired indicator (renewal). (reviewer regression)
    s = IntelStore()
    lifecycle.ingest(s, [rec("10.0.0.2", "ip", 80, 0.9, "f", expiry=PAST)], NOW)
    assert lifecycle.match(s, "t1", "ip", "10.0.0.2", NOW) is None
    lifecycle.ingest(s, [rec("10.0.0.2", "ip", 80, 0.9, "f", expiry=FUTURE)], NOW)
    m = lifecycle.match(s, "t1", "ip", "10.0.0.2", NOW)
    assert m is not None and m["disposition"] == "active"


def test_refresh_updated_valid_until_supersedes_and_expires():
    # A refresh from the SAME source/feed must adopt its newest validity window, not keep
    # the stale longer one alive. Re-ingesting with an earlier valid_until now in the past
    # must supersede the stored assertion so the indicator stops matching. (reviewer
    # regression: merge accumulated a second provenance entry, so derive kept max/stale expiry.)
    s = IntelStore()
    lifecycle.ingest(s, [rec("9.9.9.9", "ip", 80, 0.9, "f", expiry=FUTURE)], NOW)
    assert lifecycle.match(s, "t1", "ip", "9.9.9.9", NOW) is not None
    lifecycle.ingest(s, [rec("9.9.9.9", "ip", 80, 0.9, "f", expiry=PAST)], NOW)   # refresh: shorter window
    r = s.get("t1", "ip", "9.9.9.9")
    assert len(r["provenance"]) == 1 and r["expiry"] == PAST     # superseded, newest window adopted
    assert lifecycle.match(s, "t1", "ip", "9.9.9.9", NOW) is None


def test_stix_refresh_shorter_future_valid_until_expires_at_new_boundary():
    # The bug's exact shape: a refresh with an EARLIER-but-still-future valid_until. It stays
    # within its window so it re-enters via records() (not the revocation channel); merge must
    # still supersede the old entry so matching stops at the NEW (earlier) boundary, not the old.
    s = IntelStore()
    c = feeds.StixTaxiiConnector(feed="taxii", source="vendorX", source_trust=0.7)
    mid = "2026-10-15T00:00:00Z"        # PAST < NOW(09-29) is false; mid is after NOW, before FUTURE
    far = _json.dumps({"objects": [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '8.8.8.8']", "confidence": 80,
         "valid_from": PAST, "valid_until": FUTURE}]})
    lifecycle.ingest(s, c.records(far, "t1", NOW), NOW)
    near = _json.dumps({"objects": [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '8.8.8.8']", "confidence": 80,
         "valid_from": PAST, "valid_until": mid}]})
    lifecycle.ingest(s, c.records(near, "t1", NOW), NOW,
                     revocations=c.revocations(near, "t1", NOW))
    after_mid = lifecycle.epoch(mid) + 1
    assert lifecycle.match(s, "t1", "ip", "8.8.8.8", NOW) is not None            # still valid before mid
    assert lifecycle.match(s, "t1", "ip", "8.8.8.8", after_mid) is None          # new boundary honored


def test_stix_refresh_revoked_stops_matching():
    # Revoked-on-refresh: a later bundle marking the same indicator revoked=true must stop it
    # matching (withdraws this feed's stored assertion via the revocation channel).
    s = IntelStore()
    c = feeds.StixTaxiiConnector(feed="taxii", source="vendorX", source_trust=0.7)
    active = _json.dumps({"objects": [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '7.7.7.8']", "confidence": 80}]})
    lifecycle.ingest(s, c.records(active, "t1", NOW), NOW)
    assert lifecycle.match(s, "t1", "ip", "7.7.7.8", NOW) is not None
    revoked = _json.dumps({"objects": [
        {"type": "indicator", "revoked": True, "pattern": "[ipv4-addr:value = '7.7.7.8']"}]})
    lifecycle.ingest(s, c.records(revoked, "t1", NOW), NOW,
                     revocations=c.revocations(revoked, "t1", NOW))
    assert lifecycle.match(s, "t1", "ip", "7.7.7.8", NOW) is None


def test_url_norm_preserves_case_sensitive_components():
    # scheme+host are case-insensitive; path/query are NOT — distinct resources stay distinct.
    a = lifecycle.norm_indicator("url", "HTTPS://Example.TEST/Secret?Token=ABC")
    b = lifecycle.norm_indicator("url", "https://example.test/secret?token=abc")
    assert a == "https://example.test/Secret?Token=ABC"
    assert a != b


# --- TLP export ---------------------------------------------------------------
def test_tlp_red_not_exportable():
    s = IntelStore()
    lifecycle.ingest(s, [rec("5.5.5.5", "ip", 80, 0.9, "f", tlp="red"),
                         rec("6.6.6.6", "ip", 80, 0.9, "f", tlp="green")], NOW)
    exportable = lifecycle.exportable(s.list(["t1"]))
    inds = {r["indicator"] for r in exportable}
    assert inds == {"6.6.6.6"} and not lifecycle.is_exportable(s.get("t1", "ip", "5.5.5.5"))


# --- suppression (auditable, expiring) ----------------------------------------
def test_suppression_recorded_and_expiring():
    s = IntelStore()
    lifecycle.ingest(s, [rec("7.7.7.7", "ip", 80, 0.9, "f")], NOW)
    exp = NOW + 3600
    supp = s.suppress("t1", "ip", "7.7.7.7", owner="analyst-a",
                      justification="known benign scanner", expires_at=exp, now=NOW)
    assert supp["owner"] == "analyst-a" and supp["justification"] and supp["expires_at"] == exp
    assert s.is_suppressed("t1", "ip", "7.7.7.7", NOW) is True
    assert lifecycle.match(s, "t1", "ip", "7.7.7.7", NOW) is None          # suppressed -> no match
    assert lifecycle.match(s, "t1", "ip", "7.7.7.7", exp + 1) is not None  # lapses -> matches again
    assert any(e["action"] == "intel.suppress" for e in s.audit_log(["t1"]))


def test_suppression_requires_owner_and_future_expiry():
    s = IntelStore()
    lifecycle.ingest(s, [rec("8.8.8.8", "ip", 80, 0.9, "f")], NOW)
    for bad in ({"owner": "", "justification": "x"}, {"owner": "a", "justification": " "}):
        try:
            s.suppress("t1", "ip", "8.8.8.8", expires_at=NOW + 10, now=NOW, **bad)
            assert False, "expected ValueError"
        except ValueError:
            pass
    try:
        s.suppress("t1", "ip", "8.8.8.8", owner="a", justification="x", expires_at=NOW - 10, now=NOW)
        assert False, "expected ValueError on past expiry"
    except ValueError:
        pass


# --- feed failure durability --------------------------------------------------
def _refresh(store, conn, tenant, now, opener):
    """The U2 refresh flow: fetch -> parse/normalize -> lifecycle.ingest (with the feed's
    revocation channel, as app._intel_refresh does). A fetch that raises never reaches
    ingest, so the store is untouched."""
    payload = conn.fetch(opener=opener)
    return lifecycle.ingest(store, conn.records(payload, tenant, now), now,
                            revocations=conn.revocations(payload, tenant, now))


def test_feed_failure_and_retry_does_not_corrupt_store():
    s = IntelStore()
    lifecycle.ingest(s, [rec("9.9.9.1", "ip", 80, 0.9, "seed")], NOW)     # pre-existing state

    class _Resp:
        def __init__(self, body): self._b = body
        def read(self): return self._b.encode()

    def failing(_req):
        raise OSError("connection refused")

    c = feeds.HttpConnector(feed="remote", source="acme", source_trust=0.6, url="https://feed/x")
    try:
        _refresh(s, c, "t1", NOW, opener=failing)
        assert False, "fetch should have raised"
    except OSError:
        pass
    assert {r["indicator"] for r in s.list(["t1"])} == {"9.9.9.1"}         # unchanged by failure

    _refresh(s, c, "t1", NOW, opener=lambda _req: _Resp("9.9.9.2\n"))      # retry succeeds
    assert {r["indicator"] for r in s.list(["t1"])} == {"9.9.9.1", "9.9.9.2"}


def test_tls_pin_verify_accepts_and_rejects():
    import hashlib
    der = b"\x30\x82fake-cert-der"
    good = hashlib.sha256(der).hexdigest()
    feeds.verify_pin(der, "sha256:" + good.upper())                        # matches (case-insensitive)
    try:
        feeds.verify_pin(der, "sha256:" + "0" * 64)
        assert False, "expected FeedTrustError"
    except feeds.FeedTrustError:
        pass


# --- transport: credentials must not leak via redirect/downgrade (reviewer regression) ---
def test_redirect_policy_refuses_credential_and_pin_leaks():
    # An authenticated feed must not follow ANY redirect (urllib's default retained
    # Authorization across an https->http/other-host redirect). Same for a pinned feed.
    for kw in ({"has_auth": True, "has_pin": False}, {"has_auth": False, "has_pin": True}):
        for loc in ("http://evil.other/x", "https://evil.other/x", "/same-host"):
            try:
                feeds._redirect_target("https://feed.test/a", loc, **kw)
                assert False, "authenticated/pinned feed must refuse redirects"
            except feeds.FeedTrustError:
                pass
    # An https->http downgrade is refused even without credentials (no plaintext hop).
    try:
        feeds._redirect_target("https://feed.test/a", "http://feed.test/b",
                               has_auth=False, has_pin=False)
        assert False, "https->http downgrade must be refused"
    except feeds.FeedTrustError:
        pass
    # An unauthenticated cross-origin https redirect is allowed (nothing to leak).
    assert feeds._redirect_target("https://a.test/x", "https://b.test/y",
                                  has_auth=False, has_pin=False) == "https://b.test/y"


def test_credentials_never_sent_over_plaintext():
    # _fetch refuses before opening any connection when auth would ride plaintext http,
    # and a pin on a non-https URL is refused too — both fail-closed, offline.
    c = feeds.HttpConnector(feed="f", source="s", source_trust=0.6,
                            url="http://insecure.test/x", auth="Bearer secret")
    try:
        c._fetch("http://insecure.test/x", {})
        assert False, "must refuse credentials over http"
    except feeds.FeedTrustError:
        pass
    c2 = feeds.HttpConnector(feed="f", source="s", source_trust=0.6,
                             url="http://insecure.test/x", tls_pin="sha256:" + "0" * 64)
    try:
        c2._fetch("http://insecure.test/x", {})
        assert False, "must refuse a pin on a non-https URL"
    except feeds.FeedTrustError:
        pass


# --- IPv6 canonicalization (reviewer regression) ------------------------------
def test_ipv6_canonicalization_ip_and_url():
    assert (lifecycle.norm_indicator("ip", "2001:0db8:0:0:0:0:0:1")
            == lifecycle.norm_indicator("ip", "2001:db8::1") == "2001:db8::1")
    # URL keeps IPv6 brackets and canonicalizes equivalent forms to the same key.
    u = lifecycle.norm_indicator("url", "https://[2001:db8::1]/X")
    assert u == "https://[2001:db8::1]/X"                                   # not .../X on a bare host
    assert lifecycle.norm_indicator("url", "https://[2001:0db8:0:0:0:0:0:1]/X") == u


def test_ipv6_equivalent_forms_match_through_ingest():
    s = IntelStore()
    lifecycle.ingest(s, [rec("2001:0db8:0:0:0:0:0:1", "ip", 80, 0.9, "f")], NOW)
    assert lifecycle.match(s, "t1", "ip", "2001:db8::1", NOW)["score"] == 80  # equivalent form matches


# --- ingest atomicity (reviewer regression) -----------------------------------
def test_ingest_atomic_on_malformed_record_and_retry():
    s = IntelStore()
    good = rec("1.1.1.1", "ip", 80, 0.9, "f")
    bad = rec("2.2.2.2", "ip", 80, 0.9, "f", expiry="not-a-date")           # invalid expiry
    try:
        lifecycle.ingest(s, [good, bad], NOW)
        assert False, "malformed record must abort the whole batch"
    except Exception:
        pass
    assert s.list(["t1"]) == []                                             # not even `good` persisted
    lifecycle.ingest(s, [good], NOW)                                        # retry with a clean batch
    assert {r["indicator"] for r in s.list(["t1"])} == {"1.1.1.1"}


# --- suppression must have a finite future expiry (reviewer regression) -------
def test_suppression_rejects_nonfinite_expiry():
    s = IntelStore()
    lifecycle.ingest(s, [rec("8.8.4.4", "ip", 80, 0.9, "f")], NOW)
    for bad in (float("inf"), float("-inf"), float("nan")):
        try:
            s.suppress("t1", "ip", "8.8.4.4", owner="a", justification="x",
                       expires_at=bad, now=NOW)
            assert False, f"expected ValueError for expiry={bad}"
        except ValueError:
            pass
    assert s.is_suppressed("t1", "ip", "8.8.4.4", NOW) is False             # nothing recorded


# --- tenant isolation ---------------------------------------------------------
def test_tenant_isolation():
    s = IntelStore()
    lifecycle.ingest(s, [rec("1.2.3.4", "ip", 90, 0.9, "f", tenant="tenant-a")], NOW)
    lifecycle.ingest(s, [rec("1.2.3.4", "ip", 10, 0.2, "f", tenant="tenant-b")], NOW)
    assert s.get("tenant-a", "ip", "1.2.3.4")["score"] == 90               # not merged across tenants
    assert s.get("tenant-b", "ip", "1.2.3.4")["score"] == 10
    assert {r["tenant"] for r in s.list(["tenant-a"])} == {"tenant-a"}     # scoped list
    assert s.list([]) == []                                                # empty grant -> nothing
    # suppressing in tenant-a must not suppress tenant-b's identical indicator
    s.suppress("tenant-a", "ip", "1.2.3.4", owner="a", justification="x", expires_at=NOW + 60, now=NOW)
    assert lifecycle.match(s, "tenant-a", "ip", "1.2.3.4", NOW) is None
    assert lifecycle.match(s, "tenant-b", "ip", "1.2.3.4", NOW) is not None


# --- U1 blocker 1: runtime intel.v1 + feed-trust enforcement at ingest --------
def test_feed_config_rejects_bad_trust_and_tlp():
    # A feed's trust/TLP settings are enforced up front (loud config error), not silently.
    for bad in ({"source_trust": 1.5}, {"source_trust": -0.1}, {"tlp": "orange"}):
        try:
            feeds.HttpConnector(feed="f", source="s",
                                source_trust=bad.get("source_trust", 0.5),
                                tlp=bad.get("tlp", "amber"))
            assert False, f"expected ValueError for {bad}"
        except ValueError:
            pass


def test_connector_quarantines_invalid_records_before_store():
    class _BadType(feeds.HttpConnector):
        def parse(self, payload):
            return [{"indicator": "9.9.9.9", "type": "ip"},          # valid
                    {"indicator": "x", "type": "not-a-type"}]        # invalid enum -> quarantine
    c = _BadType(feed="f", source="s", source_trust=0.6)
    out = c.records("ignored", "t1", NOW)
    assert {r["indicator"] for r in out} == {"9.9.9.9"}              # bad one dropped by validation
    s = IntelStore()
    lifecycle.ingest(s, out, NOW)
    assert {r["type"] for r in s.list(["t1"])} == {"ip"}            # only the valid record stored
    if _VALIDATE:
        for r in s.list(["t1"]):
            _VALIDATE(r)                                            # every stored record is intel.v1


def test_malformed_timestamp_from_feed_is_quarantined():
    class _BadTS(feeds.HttpConnector):
        def parse(self, payload):
            return [{"indicator": "8.8.8.8", "type": "ip", "expiry": "not-a-date"}]
    c = _BadTS(feed="f", source="s", source_trust=0.6)
    assert c.records("x", "t1", NOW) == []                          # unparseable expiry -> not stored


def test_validate_intel_enforces_datetime_pattern_and_additionalproperties():
    # The runtime validator must reject what the intel.v1 schema rejects even though
    # datetime.fromisoformat is more permissive (reviewer regression): a space-separated or
    # tz-naive timestamp, and any additionalProperties, must not pass and must not reach
    # the store.
    from copy import deepcopy
    valid = rec("1.2.3.4", "ip", 90, 0.9, "feodo", source="abuse.ch")
    assert feeds.validate_intel(valid) is True
    for mut in ({"first_seen": "2026-01-01 00:00:00+00:00"},   # space, not 'T'
                {"expiry": "2026-01-01T00:00:00"},             # tz-naive
                {"last_seen": "2026-01-01T00:00:00.5"},        # frac but no offset
                {"surprise": 1}):                              # unknown top-level property
        bad = deepcopy(valid); bad.update(mut)
        assert feeds.validate_intel(bad) is False, mut
        if _VALIDATE:                                          # parity: real schema agrees
            try:
                _VALIDATE(bad); assert False, mut
            except Exception:
                pass
    # unknown property inside a provenance entry
    bad = deepcopy(valid); bad["provenance"][0]["surprise"] = 1
    assert feeds.validate_intel(bad) is False
    # space-separated timestamp inside a provenance entry
    bad = deepcopy(valid); bad["provenance"][0]["first_seen"] = "2026-01-01 00:00:00+00:00"
    assert feeds.validate_intel(bad) is False


def test_stix_space_separated_timestamp_quarantined_before_store():
    # A STIX valid_from that parses via fromisoformat but violates the intel.v1 datetime
    # pattern (space separator) must be quarantined, never stored (reviewer regression).
    s = IntelStore()
    bundle = _json.dumps({"objects": [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '1.1.1.1']",
         "valid_from": "2026-01-01 00:00:00+00:00"}]})
    c = feeds.StixTaxiiConnector(feed="taxii", source="vendorX", source_trust=0.7)
    out = c.records(bundle, "t1", NOW)
    assert out == []                                            # not emitted
    lifecycle.ingest(s, out, NOW)
    assert s.list(["t1"]) == []                                 # nothing reached the store


def test_feed_tlp_is_a_floor_incoming_marking_cannot_downgrade():
    # A green-marked record on a feed configured tlp=red stays red (floor) and is not
    # exportable; a record MORE restrictive than the feed floor is still honored.
    class _Green(feeds.HttpConnector):
        def parse(self, payload): return [{"indicator": "9.9.9.9", "type": "ip", "tlp": "green"}]

    c = _Green(feed="f", source="s", source_trust=0.6, tlp="red")
    r = c.records("x", "t1", NOW)[0]
    assert r["tlp"] == "red" and r["provenance"][0]["tlp"] == "red"
    assert lifecycle.is_exportable(r) is False

    class _Red(feeds.HttpConnector):
        def parse(self, payload): return [{"indicator": "9.9.9.9", "type": "ip", "tlp": "red"}]

    c2 = _Red(feed="f", source="s", source_trust=0.6, tlp="green")
    assert c2.records("x", "t1", NOW)[0]["tlp"] == "red"        # more-restrictive marking honored


def test_stix_feed_tlp_floor_not_downgraded_through_ingest():
    # End-to-end: a green-marked STIX indicator on a tlp=red feed lands red / non-exportable.
    s = IntelStore()
    bundle = _json.dumps({"objects": [
        {"type": "marking-definition", "id": "marking-definition--g", "definition_type": "tlp",
         "name": "TLP:GREEN", "definition": {"tlp": "green"}},
        {"type": "indicator", "pattern": "[ipv4-addr:value = '9.9.9.9']",
         "object_marking_refs": ["marking-definition--g"]}]})
    c = feeds.StixTaxiiConnector(feed="taxii", source="vendorX", source_trust=0.7, tlp="red")
    lifecycle.ingest(s, c.records(bundle, "t1", NOW), NOW)
    r = s.get("t1", "ip", "9.9.9.9")
    assert r["tlp"] == "red" and lifecycle.is_exportable(r) is False
    assert lifecycle.exportable(s.list(["t1"])) == []


def test_stix_active_to_revoked_refresh_invalidates_stored_assertion():
    # active -> revoked refresh: a later bundle marking the same indicator revoked=true must
    # withdraw this feed's stored assertion; match no longer returns it, and the row is gone
    # once its last contributor is withdrawn (reviewer regression).
    s = IntelStore()
    c = feeds.StixTaxiiConnector(feed="taxii", source="vendorX", source_trust=0.7)
    active = _json.dumps({"objects": [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '1.1.1.1']", "confidence": 80}]})
    lifecycle.ingest(s, c.records(active, "t1", NOW), NOW)
    assert lifecycle.match(s, "t1", "ip", "1.1.1.1", NOW) is not None
    revoked = _json.dumps({"objects": [
        {"type": "indicator", "revoked": True, "pattern": "[ipv4-addr:value = '1.1.1.1']"}]})
    lifecycle.ingest(s, c.records(revoked, "t1", NOW), NOW,
                     revocations=c.revocations(revoked, "t1", NOW))
    assert lifecycle.match(s, "t1", "ip", "1.1.1.1", NOW) is None
    assert s.get("t1", "ip", "1.1.1.1") is None                 # last assertion withdrawn -> removed


def test_stix_revocation_preserves_other_contributors():
    # Revoking this feed's assertion must not remove a different feed's still-valid one.
    s = IntelStore()
    lifecycle.ingest(s, [rec("1.1.1.1", "ip", 70, 0.9, "otherfeed", source="othersrc")], NOW)
    c = feeds.StixTaxiiConnector(feed="taxii", source="vendorX", source_trust=0.7)
    active = _json.dumps({"objects": [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '1.1.1.1']", "confidence": 80}]})
    lifecycle.ingest(s, c.records(active, "t1", NOW), NOW)
    assert len(s.get("t1", "ip", "1.1.1.1")["provenance"]) == 2
    revoked = _json.dumps({"objects": [
        {"type": "indicator", "revoked": True, "pattern": "[ipv4-addr:value = '1.1.1.1']"}]})
    lifecycle.ingest(s, c.records(revoked, "t1", NOW), NOW,
                     revocations=c.revocations(revoked, "t1", NOW))
    m = lifecycle.match(s, "t1", "ip", "1.1.1.1", NOW)
    assert m is not None and [p["feed"] for p in m["provenance"]] == ["otherfeed"]


def test_stix_updated_validity_window_past_invalidates_stored_assertion():
    # Equivalent coverage for updated validity windows: re-ingesting the same indicator with
    # valid_until now in the past withdraws the stored assertion (reviewer regression).
    s = IntelStore()
    c = feeds.StixTaxiiConnector(feed="taxii", source="vendorX", source_trust=0.7)
    active = _json.dumps({"objects": [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '5.5.5.5']", "confidence": 80,
         "valid_from": PAST, "valid_until": FUTURE}]})
    lifecycle.ingest(s, c.records(active, "t1", NOW), NOW)
    assert lifecycle.match(s, "t1", "ip", "5.5.5.5", NOW) is not None
    expired = _json.dumps({"objects": [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '5.5.5.5']", "confidence": 80,
         "valid_from": PAST, "valid_until": PAST}]})
    lifecycle.ingest(s, c.records(expired, "t1", NOW), NOW,
                     revocations=c.revocations(expired, "t1", NOW))
    assert lifecycle.match(s, "t1", "ip", "5.5.5.5", NOW) is None


def test_validate_intel_matches_jsonschema_contract():
    # The self-contained runtime validator must agree with contracts/intel.schema.json
    # (guards against drift). Only runs where jsonschema is installed.
    if _VALIDATE is None:
        return
    from copy import deepcopy
    valid = rec("1.2.3.4", "ip", 90, 0.9, "feodo", source="abuse.ch")
    assert feeds.validate_intel(valid) is True
    _VALIDATE(valid)
    for mut in ({"type": "nope"}, {"tlp": "orange"}, {"score": 101}, {"score": -1},
                {"source_trust": 1.5}, {"source_trust": -0.1}, {"disposition": "ignored"},
                {"expiry": "not-a-date"}, {"expiry": "2026-13-01T00:00:00Z"},
                {"indicator": "   "}, {"provenance": []}):
        bad = deepcopy(valid)
        bad.update(mut)
        assert feeds.validate_intel(bad) is False, mut


# --- U1 blocker 2: TAXII pagination completeness ------------------------------
def test_stix_taxii_pagination_more_without_next_raises():
    # more=true but the server returns no usable continuation token (missing or empty) ->
    # explicit incomplete-fetch error, never a silently truncated collection.
    class _R:
        def __init__(self, b): self._b = b
        def read(self): return self._b.encode()

    for env in ({"more": True, "objects": []},                       # `next` missing
                {"more": True, "next": "", "objects": []}):          # `next` empty
        c = feeds.StixTaxiiConnector(feed="taxii", source="vendorX", source_trust=0.7,
                                     url="https://taxii/x/objects/")
        try:
            c.fetch(opener=lambda _req, e=env: _R(_json.dumps(e)))
            assert False, "must not silently return an incomplete collection"
        except feeds.FeedFetchIncomplete:
            pass


def test_stix_taxii_pagination_exceeds_page_cap_raises():
    # Every page reports more=true with a fresh cursor -> paging can't complete; hitting
    # the cap must surface an incomplete-fetch error, not a partial result.
    class _R:
        def read(self):
            return _json.dumps({"more": True, "next": "N", "objects": []}).encode()

    c = feeds.StixTaxiiConnector(feed="taxii", source="vendorX", source_trust=0.7,
                                 url="https://taxii/x/objects/")
    c.max_pages = 3
    try:
        c.fetch(opener=lambda _req: _R())
        assert False, "page cap with more=true still set must raise"
    except feeds.FeedFetchIncomplete:
        pass


# --- U1 blocker 3: STIX revocation + validity window --------------------------
def test_stix_revoked_indicator_not_emitted():
    bundle = _json.dumps({"objects": [
        {"type": "indicator", "revoked": True, "pattern": "[ipv4-addr:value = '1.1.1.1']"},
        {"type": "indicator", "pattern": "[ipv4-addr:value = '2.2.2.2']"}]})
    c = feeds.StixTaxiiConnector(feed="taxii", source="vendorX", source_trust=0.7)
    assert {r["indicator"] for r in c.records(bundle, "t1", NOW)} == {"2.2.2.2"}


def test_stix_future_valid_from_not_emitted():
    bundle = _json.dumps({"objects": [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '1.1.1.1']", "valid_from": FUTURE},
        {"type": "indicator", "pattern": "[ipv4-addr:value = '2.2.2.2']"}]})
    c = feeds.StixTaxiiConnector(feed="taxii", source="vendorX", source_trust=0.7)
    assert {r["indicator"] for r in c.records(bundle, "t1", NOW)} == {"2.2.2.2"}


def test_stix_past_valid_until_not_emitted():
    bundle = _json.dumps({"objects": [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '1.1.1.1']",
         "valid_from": PAST, "valid_until": PAST},
        {"type": "indicator", "pattern": "[ipv4-addr:value = '2.2.2.2']"}]})
    c = feeds.StixTaxiiConnector(feed="taxii", source="vendorX", source_trust=0.7)
    assert {r["indicator"] for r in c.records(bundle, "t1", NOW)} == {"2.2.2.2"}


def test_stix_revoked_and_out_of_window_never_match():
    # End-to-end: a revoked, a not-yet-valid, and an expired-window indicator must never
    # reach the store or match; only the plain valid one does.
    s = IntelStore()
    bundle = _json.dumps({"objects": [
        {"type": "indicator", "revoked": True, "pattern": "[ipv4-addr:value = '1.1.1.1']"},
        {"type": "indicator", "pattern": "[ipv4-addr:value = '2.2.2.2']", "valid_from": FUTURE},
        {"type": "indicator", "pattern": "[ipv4-addr:value = '3.3.3.3']",
         "valid_from": PAST, "valid_until": PAST},
        {"type": "indicator", "pattern": "[ipv4-addr:value = '4.4.4.4']"}]})
    c = feeds.StixTaxiiConnector(feed="taxii", source="vendorX", source_trust=0.7)
    lifecycle.ingest(s, c.records(bundle, "t1", NOW), NOW)
    for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
        assert lifecycle.match(s, "t1", "ip", ip, NOW) is None
    assert lifecycle.match(s, "t1", "ip", "4.4.4.4", NOW) is not None


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} intel lifecycle tests passed")
