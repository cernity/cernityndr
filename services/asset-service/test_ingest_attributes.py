"""U3c observed-only attribute ingestion (extract_evidence additive branches).

Pins the HONESTY contract: an attribute is populated ONLY from a field the EVE
record actually carries, attached to the entity that field truthfully describes —
never inferred, defaulted, or misattributed. A client's TLS fingerprint (ja4) and
HTTP user-agent belong to the CLIENT (src); the server's fingerprint (ja4s), its
presented certificate, and the Host header belong to the SERVER (dst). dns/flow
produce relationship edges, never attributes. The shipped flow/arp/dhcp identity
branches are untouched.
"""
import resolution as r

TS = "2026-09-28T12:05:00Z"

TLS = {"event_type": "tls", "src_ip": "10.0.0.5", "dest_ip": "93.184.216.34",
       "tls": {"ja4": "t13d1516h2_8daaf6152771", "ja4s": "t130200_1234_abcd",
               "subject": "CN=example.com", "issuerdn": "CN=DigiCert",
               "fingerprint": "sha256:deadbeef"}}
HTTP = {"event_type": "http", "src_ip": "10.0.0.5", "dest_ip": "93.184.216.34",
        "http": {"http_user_agent": "curl/8.4.0", "hostname": "example.com"}}
ARP = {"event_type": "arp", "arp": {"src_ip": "10.0.0.5", "src_mac": "AA:BB:CC:00:11:22"}}
FLOW = {"event_type": "flow", "src_ip": "10.0.0.5", "dest_ip": "1.1.1.1", "flow": {}}


def _by_ip(obs_rows):
    return {o["ip"]: o for o in obs_rows}


# ── (1) tls: client ja4 on src; server ja4s + cert on dst, with provenance ─────

def test_tls_sets_client_ja4_on_src_and_server_ja4s_cert_on_dst():
    by = _by_ip(r.extract_evidence(TLS))
    src = r.merge(None, by["10.0.0.5"], TS)
    dst = r.merge(None, by["93.184.216.34"], TS)
    assert src["ja4"] == ["t13d1516h2_8daaf6152771"]          # client fingerprint on the client
    assert "certificates" not in src                           # client is NOT the cert holder
    assert dst["ja4"] == ["t130200_1234_abcd"]                 # server fingerprint on the server
    assert set(dst["certificates"]) == {"CN=example.com", "CN=DigiCert", "sha256:deadbeef"}
    assert src["attribute_provenance"]["ja4"] == {"source": "tls", "observed_at": TS}
    assert dst["attribute_provenance"]["certificates"] == {"source": "tls", "observed_at": TS}


# ── (2) http: user-agent -> applications on src; Host -> hostname on dst ────────

def test_http_sets_user_agent_app_on_src_and_host_on_dst():
    by = _by_ip(r.extract_evidence(HTTP))
    src = r.merge(None, by["10.0.0.5"], TS)
    dst = r.merge(None, by["93.184.216.34"], TS)
    assert src["applications"] == ["curl/8.4.0"]               # the client's software
    assert "application" not in dst or not dst.get("applications")
    assert "example.com" in dst["hostname_set"]                # the server's name (Host header)
    assert src["attribute_provenance"]["applications"] == {"source": "http", "observed_at": TS}


# ── (3) a record missing those fields yields NO attribute (no default) ─────────

def test_tls_missing_fields_sets_no_attribute():
    eve = {"event_type": "tls", "src_ip": "10.0.0.5", "dest_ip": "1.2.3.4", "tls": {}}
    assert r.extract_evidence(eve) == []                       # no field -> no row, no default


def test_http_missing_fields_sets_no_attribute():
    eve = {"event_type": "http", "src_ip": "10.0.0.5", "dest_ip": "1.2.3.4", "http": {}}
    assert r.extract_evidence(eve) == []


# ── (4) dns / flow set NO attribute (they produce edges) ───────────────────────

def test_dns_and_flow_set_no_attribute():
    dns = {"event_type": "dns", "src_ip": "10.0.0.5", "dest_ip": "1.1.1.1",
           "dns": {"queries": [{"rrname": "example.com"}],
                   "answers": [{"rrtype": "A", "rdata": "93.184.216.34"}]}}
    assert r.extract_evidence(dns) == []                       # dns -> edges only, no attr row
    for o in r.extract_evidence(FLOW):                         # flow keeps ip-only identity rows
        for attr in (*r._ATTR_SCALARS, *r._ATTR_LISTS):
            assert attr not in o


# ── (5) shipped flow / arp identity extraction unchanged ───────────────────────

def test_shipped_arp_extraction_unchanged():
    assert r.extract_evidence(ARP) == [
        {"ip": "10.0.0.5", "mac": "AA:BB:CC:00:11:22", "hostname": None,
         "lease_secs": None, "src": "arp"}]


def test_shipped_flow_extraction_unchanged():
    assert r.extract_evidence(FLOW) == [
        {"ip": "10.0.0.5", "mac": None, "hostname": None, "lease_secs": None, "src": "flow"},
        {"ip": "1.1.1.1", "mac": None, "hostname": None, "lease_secs": None, "src": "flow"}]
