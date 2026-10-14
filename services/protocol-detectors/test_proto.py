"""Protocol detector tests (pure)."""
import proto as p


def test_multicast_not_external():
    assert p.is_multicast("239.255.255.250") and not p.is_external("239.255.255.250")
    assert p.is_multicast("ff02::fb") and p.is_external("8.8.8.8")


def _fp(i=0, c=0):
    return f"t13d1516h2_{i:012x}_{c:012x}"


def test_ja4_validation_and_parts():
    fp = "t13d1516h2_8daaf6152771_02713d6af862"
    assert p.ja4_valid(fp)
    assert p.ja4_parts(fp) == tuple(fp.split("_"))
    assert p.ja4_ac(fp) == "t13d1516h2_02713d6af862"
    for bad in (None, "", "8daaf6152771", {}, {"hash": fp}, 42,
                fp + "_extra", fp.replace("8daaf", "zzzzz"), fp[1:],
                fp.replace("t13d", "x13d")):
        assert not p.ja4_valid(bad)
        assert p.ja4_parts(bad) is None and p.ja4_ac(bad) == ""


def test_baseline_maturity():
    assert p.baseline_maturity(1, 1, 0, 100000) == "cold"
    assert p.baseline_maturity(100, 1, 0, 60) == "warming"
    assert p.baseline_maturity(100, 1, 0, 86400) == "ready"
    assert p.baseline_maturity(2, 1, 0, 10, 2, 10) == "ready"
    assert p.baseline_maturity(100, 0, None, 100000) == "cold"


def test_ja4_novelty():
    fp = _fp()
    for maturity in ("cold", "warming"):
        assert p.ja4_novelty(fp, set(), set(), 0, maturity) == (False, [], 0.0, 0)
    standalone = p.ja4_novelty(fp, set(), set(), 100, "ready")
    assert standalone[0] and standalone[1] == ["JA4_NEW_TO_ENTITY"]
    assert 1 <= standalone[3] <= 2 and standalone[2] <= 0.3
    rare = p.ja4_novelty(fp, set(), set(), 2, "ready")
    assert "JA4_RARE_IN_FLEET" in rare[1]
    assert standalone[3] < rare[3] <= 6 and standalone[2] < rare[2]
    similar = p.ja4_novelty(fp, set(), {p.ja4_ac(fp)}, 2, "ready")
    assert "JA4_AC_SIMILARITY" in similar[1]
    assert similar[3] < rare[3] and similar[2] < rare[2]
    corroborated = p.ja4_novelty(fp, set(), set(), 100, "ready", corroborated=True)
    assert standalone[3] < corroborated[3] <= 6
    assert not p.ja4_novelty(fp, {fp}, set(), 0, "ready")[0]
    assert not p.ja4_novelty("invalid", set(), set(), 0, "ready")[0]


def test_ja4_transition_burst():
    assert p.ja4_transition_burst([(i, _fp(i)) for i in range(5)]) == (True, 5)
    assert p.ja4_transition_burst([(i, _fp()) for i in range(10)]) == (False, 1)
    assert p.ja4_transition_burst([(0, _fp()), (601, _fp(1))]) == (False, 1)
    assert p.ja4_transition_burst([(0, "bad")]) == (False, 0)
    assert p.ja4_transition_burst([]) == (False, 0)


def test_cloud_staging():
    assert p.cloud_staging_hit("dl.dropboxusercontent.com")[0]
    assert p.cloud_staging_hit("files.mega.nz")[0]
    assert not p.cloud_staging_hit("www.google.com")[0]


def test_doh():
    assert p.doh_hit("cloudflare-dns.com", 443, set())[0]
    assert p.doh_hit("", 853, set())[0]              # DoT port
    assert not p.doh_hit("dns.google", 443, {"dns.google"})[0]   # approved
    assert not p.doh_hit("example.com", 443, set())[0]


def test_cert_anomaly():
    assert p.cert_anomaly("CN=evil", "CN=evil", "", "")[0]        # self-signed
    hit, why = p.cert_anomaly("CN=a", "CN=DigiCert",
                              "2026-01-01T00:00:00Z", "2026-01-01T12:00:00Z")
    assert hit and why == "short_validity"
    assert not p.cert_anomaly("CN=a", "CN=DigiCert",
                              "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")[0]


def test_suspicious_ua():
    assert p.suspicious_ua("")[0] == True
    assert p.suspicious_ua(None)[0] == True
    assert p.suspicious_ua("curl/8.4.0")[0]
    assert p.suspicious_ua("python-requests/2.31")[0]
    assert not p.suspicious_ua("Mozilla/5.0 (Macintosh) Safari/605")[0]


def test_ssh_brute():
    assert p.ssh_brute_hit(20) and not p.ssh_brute_hit(3)


def test_icmp_exfil():
    assert p.icmp_exfil_hit("ICMP", 2_000_000, "8.8.8.8")
    assert not p.icmp_exfil_hit("ICMP", 2_000_000, "10.0.0.1")   # internal
    assert not p.icmp_exfil_hit("TCP", 2_000_000, "8.8.8.8")     # not icmp
    assert not p.icmp_exfil_hit("ICMP", 500, "8.8.8.8")          # small


def test_port_proto_mismatch():
    assert p.port_proto_mismatch("ssh", 443)[0]                  # ssh on 443 fires
    assert p.port_proto_mismatch("http", 443)[0]                 # cleartext on TLS port fires
    assert p.port_proto_mismatch("tls", 22)[0]                   # tls on ssh port fires
    assert not p.port_proto_mismatch("tls", 443)[0]              # https on 443 is fine
    assert not p.port_proto_mismatch("ssl", 443)[0]              # ssl==tls normalized
    assert not p.port_proto_mismatch("http", 8080)[0]            # http on 8080 fine
    assert not p.port_proto_mismatch("tls", 9999)[0]             # no expectation for 9999
    assert not p.port_proto_mismatch("", 443)[0]                 # absent app_proto no-fire
    assert not p.port_proto_mismatch("unknown", 22)[0]           # unknown no-fire
    assert not p.port_proto_mismatch("ssh", 443, allow_ports={443})[0]  # allowlisted no-fire


def test_ech_present():
    assert p.ech_present({"ech": True})
    assert p.ech_present({"encrypted_client_hello": {}})
    assert p.ech_present({"extensions": ["sni", "65037"]})       # ECH ext type
    assert not p.ech_present({})
    assert not p.ech_present({"extensions": ["sni", "alpn"]})


def test_host_sni_mismatch():
    assert p.host_sni_mismatch("cdn.akamai.com", "evil.com")     # fronting
    assert not p.host_sni_mismatch("www.example.com", "example.com")   # www-insensitive
    assert not p.host_sni_mismatch("example.com", "")            # host absent
    assert not p.host_sni_mismatch("", "example.com")            # sni absent


def test_ech_or_host_sni_mismatch():
    assert p.ech_or_host_sni_mismatch({"ech": True}, "", "")[0]  # ECH alone fires
    hit, why = p.ech_or_host_sni_mismatch({}, "cdn.akamai.com", "evil.com")
    assert hit and "host_sni_mismatch" in why
    assert not p.ech_or_host_sni_mismatch({}, "example.com", "example.com")[0]   # Host==SNI
    # fully-encrypted HTTPS: no visible Host -> explicitly no-fire (documented limit)
    assert not p.ech_or_host_sni_mismatch({}, "example.com", "")[0]


def test_is_external_ipv6_ula():
    # F06: IPv6 ULA (fc00::/7) is internal; global v6 is external — parity with behavioral
    # and east-west so IPv6 traffic is classified consistently across detectors.
    assert not p.is_external("fd00::1") and not p.is_external("fc00::abcd")
    assert not p.is_external("fe80::1")
    assert p.is_external("2606:4700:4700::1111")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} protocol detector tests passed")
