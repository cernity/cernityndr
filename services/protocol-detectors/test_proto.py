"""Protocol detector tests (pure)."""
import proto as p


def test_multicast_not_external():
    assert p.is_multicast("239.255.255.250") and not p.is_external("239.255.255.250")
    assert p.is_multicast("ff02::fb") and p.is_external("8.8.8.8")


def test_rare_ja4():
    seen = {f"ja4_{i}" for i in range(35)}
    assert p.is_rare_ja4("brand_new_ja4", seen)
    assert not p.is_rare_ja4("ja4_5", seen)          # already seen
    assert not p.is_rare_ja4("x", {"a", "b"})        # pre-warmup


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


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} protocol detector tests passed")
