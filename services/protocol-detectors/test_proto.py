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


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} protocol detector tests passed")
