"""Tests for DNS detections (DGA + NXDOMAIN burst)."""
import dns_detect as d


def test_dga_flags_algorithmic_domains():
    for dom in ("vhrtbxlqkm.net", "kq3v9z7jx2.com", "xkqjmbvwzn.org"):
        hit, score, _ = d.is_dga(dom)
        assert hit, f"{dom} scored {score}, expected DGA"


def test_dga_ignores_benign_domains():
    for dom in ("google.com", "microsoft.com", "cloudflare.com", "wikipedia.org"):
        hit, score, _ = d.is_dga(dom)
        assert not hit, f"{dom} scored {score}, false positive"


def test_no_fp_on_random_cdn_subdomain():
    # The random-looking label is a SUBDOMAIN under a benign registered domain;
    # scoring the registered label (cloudfront / s3) avoids the false positive.
    assert d.is_dga("d2k1ftgv7pobq7.cloudfront.net")[0] is False
    assert d.is_dga("a1b2c3d4e5f6g7.s3.amazonaws.com")[0] is False


def test_short_label_never_dga():
    assert d.is_dga("abc.com")[0] is False
    assert d.dga_score("xy.io")[0] == 0.0


def test_dga_domains_outscore_benign():
    assert d.dga_score("vhrtbxlqkm.net")[0] > d.dga_score("microsoft.com")[0]


def test_query_name_extraction_v3_and_flat():
    assert d.query_name({"dns": {"queries": [{"rrname": "Evil.COM"}]}}) == "evil.com"
    assert d.query_name({"dns": {"rrname": "flat.example"}}) == "flat.example"
    assert d.query_name({"dns": {}}) == ""


def test_rcode_and_nxdomain_burst():
    assert d.rcode({"dns": {"rcode": "NXDOMAIN"}}) == "NXDOMAIN"
    assert d.nxdomain_burst(20) is True
    assert d.nxdomain_burst(19) is False


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} dns-detector tests passed")
