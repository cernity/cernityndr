"""Tests for Zeek notice.log -> finding promotion. Real-shaped notice records."""
import promote_notice as p

# An Intel-framework IOC hit (the highest-value Zeek detection): a fed indicator
# matched. Zeek fills src/dst and puts the matched value in `sub`.
INTEL = {"note": "Intel::Notice", "msg": "Intel hit on 45.9.148.2",
         "sub": "45.9.148.2", "src": "10.0.0.9", "dst": "45.9.148.2",
         "id.orig_h": "10.0.0.9", "id.resp_h": "45.9.148.2", "uid": "CxYz1"}
BADCERT = {"note": "SSL::Invalid_Server_Cert", "msg": "self-signed cert",
           "id.orig_h": "10.0.0.5", "id.resp_h": "1.2.3.4"}
SCAN = {"note": "Scan::Address_Scan", "msg": "10.0.0.9 scanned 25 hosts",
        "src": "10.0.0.9"}
UNKNOWN_SSL = {"note": "SSL::Some_New_Notice", "id.orig_h": "a", "id.resp_h": "b"}
UNKNOWN_PKG = {"note": "CoolPackage::Detected", "id.orig_h": "a", "id.resp_h": "b"}
NO_NOTE = {"msg": "nothing", "id.orig_h": "a", "id.resp_h": "b"}


def test_intel_hit_is_high_severity_c2_with_indicator():
    c = p.to_candidate(INTEL)
    assert c and c["detector_id"] == "zeek_notice"
    assert c["category"] == "c2" and c["severity"] == 8
    assert '"indicator"' in c["entities"] and "45.9.148.2" in c["entities"]
    assert '"zeek_uid"' in c["entities"]      # join key back to the connection


def test_bad_cert_is_c2():
    c = p.to_candidate(BADCERT)
    assert c and c["category"] == "c2" and c["severity"] == 6
    assert "10.0.0.5" in c["entities"] and "1.2.3.4" in c["entities"]  # id.* endpoints used


def test_scan_is_recon():
    c = p.to_candidate(SCAN)
    assert c and c["category"] == "recon" and c["severity"] == 5


def test_unknown_note_falls_back_on_prefix():
    assert p.classify("SSL::Some_New_Notice") == ("c2", 5)      # SSL prefix
    c = p.to_candidate(UNKNOWN_SSL)
    assert c and c["category"] == "c2"


def test_unknown_package_promotes_at_default_not_dropped():
    # Zeek only raises a notice when a script decided it is worth raising, so an
    # unknown notice still promotes (permissive), unlike the Suricata raw stream.
    c = p.to_candidate(UNKNOWN_PKG)
    assert c and c["category"] == "malware" and c["severity"] == 6


def test_no_note_is_not_a_finding():
    assert p.to_candidate(NO_NOTE) is None
    assert p.to_candidate({"note": "-"}) is None


def test_operational_notices_are_dropped_not_promoted():
    # SIEM/DE feedback: capture-loss / packet-filter / software notices are the
    # sensor talking about itself, not detections. They must not become findings.
    assert p.is_operational("CaptureLoss::Too_Much_Loss")
    assert p.to_candidate({"note": "CaptureLoss::Too_Much_Loss",
                           "msg": "estimated loss 3.2%"}) is None
    assert p.to_candidate({"note": "PacketFilter::Dropped_Packets"}) is None
    assert p.to_candidate({"note": "Software::Vulnerable_Version"}) is None
    # a real detection notice still promotes
    assert p.to_candidate(INTEL) is not None


def test_tsv_parser_reads_zeek_notice_log():
    tsv = ("#separator \\x09\n"
           "#fields\tts\tnote\tmsg\tsrc\tdst\n"
           "1692000000.0\tIntel::Notice\thit\t10.0.0.9\t45.9.148.2\n")
    rows = p.parse_notice_tsv(tsv)
    assert len(rows) == 1 and rows[0]["note"] == "Intel::Notice"
    c = p.to_candidate(rows[0])
    assert c and c["category"] == "c2" and c["severity"] == 8


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} zeek-notice tests passed")
