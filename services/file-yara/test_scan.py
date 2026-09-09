"""U6 file-yara scan-logic tests (pure, stdlib only; no yara import exercised)."""
import scan as s


def _ev(size=1000, sha="ab" * 32, mime="application/x-dosexec",
        ref="ndr-files/x.bin", sensor="sensor-1"):
    return {"size": size, "sha256": sha, "mime": mime,
            "object_ref": ref, "sensor_id": sensor}


def test_no_match_no_finding():
    assert s.finding_from_matches(_ev(), []) is None


def test_match_makes_sev9_malware_finding():
    f = s.finding_from_matches(_ev(), ["Win32_Malware_Generic"])
    assert f["detector_id"] == "file_yara"
    assert f["severity"] == 9 and f["category"] == "malware"
    assert "Win32_Malware_Generic" in f["entities"]
    assert f["evidence_refs"] == ["minio://ndr-files/x.bin"]
    assert f["mitre"] == ["T1204"]


def test_match_without_hash_still_shapes():
    f = s.finding_from_matches(_ev(sha=""), ["EICAR_Test_File"])
    assert f["finding_id"].endswith("nohash")


def test_should_scan_skips_empty_and_oversize():
    assert s.should_scan(_ev(size=1000), max_bytes=10_000)
    assert not s.should_scan(_ev(size=0), max_bytes=10_000)
    assert not s.should_scan(_ev(size=20_000), max_bytes=10_000)


def test_scan_bytes_no_rules_is_empty():
    assert s.scan_bytes(None, b"anything") == []


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("ok ", fn.__name__)
    print(f"\nall {len(fns)} scan tests passed")
