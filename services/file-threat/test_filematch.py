"""Tests for file-based malware detection (G2)."""
import filematch as fm

HASHES = {fm.EICAR_SHA256, "deadbeef" * 8}
# A fully-captured file: explicit CLOSED, no gaps, starts at byte 0.
EICAR = {"event_type": "fileinfo", "src_ip": "45.9.1.2", "dest_ip": "10.0.0.5",
         "fileinfo": {"filename": "invoice.exe", "mime_type": "application/x-dosexec",
                      "sha256": fm.EICAR_SHA256, "state": "CLOSED", "gaps": False, "start": 0}}
EXE_NOHIT = {"event_type": "fileinfo", "src_ip": "1.2.3.4", "dest_ip": "10.0.0.5",
             "fileinfo": {"filename": "setup.exe", "mime_type": "application/x-dosexec",
                          "sha256": "0" * 64}}
BENIGN = {"event_type": "fileinfo", "src_ip": "1.2.3.4", "dest_ip": "10.0.0.5",
          "fileinfo": {"filename": "photo.jpg", "mime_type": "image/jpeg", "sha256": "1" * 64}}
FLOW = {"event_type": "flow"}


def test_known_malware_hash_high_severity():
    c = fm.to_candidate(EICAR, HASHES)
    assert c and c["detector_id"] == "file_malware_hash"
    assert c["severity"] == 9 and c["confidence"] == 0.95
    assert fm.EICAR_SHA256 in c["entities"]


def test_risky_executable_without_hit_is_moderate():
    c = fm.to_candidate(EXE_NOHIT, HASHES)
    assert c and c["detector_id"] == "risky_file_delivery" and c["severity"] == 6


def test_benign_file_no_finding():
    assert fm.to_candidate(BENIGN, HASHES) is None


def test_finding_carries_community_id_join_key():
    # A finding that carries community_id/flow_id can be joined back to the exact
    # connection's flow/tls/dns telemetry in ClickHouse (metadata enrichment).
    eve = dict(EICAR, community_id="1:abc", flow_id=42)
    c = fm.to_candidate(eve, HASHES)
    assert '"community_id"' in c["entities"] and '"1:abc"' in c["entities"]
    assert '"flow_id"' in c["entities"]


def test_no_join_key_when_source_event_lacks_it():
    c = fm.to_candidate(EICAR, HASHES)     # EICAR has no community_id/flow_id
    assert "community_id" not in c["entities"] and "flow_id" not in c["entities"]


def test_join_key_entities_helper():
    assert fm.join_key_entities({"community_id": "1:x", "flow_id": 7}) == [
        {"type": "community_id", "value": "1:x"}, {"type": "flow_id", "value": 7}]
    assert fm.join_key_entities({}) == []


def test_ignores_non_fileinfo():
    assert fm.to_candidate(FLOW, HASHES) is None


def test_hash_hit_matches_any_algo():
    assert fm.hash_hit({"md5": "deadbeef" * 4, "sha256": "x"}, {"deadbeef" * 4}) == "deadbeef" * 4
    assert fm.hash_hit({"sha256": "safe"}, {"bad"}) is None


def test_hash_is_complete_requires_positive_evidence_fail_closed():
    ok = {"sha256": "a" * 64, "state": "CLOSED", "gaps": False, "start": 0}
    assert fm.hash_is_complete(ok)
    assert not fm.hash_is_complete({"sha256": "a" * 64})                   # missing state/gaps -> fail closed
    assert not fm.hash_is_complete(dict(ok, state="TRUNCATED"))            # truncated -> partial
    assert not fm.hash_is_complete({"sha256": "a" * 64, "gaps": False})    # missing state -> fail closed
    assert not fm.hash_is_complete({"sha256": "a" * 64, "state": "CLOSED"})  # missing gaps -> fail closed
    assert not fm.hash_is_complete(dict(ok, gaps=True))                    # gap -> unreliable
    assert not fm.hash_is_complete(dict(ok, start=5))                      # mid-stream -> partial
    assert not fm.hash_is_complete(dict(ok, sha256=None))                  # no sha256


def _malware_fi(**over):
    fi = {"filename": "x.exe", "mime_type": "application/x-dosexec",
          "sha256": fm.EICAR_SHA256, "state": "CLOSED", "gaps": False, "start": 0}
    fi.update(over)
    return {"event_type": "fileinfo", "src_ip": "45.9.1.2", "dest_ip": "10.0.0.5", "fileinfo": fi}


def test_incomplete_file_never_produces_malware_hash_finding():
    # A malware-hash file that is NOT fully captured must not become
    # file_malware_hash. As an executable it still surfaces as risky_file_delivery.
    for bad in (_malware_fi(state="TRUNCATED"), _malware_fi(state=None),
                _malware_fi(gaps=None), _malware_fi(gaps=True), _malware_fi(start=5)):
        c = fm.to_candidate(bad, HASHES)
        assert c is not None and c["detector_id"] == "risky_file_delivery", bad["fileinfo"]
        assert '"hash_complete", "value": false' in c["entities"]


def test_incomplete_benign_mime_with_bad_hash_yields_nothing():
    # A truncated non-executable whose partial hash coincidentally matches must
    # produce no malware finding at all (no risky-delivery either).
    fi = {"event_type": "fileinfo", "src_ip": "1.2.3.4", "dest_ip": "10.0.0.5",
          "fileinfo": {"filename": "doc.pdf", "mime_type": "application/pdf",
                       "sha256": fm.EICAR_SHA256, "state": "TRUNCATED"}}
    assert fm.to_candidate(fi, HASHES) is None


def test_complete_file_carries_hash_complete_true():
    c = fm.to_candidate(EICAR, HASHES)
    assert c["detector_id"] == "file_malware_hash"
    assert '"hash_complete", "value": true' in c["entities"]


def test_candidate_is_schema_complete_and_deterministic():
    # F13: schema-required first_seen/last_seen present (were missing). F07: SHA-1 id
    # (shared _stable pattern; cross-process stability proven in ids-alerts).
    import json, pathlib
    req = json.loads((pathlib.Path(__file__).parents[2] / "contracts"
                      / "finding.schema.json").read_text())["required"]
    c = fm.to_candidate(EICAR, HASHES)
    assert all(k in c for k in req), [k for k in req if k not in c]
    assert c["finding_id"] == fm.to_candidate(EICAR, HASHES)["finding_id"]


if __name__ == "__main__":
    for n, f in sorted(globals().items()):
        if n.startswith("test_") and callable(f):
            f(); print("ok", n)
    print("all passed")
