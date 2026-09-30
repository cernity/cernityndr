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


# U4: use real yara-python and forked children. The macOS development host lacks
# RLIMIT_AS; test_workers separately tests fail-closed setup and Linux enforcement.
import hashlib
from pathlib import Path
import signal
import pytest
import registry
import workers
from test_workers import portable_limits


def registered(source, status='active', **kwargs):
    reg = registry.RulesetRegistry()
    row = reg.register_draft('test', 'v1', source, 'unit-test', **kwargs)
    auth = registry.allow_actors('tester')
    reg.promote(row['id'], 'shadow', 'tester', auth)
    if status == 'active':
        reg.promote(row['id'], 'active', 'tester', auth)
    return reg, row


def test_eicar_benign_and_provenance(portable_limits):
    source = (Path(__file__).parent / 'rules/eicar.yar').read_bytes()
    reg, row = registered(source)
    results = s.scan_bytes(reg, b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE $H+H*', pcap_evidence_id='pcap-123')
    result = results[0]
    assert result['scan_error'] is None
    assert result['acted'] is True
    assert result['matches'][0]['rule'] == 'EICAR_Test_File'
    assert result['ruleset_id'] == row['id']
    assert result['ruleset_version'] == 'v1'
    assert result['ruleset_sha256'] == hashlib.sha256(source).hexdigest()
    assert result['engine_version']
    assert result['pcap_evidence_id'] == 'pcap-123'
    assert s.finding_from_results(_ev(), results)['file_forensics']['size'] > 0
    benign = s.scan_bytes(reg, b'ordinary benign document')[0]
    assert benign['scan_error'] is None and not benign['matches'] and not benign['acted']


def test_truncated_hex_strings(portable_limits):
    reg, _ = registered(b'rule binary { strings: $a = /A{100}\\x00\\xff/ condition: $a }')
    result = s.scan_bytes(reg, b'A' * 100 + b'\x00\xff')[0]
    preview = result['matches'][0]['strings'][0]
    assert preview['offset'] == 0
    assert preview['truncated'] is True
    assert preview['data'] == '\\x41' * workers.STRING_BYTES
    assert len(preview['data']) == 4 * workers.STRING_BYTES
    assert workers.escaped_preview(b'A\x00\xff') == '\\x41\\x00\\xff'


def test_shadow_hit_never_acted(portable_limits):
    reg, _ = registered(b'rule canary {condition:true}', 'shadow')
    results = s.scan_bytes(reg, b'hello')
    assert results[0]['matches'] and not results[0]['acted']
    assert s.finding_from_results(_ev(), results) is None


@pytest.mark.parametrize('failure', ['timeout', 'oom'])
def test_resource_errors_are_scan_errors(portable_limits, monkeypatch, failure):
    from test_workers import _hang, _oom
    monkeypatch.setattr(workers, '_match', _hang if failure == 'timeout' else _oom)
    reg, _ = registered(b'rule a {condition:true}')
    result = s.scan_bytes(reg, b'abc', limits=workers.Limits(wall_seconds=.1))[0]
    assert result['scan_error'] == failure
    assert result['exitcode'] == -signal.SIGKILL
    assert not result['acted']
    assert result['ruleset_version'] and result['ruleset_sha256'] and result['engine_version']
    assert s.finding_from_results(_ev(), [result]) is None


def test_registry_retirement_and_integrity(portable_limits):
    reg, row = registered(b'rule a {condition:true}')
    reg._db.execute('UPDATE ruleset_bytes SET data=?', (b'corrupt',))
    result = s.scan_bytes(reg, b'abc')[0]
    assert result['scan_error'] == 'ruleset_integrity'
    assert not result['acted']
    reg.promote(row['id'], 'retired', 'tester', registry.allow_actors('tester'))
    assert s.scan_bytes(reg, b'abc') == []


def test_observation_active_shadow_error_contract(portable_limits):
    import app
    reg, _ = registered(b'rule a {condition:true}')
    result = s.scan_bytes(reg, b'abc', pcap_evidence_id='pcap-123')[0]
    for extra, verdict in [({}, True), ({'status': 'shadow', 'acted': False}, False),
                            ({'scan_error': 'timeout', 'acted': False}, False)]:
        doc, raw = app.observation(_ev(), {**result, **extra}, tenant='trusted',
                                   topic=app.IN_TOPIC, partition=0, offset=4,
                                   ingested_at='2026-09-29T12:00:00Z')
        app._validator().validate(doc)
        file = doc['fields']['file']
        assert file['state'] == 'bytes_available'
        assert ('scan_verdict' in file) is verdict
        assert file['file_artifact_id'] == _ev()['sha256']
        assert doc['source_ref']['sha256'] == hashlib.sha256(raw.encode()).hexdigest()
        assert 'pcap-123' in raw
        assert 'ruleset_version' in raw and 'engine_version' in raw


def test_process_uses_u2_and_persists_before_publish(portable_limits, monkeypatch):
    import app
    import object_keys
    reg, _ = registered(b'rule a {condition:true}')
    data = b'abc'
    digest = hashlib.sha256(data).hexdigest()
    ref = object_keys.accepted_key(object_keys.tenant_segment('trusted'), digest, 'ndr-files')
    event = {**_ev(sha=digest, ref=ref), 'tenant_id': 'forged'}
    operations = []
    def retrieve(actual_ref, auth, grants, s3, audit, **kwargs):
        assert actual_ref == ref
        assert grants['internal']['tenant_id'] == 'trusted'
        operations.append('retrieve')
        return data
    monkeypatch.setattr(workers.artifact_store, 'retrieve', retrieve)
    class CH:
        def insert(self, table, rows, **kwargs):
            assert table == 'ndr.file_observation'
            operations.append('insert')
    class Ack:
        def get(self, **kwargs):
            operations.append('ack')
    class Producer:
        def send(self, topic, record):
            operations.append(topic)
            return Ack()
    results = app.process_one(event, reg, None, Producer(), CH(), app._validator(),
                              topic=app.IN_TOPIC, partition=0, offset=1,
                              ingested_at='2026-09-29T12:00:00Z', tenant='trusted')
    assert results[0]['acted']
    assert operations == ['retrieve', 'insert', 'ndr.observation.normalized.v1', 'ack',
                          app.OUT_TOPIC, 'ack']
    event['object_ref'] = object_keys.accepted_key(object_keys.tenant_segment('other'), digest, 'ndr-files')
    with pytest.raises(ValueError):
        app.process_one(event, reg, None, Producer(), CH(), app._validator(),
                        topic=app.IN_TOPIC, partition=0, offset=1,
                        ingested_at='2026-09-29T12:00:00Z', tenant='trusted')


def test_draft_never_served_and_mime_is_not_wire_claim(portable_limits):
    reg, _ = registered(b'rule a {condition:true}', target_mime_types=['application/pdf'])
    reg.register_draft('draft', '1', b'rule draft {condition:true}', 'test')
    results = s.scan_bytes(reg, b'ordinary text')
    assert len(results) == 1
    assert results[0]['scan_error'] == 'mime_not_targeted'
    assert results[0]['mime'] == 'text/plain'
    assert not results[0]['acted']


def test_match_and_instance_counts_bounded(portable_limits):
    source = b'\n'.join(f'rule r{i} {{strings: $a = "X" condition: $a}}'.encode()
                        for i in range(workers.MAX_MATCHES + 1))
    reg, _ = registered(source)
    result = s.scan_bytes(reg, b'X' * (workers.MAX_STRINGS + 1))[0]
    assert len(result['matches']) == workers.MAX_MATCHES
    assert result['matches_truncated'] is True
    for match in result['matches']:
        assert len(match['strings']) == workers.MAX_STRINGS
        assert match['strings_truncated'] is True


def test_shadow_cannot_contaminate_active_verdict(portable_limits):
    reg, _ = registered(b'rule active_nohit {condition:false}')
    shadow = reg.register_draft('canary', '2', b'rule shadow_hit {condition:true}', 'test')
    reg.promote(shadow['id'], 'shadow', 'tester', registry.allow_actors('tester'))
    results = s.scan_bytes(reg, b'abc')
    assert any(r['matches'] for r in results)
    assert not any(r['acted'] for r in results)
    assert s.finding_from_results(_ev(), results) is None


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-q']))
