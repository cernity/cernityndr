"""U6 unit tests. Mock object store and producer, NOT a live e2e proof."""
import copy
import io
import struct
from unittest.mock import Mock
import pytest
import agent
import capture_v2


def policy():
    return dict(enabled=True, sensitive=False, tenant_id='acme', sensor_id='s1', policy_id='p1',
                expires_at=1000, signing_key='test-only-secret-not-a-deployment-key',
                ring_bytes=65536, ring_seconds=60, max_bytes=4096, max_duration_s=60,
                retention_s=86400, min_free_bytes=0,
                max_jobs=1, requests_per_hour=10, bytes_per_hour=40960,
                tenant_bytes_per_hour=40960)


def directive():
    d = dict(schema_version='capture-request.v2', mode='preserve', request_id='r1',
             tenant_id='acme', sensor_id='s1', finding_id='f1', policy_id='p1', reason='beacon',
             capture_profile='ip', value='192.0.2.1', window={'start': 80, 'end': 100},
             limits={'max_bytes': 4096, 'max_duration_s': 60, 'retention_s': 86400}, expires_at=150)
    d['authorization'] = capture_v2.sign(d, policy()['signing_key'])
    return d


HEADER = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)


def packet(ts, ip=b'\xc0\x00\x02\x01'):
    # Ethernet + IPv4 UDP, sufficiently complete for tcpdump BPF.
    data = b'\x00' * 12 + b'\x08\x00' + bytes.fromhex('4500001c0000000040110000') + ip + b'\xc0\x00\x02\x02' + b'\x00' * 8
    return struct.pack('<IIII', ts, 0, len(data), len(data)) + data


def make_ring(audit=None, p=None, clock=None):
    ring = agent.PacketRing(p or policy(), audit or (lambda _: None), clock=clock or (lambda: 100), wall=lambda: 100)
    ring.ingest(io.BytesIO(HEADER + packet(79) + packet(80) + packet(99) + packet(100)))
    return ring


class Store:
    def __init__(self):
        self.objects = {}
        self.reads = 0

    def get_bucket_versioning(self, **kw):
        return {}

    def get_bucket_lifecycle_configuration(self, **kw):
        return {'Rules': [{'Status': 'Enabled', 'Filter': {'Tag': {'Key': 'cernity-pcap', 'Value': 'v2'}},
                           'Expiration': {'Days': 1}}]}

    def put_object(self, **kw):
        self.objects[kw['Bucket'] + '/' + kw['Key']] = kw

    def get_object(self, Bucket, Key):
        self.reads += 1
        obj = self.objects[Bucket + '/' + Key]
        return {'Body': io.BytesIO(obj['Body']), 'ContentLength': len(obj['Body']), 'Metadata': obj['Metadata']}


def test_pretrigger_exact_window_mock_store_and_key():
    audit, store = [], Store()
    status = agent.preserve(directive(), make_ring(audit.append), store, audit.append, capture_v2.Budget())
    obj = store.objects[status['pcap_ref']]
    assert obj['Body'] == HEADER + packet(80) + packet(99)
    assert status['bytes'] <= 4096 and status['coverage']['selected_packets'] == 2
    assert agent.tenant_segment('acme') in status['pcap_ref']
    assert obj['ServerSideEncryption'] == 'AES256'
    assert any(e['action'] == 'pcap.upload.success' for e in audit)
    assert status['coverage']['complete'] is False


def test_ring_drops_oldest_for_bytes_and_time_even_when_idle():
    t = [100]
    ring = make_ring(clock=lambda: t[0])
    for i in range(1000):
        ring.append(i, packet(i))
    assert ring.size + 24 <= 65536
    assert ring.dropped > 0 and ring.records[-1][1] == 999
    assert ring.records[0][1] > 0
    t[0] = 161
    ring.expire()
    assert ring.size == 0 and not ring.records


def test_policy_opt_in_and_expiry():
    for change in ({'enabled': False}, {'sensitive': True}, {'expires_at': 99}):
        with pytest.raises(PermissionError):
            make_ring(p={**policy(), **change})
    ring = make_ring()
    ring.wall = lambda: 1001
    assert ring.expire() is False and not ring.records


@pytest.mark.parametrize('change', [
    {'authorization': 'a' * 64}, {'authorized': True, 'authorization': ''},
    {'tenant_id': 'other'}, {'sensor_id': 'other'}, {'expires_at': 99},
    {'window': {'start': 80, 'end': 101}}, {'value': '192.0.2.1 or host 192.0.2.2'},
])
def test_v2_rejects_forgery_or_invalid_request_before_storage(change):
    audit, store = [], Store()
    with pytest.raises((ValueError, PermissionError)):
        agent.preserve({**directive(), **change}, make_ring(), store, audit.append, capture_v2.Budget())
    assert not store.objects
    assert audit[-1]['action'] == 'pcap.preserve.failed'


def test_budget_truncation_and_exhaustion_safe():
    d = directive()
    d['limits']['max_bytes'] = 82  # header + one record
    del d['authorization']
    d['authorization'] = capture_v2.sign(d, policy()['signing_key'])
    store, budget = Store(), capture_v2.Budget()
    out = agent.preserve(d, make_ring(), store, lambda _: None, budget)
    assert out['bytes'] == 82 and out['coverage']['truncated']
    with pytest.raises(ValueError, match='duplicate'):
        agent.preserve(d, make_ring(), store, lambda _: None, budget)
    exhausted = make_ring(p={**policy(), 'bytes_per_hour': 1})
    with pytest.raises(ValueError, match='budget'):
        agent.preserve(directive(), exhausted, store, lambda _: None, capture_v2.Budget())


def test_carve_failure_does_not_upload_unfiltered_data():
    store = Store()
    def fail(*_):
        raise RuntimeError('tcpdump failed')
    with pytest.raises(RuntimeError):
        agent.preserve(directive(), make_ring(), store, lambda _: None, capture_v2.Budget(), carve=fail)
    assert not store.objects


def test_unrelated_host_not_uploaded():
    ring = make_ring()
    ring.records.clear()
    ring.size = 0
    ring.ingest(io.BytesIO(HEADER + packet(90, b'\xc6\x33\x64\x01')))
    store = Store()
    with pytest.raises(ValueError, match='empty slice'):
        agent.preserve(directive(), ring, store, lambda _: None, capture_v2.Budget())
    assert not store.objects


def test_download_auth_tenant_privilege_expiry_and_audit():
    audit, store = [], Store()
    out = agent.preserve(directive(), make_ring(), store, audit.append, capture_v2.Budget())
    tokens = {'yes': {'actor': 'analyst', 'tenant_id': 'acme', 'pcap_read': True},
              'other': {'actor': 'other', 'tenant_id': 'other', 'pcap_read': True},
              'metadata': {'actor': 'reader', 'tenant_id': 'acme', 'pcap_read': False}}
    for token in ('', 'Bearer unknown', 'Bearer other', 'Bearer metadata'):
        with pytest.raises(PermissionError):
            agent.retrieve_pcap(out['pcap_ref'], token, tokens, store, audit.append, now=101)
        assert audit[-1]['outcome'] == 'denied'
    assert store.reads == 0
    body = agent.retrieve_pcap(out['pcap_ref'], 'Bearer yes', tokens, store, audit.append, now=101)
    assert body == HEADER + packet(80) + packet(99)
    assert audit[-1]['outcome'] == 'success' and audit[-1]['actor'] == 'analyst'
    with pytest.raises(PermissionError):
        agent.retrieve_pcap(out['pcap_ref'], 'Bearer yes', tokens, store, audit.append, now=86500)
    assert audit[-1]['outcome'] == 'failed'


def test_download_fails_closed_if_audit_unavailable():
    def broken(_):
        raise OSError('audit unavailable')
    store = Store()
    ref = agent.pcap_key({'tenant_id': 'acme', 'finding_id': 'f1'})
    with pytest.raises(OSError):
        agent.retrieve_pcap(ref, 'Bearer yes', {'yes': {'tenant_id': 'acme', 'pcap_read': True}}, store, broken)
    assert store.reads == 0


def test_object_keys_differ_for_tenants():
    a = directive()
    b = copy.deepcopy(a)
    b['tenant_id'] = 'other'
    del b['authorization']
    b['authorization'] = capture_v2.sign(b, policy()['signing_key'])
    store = Store()
    agent.preserve(a, make_ring(), store, lambda _: None, capture_v2.Budget())
    agent.preserve(b, make_ring(p={**policy(), 'tenant_id': 'other'}), store, lambda _: None, capture_v2.Budget())
    assert len(store.objects) == 2


def test_parser_rejects_truncated_and_oversize():
    for stream in (HEADER + b'x', HEADER + struct.pack('<IIII', 100, 0, 10000000, 10000000)):
        with pytest.raises(ValueError):
            make_ring().ingest(io.BytesIO(stream))


def test_preserve_shell_uses_existing_result_family():
    import app
    producer, store = Mock(), Store()
    app._preserve_capture(directive(), make_ring(), producer, store, capture_v2.Budget())
    sent = [c.args for c in producer.send.call_args_list]
    result = next(value for topic, value in sent if topic == 'ndr.enrichment.result.v1')
    assert result['tenant_id'] == 'acme' and result['finding_id'] == 'f1'
    assert result['evidence_refs'][0] in store.objects
    assert not any(topic == app.ARM_TOPIC for topic, _ in sent)


def test_store_policy_required_and_versioned_bucket_refused():
    store = Store()
    store.get_bucket_lifecycle_configuration = lambda **_: {'Rules': []}
    with pytest.raises(PermissionError, match='lifecycle'):
        agent.preserve(directive(), make_ring(), store, lambda _: None, capture_v2.Budget())
    assert not store.objects
    store = Store()
    store.get_bucket_versioning = lambda **_: {'Status': 'Enabled'}
    with pytest.raises(PermissionError, match='nonversioned'):
        agent.preserve(directive(), make_ring(), store, lambda _: None, capture_v2.Budget())
    assert not store.objects


def test_store_upload_failure_releases_concurrency_but_keeps_hourly_charge():
    store, budget = Store(), capture_v2.Budget()
    def fail(**_):
        raise OSError('store unavailable')
    store.put_object = fail
    with pytest.raises(OSError):
        agent.preserve(directive(), make_ring(), store, lambda _: None, budget)
    reservation = next(iter(budget.entries.values()))
    assert reservation['active'] is False and reservation['bytes'] == 4096


def test_low_disk_refuses_and_does_not_touch_objects(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, 'disk_usage', lambda _: type('Disk', (), {'free': 0})())
    store = Store()
    with pytest.raises(ValueError, match='disk free'):
        agent.preserve(directive(), make_ring(), store, lambda _: None, capture_v2.Budget())
    assert not store.objects


def test_persisted_quota_survives_restart(tmp_path):
    path = str(tmp_path / 'budget.json')
    budget = capture_v2.Budget(clock=lambda: 100, state_path=path)
    budget.reserve(directive(), policy())
    budget.finish(directive())
    restored = capture_v2.Budget(clock=lambda: 101, state_path=path)
    with pytest.raises(ValueError, match='duplicate'):
        restored.reserve(directive(), policy())
    assert next(iter(restored.entries.values()))['bytes'] == 4096
    # Expired hourly reservations become admissible again (request expiry is
    # separately enforced before reserve is called in either runtime).
    later = capture_v2.Budget(clock=lambda: 3701, state_path=path)
    later.reserve(directive(), policy())


def test_http_adapter_calls_authenticated_audited_reader():
    import retrieval
    store, audit = Store(), []
    out = agent.preserve(directive(), make_ring(), store, audit.append, capture_v2.Budget())
    # Move logical expiry forward for the adapter's real wall clock.
    store.objects[out['pcap_ref']]['Metadata']['expires-at'] = '9999999999'
    tokens = {'yes': {'tenant_id': 'acme', 'actor': 'analyst', 'pcap_read': True}}
    handler_type = retrieval.make_handler(store, tokens, audit.append)
    for token, expected in (('', 403), ('Bearer yes', 200)):
        handler = object.__new__(handler_type)
        handler.path = '/pcap/' + out['pcap_ref']
        handler.headers = {'Authorization': token}
        handler.wfile = io.BytesIO()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.do_GET()
        handler.send_response.assert_called_once_with(expected)
        assert audit[-1]['outcome'] == ('success' if expected == 200 else 'denied')


def test_download_detects_object_corruption():
    audit, store = [], Store()
    status = agent.preserve(directive(), make_ring(), store, audit.append, capture_v2.Budget())
    store.objects[status['pcap_ref']]['Body'] += b'tampered'
    with pytest.raises(ValueError, match='digest'):
        agent.retrieve_pcap(status['pcap_ref'], 'Bearer yes',
                            {'yes': {'actor': 'a', 'tenant_id': 'acme', 'pcap_read': True}},
                            store, audit.append, now=101)
    assert audit[-1]['outcome'] == 'failed'


def test_closed_ring_cannot_accept_or_preserve_late_packets():
    ring = make_ring()
    ring.close()
    assert not ring.records and ring.size == 0
    assert not ring.append(99, packet(99))
    assert ring.slice(80, 100, 4096)[1]['selected_packets'] == 0


def test_elapsed_window_is_not_extended_by_wall_clock_rollback():
    t = [100]
    ring = make_ring(clock=lambda: t[0])
    ring.wall = lambda: 1
    t[0] = 161
    ring.expire()
    assert not ring.records
