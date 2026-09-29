"""Exercise the service I/O path with deterministic broker/ClickHouse doubles."""
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

HERE = Path(__file__).parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def service(monkeypatch):
    monkeypatch.setenv('CLICKHOUSE_PASSWORD', 'test')
    monkeypatch.setitem(sys.modules, 'models', load('u4_emit_models', HERE / 'models.py'))
    monkeypatch.setitem(sys.modules, 'clickhouse_connect', SimpleNamespace(get_client=Mock()))
    return load('u4_normalizer_app', HERE / 'app.py')


def row(service):
    return service.models.observation(
        {'event_type': 'flow', 'timestamp': '2026-09-28T12:00:00Z',
         'src_ip': '10.0.0.1', 'flow': {'bytes_toserver': 1}}, 'a', 's',
        topic='suricata.flow.v1', partition=0, offset=2,
        ingested_at='2026-09-28T12:00:01Z')[1]


def test_insert_before_publish_with_source_resolvable(service):
    stored = {}
    def insert(table, data, column_names):
        stored[table] = dict(zip(column_names, data[0]))
    def send(topic, key, value):
        assert topic == 'ndr.observation.normalized.v1'
        assert json.loads(key) == ['a', '10.0.0.1']
        ref = value['source_ref']
        source = stored[ref['table']]
        assert json.loads(source['observation'])['obs_id'] == ref['obs_id']
        assert json.loads(source['raw_record'])['flow']['bytes_toserver'] == 1
        return Mock()
    buffers = {'network_flow': [row(service)]}
    service.flush(SimpleNamespace(insert=insert), buffers, SimpleNamespace(send=send))
    assert buffers == {}


@pytest.mark.parametrize('failure', ['insert', 'publish', 'ack'])
def test_failed_delivery_retains_buffer(service, failure):
    ch, producer = Mock(), Mock()
    if failure == 'insert':
        ch.insert.side_effect = RuntimeError('unavailable')
    elif failure == 'publish':
        producer.send.side_effect = RuntimeError('unavailable')
    else:
        producer.send.return_value.get.side_effect = RuntimeError('unavailable')
    buffers = {'network_flow': [row(service)]}
    with pytest.raises(RuntimeError):
        service.flush(ch, buffers, producer)
    assert buffers
    if failure == 'insert':
        producer.send.assert_not_called()


@pytest.mark.parametrize('fail_publish', [False, True])
def test_main_commits_only_after_storage_and_ack(service, monkeypatch, fail_publish):
    calls = []
    record = SimpleNamespace(value=json.loads(row(service)['raw_record']), timestamp=1790596801000,
                             timestamp_type=1, topic='suricata.flow.v1', partition=0, offset=2)
    consumer = Mock()
    def poll(**kwargs):
        service._running = False
        return {0: [record]}
    consumer.poll.side_effect = poll
    consumer.commit.side_effect = lambda: calls.append('commit')
    ch = Mock()
    ch.insert.side_effect = lambda *a, **kw: calls.append('insert')
    producer = Mock()
    def ack(**kwargs):
        calls.append('ack')
        if fail_publish:
            raise RuntimeError('failed ack')
    producer.send.return_value.get.side_effect = ack
    def make_consumer(*args, **kwargs):
        assert kwargs['enable_auto_commit'] is False
        assert 'suricata.http.v1' in args
        return consumer
    monkeypatch.setattr(service.ndr_runtime, 'make_consumer', make_consumer)
    monkeypatch.setattr(service.ndr_runtime, 'make_producer', lambda **kw: producer)
    monkeypatch.setattr(service.ndr_runtime, 'start_health', lambda: None)
    monkeypatch.setattr(service.clickhouse_connect, 'get_client', lambda **kw: ch)
    monkeypatch.setattr(service.signal, 'signal', lambda *a: None)
    if fail_publish:
        with pytest.raises(RuntimeError):
            service.main()
        assert calls == ['insert', 'ack']
    else:
        service.main()
        assert calls == ['insert', 'ack', 'commit']


def test_create_time_is_not_claimed_as_ingest_time(service, monkeypatch):
    consumer = Mock()
    record = SimpleNamespace(timestamp=123, timestamp_type=0)
    consumer.poll.return_value = {0: [record]}
    monkeypatch.setattr(service.ndr_runtime, 'make_consumer', lambda *a, **kw: consumer)
    monkeypatch.setattr(service.ndr_runtime, 'make_producer', lambda **kw: Mock())
    monkeypatch.setattr(service.ndr_runtime, 'start_health', lambda: None)
    monkeypatch.setattr(service.signal, 'signal', lambda *a: None)
    with pytest.raises(RuntimeError, match='LogAppendTime'):
        service.main()
    consumer.commit.assert_not_called()
