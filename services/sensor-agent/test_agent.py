"""Deterministic collector/heartbeat tests; no broker or capture agent needed."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


a = load('sensor_health_agent', Path(__file__).with_name('agent.py'))
c = load('sensor_health_contract', ROOT / 'contracts/test_sensor_health.py')


def tracking(correction='0.0125', leap='Normal', refid='C000027B'):
    return f'{refid},192.0.2.123,3,1790553600,{correction},-0.99,0.001,0,0,0,0.01,0.001,64,{leap}\n'


def test_measured_clock_delta_sign_and_source():
    for raw, expected in [('0.0125', -12.5), ('-0.025', 25), ('0', 0)]:
        def run(command, **kwargs):
            assert command == ['chronyc', '-c', '-h', '127.0.0.1', 'tracking']
            assert kwargs['timeout'] == 2 and kwargs['check']
            return SimpleNamespace(stdout=tracking(raw))
        measurement = a.clock_measurement(run)
        assert measurement == {'clock_offset_ms': expected, 'time_source': '192.0.2.123',
                               'clock_status': 'synchronized'}


def test_clock_failure_does_not_claim_zero():
    for output in ('garbage', tracking(leap='Not synchronised'), tracking('nan'),
                   tracking('inf'), tracking(refid='7F7F0101')):
        assert a.clock_measurement(lambda *_, **kw: SimpleNamespace(stdout=output)) == {
            'clock_offset_ms': None, 'time_source': None, 'clock_status': 'unavailable'}
    for error in (FileNotFoundError(), subprocess.TimeoutExpired('chronyc', 2),
                  subprocess.CalledProcessError(1, 'chronyc')):
        def fail(*_, **kw):
            raise error
        assert a.clock_measurement(fail)['clock_offset_ms'] is None


def make_agent(**kwargs):
    return a.Agent(c.FULL['sensor_uuid'], 'acme', 'dc1',
                   clock=lambda: a.clock_measurement(lambda *_, **kw: SimpleNamespace(stdout=tracking())),
                   **kwargs)


def test_no_capture_service_heartbeat_validates():
    record = make_agent().heartbeat()
    c.VALIDATOR.validate(record)
    assert record['capture']['kernel_drops_total'] is None
    assert record['clock_offset_ms'] == -12.5
    assert record['schema_version'] == 'sensor-health.v1'


class Stop:
    def __init__(self, count=3):
        self.now, self.waits, self.count = 0, [], count

    def is_set(self):
        return len(self.waits) >= self.count

    def wait(self, seconds):
        self.waits.append(seconds)
        self.now += seconds


def test_heartbeat_interval_recovery_and_ack_state():
    stop, records, sent_at = Stop(), [], []
    agent = make_agent()
    def publish(record):
        records.append(record)
        sent_at.append(stop.now)
        if len(records) == 1:
            raise OSError('bus unavailable')
    agent.run(publish, stop, interval=7, monotonic=lambda: stop.now)
    assert sent_at == [0, 7, 14]
    assert [r['connectivity']['bus'] for r in records] == ['unknown', 'disconnected', 'connected']
    assert all(r['clock_offset_ms'] == -12.5 for r in records)


def test_interval_validation_and_slow_publish():
    agent = make_agent()
    for value in (0, -1, float('nan'), float('inf')):
        try:
            agent.run(lambda _: None, Stop(), value)
        except ValueError:
            continue
        raise AssertionError('invalid interval accepted')
    stop = Stop(2)
    def publish(_):
        stop.now += 12
    agent.run(publish, stop, interval=5, monotonic=lambda: stop.now)
    assert stop.waits == [3, 3]


def test_resources_are_measured():
    with tempfile.TemporaryDirectory() as tmp:
        proc = Path(tmp)
        (proc / 'stat').write_text('cpu  10 0 10 80 0 0 0 0 0 0\n')
        (proc / 'meminfo').write_text('MemTotal: 1000 kB\nMemAvailable: 250 kB\n')
        resources = a.Resources(proc, tmp)
        first = resources.sample()
        assert first['cpu_pct'] is None
        assert first['mem_pct'] == 75
        assert first['disk_free_bytes'] > 0
        (proc / 'stat').write_text('cpu  30 0 10 100 0 0 0 0 0 0\n')
        assert resources.sample()['cpu_pct'] == 50


def test_eve_rates_partial_rotation_and_overflow():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'eve.json'
        path.write_bytes(b'')
        eve = a.EveRates([path], max_bytes=40)
        assert eve.sample(0)['events_per_second'] is None
        path.write_bytes(b'{}\n{}\n{')
        assert eve.sample(2) == {'events_per_second': 1, 'bytes_per_second': 3}
        with path.open('ab') as stream:
            stream.write(b'}\n')
        assert eve.sample(4) == {'events_per_second': 0.5, 'bytes_per_second': 1.5}
        path.rename(Path(tmp) / 'old.json')
        path.write_bytes(b'{}\n')
        assert eve.sample(6)['events_per_second'] is None
        path.write_bytes(b'{}\n' * 20)
        assert eve.sample(8)['events_per_second'] is None
        path.unlink()
        assert eve.sample(10)['events_per_second'] is None


def test_supplemental_metrics_fresh_stale_and_invalid():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'metrics.json'
        data = {'observed_at_unix': 100, 'capture': {'kernel_drops_total': 4},
                'shipper': {'queue_depth': 7, 'oldest_unsent_age_s': 2}}
        path.write_text(json.dumps(data))
        assert a.supplemental_metrics(path, 120)['capture']['kernel_drops_total'] == 4
        assert a.supplemental_metrics(path, 120)['shipper']['queue_depth'] == 7
        assert a.supplemental_metrics(path, 170) == a.empty_metrics()
        assert a.supplemental_metrics(path, 90) == a.empty_metrics()
        path.write_text('{broken')
        assert a.supplemental_metrics(path, 120) == a.empty_metrics()
        data['shipper']['queue_depth'] = -2
        path.write_text(json.dumps(data))
        assert a.supplemental_metrics(path, 120)['shipper']['queue_depth'] is None


def test_compose_agent_is_mandatory_and_topic_permitted():
    text = (ROOT / 'deploy/sensor/docker-compose.yml').read_text()
    block = text.split('\n  sensor-agent:\n')[1].split('\n  capture-agent:\n')[0]
    assert 'profiles:' not in block
    assert 'network_mode: host' in block
    assert 'NDR_SENSOR_UUID:' in block and 'NDR_SITE:' in block
    assert '--topic ndr.sensor.health.v1 --resource-pattern-type literal' in (
        ROOT / 'deploy/central/redpanda/entrypoint.sh').read_text()




def test_app_publishes_tenant_key_and_waits_for_ack():
    import sys
    from unittest.mock import Mock

    runtime = load('sensor_health_runtime', ROOT / 'shared/ndr_runtime.py')
    with patch.dict(sys.modules, {'agent': a, 'ndr_runtime': runtime}):
        app = load('sensor_health_app', Path(__file__).with_name('app.py'))
    stop = Stop(1)
    producer = Mock()
    factory = Mock(return_value=producer)
    env = {'NDR_SENSOR_UUID': c.FULL['sensor_uuid'], 'NDR_TENANT': 'acme',
           'NDR_SITE': 'dc1', 'SENSOR_HEARTBEAT_SECONDS': '7'}
    with patch.dict('os.environ', env, clear=True), \
            patch.object(app, 'make_producer', factory), \
            patch.object(app, 'setup_logging'), \
            patch.object(app.signal, 'signal'), \
            patch.object(app.threading, 'Event', return_value=stop):
        app.main()
    args, kwargs = producer.send.call_args
    assert args == ('ndr.sensor.health.v1',)
    assert json.loads(kwargs['key']) == ['acme', c.FULL['sensor_uuid']]
    c.VALIDATOR.validate(kwargs['value'])
    producer.send.return_value.get.assert_called_once_with(timeout=5)
    producer.close.assert_called_once_with(timeout=5)
    assert factory.call_args.kwargs['acks'] == 'all'
    encoded = factory.call_args.kwargs['value_serializer'](kwargs['value'])
    assert json.loads(encoded) == kwargs['value']


def test_eve_startup_partial_record_not_counted():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'eve.json'
        path.write_bytes(b'{"event_')
        eve = a.EveRates([path])
        eve.sample(0)
        with path.open('ab') as stream:
            stream.write(b'type":"flow"}\n{}\n')
        assert eve.sample(2) == {'events_per_second': 0.5, 'bytes_per_second': 1.5}


if __name__ == '__main__':
    for name, fn in list(globals().items()):
        if name.startswith('test_'):
            fn()
