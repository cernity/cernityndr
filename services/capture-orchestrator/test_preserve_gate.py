"""U6 local gate and v1/v2 coexistence; mocked publication, no live bus claim."""
import importlib.util
from pathlib import Path
from unittest.mock import Mock
import pytest
import gates
import capture_v2


# Both capture services have app.py; a bare import can reuse the agent's cached
# module when pytest collects both suites in one process. Keep this load local
# and uniquely named without replacing sys.modules['app'] for the agent tests.
_spec = importlib.util.spec_from_file_location(
    'capture_orchestrator_preserve_app', Path(__file__).with_name('app.py'))
app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(app)


def policy(tenant='acme', sensor='s1'):
    return dict(enabled=True, sensitive=False, tenant_id=tenant, sensor_id=sensor,
                policy_id='p1', expires_at=1000, signing_key='test-only-key-long-enough-for-unit-tests',
                ring_seconds=120, max_bytes=4096, max_duration_s=120, retention_s=86400,
                lookback_s=60, max_jobs=2, requests_per_hour=2, bytes_per_hour=8192,
                tenant_bytes_per_hour=8192, max_loss_pct=1, max_cpu_pct=85)


REQ = {'tenant_id': 'acme', 'sensor_id': 's1', 'finding_id': 'f1', 'capture_profile': 'ip', 'value': '192.0.2.1'}
HEALTH = {'measured': True, 'cpu_pct': 10, 'packet_loss_pct': 0}


def test_preserve_gate_signs_only_policy_authorized_request():
    doc = gates.decide_preserve(REQ, policy(), HEALTH, capture_v2.Budget(), 100)
    assert doc['schema_version'] == 'capture-request.v2'
    assert doc['window'] == {'start': 40, 'end': 100}
    capture_v2.authorize(doc, policy(), 100)


@pytest.mark.parametrize('change', [{'enabled': False}, {'sensitive': True}, {'tenant_id': 'other'},
                                    {'sensor_id': 'other'}, {'expires_at': 99}])
def test_policy_denial(change):
    with pytest.raises(PermissionError):
        gates.decide_preserve(REQ, {**policy(), **change}, HEALTH, capture_v2.Budget(), 100)


def test_unmeasured_or_unhealthy_refused():
    for health in ({'measured': False}, {**HEALTH, 'cpu_pct': 99}):
        with pytest.raises(PermissionError):
            gates.decide_preserve(REQ, policy(), health, capture_v2.Budget(), 100)


def test_budget_tenant_aggregate_and_hour_rollover():
    now = [0]
    budget = capture_v2.Budget(clock=lambda: now[0])
    a = gates.decide_preserve(REQ, policy(), HEALTH, budget, 100)
    budget.finish(a)
    b = gates.decide_preserve({**REQ, 'sensor_id': 's2'}, policy(sensor='s2'), HEALTH, budget, 100)
    budget.finish(b)
    with pytest.raises(ValueError, match='budget'):
        gates.decide_preserve({**REQ, 'sensor_id': 's3'}, policy(sensor='s3'), HEALTH, budget, 100)
    now[0] = 3601
    gates.decide_preserve({**REQ, 'sensor_id': 's3'}, policy(sensor='s3'), HEALTH, budget, 100)


def test_v1_remains_arm_v1_and_opt_in_emits_v2(monkeypatch):
    monkeypatch.setattr(app, 'PRESERVE_POLICIES', {})
    monkeypatch.setattr(app, '_budget', {})
    producer = Mock()
    app._handle_request(REQ, producer)
    assert any(c.args[0] == app.ARM_TOPIC for c in producer.send.call_args_list)
    monkeypatch.setattr(app, 'PRESERVE_POLICIES', {'s1': policy()})
    monkeypatch.setattr(app, 'probe_health', lambda _: HEALTH)
    monkeypatch.setattr(app.time, 'time', lambda: 100)
    monkeypatch.setattr(app, '_preserve_budget', capture_v2.Budget())
    producer.reset_mock()
    app._handle_request(REQ, producer)
    sent = [c.args for c in producer.send.call_args_list]
    assert [t for t, _ in sent] == [capture_v2.TOPIC]
    capture_v2.authorize(sent[0][1], policy(), 100)
    # v2 status does not decrement a v1 arm's concurrency reservation.
    app._handle_completion({**sent[0][1], 'state': 'completed', 'kind': 'preserve'})
    assert app._budget['s1']['active_jobs'] == 1
    assert not next(iter(app._preserve_budget.entries.values()))['active']


def test_explicit_preserve_never_downgrades_to_unauthorized_v1(monkeypatch):
    monkeypatch.setattr(app, 'PRESERVE_POLICIES', {})
    producer = Mock()
    app._handle_request({**REQ, 'mode': 'preserve', 'authorized': True}, producer)
    sent = [c.args for c in producer.send.call_args_list]
    assert len(sent) == 1 and sent[0][0] == app.STATUS_TOPIC
    assert sent[0][1]['state'] == 'refused'


def test_completion_duplicate_is_idempotent():
    budget = capture_v2.Budget()
    doc = gates.decide_preserve(REQ, policy(), HEALTH, budget, 100)
    budget.finish(doc)
    budget.finish(doc)
    with pytest.raises(ValueError, match='duplicate'):
        gates.decide_preserve(REQ, policy(), HEALTH, budget, 100)


def test_real_snapshot_adapter_refuses_stale_wrong_tenant_missing_fields(tmp_path, monkeypatch):
    import json
    path = tmp_path / 'health.json'
    monkeypatch.setenv('PCAP_HEALTH_SNAPSHOT', str(path))
    monkeypatch.setattr(app, 'PRESERVE_POLICIES', {'s1': policy()})
    monkeypatch.setattr(app.time, 'time', lambda: 100)
    row = {**HEALTH, 'observed_at': 90, 'tenant_id': 'acme'}
    path.write_text(json.dumps({'s1': row}))
    assert app.probe_health('s1')['measured'] is True
    for change in ({'observed_at': 1}, {'tenant_id': 'other'}, {'cpu_pct': None}, {'packet_loss_pct': float('nan')}):
        path.write_text(json.dumps({'s1': {**row, **change}}))
        assert app.probe_health('s1')['measured'] is False


def test_invalid_health_and_nan_policy_fail_closed():
    for health in ({'measured': True}, {**HEALTH, 'cpu_pct': float('nan')}):
        with pytest.raises(PermissionError):
            gates.decide_preserve(REQ, policy(), health, capture_v2.Budget(), 100)
    with pytest.raises(PermissionError):
        gates.decide_preserve(REQ, {**policy(), 'expires_at': float('nan')}, HEALTH, capture_v2.Budget(), 100)
