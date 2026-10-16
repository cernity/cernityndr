"""Tests for protocol-anomaly promotion (G4)."""
import anomaly as a

APPLAYER = {"event_type": "anomaly", "src_ip": "10.0.0.5", "dest_ip": "1.2.3.4",
            "app_proto": "http", "anomaly": {"type": "applayer", "event": "http.unexpected_data"}}
STREAM_EVASION = {"event_type": "anomaly", "src_ip": "a", "dest_ip": "b",
                  "anomaly": {"type": "stream", "event": "stream.reassembly_overlap_different_data"}}
DECODE_NOISE = {"event_type": "anomaly", "src_ip": "a", "dest_ip": "b",
                "anomaly": {"type": "decode", "event": "decoder.udp.invalid_checksum"}}
FLOW = {"event_type": "flow"}


def test_promotes_applayer_anomaly():
    c = a.to_candidate(APPLAYER)
    assert c and c["detector_id"] == "protocol_anomaly" and c["category"] == "anomaly"
    assert "http.unexpected_data" in c["entities"]


def test_promotes_stream_evasion():
    assert a.to_candidate(STREAM_EVASION) is not None


def test_suppresses_decode_noise():
    assert a.to_candidate(DECODE_NOISE) is None
    assert a.is_threat_anomaly(DECODE_NOISE["anomaly"]) is False


def test_ignores_non_anomaly():
    assert a.to_candidate(FLOW) is None


def test_candidate_is_schema_complete_and_deterministic():
    # F13: schema-required first_seen/last_seen present (were missing). F07 cross-process
    # id stability is proven by the shared _stable() pattern (see ids-alerts subprocess test).
    import json, os, pathlib
    _here = pathlib.Path(__file__).resolve()
    _cands = ([pathlib.Path(os.environ["CERNITY_FINDING_SCHEMA"])]
              if os.environ.get("CERNITY_FINDING_SCHEMA") else [])
    _cands += [pp / "contracts" / "finding.schema.json" for pp in _here.parents]
    req = json.loads(next(c for c in _cands if c.is_file()).read_text())["required"]
    c = a.to_candidate(APPLAYER)
    assert all(k in c for k in req), [k for k in req if k not in c]
    assert c["finding_id"] == a.to_candidate(APPLAYER)["finding_id"]


from features import FeatureExtractor, iso


def observation(window, host=1, value=10000, tenant='a', suffix=''):
    return {'schema': 'cernity.observation.v1', 'type': 'conn',
            'tenant': tenant, 'sensor_id': 'sensor',
            'obs_id': f'obs:{tenant}:{window}:{host}:{suffix}',
            'ts': {'normalized': iso(window * 300 + 1), 'method': 'ingest-fallback'},
            'entities': [{'type': 'ip', 'role': 'src', 'value': f'10.0.0.{host}'}],
            'fields': {'src_ip': f'10.0.0.{host}',
                       'flow': {'bytes_toserver': value, 'bytes_toclient': 999999999}}}


def run_window(extractor, model, window, values, tenant='a'):
    for host, value in values.items():
        extractor.add(observation(window, host, value, tenant))
    return model.evaluate(extractor.close((window + 1) * 300))


def trained():
    extractor, model = FeatureExtractor(), a.OutboundBytesModel()
    for w in range(5):
        assert not run_window(extractor, model, w, {1: 10000, 2: 11000, 3: 9000})
    return extractor, model


def test_spike_explanation_and_finding_contract():
    import jsonschema
    import json
    from pathlib import Path
    ex, model = trained()
    findings = run_window(ex, model, 5, {1: 1000000, 2: 10000, 3: 10000})
    assert len(findings) == 1
    c = findings[0]
    jsonschema.validate(c, json.loads((Path(__file__).resolve().parents[2] / 'contracts/finding.schema.json').read_text()))
    e = c['summary']['anomaly']
    assert e['features']['bytes_out'] == 1000000
    assert e['entity_baseline']['median'] == 10000
    assert e['peer_baseline']['median'] == 10000
    assert e['cohort']['peer_members'] == ['10.0.0.2', '10.0.0.3']
    assert e['cohort']['subnet'] == '10.0.0.0/24'
    assert e['model']['version'] == model.VERSION
    assert all(z > e['threshold'] for z in e['deviations'].values())
    assert e['entity_baseline']['trained_to'] == iso(1500)
    assert c['evidence_refs'] == ['obs:a:5:1:']


def test_cold_start_peer_only_lower_confidence():
    ex, model = trained()
    c = run_window(ex, model, 5, {4: 1000000})[0]
    assert c['confidence'] < 0.8
    e = c['summary']['anomaly']
    assert e['mode'] == 'peer-only-cold-start'
    assert not e['entity_baseline']['available']
    assert e['peer_baseline']['available']


def test_benign_control_fixture_stays_quiet():
    ex, model = FeatureExtractor(), a.OutboundBytesModel()
    for w in range(30):
        assert not run_window(ex, model, w, {h: 10000 + ((w + h) % 5) * 100 for h in range(1, 6)})


def test_requires_both_baselines_when_warm():
    ex, model = FeatureExtractor(), a.OutboundBytesModel()
    for w in range(5):
        run_window(ex, model, w, {1: 10000, 2: 1000000, 3: 1000000})
    assert not run_window(ex, model, 5, {1: 1000000})


def test_no_peer_support_no_alert_and_tenant_isolation():
    ex, model = trained()
    assert not run_window(ex, model, 5, {1: 1000000}, tenant='other')
    ex, model = FeatureExtractor(), a.OutboundBytesModel()
    for w in range(5):
        run_window(ex, model, w, {1: 10000})
    assert not run_window(ex, model, 5, {1: 1000000})


def test_dedup_aggregation_and_late_drop():
    ex = FeatureExtractor()
    obs = observation(0)
    ex.add(obs); ex.add(obs)
    ex.add(observation(0, value=5000, suffix='second'))
    assert not ex.close(299)
    row = ex.close(300)[0]
    assert row['bytes_out'] == 15000
    assert len(row['evidence_refs']) == 2
    ex.add(obs)
    assert ex.late_observations == 1
    assert not ex.close(600)


def test_missing_invalid_and_non_conn_counters_are_not_zero():
    ex = FeatureExtractor()
    for value in (None, -1, True, '100', float('inf')):
        ex.add(observation(0, value=value))
    obs = observation(0); obs['type'] = 'dns'; ex.add(obs)
    assert not ex.close(300)


def test_rolling_history_expires_and_no_current_window_leakage():
    ex, model = trained()
    assert not run_window(ex, model, 500, {1: 1000000, 2: 1000000, 3: 1000000})
    assert len(model.history) == 3


def test_order_independent_and_subnet_isolation():
    ex, model = trained()
    obs = observation(5, 4, 1000000)
    obs['fields']['src_ip'] = '10.1.0.4'
    obs['entities'][0]['value'] = '10.1.0.4'
    ex.add(obs)
    assert not model.evaluate(ex.close(1800))
    ex1, m1 = trained(); ex2, m2 = trained()
    assert run_window(ex1, m1, 5, {1: 1000000, 2: 10000}) == run_window(ex2, m2, 5, {2: 10000, 1: 1000000})


def test_service_consumes_observations_and_publishes_explained_candidate(monkeypatch):
    import app
    from types import SimpleNamespace
    records = [SimpleNamespace(topic='ndr.observation.normalized.v1',
                               value=observation(w, h, 1000000 if w == 5 and h == 1 else 10000))
               for w in range(6) for h in range(1, 4)]
    records.append(SimpleNamespace(topic='suricata.anomaly.v1', value=APPLAYER))
    sent, subscriptions = [], []

    class Consumer:
        first = True

        def poll(self, **kwargs):
            if self.first:
                self.first = False
                return {0: records}
            app._running = False
            return {}

        def close(self):
            pass

    class Producer:
        def send(self, topic, candidate):
            sent.append((topic, candidate))
            return SimpleNamespace(get=lambda **kwargs: None)

        def flush(self):
            pass

        def close(self):
            pass

    def consumer(*topics, **kwargs):
        subscriptions.extend(topics)
        return Consumer()

    monkeypatch.setattr(app.ndr_runtime, 'make_consumer', consumer)
    monkeypatch.setattr(app.ndr_runtime, 'make_producer', Producer)
    monkeypatch.setattr(app.ndr_runtime, 'start_health', lambda: None)
    monkeypatch.setattr(app.signal, 'signal', lambda *args: None)
    monkeypatch.setattr(app.time, 'time', lambda: 2100)
    monkeypatch.setattr(app, '_running', True)
    monkeypatch.setattr(app, '_emitted', set())
    monkeypatch.setenv('FEATURE_WINDOW_SECS', '300')
    monkeypatch.setenv('FEATURE_LATENESS_SECS', '60')
    app.main()
    assert subscriptions == ['suricata.anomaly.v1', 'ndr.observation.normalized.v1']
    assert {c['detector_id'] for _, c in sent} == {'protocol_anomaly', 'outbound_bytes_anomaly'}
    assert all(topic == app.CANDIDATE_TOPIC for topic, _ in sent)
    assert next(c for _, c in sent if c['detector_id'] == 'outbound_bytes_anomaly')['summary']['anomaly']['features']['bytes_out'] == 1000000


def test_single_outlier_does_not_shift_robust_center():
    ex, model = trained()
    run_window(ex, model, 5, {1: 1000000000, 2: 10000, 3: 10000})
    c = run_window(ex, model, 6, {1: 1000000})[0]
    assert c['summary']['anomaly']['entity_baseline']['median'] == 10000


from store import InMemoryStore, RedisStore
import os
import json


def rows_at(window, values=None, tenant='a'):
    ex = FeatureExtractor()
    for host, value in (values or {1: 10000, 2: 11000, 3: 9000}).items():
        ex.add(observation(window, host, value, tenant))
    return ex.close((window + 1) * 300)


def test_external_parity_restart_replicas_and_isolation():
    stores = [InMemoryStore(clock=lambda: 1800)]
    if os.environ.get('NDR_TEST_REDIS_URL'):
        redis = RedisStore(os.environ['NDR_TEST_REDIS_URL'])
        redis._r.flushdb()
        stores.append(redis)
    for store in stores:
        # Redis uses wall time; offset the fixture, keeping identical input on both paths.
        base = int(a.time.time() // 300) - 10 if isinstance(store, RedisStore) else 0
        clock = a.time.time if isinstance(store, RedisStore) else lambda: 1800
        local = a.OutboundBytesModel()
        model = a.OutboundBytesModel(store=store, clock=clock)
        for w in range(base, base + 5):
            batch = rows_at(w)
            assert model.evaluate(batch) == local.evaluate(batch) == []
        if isinstance(store, RedisStore):
            store = RedisStore(os.environ['NDR_TEST_REDIS_URL'])
        model = a.OutboundBytesModel(store=store, clock=clock)
        spike = rows_at(base + 5, {1: 1000000, 2: 10000, 3: 10000})
        expected = local.evaluate(spike)
        assert expected
        assert json.dumps(model.evaluate(spike), sort_keys=True) == json.dumps(expected, sort_keys=True)
        replica = a.OutboundBytesModel(store=store, clock=clock)
        # Another replica already learned this entire window; none of it may leak.
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda m: m.evaluate(list(reversed(spike))),
                                    [model, replica]))
        assert results == [expected, expected]
        assert len(store.keys_matching(model.history_prefix(spike[0]))) == 18
        explanation = expected[0]['summary']['anomaly']
        assert explanation['cohort']['peer_members'] == ['10.0.0.2', '10.0.0.3']
        assert explanation['peer_baseline']['samples'] == 10
        assert explanation['entity_baseline']['samples'] == 5
        assert not replica.evaluate(rows_at(base + 5, {1: 1000000}, tenant='other'))
        # Keep the existing 24h scoring window even though the archive is multi-week.
        assert not replica.evaluate(rows_at(base + 500, {1: 1000000}))


def test_service_external_history_wiring(monkeypatch):
    import store as store_module
    from types import SimpleNamespace
    memory = InMemoryStore(clock=lambda: 2100)
    pings, urls = [], []
    memory._r = SimpleNamespace(ping=lambda: pings.append(True))
    def connect(url):
        urls.append(url)
        return memory
    original = a.OutboundBytesModel
    monkeypatch.setattr(store_module, 'RedisStore', connect)
    monkeypatch.setattr(a, 'OutboundBytesModel',
                        lambda **kw: original(clock=lambda: 2100, **kw))
    monkeypatch.setenv('OUTBOUND_HISTORY_STORE', '1')
    monkeypatch.setenv('OUTBOUND_HISTORY_REDIS_URL', 'redis://history/0')
    test_service_consumes_observations_and_publishes_explained_candidate(monkeypatch)
    assert urls == ['redis://history/0'] and pings == [True]
    assert len(memory.keys_matching('ob:v1:')) == 18


def test_external_retention_and_replay_do_not_extend_expiry():
    now = [300.0]
    store = InMemoryStore(clock=lambda: now[0])
    model = a.OutboundBytesModel(store=store, clock=lambda: now[0])
    oldest = rows_at(0)
    model.evaluate(oldest)
    now[0] = 14 * 86400
    model.evaluate(rows_at(int(now[0] // 300)))
    prefix = model.history_prefix(oldest[0])
    assert len(store.keys_matching(prefix)) == 6
    model.evaluate(oldest)  # redelivery two weeks later must not reset the TTL
    now[0] = 28 * 86400 + 299
    assert len(store.keys_matching(prefix)) == 6
    now[0] += 1
    assert len(store.keys_matching(prefix)) == 3
    store.kv_prune()
    assert len(store._kv) == 3
    model.evaluate(oldest)  # expired event-time rows cannot be resurrected
    assert len(store.keys_matching(prefix)) == 3


def test_external_degenerate_histories():
    class EmptyStore(InMemoryStore):
        def keys_matching(self, prefix):
            return []
    for store in (InMemoryStore(clock=lambda: 0), EmptyStore(clock=lambda: 0)):
        model = a.OutboundBytesModel(store=store, clock=lambda: 0)
        assert model.evaluate([]) == []
        assert model.score(rows_at(0)[0]) is None
        assert not model.evaluate(rows_at(0, {1: 0}))
        for w in range(1, 5):
            assert not model.evaluate(rows_at(w, {1: 1000000}))
    model = a.OutboundBytesModel(store=InMemoryStore(clock=lambda: 0), clock=lambda: 0)
    for w in range(5):
        assert not model.evaluate(rows_at(w, {1: 0, 2: 0, 3: 0}))


def test_external_row_volume_bound():
    # Derived load: 100 active entities, one conn/s each, one row/300s/entity.
    # Four weeks = 806,400 keys; a rolling extra day must not raise this ceiling.
    now = [0.0]
    store = InMemoryStore(clock=lambda: now[0])
    horizon = 28 * 86400
    sample = rows_at(0)[0]
    compact = {k: sample[k] for k in ('tenant', 'cohort', 'entity', 'start', 'end', 'bytes_out')}
    for window in range(29 * 288):
        now[0] = (window + 1) * 300
        for entity in range(100):
            store.kv_set_once(f'ob:volume:{window}:{entity}', compact, horizon)
        if window % 288 == 287:
            store.kv_prune()
            assert len(store._kv) <= 806400
    assert len(store.keys_matching('ob:volume:')) == 806400
    print('volume: 100 conn/s, 100 entities, 28 days: 806400 live row keys')


if __name__ == '__main__':
    # The service integration test already uses a monkeypatch-shaped argument.
    # Keep the image gate plain Python and restore every patched value on exit.
    from contextlib import ExitStack
    from unittest.mock import patch
    class Patches:
        def __init__(self, stack):
            self.stack = stack
        def setattr(self, obj, name, value):
            self.stack.enter_context(patch.object(obj, name, value))
        def setenv(self, name, value):
            self.stack.enter_context(patch.dict(os.environ, {name: value}))
    for name, fn in sorted(list(globals().items())):
        if name.startswith('test_') and callable(fn):
            with ExitStack() as stack:
                if fn.__code__.co_argcount:
                    fn(Patches(stack))
                else:
                    fn()
            print('ok', name)
    print('all anomaly tests passed')
