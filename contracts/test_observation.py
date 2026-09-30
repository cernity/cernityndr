"""U4 contract and source fidelity, using the actual normalizer transform."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('u4_models', ROOT / 'services/normalizer/models.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
SCHEMA = json.loads((ROOT / 'contracts/observation.schema.json').read_text())
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.FormatChecker())


def event(kind):
    payloads = {'flow': {'bytes_toserver': 0},
                'dns': {'version': 3, 'queries': [{'rrname': 'example.test', 'rrtype': 'A'}]},
                'tls': {'sni': 'example.test', 'ja3': {'hash': 'abc'}, 'ja4': 'def'},
                'http': {'hostname': 'example.test', 'http_method': 'GET'}}
    return {'event_type': kind, 'timestamp': '2026-09-28T12:00:02+00:00',
            'src_ip': '10.0.0.1', 'dest_ip': '10.0.0.2',
            'community_id': '1:test', kind: payloads[kind]}


def transform(kind='flow', **kwargs):
    options = dict(topic=f'suricata.{kind}.v1', partition=0, offset=10,
                   ingested_at='2026-09-28T12:00:05Z')
    options.update(kwargs)
    return m.observation(event(kind), 'tenant-a', 'sensor-a', **options)


@pytest.mark.parametrize('kind', ['flow', 'dns', 'tls', 'http'])
def test_observation_types_and_preserved_source(kind):
    table, row, doc = transform(kind)
    VALIDATOR.validate(doc)
    assert json.loads(row['observation']) == doc
    assert json.loads(row['raw_record']) == event(kind)
    ref = doc['source_ref']
    assert ref['table'] == 'ndr.' + table
    assert ref['obs_id'] == doc['obs_id'] and ref['tenant'] == doc['tenant']
    assert ref['sha256'] == hashlib.sha256(row['raw_record'].encode()).hexdigest()
    assert doc['ts']['normalized'] == '2026-09-28T12:00:05+00:00'
    assert doc['ts']['method'] == 'ingest-fallback'
    assert doc['ts']['clock_offset_ms'] is None


@pytest.mark.parametrize('kind', ['flow', 'dns', 'tls', 'http'])
def test_existing_types_reject_file_source_table(kind):
    doc = transform(kind)[2]
    doc['source_ref']['table'] = 'ndr.file_observation'
    with pytest.raises(jsonschema.ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize('kind', ['flow', 'dns', 'tls', 'http'])
def test_existing_types_reject_even_valid_file_payload(kind):
    doc = transform(kind)[2]
    payload = dict(state='metadata_only', first_seen=doc['ts']['sensor'],
                   last_seen=doc['ts']['sensor'], mime=None, size=None,
                   filename=None, transfer_ref=None, session_ref=None,
                   source_obs_ref=None, file_artifact_id=None)
    # Prove rejection is due to mixing observation types, not invalid metadata.
    jsonschema.Draft202012Validator(SCHEMA['$defs']['file']).validate(payload)
    doc['fields']['file'] = payload
    with pytest.raises(jsonschema.ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize('field', list(SCHEMA['required']))
def test_missing_required_rejected(field):
    doc = transform()[2]
    del doc[field]
    with pytest.raises(jsonschema.ValidationError):
        VALIDATOR.validate(doc)


def test_missing_normalized_timestamp_and_invalid_date_rejected():
    doc = transform()[2]
    del doc['ts']['normalized']
    with pytest.raises(jsonschema.ValidationError):
        VALIDATOR.validate(doc)
    doc['ts']['normalized'] = 'not-a-date'
    with pytest.raises(jsonschema.ValidationError):
        VALIDATOR.validate(doc)


def test_fidelity_flow_has_no_packet_or_handshake_fields():
    doc = transform()[2]
    assert set(doc['capabilities']) == {'flow-only', 'community-id'}
    assert doc['fields']['flow']['bytes_toserver'] == 0
    assert 'bytes_toclient' not in doc['fields']['flow']
    for field in ('tls', 'http', 'dns', 'payload', 'pcap_cnt'):
        assert field not in doc['fields']
    for cap in ('packet-metadata', 'payload-visible', 'tls-handshake', 'ja4'):
        invalid = copy.deepcopy(doc)
        invalid['capabilities'].append(cap)
        with pytest.raises(jsonschema.ValidationError):
            VALIDATOR.validate(invalid)
    doc['fields']['tls'] = {'ja4': 'fake'}
    with pytest.raises(jsonschema.ValidationError):
        VALIDATOR.validate(doc)


def test_tls_fingerprints_only_when_present():
    eve = event('tls')
    eve['tls'] = {'sni': 'example.test'}
    _, _, doc = m.observation(eve, 'a', 's', topic='suricata.tls.v1', partition=0,
                             offset=1, ingested_at='2026-09-28T12:00:05Z')
    VALIDATOR.validate(doc)
    assert 'ja3' not in doc['capabilities'] and 'ja4' not in doc['capabilities']
    doc['capabilities'].append('ja4')
    with pytest.raises(jsonschema.ValidationError):
        VALIDATOR.validate(doc)


def test_measured_offset_sign_and_sensor_time_preserved():
    doc = transform(clock_offset_ms=2000)[2]
    VALIDATOR.validate(doc)
    assert doc['ts']['sensor'] == event('flow')['timestamp']
    assert doc['ts']['normalized'] == '2026-09-28T12:00:00+00:00'
    assert doc['ts']['method'] == 'clock-offset'
    assert transform(clock_offset_ms=-2000)[2]['ts']['normalized'] == '2026-09-28T12:00:04+00:00'


def test_replay_identity_and_finding_reference_resolution():
    table, row, doc = transform()
    assert transform()[2] == doc
    assert transform(offset=11)[2]['obs_id'] != doc['obs_id']
    assert transform(partition=1)[2]['obs_id'] != doc['obs_id']
    other = m.observation(event('flow'), 'tenant-b', 'sensor-a',
                          topic='suricata.flow.v1', partition=0, offset=10,
                          ingested_at='2026-09-28T12:00:05Z')[2]
    assert other['obs_id'] != doc['obs_id']
    finding = {'tenant_id': doc['tenant'], 'evidence_refs': [doc['obs_id']]}
    # Exact reference join contract; this is not a live ClickHouse API test.
    index = {(doc['tenant'], doc['obs_id']): json.loads(row['observation'])}
    resolved = index[(finding['tenant_id'], finding['evidence_refs'][0])]
    assert resolved['source_ref']['table'] == 'ndr.' + table
    assert ('tenant-b', doc['obs_id']) not in index


@pytest.mark.parametrize('stamp', [None, '', 'bad', '2026-09-28T12:00:00'])
def test_bad_sensor_time_quarantined(stamp):
    eve = event('flow')
    eve['timestamp'] = stamp
    with pytest.raises(m.QuarantineError):
        m.observation(eve, 'a', 's', topic='suricata.flow.v1', partition=0,
                      offset=1, ingested_at='2026-09-28T12:00:05Z')


def test_payload_cannot_supply_tenant_or_clock_correction():
    eve = event('flow')
    eve.update(tenant='evil', clock_offset_ms=99999, capabilities=['payload-visible'])
    doc = m.observation(eve, 'trusted', 's', topic='suricata.flow.v1', partition=0,
                        offset=1, ingested_at='2026-09-28T12:00:05Z')[2]
    assert doc['tenant'] == 'trusted'
    assert doc['ts']['clock_offset_ms'] is None
    assert 'payload-visible' not in doc['capabilities']
