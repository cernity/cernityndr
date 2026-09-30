"""U1a contract gate; optional real SQL execution with CLICKHOUSE_LOCAL binary."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

import jsonschema
import pytest
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = json.loads((ROOT / 'contracts/observation.schema.json').read_text())
SCHEMA = json.loads((ROOT / 'contracts/file_observation.schema.json').read_text())
REGISTRY = Registry().with_resource(CANONICAL['$id'], Resource.from_contents(CANONICAL))
FORMATS = jsonschema.FormatChecker()


@FORMATS.checks('date-time', raises=ValueError)
def date_time(value):
    # jsonschema's optional RFC3339 dependency is absent in some gate envs.
    # Keep calendar validation active; the canonical pattern enforces wire syntax.
    if not isinstance(value, str):
        return True
    return datetime.fromisoformat(value.replace('Z', '+00:00')).tzinfo is not None


VALIDATORS = [jsonschema.Draft202012Validator(s, registry=REGISTRY,
              format_checker=FORMATS) for s in (SCHEMA, CANONICAL)]
SQL = (ROOT / 'deploy/clickhouse/init/06-file-observation.sql').read_text()
STAMP = '2026-09-29T12:00:00Z'
RAW = '{"event_type":"fileinfo"}'


def observation(state='metadata_only'):
    obs_id = 'obs:' + hashlib.sha256(b'tenant-a:sensor-a:suricata.file.v1:0:1').hexdigest()
    payload = dict(state=state, first_seen=STAMP, last_seen=STAMP, mime=None,
                   size=None, filename=None, transfer_ref=None, session_ref=None,
                   source_obs_ref=None, file_artifact_id=None)
    if state == 'hashes_only':
        payload['sha256'] = 'a' * 64
    if state == 'bytes_available':
        payload['file_artifact_id'] = 'artifact:example'
    return dict(schema='cernity.observation.v1', obs_id=obs_id, tenant='tenant-a',
                sensor_id='sensor-a', type='file',
                ts=dict(sensor=STAMP, normalized=STAMP, ingested=STAMP,
                        method='ingest-fallback', clock_offset_ms=None),
                entities=[dict(type='ip', role='src', value='10.0.0.1')],
                fields={'file': payload}, capabilities=[],
                source_ref=dict(kind='clickhouse-row', table='ndr.file_observation',
                                tenant='tenant-a', obs_id=obs_id,
                                sha256=hashlib.sha256(RAW.encode()).hexdigest(),
                                topic='suricata.file.v1', partition=0, offset=1))


def validate(doc):
    for validator in VALIDATORS:
        validator.validate(doc)


def reject(doc):
    for validator in VALIDATORS:
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(doc)


def verdict():
    return dict(engine='yara', ruleset_sha256='b' * 64,
                matched_rules=['example_rule'], scanned_at=STAMP)


def test_schemas_well_formed_and_shared_envelope():
    for schema in (SCHEMA, CANONICAL):
        jsonschema.Draft202012Validator.check_schema(schema)
    assert SCHEMA['allOf'][0] == {'$ref': CANONICAL['$id']}


@pytest.mark.parametrize('state', ['metadata_only', 'hashes_only', 'bytes_available'])
def test_states_and_canonical_envelope(state):
    doc = observation(state)
    validate(doc)
    assert doc['source_ref']['obs_id'] == doc['obs_id']
    assert doc['source_ref']['tenant'] == doc['tenant']
    assert doc['source_ref']['sha256'] != doc['fields']['file'].get('sha256')


@pytest.mark.parametrize('state', ['metadata_only', 'hashes_only', 'bytes_available'])
def test_scan_verdict_only_with_bytes(state):
    doc = observation(state)
    doc['fields']['file']['scan_verdict'] = verdict()
    (validate if state == 'bytes_available' else reject)(doc)


@pytest.mark.parametrize('field', ['engine', 'ruleset_sha256', 'matched_rules', 'scanned_at'])
def test_scan_requires_rule_stamp(field):
    doc = observation('bytes_available')
    doc['fields']['file']['scan_verdict'] = verdict()
    del doc['fields']['file']['scan_verdict'][field]
    reject(doc)


@pytest.mark.parametrize('field,length', [('sha256', 64), ('sha1', 40), ('md5', 32)])
def test_hash_presence_and_format_by_state(field, length):
    doc = observation('hashes_only')
    del doc['fields']['file']['sha256']
    reject(doc)
    doc['fields']['file'][field] = 'a' * length
    validate(doc)
    doc['fields']['file']['state'] = 'metadata_only'
    reject(doc)
    doc['fields']['file']['state'] = 'hashes_only'
    for bad in ('', 'g' * length, 'a' * (length - 1), None):
        doc['fields']['file'][field] = bad
        reject(doc)


@pytest.mark.parametrize('state', ['metadata_only', 'hashes_only', 'bytes_available'])
def test_artifact_availability(state):
    doc = observation(state)
    doc['fields']['file']['file_artifact_id'] = None if state == 'bytes_available' else 'artifact:fake'
    reject(doc)


@pytest.mark.parametrize('field', CANONICAL['required'])
def test_missing_canonical_field(field):
    doc = observation()
    del doc[field]
    reject(doc)


@pytest.mark.parametrize('field', CANONICAL['properties']['ts']['required'])
def test_missing_canonical_timestamp_field(field):
    doc = observation()
    del doc['ts'][field]
    reject(doc)


@pytest.mark.parametrize('field', CANONICAL['properties']['source_ref']['required'])
def test_missing_source_reference_field(field):
    doc = observation()
    del doc['source_ref'][field]
    reject(doc)


@pytest.mark.parametrize('field', ['sensor', 'normalized', 'ingested', 'first_seen', 'last_seen'])
@pytest.mark.parametrize('bad', ['bad', '2026-09-29T12:00:00', '2026-02-30T12:00:00Z'])
def test_invalid_timestamps(field, bad):
    doc = observation()
    target = doc['fields']['file'] if field in ('first_seen', 'last_seen') else doc['ts']
    target[field] = bad
    reject(doc)


def test_clock_method_contract():
    doc = observation()
    doc['ts']['clock_offset_ms'] = 100
    reject(doc)
    doc['ts']['method'] = 'clock-offset'
    validate(doc)
    doc['ts']['clock_offset_ms'] = None
    reject(doc)


@pytest.mark.parametrize('field', CANONICAL['$defs']['file']['required'])
def test_missing_file_field(field):
    doc = observation()
    del doc['fields']['file'][field]
    reject(doc)


@pytest.mark.parametrize('field,bad', [('kind', 'file'), ('table', 'ndr.network_flow'),
                                      ('obs_id', 'file:abc'), ('sha256', 'xyz'),
                                      ('partition', -1), ('offset', -1), ('topic', '')])
def test_invalid_source_reference(field, bad):
    doc = observation()
    doc['source_ref'][field] = bad
    reject(doc)


def test_no_unearned_capabilities_or_mixed_protocol_payload():
    for capability in ('flow-only', 'http-metadata', 'ja4', 'payload-visible'):
        doc = observation()
        doc['capabilities'] = [capability]
        reject(doc)
    doc = observation()
    doc['fields']['http'] = {'hostname': 'example.test'}
    reject(doc)
    doc = observation()
    doc['fields']['file']['yara_verdict'] = 'matched'
    reject(doc)  # Undeclared verdict aliases cannot bypass scan_verdict rules.


def view(sql):
    return re.search(r'CREATE OR REPLACE VIEW ndr.evidence_observations AS\n(.*?);',
                     sql, re.S).group(1)


def test_sql_preserves_existing_view_and_materializes_canonical_identity():
    old = view((ROOT / 'deploy/clickhouse/init/05-evidence.sql').read_text())
    new = view(SQL)
    member = "UNION ALL\n    SELECT tenant_id, obs_id, normalized_time, entity_values, observation FROM ndr.file_observation WHERE observation != ''\n"
    assert new.count(member) == 1
    assert new.replace(member, '') == old
    assert "obs_id String MATERIALIZED JSONExtractString(observation, 'obs_id')" in SQL
    assert "JSONExtractRaw(observation, 'source_ref') AS source_ref" in new
    assert "CHECK match(obs_id, '^obs:[a-f0-9]{64}$')" in SQL
    assert "CHECK JSONExtractString(observation, 'source_ref', 'table') = 'ndr.file_observation'" in SQL
    assert "CHECK JSONExtractString(observation, 'source_ref', 'obs_id') = obs_id" in SQL
    assert "CHECK JSONExtractString(observation, 'source_ref', 'tenant') = tenant_id" in SQL


@pytest.mark.skipif(not os.environ.get('CLICKHOUSE_LOCAL'),
                    reason='Set CLICKHOUSE_LOCAL to a ClickHouse local executable for real SQL verification')
def test_clickhouse_file_row_roundtrip(tmp_path):
    # Private local database only. Real DDL/view execution, with the existing
    # UNION members represented by empty tables exposing their actual columns.
    tables = ['network_flow', 'dns_transaction', 'tls_observation',
              'http_observation', 'identity_observation']
    setup = 'CREATE DATABASE ndr;\n' + '\n'.join(
        f'CREATE TABLE ndr.{table} (tenant_id String, obs_id String, '
        "normalized_time DateTime64(3, 'UTC'), entity_values Array(String), "
        'observation String) ENGINE=Memory;' for table in tables)
    doc = observation('bytes_available')
    stamp = datetime.now(timezone.utc).isoformat()
    for field in ('sensor', 'normalized', 'ingested'):
        doc['ts'][field] = stamp
    for field in ('first_seen', 'last_seen'):
        doc['fields']['file'][field] = stamp
    doc['fields']['file']['scan_verdict'] = verdict()
    validate(doc)
    def literal(value):
        return "'" + value.replace('\\', '\\\\').replace("'", "\\'") + "'"
    insert = 'INSERT INTO ndr.file_observation (observation, raw_record) VALUES (' + literal(json.dumps(doc)) + ', ' + literal(RAW) + ');'
    query = setup + SQL + SQL + insert + insert + '''
SELECT obs_id, source_ref, observation FROM ndr.evidence_observations FORMAT JSONEachRow;
'''
    result = subprocess.run([os.environ['CLICKHOUSE_LOCAL'], '--path', str(tmp_path / 'ch'),
                             '--multiquery', '--query', query],
                            text=True, capture_output=True, check=True)
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(rows) == 1  # DISTINCT removes identical replay rows.
    assert re.fullmatch(r'obs:[a-f0-9]{64}', rows[0]['obs_id'])
    assert json.loads(rows[0]['source_ref']) == doc['source_ref']
    assert json.loads(rows[0]['observation']) == doc


@pytest.mark.parametrize('field,bad', [('state', 'unknown'), ('size', -1),
                                      ('size', 1.5), ('size', 2 ** 64),
                                      ('source_obs_ref', 'file:unknown')])
def test_invalid_file_metadata(field, bad):
    doc = observation()
    doc['fields']['file'][field] = bad
    reject(doc)


def test_bytes_can_include_hashes_and_an_empty_scan_result():
    doc = observation('bytes_available')
    doc['fields']['file'].update(sha256='a' * 64, sha1='b' * 40, md5='c' * 32,
                               size=0, scan_verdict=verdict())
    doc['fields']['file']['scan_verdict']['matched_rules'] = []
    validate(doc)
