"""Offline deployment contract only; never claims broker or S3 connectivity.

Needs: deploy/security/requirements-test.txt. Run from repository root:
PYTHONPATH=shared .venv/bin/python -m pytest -q deploy/security/test_forensics_config.py
"""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlparse

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {
    ('topic', 'ndr.capture.request.v1'): {'describe'},
    ('topic', 'ndr.capture.arm.v1'): {'read', 'describe'},
    ('topic', 'ndr.capture.status.v1'): {'write', 'describe'},
    ('topic', 'ndr.capture.request.v2'): {'read', 'describe'},
    ('group', 'ndr-capture-agent-${NDR_SENSOR:-sensor-1}'): {'read'},
}


def load(path):
    return yaml.safe_load((ROOT / path).read_text())


def validate(overlay, compose, sensor):
    contract = overlay['x-forensics']
    env = compose['services']['redpanda']['environment']
    assert contract['principal'] == '${CERNITY_BUS_CAPTURE_USER:-cernity-capture}'
    assert env['CERNITY_BUS_CAPTURE_USER'] == contract['principal']
    assert env['CERNITY_BUS_CAPTURE_PASSWORD'] == '${CERNITY_BUS_CAPTURE_PASSWORD:-}'
    assert contract['principal'] not in [env[k] for k in (
        'CERNITY_BUS_USER', 'CERNITY_BUS_ADMIN_USER', 'CERNITY_BUS_CENTRAL_USER')]
    assert env['CERNITY_CAPTURE_ENABLED'] == '0'
    assert overlay['services']['redpanda']['environment']['CERNITY_CAPTURE_ENABLED'] == '1'
    rows = contract['acls']
    assert len(rows) == len(EXPECTED)
    actual = {}
    for row in rows:
        assert row['pattern'] == 'literal'
        assert '*' not in row['name']
        key = (row['resource'], row['name'])
        assert key not in actual
        actual[key] = set(row['operations'])
    assert actual == EXPECTED
    assert './redpanda/provision-capture.sh:/provision-capture.sh:ro' in compose['services']['redpanda']['volumes']
    minio = overlay['services']['minio']
    assert minio['command'].startswith('server /data')
    assert minio['ports'] == ['${CERNITY_CAPTURE_S3_BIND_IP:?set private central interface}:9000:9000']
    assert 'network_mode' not in minio and 'networks' not in minio
    endpoint = '${CERNITY_CAPTURE_S3_ENDPOINT:?set sensor-routable S3 URL}'
    assert contract['sensor_endpoint'] == endpoint
    agent = sensor['services']['capture-agent']['environment']
    assert agent['MINIO_ENDPOINT'] == endpoint
    assert agent['NDR_BUS_SASL_USER'] == contract['principal']
    assert agent['NDR_BUS_SASL_PASSWORD'].startswith('${CERNITY_BUS_CAPTURE_PASSWORD:?')
    assert agent['NDR_BUS_SASL_MECHANISM'] == 'SCRAM-SHA-512'
    assert agent['AWS_ACCESS_KEY_ID'].startswith('${CERNITY_MINIO_CAPTURE_USER:?')
    assert agent['AWS_SECRET_ACCESS_KEY'].startswith('${CERNITY_MINIO_CAPTURE_PASSWORD:?')
    # Topology proof with an explicit private-interface example, not a network probe.
    example = {'CERNITY_CAPTURE_S3_BIND_IP': '10.20.30.40',
               'CERNITY_CAPTURE_S3_ENDPOINT': 'http://10.20.30.40:9000'}
    def expand(value):
        return re.sub(r'\$\{([^:}]+):\?[^}]+\}', lambda m: example[m[1]], value)
    url = urlparse(expand(agent['MINIO_ENDPOINT']))
    binding = expand(minio['ports'][0]).split(':')
    assert url.scheme == 'http' and url.hostname == binding[0]
    assert url.port == int(binding[1]) == int(binding[2]) == 9000
    for service in ('zeek-central', 'file-yara'):
        svc = overlay['services'][service]
        assert svc['environment']['MINIO_ENDPOINT'] == 'http://minio:9000'
        assert svc['depends_on']['minio']['condition'] == 'service_healthy'
    init = overlay['services']['minio-init']
    assert init['entrypoint'][1] == '-ec'
    assert init['environment']['CAPTURE_OBJECT_PREFIX'].startswith('${CERNITY_CAPTURE_OBJECT_PREFIX:?')
    script = init['entrypoint'][2]
    assert 's3:PutObject' in script and 's3:GetObject' in script
    assert 'arn:aws:s3:::ndr-pcap/%s/*' in script
    assert 'mc admin policy attach' in script


@pytest.fixture
def configs():
    return (load('deploy/overlays/forensics.yml'), load('deploy/central/docker-compose.yml'),
            load('deploy/overlays/forensics-sensor.yml'))


def test_forensics_config(configs):
    validate(*configs)


@pytest.mark.parametrize('fault', ['wildcard', 'prefix', 'extra_topic', 'cluster', 'all',
                                  'missing_topic', 'principal', 'endpoint', 'unpublished'])
def test_rejects_unsafe_config(configs, fault):
    overlay, compose, sensor = copy.deepcopy(configs)
    acls = overlay['x-forensics']['acls']
    if fault == 'wildcard':
        acls[0]['name'] = '*'
    elif fault == 'prefix':
        acls[0]['pattern'] = 'prefixed'
    elif fault == 'extra_topic':
        acls.append(dict(resource='topic', name='ndr.finding.final.v1', pattern='literal', operations=['write']))
    elif fault == 'cluster':
        acls[0]['resource'] = 'cluster'
    elif fault == 'all':
        acls[0]['operations'].append('all')
    elif fault == 'missing_topic':
        acls.pop(0)
    elif fault == 'principal':
        overlay['x-forensics']['principal'] = compose['services']['redpanda']['environment']['CERNITY_BUS_CENTRAL_USER']
    elif fault == 'endpoint':
        sensor['services']['capture-agent']['environment']['MINIO_ENDPOINT'] = 'http://minio:9000'
    elif fault == 'unpublished':
        overlay['services']['minio']['ports'] = []
    with pytest.raises(AssertionError):
        validate(overlay, compose, sensor)


def provision(tmp_path, **overrides):
    """Execute real provisioning shell; fake only the external broker CLI."""
    fake = tmp_path / 'rpk'
    fake.write_text('#!' + os.sys.executable + '\nimport json, os, sys\n'
                    'with open(os.environ["CALLS"], "a") as f: f.write(json.dumps(sys.argv[1:])+"\\n")\n'
                    'sys.exit(1 if os.environ.get("FAIL_ACL") == "1" and "acl" in sys.argv else 0)\n')
    fake.chmod(0o755)
    calls = tmp_path / 'calls'
    env = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ['PATH'], CALLS=str(calls),
               CERNITY_BUS_CAPTURE_PASSWORD='capture password:with punctuation',
               CERNITY_BUS_CAPTURE_USER='cernity-capture', NDR_SENSOR='sensor-1',
               ADMIN_USER='cernity-admin', CENTRAL_USER='cernity-central', CERNITY_BUS_USER='cernity-sensor',
               CERNITY_BUS_ADMIN_PASSWORD='admin secret', ADMIN='local:9644', KAFKA='local:9092')
    env.update(overrides)
    result = subprocess.run(['sh', str(ROOT / 'deploy/central/redpanda/provision-capture.sh')],
                            env=env, capture_output=True, text=True)
    return result, [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []


def test_actual_provisioning_matches_declaration(tmp_path, configs):
    result, calls = provision(tmp_path)
    assert result.returncode == 0, result.stderr
    observed = {}
    delete_index = next(i for i, c in enumerate(calls) if c[:3] == ['security', 'acl', 'delete'])
    for i, args in enumerate(calls):
        if args[:3] != ['security', 'acl', 'create']:
            continue
        assert i > delete_index
        assert args[args.index('--allow-principal') + 1] == 'User:cernity-capture'
        assert args[args.index('--resource-pattern-type') + 1] == 'literal'
        kind = 'topic' if '--topic' in args else 'group'
        name = args[args.index('--' + kind) + 1]
        ops = {args[n + 1] for n, arg in enumerate(args) if arg == '--operation'}
        observed[kind, name] = ops
    expected = {(k, n.replace('${NDR_SENSOR:-sensor-1}', 'sensor-1')): v for (k, n), v in EXPECTED.items()}
    assert observed == expected
    entrypoint = (ROOT / 'deploy/central/redpanda/entrypoint.sh').read_text()
    assert '. /provision-capture.sh' in entrypoint
    assert 'set kafka_enable_authorization true -X admin.hosts="$ADMIN" >/dev/null\n' in entrypoint
    assert "set superusers \"['$ADMIN_USER','$CENTRAL_USER']\"" in entrypoint


@pytest.mark.parametrize('override', [dict(CERNITY_BUS_CAPTURE_USER='cernity-admin'),
                                     dict(CERNITY_BUS_CAPTURE_USER='*'), dict(NDR_SENSOR='*'),
                                     dict(CERNITY_BUS_CAPTURE_PASSWORD=''), dict(FAIL_ACL='1')])
def test_provisioning_fails_closed(tmp_path, override):
    result, _ = provision(tmp_path, **override)
    assert result.returncode != 0
