"""U6 wire validation. Runtime authorization is tested separately."""
import copy
import json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator, ValidationError

SCHEMA = json.loads(Path(__file__).with_name('capture-request.schema.json').read_text())
VALIDATOR = Draft202012Validator(SCHEMA)
VALID = {
    'schema_version': 'capture-request.v2', 'mode': 'preserve', 'request_id': 'r1',
    'tenant_id': 'acme', 'sensor_id': 's1', 'finding_id': 'f1', 'policy_id': 'p1',
    'reason': 'beacon', 'capture_profile': 'ip', 'value': '192.0.2.1',
    'window': {'start': 100, 'end': 120},
    'limits': {'max_bytes': 10000, 'max_duration_s': 60, 'retention_s': 86400},
    'expires_at': 180, 'authorization': 'a' * 64,
}


def test_valid():
    Draft202012Validator.check_schema(SCHEMA)
    VALIDATOR.validate(VALID)


@pytest.mark.parametrize('field', list(VALID))
def test_required(field):
    doc = copy.deepcopy(VALID)
    del doc[field]
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize('patch', [
    {'mode': 'arm'}, {'schema_version': 'capture-request.v1'},
    {'tenant_id': None}, {'authorization': True}, {'authorized': True},
    {'limits': {'max_bytes': 0, 'max_duration_s': 60, 'retention_s': 1}},
    {'window': {'start': 'yesterday', 'end': 120}},
])
def test_invalid(patch):
    with pytest.raises(ValidationError):
        VALIDATOR.validate({**VALID, **patch})
