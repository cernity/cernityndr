from datetime import datetime
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

SCHEMA = json.loads(Path(__file__).with_name('disposition.schema.json').read_text())
FORMATS = FormatChecker()


@FORMATS.checks('date-time', raises=ValueError)
def valid_timestamp(value):
    return not isinstance(value, str) or datetime.fromisoformat(value.upper().replace('Z', '+00:00')).tzinfo is not None


VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FORMATS)


def disposition(verdict='true_positive'):
    return {'finding_id': 'f1', 'entity': {'type': 'ip', 'value': '192.0.2.1'},
            'verdict': verdict, 'reason': 'Investigated evidence', 'analyst': 'claimed',
            'ts': '2026-09-28T12:00:00Z', 'scope': 'entity' if verdict == 'allowlist' else 'finding'}


@pytest.mark.parametrize('verdict', ['true_positive', 'false_positive', 'benign', 'allowlist'])
def test_forms(verdict):
    Draft202012Validator.check_schema(SCHEMA)
    doc = disposition(verdict)
    if verdict == 'allowlist':
        doc['finding_id'] = None
    VALIDATOR.validate(doc)


@pytest.mark.parametrize('field', SCHEMA['required'])
def test_missing(field):
    doc = disposition()
    del doc[field]
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize('change', [
    {'verdict': 'suppress'}, {'finding_id': None}, {'reason': '   '},
    {'ts': 'bad'}, {'ts': '2026-02-30T12:00:00Z'}, {'ts': '2026-09-28T12:00:00'}, {'entity': {}},
    {'entity': {'type': 'anything', 'value': '*'}}, {'scope': {}},
    {'verdict': 'allowlist', 'scope': 'tenant'}, {'expires_at': 9999999999},
    {'analyst': 4}, {'tenant': []},
])
def test_malformed(change):
    doc = disposition()
    doc.update(change)
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)
