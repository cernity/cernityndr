"""intel.v1 contract test (plan U1). Valid + invalid fixtures against the JSON Schema."""
from datetime import datetime
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

SCHEMA = json.loads(Path(__file__).with_name('intel.schema.json').read_text())
FORMATS = FormatChecker()


@FORMATS.checks('date-time', raises=ValueError)
def valid_timestamp(value):
    return not isinstance(value, str) or datetime.fromisoformat(value.upper().replace('Z', '+00:00')).tzinfo is not None


VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FORMATS)


def indicator(**over):
    doc = {
        'indicator': '185.100.87.202', 'type': 'ip',
        'source': 'abuse.ch', 'feed': 'feodo', 'score': 90, 'tlp': 'amber',
        'source_trust': 0.9,
        'first_seen': '2026-09-01T00:00:00Z', 'last_seen': '2026-09-29T00:00:00Z',
        'expiry': '2026-10-29T00:00:00Z', 'disposition': 'active', 'tenant': 'customer-381',
        'provenance': [{
            'source': 'abuse.ch', 'feed': 'feodo', 'score': 90, 'tlp': 'amber',
            'source_trust': 0.9, 'first_seen': '2026-09-01T00:00:00Z',
            'last_seen': '2026-09-29T00:00:00Z',
        }],
    }
    doc.update(over)
    return doc


def test_schema_is_valid():
    Draft202012Validator.check_schema(SCHEMA)


@pytest.mark.parametrize('itype', ['ip', 'domain', 'url', 'hash', 'ja3', 'ja4', 'cert'])
def test_all_indicator_types(itype):
    VALIDATOR.validate(indicator(type=itype))


@pytest.mark.parametrize('tlp', ['clear', 'green', 'amber', 'amber+strict', 'red'])
def test_all_tlp_levels(tlp):
    doc = indicator(tlp=tlp)
    doc['provenance'][0]['tlp'] = tlp
    VALIDATOR.validate(doc)


@pytest.mark.parametrize('field', SCHEMA['required'])
def test_missing_required(field):
    doc = indicator()
    del doc[field]
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize('change', [
    {'type': 'nonsense'},
    {'tlp': 'orange'},
    {'score': 101},
    {'score': -1},
    {'source_trust': 1.5},
    {'source_trust': -0.1},
    {'first_seen': 'not-a-date'},
    {'expiry': '2026-13-01T00:00:00Z'},
    {'disposition': 'ignored'},
    {'indicator': '   '},
    {'provenance': []},
    {'tenant': ['a']},
    {'unexpected': 'x'},
])
def test_malformed_rejected(change):
    doc = indicator()
    doc.update(change)
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


def test_provenance_entry_needs_trust_and_tlp():
    doc = indicator()
    del doc['provenance'][0]['source_trust']
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


if __name__ == '__main__':
    test_schema_is_valid()
    VALIDATOR.validate(indicator())
    print('ok  intel.v1 contract')
