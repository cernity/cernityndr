"""asset-fact (CMDB-ingest) contract — U4.

Pins the U4 invariants on the wire shape: the connector emits ONLY the externally-assigned
predicates {owner, criticality} with provenance (source=netbox-cmdb, authority, synced_at), and
can NEVER emit an observed predicate. Mirrors test_asset.py's validator setup (RFC3339 date-time
shim for the base env).
"""
import copy
from datetime import datetime
import json
from pathlib import Path
import re

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

SCHEMA = json.loads((Path(__file__).parent / 'asset-fact.schema.json').read_text())
CHECKER = FormatChecker()


@CHECKER.checks('date-time', raises=ValueError)
def date_time(value):
    # jsonschema's optional RFC3339 dependency is absent in the base test env.
    if not isinstance(value, str):
        return True
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})', value):
        return False
    return datetime.fromisoformat(value.upper().replace('Z', '+00:00')).tzinfo is not None


VALIDATOR = Draft202012Validator(SCHEMA, format_checker=CHECKER)

OWNER_FACT = {
    'tenant_id': 'acme',
    'entity_ref': '10.0.0.5',
    'predicate': 'owner',
    'value': 'it-ops',
    'source': 'netbox-cmdb',
    'authority': True,
    'synced_at': '2026-10-02T12:00:00Z',
}
CRITICALITY_FACT = dict(copy.deepcopy(OWNER_FACT), predicate='criticality', value='crown-jewel')


def test_schema_itself_is_valid():
    Draft202012Validator.check_schema(SCHEMA)


def test_valid_owner_and_criticality_facts_validate():
    VALIDATOR.validate(OWNER_FACT)
    VALIDATOR.validate(CRITICALITY_FACT)


def test_observed_predicate_rejected():
    # The connector cannot emit an OBSERVED predicate — only {owner, criticality}.
    for pred in ('ip', 'mac', 'hostname', 'role', 'ja4', 'applications', 'listening_services'):
        bad = dict(copy.deepcopy(OWNER_FACT), predicate=pred)
        try:
            VALIDATOR.validate(bad)
            raise AssertionError(f'expected ValidationError for observed predicate {pred!r}')
        except ValidationError:
            pass


def test_missing_required_field_rejected():
    for f in ('tenant_id', 'entity_ref', 'predicate', 'value', 'source', 'authority', 'synced_at'):
        bad = copy.deepcopy(OWNER_FACT)
        bad.pop(f)
        try:
            VALIDATOR.validate(bad)
            raise AssertionError(f'expected ValidationError for missing {f!r}')
        except ValidationError:
            pass


def test_source_must_be_netbox_cmdb():
    bad = dict(copy.deepcopy(OWNER_FACT), source='some-other-cmdb')
    try:
        VALIDATOR.validate(bad)
        raise AssertionError('expected ValidationError for non-netbox source')
    except ValidationError:
        pass


def test_unknown_field_rejected():
    bad = dict(copy.deepcopy(OWNER_FACT), not_a_real_field='x')
    try:
        VALIDATOR.validate(bad)
        raise AssertionError('expected ValidationError for unknown field')
    except ValidationError:
        pass
