"""asset (entity-spine) contract — U3a additive-attribute extension + backward-compat.

Pins the key U3a invariant: the SHIPPED record shape still validates against the extended
schema (no field renamed / retyped / newly-required), and each new attribute is optional +
nullable. Mirrors test_contracts.py's validator setup (RFC3339 date-time shim for the base env).
"""
import copy
from datetime import datetime
import json
from pathlib import Path
import re

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

SCHEMA = json.loads((Path(__file__).parent / 'asset.schema.json').read_text())
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

# A record in exactly the SHIPPED shape (pre-U3a fields only). Pinned so a later edit that
# renames/retypes/newly-requires a shipped field breaks this test loudly (backward-compat).
SHIPPED = {
    'tenant_id': 'acme',
    'asset_key': 'mac:aa:bb:cc:00:11:22',
    'first_seen': '2026-09-28T12:00:00Z',
    'last_seen': '2026-09-28T12:10:00Z',
    'ip_set': ['10.0.0.5'],
    'mac_set': ['aa:bb:cc:00:11:22'],
    'hostname_set': ['laptop-1'],
    'role_if_known': 'workstation',
    'evidence_sources': ['dhcp', 'arp'],
    'confidence': 0.7,
    'facts': [{
        'predicate': 'hostname', 'value': 'laptop-1', 'valid_from': '2026-09-28T12:00:00Z',
        'valid_to': None, 'confidence': 0.9,
        'source': {'type': 'dhcp', 'observation_id': 'obs:abc'},
    }],
}

# The same record plus every U3a additive attribute populated (+ provenance).
EXTENDED = dict(copy.deepcopy(SHIPPED),
                username='bob', role='domain-controller', os_hint='Windows Server 2022',
                criticality='crown-jewel', owner='it-ops',
                applications=['nginx/1.27'], listening_services=['tcp/443'],
                certificates=['sha256:deadbeef'], ja4=['t13d1516h2_8daaf6152771'],
                attribute_provenance={
                    'username': {'source': 'dhcp', 'observed_at': '2026-09-28T12:00:00Z'},
                    'ja4': {'source': 'tls', 'observed_at': '2026-09-28T12:05:00Z'}})


def test_schema_itself_is_valid():
    Draft202012Validator.check_schema(SCHEMA)


def test_shipped_record_still_validates_against_extended_schema():
    # BACKWARD-COMPAT: no shipped field renamed/retyped/newly-required.
    VALIDATOR.validate(SHIPPED)


def test_extended_record_with_all_new_attributes_validates():
    VALIDATOR.validate(EXTENDED)


def test_every_new_field_is_optional():
    # Dropping any single new field from EXTENDED must still validate (none is required).
    new_fields = ['username', 'role', 'os_hint', 'criticality', 'owner', 'applications',
                  'listening_services', 'certificates', 'ja4', 'attribute_provenance']
    for f in new_fields:
        rec = copy.deepcopy(EXTENDED)
        rec.pop(f)
        VALIDATOR.validate(rec)          # raises on failure


def test_every_new_scalar_field_is_nullable():
    for f in ('username', 'role', 'os_hint', 'criticality', 'owner'):
        VALIDATOR.validate(dict(copy.deepcopy(SHIPPED), **{f: None}))


def test_every_new_list_field_is_nullable():
    for f in ('applications', 'listening_services', 'certificates', 'ja4'):
        VALIDATOR.validate(dict(copy.deepcopy(SHIPPED), **{f: None}))


def test_shipped_required_fields_unchanged():
    # Required set is exactly the shipped one — no new field became required.
    assert set(SCHEMA['required']) == {'tenant_id', 'asset_key', 'first_seen', 'last_seen'}


def test_unknown_field_still_rejected():
    # additionalProperties:false preserved — the extension didn't open the record up.
    bad = dict(copy.deepcopy(SHIPPED), not_a_real_field='x')
    try:
        VALIDATOR.validate(bad)
        raise AssertionError('expected ValidationError for unknown field')
    except ValidationError:
        pass


def test_attribute_provenance_entry_shape_enforced():
    # A provenance entry must carry source + observed_at and nothing else.
    for bad_entry in ({'source': 'dhcp'},                       # missing observed_at
                      {'observed_at': '2026-09-28T12:00:00Z'},  # missing source
                      {'source': 'dhcp', 'observed_at': '2026-09-28T12:00:00Z', 'x': 1}):
        rec = dict(copy.deepcopy(SHIPPED), attribute_provenance={'username': bad_entry})
        try:
            VALIDATOR.validate(rec)
            raise AssertionError('expected ValidationError for malformed provenance entry')
        except ValidationError:
            pass
