"""detection-capability.v1 contract test (plan 021 U1). Validates per-DETECTOR Detection
Capability Manifest fixtures against the JSON Schema, plus two rules the schema can/does carry:

  * Rule 1 (golden-pcap gate): status=="verified_e2e" REQUIRES a non-empty
    backing_tests.golden_pcap. Encoded in the schema's if/then; asserted here by a dedicated check.
  * Rule 2 (KTD5 consistency): a capability/technique asserted in required_capabilities or
    attack_techniques must NOT also be listed in known_limitations as unverified. This is a
    cross-field semantic rule that JSON Schema cannot express, so it lives here as Python over
    the fixtures.

NOTE: this is the per-detector DETECTION capability manifest; it is DISTINCT from
deploy/central/capability-manifest.json (the deployment producer->topic->consumer manifest).

Fixture convention (contracts/fixtures/detection-capability/):
  valid_*.json          -> schema-valid AND KTD5-consistent
  schema_invalid_*.json -> must raise jsonschema.ValidationError
  ktd5_*.json           -> schema-valid but KTD5-INCONSISTENT
"""
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

SCHEMA = json.loads(Path(__file__).with_name('detection-capability.schema.json').read_text())
VALIDATOR = Draft202012Validator(SCHEMA)
FIXTURES = Path(__file__).with_name('fixtures') / 'detection-capability'


def _load(name):
    return json.loads((FIXTURES / name).read_text())


def _fixtures(prefix):
    return sorted(p.name for p in FIXTURES.glob(f'{prefix}*.json'))


def ktd5_consistent(manifest):
    """KTD5: no asserted capability/technique may also be flagged unverified in known_limitations."""
    asserted = set(manifest['required_capabilities']) | set(manifest['attack_techniques'])
    for limitation in manifest['known_limitations']:
        if limitation.get('unverified') and limitation.get('claim') in asserted:
            return False
    return True


def test_schema_is_valid():
    Draft202012Validator.check_schema(SCHEMA)


def test_fixtures_exist():
    # guard against a silently-empty glob making the parametrized tests pass vacuously
    assert _fixtures('valid_'), 'no valid_* fixtures found'
    assert _fixtures('schema_invalid_'), 'no schema_invalid_* fixtures found'
    assert _fixtures('ktd5_'), 'no ktd5_* fixtures found'


@pytest.mark.parametrize('name', _fixtures('valid_'))
def test_valid_fixtures_pass(name):
    doc = _load(name)
    VALIDATOR.validate(doc)                 # scenario 1: a full, well-formed manifest validates
    assert ktd5_consistent(doc), f'{name} should be KTD5-consistent'


@pytest.mark.parametrize('name', _fixtures('schema_invalid_'))
def test_schema_invalid_fixtures_raise(name):
    # scenarios 2/3/4: missing status|required_capabilities|backing_tests, bad enum, and the
    # verified_e2e empty-golden_pcap gate all surface as a schema ValidationError.
    with pytest.raises(ValidationError):
        VALIDATOR.validate(_load(name))


@pytest.mark.parametrize('field', SCHEMA['required'])
def test_missing_each_required_field_rejected(field):
    # breadth: every required top-level field is actually enforced. Precise error per field.
    doc = _load('valid_full.json')
    del doc[field]
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


def test_verified_e2e_requires_golden_pcap():
    # dedicated check for Rule 1, both directions.
    bad = _load('schema_invalid_verified_e2e_empty_golden_pcap.json')
    assert bad['status'] == 'verified_e2e' and bad['backing_tests']['golden_pcap'] == []
    with pytest.raises(ValidationError):
        VALIDATOR.validate(bad)

    good = _load('valid_verified_e2e.json')
    assert good['status'] == 'verified_e2e' and good['backing_tests']['golden_pcap']
    VALIDATOR.validate(good)

    # and the gate is specific to verified_e2e: experimental may legitimately carry no golden pcap.
    exp = _load('valid_experimental_empty_backing.json')
    assert exp['status'] != 'verified_e2e' and exp['backing_tests']['golden_pcap'] == []
    VALIDATOR.validate(exp)


@pytest.mark.parametrize('name', _fixtures('ktd5_'))
def test_ktd5_inconsistent_fixtures_are_schema_valid_but_fail_the_rule(name):
    # scenario 5: a claim both asserted and listed as unverified passes JSON Schema but violates KTD5.
    doc = _load(name)
    VALIDATOR.validate(doc)                 # schema alone cannot catch it
    assert not ktd5_consistent(doc), f'{name} should be caught by the KTD5 consistency rule'


if __name__ == '__main__':
    test_schema_is_valid()
    test_fixtures_exist()
    for _n in _fixtures('valid_'):
        test_valid_fixtures_pass(_n)
    for _n in _fixtures('schema_invalid_'):
        test_schema_invalid_fixtures_raise(_n)
    for _f in SCHEMA['required']:
        test_missing_each_required_field_rejected(_f)
    test_verified_e2e_requires_golden_pcap()
    for _n in _fixtures('ktd5_'):
        test_ktd5_inconsistent_fixtures_are_schema_valid_but_fail_the_rule(_n)
    print('ok  detection-capability.v1 contract')
