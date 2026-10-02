"""detection-registry.v1 contract test (plan 025 U1). Validates per-DETECTION registry
entry fixtures against the JSON Schema, plus one rule the schema shape enforces but cannot
fully check:

  * manifest_ref consistency: the schema's pattern enforces the detections/manifest/*.manifest.json
    SHAPE, but JSON Schema cannot check that the file EXISTS. manifest_ref must resolve to a real
    file under detections/manifest/ — asserted here as Python over the fixtures.

Lifecycle/promotion (which status transitions are legal) is U2 and intentionally NOT tested here.
change_history append-only / prior-entry immutability is a STORE invariant, covered by
services/detection-registry/test_store.py.

Fixture convention (contracts/fixtures/detection-registry/):
  valid_<source>.json   -> schema-valid AND manifest_ref resolves (one per source enum)
  schema_invalid_*.json -> must raise jsonschema.ValidationError
  inconsistent_*.json   -> schema-valid but manifest_ref does NOT resolve to a real file
"""
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

SCHEMA = json.loads(Path(__file__).with_name('detection-registry.schema.json').read_text())
VALIDATOR = Draft202012Validator(SCHEMA)
FIXTURES = Path(__file__).with_name('fixtures') / 'detection-registry'
REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCES = SCHEMA['properties']['source']['enum']


def _load(name):
    return json.loads((FIXTURES / name).read_text())


def _fixtures(prefix):
    return sorted(p.name for p in FIXTURES.glob(f'{prefix}*.json'))


def manifest_resolves(entry, root=REPO_ROOT):
    """manifest_ref must point at a real file UNDER detections/manifest/ (no escaping it)."""
    manifest_dir = (root / 'detections' / 'manifest').resolve()
    target = (root / entry['manifest_ref']).resolve()
    return target.is_file() and manifest_dir in target.parents


def test_schema_is_valid():
    Draft202012Validator.check_schema(SCHEMA)


def test_fixtures_exist():
    # guard against a silently-empty glob making the parametrized tests pass vacuously
    assert _fixtures('valid_'), 'no valid_* fixtures found'
    assert _fixtures('schema_invalid_'), 'no schema_invalid_* fixtures found'
    assert _fixtures('inconsistent_'), 'no inconsistent_* fixtures found'


def test_every_source_has_a_valid_fixture():
    # scenario 1: a valid entry for EACH source enum value exists and is covered.
    covered = {_load(n)['source'] for n in _fixtures('valid_')}
    assert covered == set(SOURCES), f'valid fixtures miss sources {set(SOURCES) - covered}'


@pytest.mark.parametrize('name', _fixtures('valid_'))
def test_valid_fixtures_pass(name):
    doc = _load(name)
    VALIDATOR.validate(doc)                       # scenario 1: a well-formed entry validates
    assert manifest_resolves(doc), f'{name} manifest_ref should resolve to a real file'


@pytest.mark.parametrize('name', _fixtures('schema_invalid_'))
def test_schema_invalid_fixtures_raise(name):
    # scenario 3: bad source/status enum (and missing/malformed manifest_ref) surface as a
    # schema ValidationError.
    with pytest.raises(ValidationError):
        VALIDATOR.validate(_load(name))


@pytest.mark.parametrize('field', SCHEMA['required'])
def test_missing_each_required_field_rejected(field):
    # breadth: every required top-level field is actually enforced.
    doc = _load('valid_dns.json')
    del doc[field]
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize('name', _fixtures('inconsistent_'))
def test_inconsistent_manifest_ref_is_schema_valid_but_fails_resolution(name):
    # scenario 2: manifest_ref with no matching file passes JSON Schema (shape is fine) but
    # fails the file-resolution consistency check.
    doc = _load(name)
    VALIDATOR.validate(doc)                       # schema alone cannot catch a dangling ref
    assert not manifest_resolves(doc), f'{name} should fail manifest_ref resolution'


if __name__ == '__main__':
    test_schema_is_valid()
    test_fixtures_exist()
    test_every_source_has_a_valid_fixture()
    for _n in _fixtures('valid_'):
        test_valid_fixtures_pass(_n)
    for _n in _fixtures('schema_invalid_'):
        test_schema_invalid_fixtures_raise(_n)
    for _f in SCHEMA['required']:
        test_missing_each_required_field_rejected(_f)
    for _n in _fixtures('inconsistent_'):
        test_inconsistent_manifest_ref_is_schema_valid_but_fails_resolution(_n)
    print('ok  detection-registry.v1 contract')
