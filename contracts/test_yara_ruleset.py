"""yara_ruleset.v1 contract test (Unit U3). Valid + invalid fixtures against the
JSON Schema (contracts/yara_ruleset.schema.json)."""
from datetime import datetime
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

SCHEMA = json.loads(Path(__file__).with_name('yara_ruleset.schema.json').read_text())
FORMATS = FormatChecker()


@FORMATS.checks('date-time', raises=ValueError)
def valid_timestamp(value):
    return not isinstance(value, str) or datetime.fromisoformat(value.upper().replace('Z', '+00:00')).tzinfo is not None


VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FORMATS)


def ruleset(**over):
    doc = {
        'id': 'rs-1a2b', 'name': 'baseline-malware', 'version': '2026.09.29',
        'sha256': 'a' * 64, 'source': 'rules-refresh',
        'created_at': '2026-09-29T00:00:00Z',
        'promoted_by': 'secops-admin', 'promoted_at': '2026-09-29T01:00:00Z',
        'status': 'active', 'target_mime_types': ['application/x-dosexec'],
        'max_file_size': 67108864, 'release_notes': 'initial baseline',
        'test_corpus_ref': 'minio://corpus/2026-09',
    }
    doc.update(over)
    return doc


def test_schema_is_valid():
    Draft202012Validator.check_schema(SCHEMA)


def test_full_row_validates():
    VALIDATOR.validate(ruleset())


@pytest.mark.parametrize('status', ['draft', 'shadow', 'active', 'retired'])
def test_all_statuses(status):
    VALIDATOR.validate(ruleset(status=status))


def test_draft_row_has_null_promotion():
    # a never-promoted draft carries null attribution, which must validate
    VALIDATOR.validate(ruleset(status='draft', promoted_by=None, promoted_at=None))


def test_empty_target_mime_types_ok():
    # [] means "applies to every scanned object"
    VALIDATOR.validate(ruleset(target_mime_types=[]))


@pytest.mark.parametrize('field', SCHEMA['required'])
def test_missing_required(field):
    doc = ruleset()
    del doc[field]
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize('change', [
    {'status': 'promoted'},                       # not in the lifecycle enum
    {'sha256': 'A' * 64},                         # uppercase hex not allowed
    {'sha256': 'a' * 63},                         # wrong length
    {'sha256': 'nothex' + 'a' * 58},
    {'created_at': 'not-a-date'},
    {'created_at': '2026-02-29T00:00:00Z'},
    {'created_at': '2026-09-29T00:00:00+00:60'},
    {'created_at': '2026-09-29T00:00:00Z\n'},
    {'target_mime_types': ['not-a-mime']},
    {'target_mime_types': ['text/*']},
    {'target_mime_types': ['text/plain; charset=utf-8']},
    {'target_mime_types': ['text/plain\n']},
    {'promoted_at': '2026-13-01T00:00:00Z'},      # bad month
    {'target_mime_types': 'application/x-dosexec'},  # must be a list, not a str
    {'target_mime_types': [123]},                 # items must be strings
    {'max_file_size': 0},                         # must be >= 1
    {'max_file_size': -1},
    {'max_file_size': 'big'},
    {'name': '   '},                              # blank name
    {'id': ''},
    {'unexpected': 'x'},                          # additionalProperties: false
])
def test_malformed_rejected(change):
    doc = ruleset()
    doc.update(change)
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


if __name__ == '__main__':
    test_schema_is_valid()
    VALIDATOR.validate(ruleset())
    print('ok  yara_ruleset.v1 contract')
