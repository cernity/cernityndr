from datetime import datetime
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

SCHEMA = json.loads(Path(__file__).with_name('case.schema.json').read_text())
FORMATS = FormatChecker()


@FORMATS.checks('date-time', raises=ValueError)
def valid_timestamp(value):
    return not isinstance(value, str) or datetime.fromisoformat(value.upper().replace('Z', '+00:00')).tzinfo is not None


VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FORMATS)


def case():
    ts = '2026-09-28T12:00:00Z'
    return {
        'case_id': 'c1', 'tenant': 'acme', 'title': 'Suspicious beaconing',
        'owner': 'alice', 'assignees': ['bob'], 'status': 'investigating',
        'notes': [{'author': 'alice', 'text': 'Started triage', 'ts': ts}],
        'linked_findings': ['f1', 'f2'],
        'linked_entities': [{'type': 'ip', 'value': '192.0.2.1'}],
        'created': ts, 'updated': ts,
        'audit': [{'event': 'created', 'actor': 'alice', 'ts': ts,
                   'detail': {'owner': 'alice'}}],
    }


def test_schema_valid():
    Draft202012Validator.check_schema(SCHEMA)
    VALIDATOR.validate(case())


@pytest.mark.parametrize('status', ['new', 'investigating', 'resolved', 'closed'])
def test_statuses(status):
    doc = case()
    doc['status'] = status
    VALIDATOR.validate(doc)


def test_owner_may_be_null():
    doc = case()
    doc['owner'] = None                 # an unowned case is valid
    VALIDATOR.validate(doc)


@pytest.mark.parametrize('field', SCHEMA['required'])
def test_missing_required(field):
    doc = case()
    del doc[field]
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize('change', [
    {'status': 'archived'},                                    # not in the enum
    {'audit': []},                                             # must have >=1 event
    {'assignees': ['bob', 'bob']},                             # uniqueItems
    {'linked_findings': ['f1', 'f1']},                         # uniqueItems
    {'linked_entities': [{'type': 'mac', 'value': 'x'}]},      # entity type not in enum
    {'linked_entities': [{'type': 'ip'}]},                     # entity missing value
    {'notes': [{'author': 'a', 'text': 'x'}]},                # note missing ts
    {'audit': [{'event': 'wat', 'actor': 'a', 'ts': '2026-09-28T12:00:00Z'}]},  # bad event
    {'created': 'not-a-time'},
    {'updated': '2026-09-28T12:00:00'},                        # naive (no tz)
    {'title': '   '},                                          # blank
    {'tenant': ''},
    {'extra': 1},                                              # additionalProperties false
])
def test_malformed(change):
    doc = case()
    doc.update(change)
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize('event', SCHEMA['$defs']['audit_event']['properties']['event']['enum'])
def test_api_audit_metadata(event):
    doc = case()
    doc['audit'].append({'event': event, 'actor': 'server-derived-analyst',
                         'ts': doc['updated'], 'detail': {
                             'audit_id': 'request-event-id', 'tenant': doc['tenant'],
                             'resource_type': 'case', 'resource_id': doc['case_id'],
                             'before_hash': 'a' * 64, 'after_hash': 'b' * 64,
                             'request_id': 'request-id', 'source_ip': '127.0.0.1',
                             'outcome': 'success', 'noop': True}})
    VALIDATOR.validate(doc)


@pytest.mark.parametrize('field', ['actor', 'ts', 'event'])
def test_api_audit_missing_identity_or_event(field):
    doc = case()
    del doc['audit'][0][field]
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)
