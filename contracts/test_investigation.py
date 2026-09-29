import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

SCHEMA = json.loads(Path(__file__).with_name('investigation.schema.json').read_text())
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())


def investigation():
    window = {'from': '2026-09-28T00:00:00Z', 'to': '2026-09-29T00:00:00Z'}
    return {'schema': 'investigation.v1', 'investigation_id': 'inv:' + 'a' * 64,
            'tenant': 'A', 'entity_id': '192.0.2.1',
            'trigger': {'finding_ids': ['f1'], 'reason': 'Triage finding'},
            'window': window, 'status': 'complete',
            'steps': [{'playbook_step': 'dns_context',
                       'query': {'kind': 'evidence.dns', 'version': '1',
                                 'params': {'entity_id': '192.0.2.1', 'finding_ids': ['f1'],
                                            'reason': 'Triage finding', 'window': window}},
                       'result_refs': ['obs:' + 'b' * 64], 'decision': 'supported',
                       'explanation': 'DNS observation provides context.'}],
            'conclusion': {'classification': 'suspicious', 'confidence': 0.75,
                           'evidence_refs': ['obs:' + 'b' * 64]},
            'recommended_actions': ['Review the evidence.'],
            'engine': {'playbook': 'c2_triage', 'version': '1'}}


def test_schema_and_valid_object():
    Draft202012Validator.check_schema(SCHEMA)
    VALIDATOR.validate(investigation())


@pytest.mark.parametrize('field', SCHEMA['required'])
def test_required_fields(field):
    doc = investigation()
    del doc[field]
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize('field', ['kind', 'version', 'params'])
def test_every_step_requires_versioned_query(field):
    doc = investigation()
    doc['steps'].append(copy.deepcopy(doc['steps'][0]))
    del doc['steps'][1]['query'][field]
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize('version', ['', None, 1])
def test_invalid_query_version(version):
    doc = investigation()
    doc['steps'][0]['query']['version'] = version
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


@pytest.mark.parametrize('actions', [[{'action': 'block', 'target': 'host'}], [None], [1], ['']])
def test_actions_are_only_nonempty_suggestion_strings(actions):
    doc = investigation()
    doc['recommended_actions'] = actions
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)


def test_unknown_fields_and_caller_tenant_in_query_rejected():
    doc = investigation()
    doc['steps'][0]['query']['params']['tenant'] = 'B'
    with pytest.raises(ValidationError):
        VALIDATOR.validate(doc)
