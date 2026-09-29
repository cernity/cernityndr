import copy
import json
import socket
import urllib.request
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker


def test_replay_is_deterministic_and_read_only(service, monkeypatch):
    s = service
    before = copy.deepcopy((s.sources.dns, s.sources.rows, s.sources.case_doc))
    snapshot = s.queries.materialize(s.sources, 'A', s.request)
    reads = list(s.sources.reads)

    def forbidden(*args, **kwargs):
        raise AssertionError('network / action / backend invocation in engine')

    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(urllib.request, 'urlopen', forbidden)
    monkeypatch.setattr(s.queries, 'urlopen', forbidden)
    monkeypatch.setattr(s.sources, 'observations', forbidden)
    monkeypatch.setattr(s.sources, 'findings', forbidden)
    monkeypatch.setattr(s.sources, 'case', forbidden)
    one = s.engine.run(s.request, snapshot)
    two = s.engine.run(s.request, snapshot)
    assert one == two
    assert reads == s.sources.reads
    assert before == (s.sources.dns, s.sources.rows, s.sources.case_doc)
    assert all(isinstance(a, str) for a in one['recommended_actions'])
    schema = json.loads((Path(__file__).resolve().parents[2] / 'contracts/investigation.schema.json').read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(one)


def test_revision_and_tenant_change_identity(service):
    s = service
    first = s.engine.run(s.request, s.queries.materialize(s.sources, 'A', s.request))
    s.sources.rows[0]['revision'] = 2
    second = s.engine.run(s.request, s.queries.materialize(s.sources, 'A', s.request))
    assert first['investigation_id'] != second['investigation_id']
    for row in s.sources.rows:
        row['tenant_id'] = 'B'
    s.sources.dns[0]['tenant'] = 'B'
    third = s.engine.run(s.request, s.queries.materialize(s.sources, 'B', s.request))
    assert second['investigation_id'] != third['investigation_id']


def test_snapshot_does_not_alias_sources_or_results(service):
    s = service
    snapshot = s.queries.materialize(s.sources, 'A', s.request)
    first = s.engine.run(s.request, snapshot)
    s.sources.rows.clear()
    first['steps'][0]['result_refs'].clear()
    assert s.engine.run(s.request, snapshot)['steps'][0]['result_refs']


@pytest.mark.parametrize('kind,version', [('raw.sql', '1'), ('evidence.dns', ''), ('evidence.dns', '2')])
def test_query_registry_fails_closed(service, kind, version):
    s = service
    snapshot = s.queries.materialize(s.sources, 'A', s.request)
    with pytest.raises(ValueError):
        snapshot.execute({'kind': kind, 'version': version, 'params': s.request})


@pytest.mark.parametrize('change', [{'tenant': 'B'}, {'entity_id': ''}, {'finding_ids': []},
                                   {'window': {'from': 'bad', 'to': 'bad'}}, {'reason': None},
                                   {'window': {'from': '2026-09-01', 'to': '2026-09-28'}}])
def test_request_validation(service, change):
    with pytest.raises(ValueError):
        service.queries.validate_request({**service.request, **change})
