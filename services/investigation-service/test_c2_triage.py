import copy
from types import SimpleNamespace

import pytest


def test_full_path_records_real_refs_and_query_versions(service):
    s = service
    s.request['case_id'] = 'c1'
    snapshot = s.queries.materialize(s.sources, 'A', s.request)
    doc = s.engine.run(s.request, snapshot)
    assert doc['status'] == 'complete'
    assert doc['conclusion']['classification'] == 'suspicious'
    assert [step['playbook_step'] for step in doc['steps']] == [
        'dns_context', 'beacon_periodicity', 'intel_match', 'entity_history']
    assert all(step['result_refs'] and step['query']['version'] == '1' for step in doc['steps'])
    assert doc['steps'][0]['result_refs'] == ['obs:' + 'a' * 64]
    assert doc['steps'][1]['result_refs'] == ['f-beacon']
    assert doc['steps'][2]['result_refs'] == ['f-intel']
    assert s.sources.reads == [('observations', 'A'), ('findings', 'A'), ('case', 'A')]


def test_missing_evidence_does_not_borrow_trigger_refs(service):
    s = service
    s.sources.dns.clear()
    s.sources.rows = s.sources.rows[:1]
    doc = s.engine.run(s.request, s.queries.materialize(s.sources, 'A', s.request))
    assert doc['status'] == 'insufficient_evidence'
    assert doc['conclusion']['classification'] == 'inconclusive'
    assert doc['steps'][0]['result_refs'] == doc['steps'][2]['result_refs'] == []


def test_fqdn_beacon_shipped_detector_name(service):
    s = service
    s.sources.rows[0]['detector_id'] = 'beacon_fqdn'
    doc = s.engine.run(s.request, s.queries.materialize(s.sources, 'A', s.request))
    assert doc['steps'][1]['result_refs'] == ['f-beacon']


def test_result_order_does_not_change_identity(service):
    s = service
    first = s.engine.run(s.request, s.queries.materialize(s.sources, 'A', s.request))
    s.sources.rows.reverse()
    assert first == s.engine.run(s.request, s.queries.materialize(s.sources, 'A', s.request))


def test_missing_trigger_and_unrelated_case_fail(service):
    s = service
    s.request['finding_ids'] = ['missing']
    with pytest.raises(KeyError):
        s.queries.materialize(s.sources, 'A', s.request)
    s.request['finding_ids'] = ['f-beacon']
    s.request['case_id'] = 'c1'
    s.sources.case_doc['linked_findings'] = []
    with pytest.raises(ValueError):
        s.queries.materialize(s.sources, 'A', s.request)
    s.sources.case_doc['tenant'] = 'B'
    with pytest.raises(PermissionError):
        s.queries.materialize(s.sources, 'A', s.request)


def test_backend_tenant_and_entity_are_verified(service):
    s = service
    s.sources.findings = lambda *args: [dict(s.sources.rows[0], tenant_id='B')]
    with pytest.raises(PermissionError):
        s.queries.materialize(s.sources, 'A', s.request)
    s.sources.findings = lambda *args: [dict(s.sources.rows[0], entities=[])]
    with pytest.raises(RuntimeError):
        s.queries.materialize(s.sources, 'A', s.request)


def test_evidence_pagination_uses_shipped_query(service):
    s = service
    calls = []
    obs = s.sources.dns[0]
    ts = s.queries.evidence._parse_ts(obs['ts']['normalized'])

    class Client:
        def query(self, sql, parameters):
            import json
            calls.append((sql, parameters))
            # First page fills the shipped page_size+1 boundary, tied timestamps.
            rows = [('obs:' + f'{i:064x}', ts, json.dumps(dict(obs, obs_id='obs:' + f'{i:064x}')))
                    for i in range(1, 1002)] if len(calls) == 1 else [
                        ('obs:' + f'{1001:064x}', ts, json.dumps(dict(obs, obs_id='obs:' + f'{1001:064x}')))]
            return SimpleNamespace(column_names=['obs_id', 'normalized_time', 'observation'], result_rows=rows)

    rows = s.queries.Sources(Client()).observations('A', s.request)
    assert len(rows) == len({r['obs_id'] for r in rows}) == 1001
    assert calls[1][1]['after'] == 'obs:' + f'{1000:064x}'
    assert all(c[1]['tenants'] == ['A'] and c[1]['type'] == 'dns' for c in calls)
    assert all('ndr.evidence_observations' in c[0] for c in calls)


def test_finding_read_is_tenant_bound_and_decodes_shipped_rows(service):
    s = service
    import json
    row = copy.deepcopy(s.sources.rows[0])
    row['entities'] = json.dumps(row['entities'])
    row['first_seen'] = s.queries.evidence._parse_ts(row['first_seen'])
    row['last_seen'] = s.queries.evidence._parse_ts(row['last_seen'])

    class Client:
        def query(self, sql, parameters):
            assert sql.strip().startswith('SELECT')
            assert 'LIMIT 1 BY tenant_id, finding_id' in sql
            assert parameters['tenant'] == 'A'
            assert parameters['entity'] == s.request['entity_id']
            return SimpleNamespace(column_names=list(row), result_rows=[list(row.values())])

    assert s.queries.Sources(Client()).findings('A', s.request) == [s.sources.rows[0]]


def test_case_adapter_only_gets_shipped_endpoint(service, monkeypatch):
    import io
    import json
    s = service
    calls = []

    def read(req, timeout):
        calls.append(req)
        assert timeout == 5
        return io.StringIO(json.dumps(s.sources.case_doc))

    monkeypatch.setattr(s.queries, 'urlopen', read)
    source = s.queries.Sources(None, 'http://case-service', {'A': 'reader-token'})
    assert source.case('A', 'c1') == s.sources.case_doc
    assert calls[0].get_method() == 'GET'
    assert calls[0].full_url == 'http://case-service/cases/c1'
    assert calls[0].get_header('Authorization') == 'Bearer reader-token'


def test_seeded_sources_conform_to_shipped_contracts(service):
    import json
    from pathlib import Path
    from jsonschema import Draft202012Validator, FormatChecker
    root = Path(__file__).resolve().parents[2] / 'contracts'
    for name, rows in [('observation', service.sources.dns), ('finding', service.sources.rows),
                       ('case', [service.sources.case_doc])]:
        validator = Draft202012Validator(json.loads((root / f'{name}.schema.json').read_text()),
                                         format_checker=FormatChecker())
        for row in rows:
            validator.validate(row)


def test_observation_overflow_fails_instead_of_partial_result(service, monkeypatch):
    s = service
    monkeypatch.setattr(s.queries, 'MAX_RECORDS', 1)
    monkeypatch.setattr(s.queries.evidence, 'fetch_observations',
                        lambda *args: {'observations': s.sources.dns * 2, 'next': None})
    with pytest.raises(ValueError, match='too many observations'):
        s.queries.Sources(None).observations('A', s.request)


def test_nonadvancing_cursor_fails(service, monkeypatch):
    s = service
    monkeypatch.setattr(s.queries.evidence, 'fetch_observations',
                        lambda *args: {'observations': [], 'next': s.request['window']['from'], 'next_after': ''})
    with pytest.raises(RuntimeError, match='non-advancing'):
        s.queries.Sources(None).observations('A', s.request)


def test_case_links_restrict_only_history(service):
    s = service
    s.request['case_id'] = 'c1'
    s.sources.case_doc['linked_findings'] = ['f-beacon']
    doc = s.engine.run(s.request, s.queries.materialize(s.sources, 'A', s.request))
    assert doc['steps'][2]['result_refs'] == ['f-intel']
    assert doc['steps'][3]['result_refs'] == ['f-beacon']
