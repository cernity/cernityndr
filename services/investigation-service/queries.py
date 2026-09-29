"""Only I/O boundary: shipped evidence query, persisted findings, read-only case API.

Intel steps reuse the shipped matcher's persisted threat_intel findings. No new
intel lookup, scoring, detection, or evidence/case mutation occurs here.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

from playbooks import c2_triage

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('investigation_evidence_query',
                                             ROOT / 'services/evidence-service/query.py')
evidence = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(evidence)
MAX_RECORDS = 10000
BEACON_DETECTORS = {'beacon', 'beacon_fqdn'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def validate_request(value):
    if not isinstance(value, dict) or set(value) - {'entity_id', 'finding_ids', 'reason', 'window', 'case_id'}:
        raise ValueError('unsupported request fields')
    result = copy.deepcopy(value)
    evidence.validate_entity(result.get('entity_id'))
    ids = result.get('finding_ids')
    if (not isinstance(ids, list) or not 1 <= len(ids) <= 100
            or any(not isinstance(i, str) or not i.strip() or len(i) > 256 for i in ids)):
        raise ValueError('finding_ids must contain 1..100 identifiers')
    result['finding_ids'] = sorted(set(ids))
    reason = result.get('reason')
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 1024:
        raise ValueError('reason is required (maximum 1024 characters)')
    window = result.get('window')
    if not isinstance(window, dict) or set(window) != {'from', 'to'}:
        raise ValueError('window requires from and to')
    frm, to = evidence.parse_window(window['from'], window['to'])
    if to - frm > evidence.MAX_WINDOW:
        raise ValueError('window must not exceed one day')
    result['window'] = {'from': evidence._iso(frm), 'to': evidence._iso(to)}
    if 'case_id' in result:
        case_id = result['case_id']
        if not isinstance(case_id, str) or not case_id.strip() or len(case_id) > 256:
            raise ValueError('invalid case_id')
    return result


class Snapshot:
    """In-memory query boundary; exact kind/version/params matching fails closed."""
    def __init__(self, tenant, request, results):
        self.tenant = tenant
        self._request = copy.deepcopy(request)
        self._results = copy.deepcopy(results)
        self.digest = hashlib.sha256(canonical(results).encode()).hexdigest()

    def execute(self, query):
        if (query['version'] != '1' or query['params'] != self._request
                or query['kind'] not in self._results):
            raise ValueError('unsupported query or snapshot parameters')
        return copy.deepcopy(self._results[query['kind']])


class Sources:
    def __init__(self, client, case_url=None, case_tokens=None):
        self.client = client
        self.case_url = case_url
        self.case_tokens = case_tokens or {}

    def observations(self, tenant, request):
        frm, to = evidence.parse_window(request['window']['from'], request['window']['to'])
        rows, after = [], ''
        while True:
            page = evidence.fetch_observations(self.client, [tenant], request['entity_id'],
                                               frm, to, 'dns', 1000, after)
            rows.extend(page['observations'])
            if len(rows) > MAX_RECORDS:
                raise ValueError('too many observations; narrow the window')
            if page['next'] is None:
                return rows
            nxt = evidence._parse_ts(page['next'])
            cursor = page.get('next_after', '')
            if (nxt, cursor) <= (frm, after):
                raise RuntimeError('non-advancing evidence cursor')
            frm, after = nxt, cursor

    def findings(self, tenant, request):
        # Match the finding-service's max-revision read pattern. Filter entity/time
        # AFTER selecting the current revision, so stale rows cannot reappear.
        sql = '''SELECT * FROM (
          SELECT finding_id, tenant_id, detector_id, category, first_seen, last_seen,
                 entities, revision, state, confidence, detector_version, severity
          FROM ndr.finding WHERE tenant_id = {tenant:String}
          ORDER BY revision DESC, ingested_at DESC LIMIT 1 BY tenant_id, finding_id
        ) WHERE first_seen < {until:DateTime64(3, 'UTC')}
            AND last_seen >= {frm:DateTime64(3, 'UTC')}
            AND arrayExists(e -> JSONExtractString(e, 'value') = {entity:String},
                            JSONExtractArrayRaw(entities))
        ORDER BY finding_id LIMIT 10001'''
        frm, to = evidence.parse_window(request['window']['from'], request['window']['to'])
        result = self.client.query(sql, parameters={'tenant': tenant, 'entity': request['entity_id'],
                                                    'frm': frm, 'until': to})
        rows = [dict(zip(result.column_names, r)) for r in result.result_rows]
        if len(rows) > MAX_RECORDS:
            raise ValueError('too many findings; narrow the window')
        for row in rows:
            for field in ('first_seen', 'last_seen'):
                row[field] = evidence._iso(evidence._parse_ts(row[field]))
            if isinstance(row['entities'], str):
                row['entities'] = json.loads(row['entities'])
        return rows

    def case(self, tenant, case_id):
        # Credentials are provisioned server-side per tenant, never forwarded from
        # an investigation request. Only the shipped GET endpoint is reachable.
        if not self.case_url or tenant not in self.case_tokens:
            raise RuntimeError('case reader not configured')
        req = Request(self.case_url.rstrip('/') + '/cases/' + quote(case_id, safe=''),
                      headers={'Authorization': 'Bearer ' + self.case_tokens[tenant]})
        with urlopen(req, timeout=5) as response:
            return json.load(response)


def materialize(sources, tenant, request):
    """Take a bounded read snapshot before invoking the engine; no writes."""
    observations = sources.observations(tenant, request)
    findings = sources.findings(tenant, request)
    frm, to = evidence.parse_window(request['window']['from'], request['window']['to'])
    entity = request['entity_id']
    for row in observations + findings:
        if row.get('tenant', row.get('tenant_id')) != tenant:
            raise PermissionError('forbidden')
        if entity not in {e['value'] for e in row.get('entities', [])}:
            raise RuntimeError('backend returned unrelated entity')
    for row in observations:
        if row['type'] != 'dns' or not frm <= evidence._parse_ts(row['ts']['normalized']) < to:
            raise RuntimeError('backend returned unrelated observation')
    for row in findings:
        if not (evidence._parse_ts(row['first_seen']) < to and evidence._parse_ts(row['last_seen']) >= frm):
            raise RuntimeError('backend returned unrelated finding')
    if not set(request['finding_ids']) <= {f['finding_id'] for f in findings}:
        raise KeyError('trigger finding not found in entity window')
    history = findings
    case = None
    if request.get('case_id'):
        case = sources.case(tenant, request['case_id'])
        if case.get('tenant') != tenant:
            raise PermissionError('forbidden')
        if case.get('case_id') != request['case_id'] or entity not in {e['value'] for e in case['linked_entities']}:
            raise ValueError('case does not link the entity')
        if not set(request['finding_ids']) <= set(case['linked_findings']):
            raise ValueError('case does not link the trigger findings')
        history = [f for f in findings if f['finding_id'] in case['linked_findings']]
    selections = [observations,
                  [f for f in findings if f['detector_id'] in BEACON_DETECTORS],
                  [f for f in findings if f['detector_id'] == 'threat_intel'], history]
    results = {}
    for (_, kind, _), rows in zip(c2_triage.STEPS, selections):
        rows = sorted(rows, key=canonical)
        results[kind] = {'refs': sorted({r.get('obs_id', r.get('finding_id')) for r in rows}),
                         'records': rows}
    if case is not None:
        results['case.entity_history']['case'] = case
    return Snapshot(tenant, request, results)
