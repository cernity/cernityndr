"""Pure deterministic reducer over a materialized typed-query snapshot.

No I/O clients, clock, randomness, detector invocation or action executor belong here.
The HTTP shell materializes reads before entering this boundary.
"""
import copy
import hashlib
import json

from playbooks import c2_triage


def run(request, snapshot):
    request = copy.deepcopy(request)
    steps = []
    for name, kind, version in c2_triage.STEPS:
        query = {'kind': kind, 'version': version, 'params': dict(request)}
        result = snapshot.execute(query)
        decision, explanation = c2_triage.decide(kind, result)
        steps.append({'playbook_step': name, 'query': query,
                      'result_refs': sorted(set(result['refs'])),
                      'decision': decision, 'explanation': explanation})
    classification, confidence, actions = c2_triage.conclude(steps)
    doc = {
        'schema': 'investigation.v1', 'tenant': snapshot.tenant,
        'entity_id': request['entity_id'],
        'trigger': {'finding_ids': request['finding_ids'], 'reason': request['reason']},
        'window': request['window'],
        'status': 'complete' if classification == 'suspicious' else 'insufficient_evidence',
        'steps': steps,
        'conclusion': {'classification': classification, 'confidence': confidence,
                       'evidence_refs': sorted({r for s in steps for r in s['result_refs']})},
        'recommended_actions': actions,
        'engine': {'playbook': c2_triage.NAME, 'version': c2_triage.VERSION},
    }
    # Include evidence content, not only IDs: a new finding revision changes identity.
    identity = json.dumps({'document': doc, 'snapshot': snapshot.digest}, sort_keys=True,
                          separators=(',', ':'), allow_nan=False)
    doc['investigation_id'] = 'inv:' + hashlib.sha256(identity.encode()).hexdigest()
    return doc
