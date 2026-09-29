"""Versioned triage of existing evidence, never a new detector or action runner."""
NAME = 'c2_triage'
VERSION = '1'
STEPS = (
    ('dns_context', 'evidence.dns', '1'),
    ('beacon_periodicity', 'finding.beacon', '1'),
    ('intel_match', 'finding.intel_match', '1'),
    ('entity_history', 'case.entity_history', '1'),
)


def decide(kind, result):
    count = len(result['refs'])
    if not count:
        return 'insufficient_evidence', 'No supporting records in the requested entity window; absence does not establish benign behavior.'
    descriptions = {
        'evidence.dns': 'DNS observations provide context, not a C2 verdict.',
        'finding.beacon': 'Existing beacon detector findings report periodicity; periodicity alone does not establish C2.',
        'finding.intel_match': 'Existing threat intel match findings were recorded in this window; this is not a fresh reputation lookup.',
        'case.entity_history': 'Entity findings provide history; optional case links restrict this history to linked findings.',
    }
    return 'supported', f'{count} supporting records. {descriptions[kind]}'


def conclude(steps):
    supported = {s['playbook_step'] for s in steps if s['decision'] == 'supported'}
    # Fixed rule confidence, not a calibrated probability or a detector score.
    if len(supported) == len(STEPS):
        return 'suspicious', 0.75, ['Review the referenced beacon and intel findings for a shared destination.',
                                   'Review DNS context and entity history before deciding on a response.']
    return 'inconclusive', 0.0, ['Review missing evidence before deciding on a response.']
