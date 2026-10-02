"""U2 service inventory, schema and honest-evidence regression gate."""
import json
from collections import Counter
from pathlib import Path

import pytest

from contracts.test_detection_capability import VALIDATOR, ktd5_consistent

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ROOT / 'detections' / 'manifest'


def detector_services(services):
    """U2 detector naming convention plus the two non-suffix producers."""
    return {
        p.name for p in services.iterdir()
        if p.is_dir()
        and (p.name.endswith(('-detector', '-detectors'))
             or p.name in {'ids-alerts', 'threat-intel'})
        and (p / 'app.py').is_file() and (p / 'Dockerfile').is_file()
    }


def repo_file(root, reference):
    path = Path(reference)
    resolved = (root / path).resolve()
    assert not path.is_absolute(), f'expected repo-relative path: {reference}'
    assert resolved.is_relative_to(root.resolve()), f'path escapes repository: {reference}'
    assert resolved.is_file(), f'missing backing file: {reference}'
    return resolved


def validate_manifest(doc, root):
    VALIDATOR.validate(doc)
    assert ktd5_consistent(doc), 'contradictory capability/technique limitation'
    for references in doc['backing_tests'].values():
        for reference in references:
            repo_file(root, reference)
    if doc['status'] == 'verified_e2e':
        assert doc['backing_tests']['golden_pcap'], 'missing golden-PCAP test'
    else:
        assert doc['known_limitations'], 'unverified detection needs limitations'


def test_shipped_detector_manifest_coverage():
    services = detector_services(ROOT / 'services')
    paths = sorted(MANIFESTS.glob('*.manifest.json'))
    assert services and paths, 'empty detector or manifest inventory'
    docs = [json.loads(path.read_text()) for path in paths]
    counts = Counter(doc['detector_id'] for doc in docs)
    assert counts == Counter({name: 1 for name in services}), counts
    for path, doc in zip(paths, docs):
        assert path.name == f"{doc['detector_id']}.manifest.json"
        validate_manifest(doc, ROOT)
        repo_file(ROOT, doc['evidence_produced']['record'])


def test_discovery_detects_new_service(tmp_path):
    for name in ('new-detector', 'new-detectors', 'normalizer', 'unfinished-detector'):
        directory = tmp_path / name
        directory.mkdir()
        (directory / 'app.py').touch()
        if name != 'unfinished-detector':
            (directory / 'Dockerfile').touch()
    assert detector_services(tmp_path) == {'new-detector', 'new-detectors'}


@pytest.mark.parametrize('reference', ['missing.py', '../outside.py', '/tmp/outside.py', '.'])
def test_verified_e2e_rejects_unresolvable_backing(tmp_path, reference):
    doc = json.loads((MANIFESTS / 'dns-detector.manifest.json').read_text())
    doc['status'] = 'verified_e2e'
    doc['backing_tests'] = {'golden_pcap': [reference], 'benign_control': [], 'performance': []}
    with pytest.raises(AssertionError):
        validate_manifest(doc, tmp_path)


def test_verified_e2e_accepts_resolvable_backing(tmp_path):
    doc = json.loads((MANIFESTS / 'dns-detector.manifest.json').read_text())
    (tmp_path / 'test_golden.py').touch()
    doc['status'] = 'verified_e2e'
    doc['backing_tests'] = {'golden_pcap': ['test_golden.py'], 'benign_control': [], 'performance': []}
    validate_manifest(doc, tmp_path)


@pytest.mark.parametrize('service,terms', [
    ('behavioral-detectors', ('beaconing', 'tunneling')),
    ('dns-detector', ('dga',)),
    ('protocol-detectors', ('tls rarity',)),
])
def test_unverified_techniques_have_explicit_limitations(service, terms):
    doc = json.loads((MANIFESTS / f'{service}.manifest.json').read_text())
    if doc['status'] != 'verified_e2e':
        descriptions = [item['description'].lower() for item in doc['known_limitations']]
        for term in terms:
            assert any(term in text and 'not e2e-verified' in text for text in descriptions)
