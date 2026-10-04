"""Document the shipped consumer boundary without importing other services' app.py."""
import ast
from pathlib import Path
import re
import shlex

import pytest


ROOT = Path(__file__).resolve().parents[2]
SERVICE = ROOT / 'services/asset-service'
INIT = ROOT / 'deploy/clickhouse/init'
U3A_ATTRIBUTES = {
    'username', 'role', 'os_hint', 'criticality', 'owner',
    'applications', 'listening_services', 'certificates', 'ja4',
}


def _sql(path):
    return re.sub(r'--[^\n]*|/\*.*?\*/', '', path.read_text(), flags=re.S)


def test_image_copies_first_party_imports_before_app_smoke():
    tree = ast.parse((SERVICE / 'app.py').read_text())
    imports = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            imports.update(alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split('.')[0])
    first_party = {
        path.relative_to(ROOT).as_posix()
        for name in imports
        for directory in (SERVICE, ROOT / 'shared')
        if (path := directory / f'{name}.py').is_file()
    }
    assert {'resolution', 'relationships'} <= imports
    required = first_party | {'services/asset-service/app.py'}
    copied = set()
    smoke_found = False
    dockerfile = re.sub(r'\\\n', ' ', (SERVICE / 'Dockerfile').read_text())
    for line in dockerfile.splitlines():
        tokens = shlex.split(line, comments=True)
        if not tokens:
            continue
        if tokens[0].upper() == 'COPY' and tokens[-1] in ('.', './', '/app/'):
            copied.update(tokens[1:-1])
        if tokens == ['RUN', 'python', '-c', 'import app']:
            assert required <= copied, f'Missing image modules: {required - copied}'
            smoke_found = True
    assert smoke_found, 'Build must import app after copying its dependencies'


def test_correlation_asset_projection_survives_additive_migration():
    source = (ROOT / 'services/correlation-service/app.py').read_text()
    strings = [node.value for node in ast.walk(ast.parse(source))
               if isinstance(node, ast.Constant) and isinstance(node.value, str)]
    assert any(re.search(
        r'SELECT\s+asset_key\s+FROM\s+ndr\.asset\s+WHERE\b.*\bhas\s*\(\s*ip_set\s*,',
        value, re.I | re.S,
    ) for value in strings), 'Check the actual correlation lookup when its shape changes'

    ddl = _sql(INIT / '03-session-reconstruction.sql')
    table = re.search(r'CREATE TABLE IF NOT EXISTS ndr\.asset\s*\((.*?)\)\s*ENGINE',
                      ddl, re.I | re.S)
    assert table
    assert re.search(r'^\s*asset_key\s+String\s*,', table[1], re.M)
    assert re.search(r'^\s*ip_set\s+Array\(String\)\s*,', table[1], re.M)

    statements = [s.strip() for s in _sql(INIT / '07-entity-graph.sql').split(';')
                  if s.strip()]
    assert statements
    added = set()
    for statement in statements:
        # Full match deliberately rejects extra comma-separated ALTER actions.
        match = re.fullmatch(
            r'ALTER\s+TABLE\s+ndr\.asset\s+ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+'
            r'(\w+)\s+(?:Nullable\(String\)|Array\(String\)\s+DEFAULT\s+\[\]|'
            r"String\s+DEFAULT\s+'')", statement, re.I,
        )
        assert match, f'Non-additive or unexpected migration action: {statement}'
        assert match[1].lower() not in {'asset_key', 'ip_set'}
        added.add(match[1])
    assert U3A_ATTRIBUTES <= added


@pytest.mark.parametrize('service', ['anomaly-detector', 'finding-service'])
def test_independent_entity_consumers_do_not_read_u3a_asset_columns(service):
    # These services own their entity representation. Enforce the stronger shipped
    # boundary: no ndr.asset reads at all, including SELECT * (which would implicitly
    # read all nine attributes). Attribute names such as role may occur legitimately
    # in their own models; do not ban those words outside asset reads. This is a
    # documentary source guard, not a general SQL/data-flow analyzer.
    paths = sorted((ROOT / 'services' / service).rglob('*.py'))
    assert paths
    for path in paths:
        if path.name.startswith('test_'):
            continue
        tree = ast.parse(path.read_text())
        literals = '\n'.join(node.value for node in ast.walk(tree)
                             if isinstance(node, ast.Constant)
                             and isinstance(node.value, str))
        assert not re.search(r'\bndr\s*\.\s*asset\b', literals, re.I), (
            f'{path.relative_to(ROOT)} references ndr.asset; review reads of '
            f'{sorted(U3A_ATTRIBUTES)} against the independent entity contract'
        )
