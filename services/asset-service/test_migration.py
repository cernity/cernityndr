"""U3b migration is additive; the shipped DDL remains byte-identical."""
import hashlib
from pathlib import Path
import re

INIT = Path(__file__).resolve().parents[2] / 'deploy/clickhouse/init'
SCALARS = ('username', 'role', 'os_hint', 'criticality', 'owner')
LISTS = ('applications', 'listening_services', 'certificates', 'ja4')


def test_migration_is_only_additive_with_exact_columns_and_types():
    sql = re.sub(r'--[^\n]*', '', (INIT / '07-entity-graph.sql').read_text())
    statements = [s.strip() for s in sql.split(';') if s.strip()]
    expected = {**dict.fromkeys(SCALARS, 'Nullable(String)'),
                **dict.fromkeys(LISTS, 'Array(String) DEFAULT []'),
                'attribute_provenance': "String DEFAULT ''"}
    assert len(statements) == len(expected)
    found = {}
    for statement in statements:
        match = re.fullmatch(r'ALTER TABLE ndr\.asset ADD COLUMN IF NOT EXISTS (\w+) (.+)',
                             statement)
        assert match, statement
        assert match[1] not in found
        found[match[1]] = match[2]
    assert found == expected
    assert not re.search(r'\b(DROP|MODIFY|DELETE|TRUNCATE|RENAME|UPDATE)\b', sql, re.I)


def test_shipped_ddl_unchanged():
    assert hashlib.sha256((INIT / '03-session-reconstruction.sql').read_bytes()).hexdigest() == (
        '5fc1bcec726a25ba0ca84a33dd21749efe3491f1184f0940a5bd6a34e31440aa')
