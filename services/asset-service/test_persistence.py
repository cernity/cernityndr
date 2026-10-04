"""Asset snapshots survive a fresh process without inventing observations."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import resolution

SCALARS = ('username', 'role', 'os_hint', 'criticality', 'owner')
LISTS = ('applications', 'listening_services', 'certificates', 'ja4')
TS = '2026-09-28T12:00:00.000Z'
KEY = 'ip:10.0.0.5'


def fresh_app():
    spec = importlib.util.spec_from_file_location('asset_persistence_app',
                                                Path(__file__).with_name('app.py'))
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    return app


class FakeCH:
    def __init__(self):
        self.rows = []
        self.fail = False

    def insert(self, table, rows, column_names):
        assert table == 'ndr.asset'
        assert len(column_names) == len(set(column_names))
        assert all(len(row) == len(column_names) for row in rows)
        if self.fail:
            raise RuntimeError('insert failed')
        self.rows.extend(copy.deepcopy([dict(zip(column_names, row)) for row in rows]))

    def query(self, sql, parameters):
        if 'FROM ndr.asset FINAL' in sql:
            assert 'WHERE tenant_id = {tenant:String}' in sql
            cols = sql.split('SELECT ', 1)[1].split(' FROM ', 1)[0].split(', ')
            rows = [[row[col] for col in cols] for row in self.rows
                    if row['tenant_id'] == parameters['tenant']]
            return SimpleNamespace(column_names=cols, result_rows=copy.deepcopy(rows))
        assert ('ndr.asset_fact FINAL' in sql or 'ndr.identity_observation FINAL' in sql
                or 'ndr.entity_relationship FINAL' in sql)
        return SimpleNamespace(column_names=[], result_rows=[])


@pytest.mark.parametrize('attributes', [
    {'username': 'alice', 'role': 'server', 'listening_services': ['tcp/443']},
    dict(username='alice', role='server', os_hint='Linux', criticality='high', owner='ops',
         applications=['nginx'], listening_services=['tcp/443'],
         certificates=['sha256:abc'], ja4=['t13d1516h2']),
    {},
])
def test_flush_restore_round_trip(attributes):
    app = fresh_app()
    original = resolution.merge(None, dict(ip='10.0.0.5', src='test', **attributes), TS)
    app._assets[KEY] = copy.deepcopy(original)
    app._dirty.add(KEY)
    ch = FakeCH()
    app.flush(ch)
    assert not app._dirty
    row = ch.rows[0]
    assert set(row) == set(app.COLS)
    for attr in SCALARS:
        assert row[attr] == attributes.get(attr)
    for attr in LISTS:
        assert row[attr] == attributes.get(attr, [])
    provenance = original.get('attribute_provenance')
    assert row['attribute_provenance'] == (json.dumps(
        provenance, sort_keys=True, separators=(',', ':'), ensure_ascii=False) if provenance else '')
    # Same key in another tenant must not contaminate the snapshot.
    ch.rows.append(dict(copy.deepcopy(row), tenant_id='other', username='intruder'))
    restarted = fresh_app()
    restarted.restore_state(ch)
    assert restarted._assets == {KEY: original}
    assert not restarted._dirty
    # A subsequent ordinary observation retains the rehydrated additions.
    merged = resolution.merge(restarted._assets[KEY], {'ip': '10.0.0.6'}, TS)
    for attr, value in attributes.items():
        assert merged[attr] == value
    assert merged.get('attribute_provenance') == provenance


@pytest.mark.parametrize('empty', [None, ''])
def test_empty_attributes_use_storage_defaults(empty):
    app = fresh_app()
    asset = resolution.merge(None, {'ip': '10.0.0.5'}, TS)
    original = copy.deepcopy(asset)
    asset.update(dict.fromkeys(SCALARS, empty))
    asset.update(dict.fromkeys(LISTS, None if empty is None else []))
    asset['attribute_provenance'] = None if empty is None else {}
    app._assets[KEY] = asset
    app._dirty.add(KEY)
    ch = FakeCH()
    app.flush(ch)
    restarted = fresh_app()
    restarted.restore_state(ch)
    assert restarted._assets == {KEY: original}


def test_failed_asset_insert_keeps_dirty_and_does_not_commit():
    app = fresh_app()
    app._assets[KEY] = resolution.merge(None, {'username': 'alice'}, TS)
    app._dirty.add(KEY)
    ch = FakeCH()
    ch.fail = True
    commits = []
    consumer = SimpleNamespace(commit=lambda: commits.append(True))
    with pytest.raises(RuntimeError, match='insert failed'):
        app.persist_and_commit(ch, consumer)
    assert app._dirty == {KEY}
    assert not commits
    ch.fail = False
    app.persist_and_commit(ch, consumer)
    assert commits == [True]
    assert ch.rows[0]['username'] == 'alice'
    assert not app._dirty
