"""NetBox CMDB connector mapping — U4. Pins the one-way-ingest invariants: owner+criticality
ONLY, never fabricated, never an observed predicate; and the config-gated run loop is a clean
no-op without NETBOX_URL. Emitted facts are validated against contracts/asset-fact.schema.json.
"""
from datetime import datetime
import json
from pathlib import Path
import re
import sys

import pytest
from jsonschema import Draft202012Validator, FormatChecker

import netbox

SCHEMA = json.loads(
    (Path(__file__).parents[2] / 'contracts' / 'asset-fact.schema.json').read_text())
CHECKER = FormatChecker()


@CHECKER.checks('date-time', raises=ValueError)
def date_time(value):
    # jsonschema's optional RFC3339 dependency is absent in the base test env.
    if not isinstance(value, str):
        return True
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})', value):
        return False
    return datetime.fromisoformat(value.upper().replace('Z', '+00:00')).tzinfo is not None


VALIDATOR = Draft202012Validator(SCHEMA, format_checker=CHECKER)

SYNCED = '2026-10-02T12:00:00Z'
# Fake NetBox payload: dc-01 has owner (tenant) + criticality (+ observed-looking fields the
# connector MUST ignore); ws-02 has owner only; noip-03 has no primary IP (no entity_ref).
DEVICES = [
    {'name': 'dc-01', 'primary_ip4': {'address': '10.0.0.5/24'},
     'tenant': {'name': 'it-ops'},
     'device_role': {'name': 'domain-controller'},            # observed-ish — must be ignored
     'custom_fields': {'criticality': 'crown-jewel'}},
    {'name': 'ws-02', 'primary_ip4': {'address': '10.0.0.6/24'},
     'tenant': {'name': 'finance'}, 'custom_fields': {}},      # owner only, no criticality
    {'name': 'noip-03', 'tenant': {'name': 'it-ops'},
     'custom_fields': {'criticality': 'low'}},                 # no entity_ref -> skipped
]


def test_5_owner_and_criticality_facts_emitted_and_valid():
    facts = netbox.netbox_to_facts(DEVICES, 'acme', synced_at=SYNCED)
    for f in facts:
        VALIDATOR.validate(f)                 # each validates against asset-fact.schema.json
    by_ref = {}
    for f in facts:
        by_ref.setdefault(f['entity_ref'], set()).add(f['predicate'])
    assert by_ref['10.0.0.5'] == {'owner', 'criticality'}   # dc-01: exactly those two
    assert set(by_ref) == {'10.0.0.5', '10.0.0.6'}          # noip-03 produced nothing


def test_6_missing_field_never_fabricated():
    facts = netbox.netbox_to_facts(DEVICES, 'acme', synced_at=SYNCED)
    ws02 = [f for f in facts if f['entity_ref'] == '10.0.0.6']
    assert [f['predicate'] for f in ws02] == ['owner']       # no criticality fabricated


def test_7_never_emits_observed_predicate():
    facts = netbox.netbox_to_facts(DEVICES, 'acme', synced_at=SYNCED)
    assert facts, 'expected some facts'
    assert all(f['predicate'] in ('owner', 'criticality') for f in facts)


def test_8_no_op_when_netbox_url_unset(monkeypatch):
    monkeypatch.delenv('NETBOX_URL', raising=False)
    created = []
    monkeypatch.setattr(netbox.ndr_runtime, 'make_producer',
                        lambda *a, **k: created.append(1))
    netbox.run()
    assert created == []                      # clean no-op: no producer created


def test_9_deterministic():
    a = netbox.netbox_to_facts(DEVICES, 'acme', synced_at=SYNCED)
    b = netbox.netbox_to_facts(DEVICES, 'acme', synced_at=SYNCED)
    assert a == b


def test_10_mapping_has_no_wall_clock_fallback():
    # synced_at is a REQUIRED explicit input: the mapping must not read a clock, so omitting it is
    # a TypeError, not a silently-stamped (non-deterministic) fact.
    try:
        netbox.netbox_to_facts(DEVICES, 'acme')
        raise AssertionError('synced_at must be a required explicit input (no wall-clock fallback)')
    except TypeError:
        pass


def test_11_no_op_when_netbox_token_unset(monkeypatch):
    # Half-configured (URL set, token absent) must NOT create a producer or fetch unauthenticated.
    monkeypatch.setenv('NETBOX_URL', 'https://netbox.example')
    monkeypatch.delenv('NETBOX_TOKEN', raising=False)
    created, fetched = [], []
    monkeypatch.setattr(netbox.ndr_runtime, 'make_producer', lambda *a, **k: created.append(1))
    monkeypatch.setattr(netbox, '_fetch_devices', lambda *a, **k: fetched.append(1) or [])
    netbox.run()
    assert created == [] and fetched == []            # clean no-op: no producer, no fetch


class _Resp:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self._body


def _fake_requests(pages, log):
    class _FakeRequests:
        @staticmethod
        def get(url, headers=None, timeout=None):
            log.append((url, headers))
            return _Resp(pages[url])
    return _FakeRequests


def test_12_fetch_follows_all_pages(monkeypatch):
    base = 'https://netbox.example'
    pages = {
        base + '/api/dcim/devices/': {
            'results': [{'name': 'a'}], 'next': base + '/api/dcim/devices/?limit=1&offset=1'},
        base + '/api/dcim/devices/?limit=1&offset=1': {
            'results': [{'name': 'b'}], 'next': None},     # last page: next=null
    }
    calls = []
    monkeypatch.setitem(sys.modules, 'requests', _fake_requests(pages, calls))
    devices = netbox._fetch_devices(base, 'tok')
    assert [d['name'] for d in devices] == ['a', 'b']      # BOTH pages ingested
    assert len(calls) == 2
    assert all(h == {'Authorization': 'Token tok'} for _, h in calls)


class _Future:
    def __init__(self, fail=False):
        self._fail = fail

    def get(self, timeout=None):
        if self._fail:
            raise RuntimeError('broker rejected the record')   # delivery failed


class _FakeProducer:
    def __init__(self, fail_send=False):
        self.sent, self.flushed, self.closed = [], 0, 0
        self._fail_send = fail_send

    def send(self, topic, key=None, value=None):
        self.sent.append((topic, key, value))
        return _Future(self._fail_send)

    def flush(self):
        self.flushed += 1

    def close(self):
        self.closed += 1


def _configured_run(monkeypatch, producer, fetch=lambda *a, **k: DEVICES):
    monkeypatch.setenv('NETBOX_URL', 'https://netbox.example')
    monkeypatch.setenv('NETBOX_TOKEN', 'tok')
    monkeypatch.setattr(netbox.ndr_runtime, 'make_producer', lambda *a, **k: producer)
    monkeypatch.setattr(netbox, '_fetch_devices', fetch)
    netbox.run()


def test_14_successful_sync_flushes_and_closes_producer(monkeypatch):
    prod = _FakeProducer()
    _configured_run(monkeypatch, prod)
    assert [t for t, _, _ in prod.sent] == [netbox.ASSET_FACT_TOPIC] * 3  # dc-01 x2 + ws-02 x1
    assert prod.flushed == 1 and prod.closed == 1                         # flushed, then closed


def test_15_failed_delivery_cannot_report_a_successful_sync(monkeypatch):
    # A send whose broker ACK fails must abort the sync: the success path (flush + "emitted" log)
    # is NEVER reached, yet the producer is still closed (no leak on the error path).
    prod = _FakeProducer(fail_send=True)
    with pytest.raises(RuntimeError):
        _configured_run(monkeypatch, prod)
    assert prod.flushed == 0        # never reached the success flush/log — not a successful sync
    assert prod.closed == 1         # closed anyway (finally)


def test_16_producer_closed_when_fetch_raises(monkeypatch):
    # A fetch error before any send must still close the producer (no per-sync leak in the app loop).
    prod = _FakeProducer()

    def _boom(*a, **k):
        raise ConnectionError('netbox unreachable')

    with pytest.raises(ConnectionError):
        _configured_run(monkeypatch, prod, fetch=_boom)
    assert prod.sent == [] and prod.closed == 1


def test_13_pagination_restricted_to_netbox_origin(monkeypatch):
    base = 'https://netbox.example'
    pages = {
        base + '/api/dcim/devices/': {
            'results': [{'name': 'a'}], 'next': 'https://evil.example/steal'},  # off-origin next
    }
    requested = []
    monkeypatch.setitem(sys.modules, 'requests', _fake_requests(pages, requested))
    devices = netbox._fetch_devices(base, 'tok')
    assert [d['name'] for d in devices] == ['a']           # stops at the origin boundary
    assert [u for u, _ in requested] == [base + '/api/dcim/devices/']  # token never sent off-origin
