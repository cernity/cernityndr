"""U10 wire payload and mixed-record durability tests; no external SIEM required."""
import copy
import json

import pytest

import adapters
from adapters import DurableSink, ElasticsearchAdapter, SplunkAdapter, export_record
from forwarder import handle_batch


def investigation(tenant="acme", identity="inv:" + "a" * 64):
    window = {"from": "2026-09-29T00:00:00Z", "to": "2026-09-29T01:00:00Z"}
    return {"schema": "investigation.v1", "investigation_id": identity,
            "tenant": tenant, "entity_id": "entity:1",
            "trigger": {"finding_ids": ["f1", "f2"], "reason": "investigate"},
            "window": window, "status": "insufficient_evidence",
            "steps": [{"playbook_step": "history", "query": {
                "kind": "history", "version": "1", "params": {
                    "entity_id": "entity:1", "finding_ids": ["f1", "f2"],
                    "reason": "investigate", "window": window}},
                "result_refs": [], "decision": "insufficient_evidence", "explanation": "No history"}],
            "conclusion": {"classification": "inconclusive", "confidence": 0,
                           "evidence_refs": []}, "recommended_actions": [],
            "engine": {"playbook": "default", "version": "1"}}


def verdict(tenant="acme", revision=1):
    return {"record_kind": "verdict", "case_id": "case:1", "tenant": tenant,
            "verdict_revision": revision, "verdict": "true_positive",
            "linked_findings": ["f1", "f2"], "incident_id": "incident:1"}


class Receiver:
    def __init__(self, fail=False):
        self.fail, self.rows = fail, []

    def emit_batch(self, rows):
        if self.fail:
            raise OSError("receiver unavailable")
        self.rows.extend(copy.deepcopy(rows))


@pytest.mark.parametrize("kind", ["splunk", "elasticsearch", "opensearch"])
@pytest.mark.parametrize("make_record", [investigation, verdict])
def test_wire_export(monkeypatch, tmp_path, kind, make_record):
    monkeypatch.setenv("SPLUNK_HEC_URL", "https://splunk.invalid")
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "test")
    requests = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return b'{"items":[{"index":{"status":201}}]}'

    def send(req, **kwargs):
        requests.append(req)
        return Response()

    monkeypatch.setattr(adapters.urllib.request, "urlopen", send)
    record = make_record()
    original = copy.deepcopy(record)
    inner = adapters._make(kind)
    sink = DurableSink(inner, kind, dlq_dir=str(tmp_path), retries=0)
    handle_batch([record, copy.deepcopy(record)], sink)
    handle_batch([record], DurableSink(inner, kind, dlq_dir=str(tmp_path)))
    if kind == "splunk":
        assert len(requests) == 1
        doc = json.loads(requests[0].data)["event"]
        assert doc["vendor_finding_id"] == ["f1", "f2"]
        assert doc["vendor_incident_id"] == record.get("incident_id")
        assert doc["vendor_investigation_id"] == record.get("investigation_id")
    else:
        bulk = [r for r in requests if r.full_url.endswith("/_bulk")]
        assert len(bulk) == 1
        action, doc = map(json.loads, bulk[0].data.decode().splitlines())
        assert action["index"]["_id"] == inner._doc_id(record)
        assert doc["event.id"] == ["f1", "f2"]
        assert doc["cernity.incident_id"] == record.get("incident_id")
        assert doc["cernity.investigation_id"] == record.get("investigation_id")
    assert doc["tenant_id"] == "acme"
    assert record == original
    assert sink.delivered == 1


@pytest.mark.parametrize("make_record", [investigation, verdict])
def test_tenant_isolation_restart_compaction_and_dlq(tmp_path, make_record):
    inner = Receiver(fail=True)
    sink = DurableSink(inner, "test", dlq_dir=str(tmp_path), retries=0)
    rows = [make_record("a"), make_record("b")]
    handle_batch(rows + rows, sink)
    assert sink.dead_lettered == 2
    entries = [json.loads(line) for line in (tmp_path / "dlq-test.jsonl").read_text().splitlines()]
    assert [r["record"]["tenant_id"] for r in entries] == ["a", "b"]
    assert sink.compact_ledger() == 2
    restarted = DurableSink(inner, "test", dlq_dir=str(tmp_path), retries=0)
    handle_batch(rows, restarted)
    assert restarted.dead_lettered == 0
    inner.fail = False
    assert restarted.replay() == (2, 0)
    assert restarted.replay() == (0, 0)
    assert len(inner.rows) == 2
    assert restarted.dlq_gauge() == {"test": 0}
    assert restarted.compact_ledger() == 2
    handle_batch(rows, DurableSink(inner, "test", dlq_dir=str(tmp_path)))
    assert len(inner.rows) == 2
    assert ElasticsearchAdapter._doc_id(rows[0]) != ElasticsearchAdapter._doc_id(rows[1])


def test_mixed_kinds_and_verdict_revisions_are_distinct(tmp_path):
    inner = Receiver()
    sink = DurableSink(inner, "test", dlq_dir=str(tmp_path))
    rows = [{"finding_id": "same", "tenant_id": "acme"},
            investigation(identity="same"), verdict(), verdict(revision=2)]
    handle_batch(rows + rows, sink)
    assert sink.delivered == 4
    assert len({ElasticsearchAdapter._doc_id(r) for r in rows}) == 4
    assert sink.compact_ledger() == 4
    handle_batch(rows, DurableSink(inner, "test", dlq_dir=str(tmp_path)))
    assert len(inner.rows) == 4


@pytest.mark.parametrize("bad", [
    {"schema": "investigation.v1", "investigation_id": "i"},
    {"schema": "investigation.v1", "tenant": "a"},
    dict(investigation(), tenant_id="other"),
    dict(verdict(), verdict_revision=None),
    dict(verdict(), verdict_revision=True),
    {"case_id": "c", "tenant": "a", "status": "closed"},
    {"record_kind": "unknown"},
])
def test_invalid_identity_is_not_admitted(tmp_path, bad):
    inner = Receiver()
    sink = DurableSink(inner, "test", dlq_dir=str(tmp_path))
    with pytest.raises(ValueError):
        handle_batch([bad], sink)
    assert not inner.rows
    assert not list(tmp_path.iterdir())


def test_per_item_fallback_projects_native_records():
    class Single:
        def __init__(self):
            self.rows = []

        def emit(self, row):
            self.rows.append(row)

    single = Single()
    handle_batch([investigation(), verdict()], single)
    assert [r["record_kind"] for r in single.rows] == ["investigation", "verdict"]
    assert all(r["finding_id"] == ["f1", "f2"] for r in single.rows)


def test_partial_mixed_failure_only_replays_failed_record(tmp_path):
    class Partial(Receiver):
        def emit_batch(self, rows):
            failed = [r for r in rows if self.fail and r.get("record_kind") == "investigation"]
            self.rows.extend(r for r in rows if r not in failed)
            return failed

    inner = Partial(fail=True)
    sink = DurableSink(inner, "test", dlq_dir=str(tmp_path), retries=1, sleep=lambda _: None)
    handle_batch([{"finding_id": "f1"}, investigation(), verdict()], sink)
    assert sink.receipt() == {"name": "test", "delivered": 2, "dead_lettered": 1}
    assert len(inner.rows) == 2
    inner.fail = False
    assert sink.replay() == (1, 0)
    assert len(inner.rows) == 3


def test_failed_dlq_write_does_not_mark_investigation_terminal(tmp_path, monkeypatch):
    sink = DurableSink(Receiver(fail=True), "test", dlq_dir=str(tmp_path), retries=0)

    def fail(*args):
        raise OSError("disk full")

    monkeypatch.setattr(sink, "_dlq", fail)
    with pytest.raises(OSError):
        handle_batch([investigation()], sink)
    assert sink._ledger.terminal(investigation(), "test") is None
    assert sink.dead_lettered == 0
