import json
import os
import tempfile

import adapters
from adapters import (FileAdapter, ElasticsearchAdapter, SplunkAdapter, WebhookAdapter,
                      SyslogCefAdapter, DevoAdapter, MultiAdapter, DurableSink, get_adapter)

F = {"finding_id": "f1", "detector_id": "beacon", "category": "c2", "severity": 8,
     "entities": [{"role": "src", "value": "10.0.0.5"}, {"role": "dst", "value": "203.0.113.10"}]}


def test_file_adapter_appends_jsonl():
    p = tempfile.mktemp()
    FileAdapter(p).emit_batch([{"finding_id": "a"}, {"finding_id": "b"}])
    assert [json.loads(x)["finding_id"] for x in open(p).read().splitlines()] == ["a", "b"]


def test_suppressed_dropped():
    p = tempfile.mktemp()
    FileAdapter(p).emit_batch([{"finding_id": "a", "state": "SUPPRESSED"}, {"finding_id": "b"}])
    assert [json.loads(x)["finding_id"] for x in open(p).read().splitlines()] == ["b"]


def test_es_doc_normalizes_dates():
    d = ElasticsearchAdapter._doc({"finding_id": "x", "last_seen": "2026-09-09 03:05:00"})
    assert d["@timestamp"] == "2026-09-09T03:05:00"


def test_es_failed_items_maps_per_item_bulk_outcomes():
    # §stage2: a 2xx bulk response with per-item errors must surface exactly the failed findings.
    fs = [{"finding_id": "a"}, {"finding_id": "b"}, {"finding_id": "c"}]
    ok = {"errors": False, "items": [{"index": {"status": 201}}] * 3}
    assert ElasticsearchAdapter._failed_items(fs, ok) == []                     # all landed
    mixed = {"errors": True, "items": [{"index": {"status": 201}},
                                       {"index": {"status": 429, "error": {"type": "es_rejected"}}},
                                       {"index": {"status": 200}}]}
    assert [f["finding_id"] for f in ElasticsearchAdapter._failed_items(fs, mixed)] == ["b"]
    allbad = {"errors": True, "items": [{"index": {"status": 503}}] * 3}
    assert len(ElasticsearchAdapter._failed_items(fs, allbad)) == 3             # none delivered
    short = {"errors": True, "items": [{"index": {"status": 201}}]}             # malformed/short
    assert len(ElasticsearchAdapter._failed_items(fs, short)) == 3             # unmapped -> all failed


def test_es_failed_items_rejects_malformed_response_structure():
    # R10: never trust the summary `errors` flag alone — a malformed/empty response cannot ack any item.
    fs = [{"finding_id": "a"}, {"finding_id": "b"}]
    assert len(ElasticsearchAdapter._failed_items(fs, {})) == 2                 # empty object acks nothing
    assert len(ElasticsearchAdapter._failed_items(fs, {"errors": False})) == 2  # flag-only, no items
    assert len(ElasticsearchAdapter._failed_items(fs, "not-json")) == 2         # non-dict
    long = {"errors": False, "items": [{"index": {"status": 201}}] * 3}         # more items than sent
    assert len(ElasticsearchAdapter._failed_items(fs, long)) == 2               # length mismatch -> all failed
    nostatus = {"errors": False, "items": [{"index": {}}, {"index": {"status": 201}}]}
    assert [f["finding_id"] for f in ElasticsearchAdapter._failed_items(fs, nostatus)] == ["a"]  # missing status


def test_es_source_events_in_source_and_mapping_guarded():
    # U5: source_events reaches the ES _source (whole finding is the body) and the index template
    # keeps it (+ summary/iocs) out of dynamic mapping so nested EVE keys can't explode it.
    d = ElasticsearchAdapter._doc({"finding_id": "x", "last_seen": "2026-09-09T03:05:00Z",
                                   "source_events": [{"event_type": "quic", "record": {"quic": {"ja4": "q13d.."}}}]})
    body = json.dumps(d)
    assert '"source_events"' in body and '"ja4": "q13d.."' in body   # native EVE in the stored doc
    tb = ElasticsearchAdapter._template_body("ndr-findings")
    props = tb["template"]["mappings"]["properties"]
    assert props["source_events"]["enabled"] is False
    assert props["summary"]["enabled"] is False and props["iocs"]["enabled"] is False


def test_es_doc_id_is_tenant_and_revision_scoped():
    # R02: two tenants sharing a finding_id must be DISTINCT documents; R03: each revision is retained.
    a = ElasticsearchAdapter._doc_id({"finding_id": "f1", "tenant_id": "t1", "revision": 1})
    b = ElasticsearchAdapter._doc_id({"finding_id": "f1", "tenant_id": "t2", "revision": 1})
    c = ElasticsearchAdapter._doc_id({"finding_id": "f1", "tenant_id": "t1", "revision": 2})
    assert a != b and a != c and len({a, b, c}) == 3
    assert ElasticsearchAdapter._doc_id({"finding_id": "f1"}) == "default:f1"    # no tenant/rev fallback


def test_ledger_scopes_obligations_by_tenant():
    # R02: the same finding_id+revision in two tenants are TWO obligations, delivered independently.
    d = tempfile.mkdtemp()
    led = adapters.DurableLedger(os.path.join(d, "obl.jsonl"))
    f_t1 = {"finding_id": "f1", "revision": 1, "tenant_id": "t1"}
    f_t2 = {"finding_id": "f1", "revision": 1, "tenant_id": "t2"}
    led.record([f_t1], "es", "delivered", "w1")
    assert led.terminal(f_t1, "es") == "delivered"
    assert led.terminal(f_t2, "es") is None                                     # other tenant NOT collapsed
    # reload from disk: tenant scoping survives a restart
    led2 = adapters.DurableLedger(os.path.join(d, "obl.jsonl"))
    assert led2.terminal(f_t1, "es") == "delivered" and led2.terminal(f_t2, "es") is None


def test_splunk_hec_body():
    os.environ.update(SPLUNK_HEC_URL="https://splunk:8088/services/collector", SPLUNK_HEC_TOKEN="t")
    body = SplunkAdapter()._body([F]).decode()
    doc = json.loads(body.strip())
    assert doc["event"]["finding_id"] == "f1" and doc["sourcetype"] == "cernity:finding"


def test_webhook_body():
    os.environ["WEBHOOK_URL"] = "https://hook"
    body = json.loads(WebhookAdapter()._body([F]))
    assert body["findings"][0]["finding_id"] == "f1"


def test_syslog_cef_frame():
    os.environ["SYSLOG_HOST"] = "siem"
    fr = SyslogCefAdapter()._frame(F)
    assert "CEF:0|Cernity|NDR|1.0|beacon|c2|8|" in fr and fr.startswith("<134>")


def test_devo_syslog_frame_json_and_cef():
    os.environ.update(DEVO_TRANSPORT="syslog", DEVO_RELAY="relay.devo", DEVO_CERT="/c", DEVO_KEY="/k",
                      DEVO_TAG="my.app.cernity.findings", DEVO_FORMAT="json")
    fr = DevoAdapter()._frame(F)
    assert "my.app.cernity.findings: " in fr and '"finding_id": "f1"' in fr
    os.environ["DEVO_FORMAT"] = "cef"
    assert "CEF:0|" in DevoAdapter()._frame(F)


def test_devo_http_config():
    os.environ.update(DEVO_TRANSPORT="http", DEVO_ENDPOINT="https://devo/api", DEVO_TOKEN="tok")
    d = DevoAdapter()
    assert d.transport == "http" and d.endpoint == "https://devo/api"


def test_get_adapter_single_and_fanout():
    os.environ["CERNITY_SINK"] = "file"
    os.environ["CERNITY_SINK_FILE"] = tempfile.mktemp()
    a = get_adapter()
    assert isinstance(a, DurableSink) and isinstance(a.inner, FileAdapter)   # durable-wrapped (F07)
    os.environ["CERNITY_SINK"] = "file,webhook"
    m = get_adapter()
    assert isinstance(m, MultiAdapter) and len(m.adapters) == 2
    assert all(isinstance(s, DurableSink) for s in m.adapters)               # each sink durable


def test_multiadapter_isolates_failure():
    class Boom:
        def emit_batch(self, fs):
            raise RuntimeError("down")
    seen = []
    class OK:
        def emit_batch(self, fs):
            seen.extend(fs)
    MultiAdapter([Boom(), OK()]).emit_batch([F])   # must not raise
    assert seen == [F]


def test_unknown_sink_raises():
    os.environ["CERNITY_SINK"] = "nope"
    try:
        get_adapter(); assert False
    except ValueError:
        pass
    finally:
        os.environ["CERNITY_SINK"] = "file"


def test_file_sink_rotates_at_size_cap():
    # F15: an unattended file sink must not fill the disk — rotate to `<path>.1` at a cap.
    p = tempfile.mktemp()
    a = FileAdapter(p, max_bytes=300)
    for i in range(60):
        a.emit_batch([{"finding_id": f"f{i}", "category": "c2", "pad": "y" * 40}])
    assert os.path.exists(p + ".1"), "file sink did not rotate at the size cap"
    assert os.path.getsize(p) < 60 * 60, "rotation did not bound the live file"


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    print("ok test_adapters")
