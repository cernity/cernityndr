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
