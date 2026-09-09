import json
import os
import tempfile

from adapters import FileAdapter, ElasticsearchAdapter, get_adapter


def test_file_adapter_appends_jsonl():
    p = tempfile.mktemp()
    a = FileAdapter(p)
    a.emit({"finding_id": "f1"})
    a.emit({"finding_id": "f2"})
    lines = open(p).read().splitlines()
    assert [json.loads(x)["finding_id"] for x in lines] == ["f1", "f2"]


def test_get_adapter_selects_file():
    os.environ["CERNITY_SINK"] = "file"
    os.environ["CERNITY_SINK_FILE"] = tempfile.mktemp()
    assert isinstance(get_adapter(), FileAdapter)


def test_get_adapter_selects_elasticsearch():
    for kind in ("elasticsearch", "opensearch", "es"):
        os.environ["CERNITY_SINK"] = kind
        assert isinstance(get_adapter(), ElasticsearchAdapter)
    os.environ["CERNITY_SINK"] = "file"


def test_es_doc_normalizes_dates_and_timestamp():
    d = ElasticsearchAdapter._doc({"finding_id": "x", "first_seen": "2026-09-09 03:00:00",
                                   "last_seen": "2026-09-09 03:05:00"})
    assert d["first_seen"] == "2026-09-09T03:00:00"
    assert d["@timestamp"] == "2026-09-09T03:05:00"


def test_unknown_sink_raises():
    os.environ["CERNITY_SINK"] = "nope"
    try:
        get_adapter()
        assert False, "expected ValueError"
    except ValueError:
        pass
    finally:
        os.environ["CERNITY_SINK"] = "file"


if __name__ == "__main__":
    test_file_adapter_appends_jsonl()
    test_get_adapter_selects_file()
    test_get_adapter_selects_elasticsearch()
    test_es_doc_normalizes_dates_and_timestamp()
    test_unknown_sink_raises()
    print("ok test_adapters")
