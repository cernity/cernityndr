import json
import os
import tempfile

from adapters import FileAdapter, get_adapter


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
    test_unknown_sink_raises()
    print("ok test_adapters")
