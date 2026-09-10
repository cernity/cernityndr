"""Build gate for bridge (run directly: `python test_bridge.py`)."""
import json

from bridge import eve_line, should_rotate


def test_eve_line_is_single_json_line():
    rec = {"event_type": "flow", "src_ip": "10.0.0.1", "dest_port": 443}
    line = eve_line(rec)
    assert line.endswith("\n")
    assert line.count("\n") == 1              # exactly one record per line
    assert json.loads(line) == rec


def test_should_rotate_threshold_and_disable():
    assert should_rotate(100, 100) is True
    assert should_rotate(101, 100) is True
    assert should_rotate(99, 100) is False
    assert should_rotate(10 ** 9, 0) is False     # 0 disables rotation
    assert should_rotate(10 ** 9, -1) is False


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok {name}")
    print("all ok")
