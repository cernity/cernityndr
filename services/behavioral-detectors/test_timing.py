"""_timing_evidence tests (pure math on window timestamps)."""
import os

os.environ.setdefault("NDR_STATE_BACKEND", "memory")   # app.py builds a store at import
import app


def _by_type(items):
    return {i["type"]: i["value"] for i in items}


def test_regular_beacon_low_jitter():
    ts = [1000, 1060, 1120, 1180, 1240]                # exactly 60s apart
    ev = _by_type(app._timing_evidence(ts))
    assert ev["interval_s"] == 60.0
    assert ev["jitter_s"] == 0.0
    assert ev["connections"] == 5


def test_jittery_intervals():
    ts = [0, 58, 122, 178, 245]                        # ~60s ± a few
    ev = _by_type(app._timing_evidence(ts))
    assert 55 <= ev["interval_s"] <= 65
    assert ev["jitter_s"] > 0
    assert ev["connections"] == 5


def test_single_point():
    ev = _by_type(app._timing_evidence([1000]))
    assert ev == {"connections": 1}


def test_unsorted_input():
    ev = _by_type(app._timing_evidence([1240, 1000, 1120, 1060, 1180]))
    assert ev["interval_s"] == 60.0


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print("ok ", fn.__name__)
    print("all %d timing tests passed" % len(fns))
