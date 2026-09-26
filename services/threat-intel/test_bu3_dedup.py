"""B-U3 (plan 010 Track B, review R04): threat-intel dedup is bounded + windowed PER HOST, not a
process-lifetime (feed,ioc) set that suppressed every other host hitting the same IOC."""
import os

os.environ.setdefault("LOG_FORMAT", "text")

import app  # noqa: E402


def test_different_host_not_suppressed():
    app._seen.clear()
    assert app._seen_once(("feodo", "1.2.3.4", "10.0.0.1", 100)) is True
    assert app._seen_once(("feodo", "1.2.3.4", "10.0.0.2", 100)) is True   # different host -> NOT suppressed


def test_same_host_ioc_window_deduped():
    app._seen.clear()
    assert app._seen_once(("feodo", "1.2.3.4", "10.0.0.1", 100)) is True
    assert app._seen_once(("feodo", "1.2.3.4", "10.0.0.1", 100)) is False  # repeat -> deduped


def test_new_window_reemits():
    app._seen.clear()
    assert app._seen_once(("feodo", "1.2.3.4", "10.0.0.1", 100)) is True
    assert app._seen_once(("feodo", "1.2.3.4", "10.0.0.1", 101)) is True   # new hour -> re-emit


def test_dedup_is_bounded():
    app._seen.clear()
    orig = app._SEEN_MAX
    app._SEEN_MAX = 3
    try:
        for i in range(10):
            app._seen_once(("f", "ioc", str(i), 0))
        assert len(app._seen) <= 3
    finally:
        app._SEEN_MAX = orig


def test_candidate_id_includes_dst():
    a = app._candidate("feodo", "1.2.3.4", "10.0.0.7", [])
    b = app._candidate("feodo", "1.2.3.4", "10.0.0.8", [])
    assert "10.0.0.7" in a["finding_id"] and a["finding_id"] != b["finding_id"]   # per-host id


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print("ok  " + fn.__name__)
    print("\nall %d B-U3 dedup tests passed" % len(fns))
