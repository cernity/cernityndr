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


def test_epoch_parses_suricata_plus0000_offset():
    # §stage5 beacon false-negative: Suricata emits a `+0000` offset (no colon) that
    # datetime.fromisoformat rejects on Python <3.11; the old parse fell back to time.time(),
    # collapsing flow timing. _epoch must now parse it (and Z, and +00:00), None on junk.
    assert app._epoch("2026-09-14T03:07:19.130741+0000") is not None
    assert app._epoch("2026-01-01T00:00:00Z") is not None
    assert app._epoch("2026-01-01T00:00:00+00:00") is not None
    assert app._epoch("not-a-time") is None
    # _event_epoch on a real +0000 flow.start returns the REAL time, not time.time()
    e = {"event_type": "flow", "flow": {"start": "2026-09-14T03:07:19.130741+0000"}}
    assert abs(app._event_epoch(e) - app._epoch("2026-09-14T03:07:19.130741+0000")) < 1e-6


def test_beacon_score_fires_on_plus0000_flow_starts():
    import detectors
    ts = [app._epoch("2026-09-14T03:%02d:%02d.000000+0000" % divmod(6 * 60 + i * 5, 60)) for i in range(12)]
    assert all(t is not None for t in ts)               # all 12 parsed (would be None pre-fix)
    is_beacon, score = detectors.beacon_score(sorted(ts))
    assert is_beacon and score >= 0.80                  # regular 5s cadence -> beacon


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print("ok ", fn.__name__)
    print("all %d timing tests passed" % len(fns))
