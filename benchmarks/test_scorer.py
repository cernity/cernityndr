"""Build gate for scorer (run: `python test_scorer.py`)."""
import scorer as s


def test_perfect_detection():
    r = s.score({"a", "b"}, {"a", "b"})
    assert r["precision"] == 1.0 and r["recall"] == 1.0 and r["f1"] == 1.0
    assert r["fp"] == 0 and r["fn"] == 0


def test_all_false_positive():
    r = s.score({"x", "y"}, {"a"})
    assert r["precision"] == 0.0 and r["tp"] == 0 and r["fp"] == 2


def test_missed_all():
    r = s.score(set(), {"a", "b"})
    assert r["recall"] == 0.0 and r["fn"] == 2 and r["f1"] == 0.0


def test_empty_both_no_divide_by_zero():
    r = s.score(set(), set())
    assert r["precision"] == 0.0 and r["recall"] == 0.0 and r["f1"] == 0.0


def test_partial_detection():
    r = s.score({"a", "b", "z"}, {"a", "b", "c"})     # tp2 fp1 fn1
    assert r["tp"] == 2 and r["fp"] == 1 and r["fn"] == 1
    assert r["precision"] == 0.6667 and r["recall"] == 0.6667


def test_noise_alerts_per_tp_and_suppression():
    n = s.noise(raw_events=100000, alerts=500, true_positives=5, delivered=20)
    assert n["alerts_per_true_positive"] == 100.0
    assert n["suppression_ratio"] == 0.96             # 1 - 20/500


def test_noise_zero_tp_and_zero_alerts_no_divide():
    n = s.noise(1000, 0, 0, 0)
    assert n["alerts_per_true_positive"] is None and n["suppression_ratio"] == 0.0


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"ok {name}")
    print("all ok")
