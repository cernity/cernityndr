"""Validation-harness smoke (plan U7). Runs in the build gate."""
import os, sys
os.environ.setdefault("NDR_STATE_BACKEND", "memory")
os.environ.setdefault("NDR_CONFIG_TOPIC_DISABLE", "1")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import precision_recall as pr

def test_demo_corpus_catches_planted_beacon_and_exfil():
    expected, got = pr.run(pr.demo())
    got_dets = {d for d, _ in got}
    assert "beacon" in got_dets, "planted beacon must be detected"
    assert "exfil" in got_dets, "planted exfil must be detected"

def test_loadtest_runs():
    import importlib, sys as _s
    _s.argv = ["loadtest.py", "--n", "500"]
    import loadtest
    loadtest.main()

if __name__ == "__main__":
    test_demo_corpus_catches_planted_beacon_and_exfil()
    test_loadtest_runs()
    print("validation smoke passed")
