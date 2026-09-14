"""Stage-5 orchestrator tests (run: python test_orchestrator.py).

The critical properties: (1) ground truth is derived from the LAUNCH LOG, never from any detector
output (independence); (2) the emitted truth is directly consumable by the production scorer, so a
qualification run scores with no schema glue. Uses a fake runner + fake clock — no tools, no wire.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))   # benchmarks/ for episodes
import orchestrator as orch
import actions
import episodes as ep


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        self.t += 5.0
        return self.t


def _norun(_cmd):
    return 0                      # fake: never actually execute a command in tests


def test_truth_comes_from_the_launch_record_not_a_detector():
    a = actions.scan("10.9.0.5", ["10.0.0.20", "10.0.0.21"])
    r = orch.run_action(a, run=_norun, clock=_Clock())
    e = orch.truth_episode(r)
    # entities + behaviour are exactly what the orchestrator LAUNCHED — no detector involved
    assert e["behavior"] == "lateral" and e["label"] == "malicious"     # SMB/RDP internal scan = lateral fan-out
    assert [x["role"] for x in e["entities"]] == ["initiator", "target", "target"]
    assert e["entities"][0]["value"] == "10.9.0.5"
    assert e["match_requires"] == ["10.9.0.5"]               # fan-out keyed on the initiator
    assert e["interval"]["end"] > e["interval"]["start"]     # wall interval stamped around the action
    # a general recon sweep keeps recon
    assert orch.truth_episode(orch.run_action(actions.scan("10.9.0.5", ["1.2.3.4"], behavior="recon"),
                                              run=_norun, clock=_Clock()))["behavior"] == "recon"


def test_campaign_writes_independent_truth_record():
    spec = {"dataset": "rt-qual", "actions": [
        actions.scan("10.9.0.5", ["10.0.0.20", "10.0.0.21"]),
        actions.beacon("10.9.0.6", "203.0.113.10"),
    ]}
    with tempfile.TemporaryDirectory() as d:
        labels, results = orch.run_campaign(spec, d, run=_norun, clock=_Clock())
        assert sorted(labels["malicious"]) == ["10.9.0.5", "10.9.0.6"]
        assert {e["behavior"] for e in labels["episodes"]} == {"lateral", "c2"}   # scan default = lateral fan-out
        assert os.path.isfile(os.path.join(d, "labels.json"))
        import json
        log = json.load(open(os.path.join(d, "run-log.json")))    # the immutable truth record
        assert [x["id"] for x in log["actions"]] == ["rt-scan", "rt-beacon"]
        assert all("cmd" in x for x in log["actions"])            # what actually ran, recorded


def test_emitted_truth_is_directly_scoreable_by_the_production_scorer():
    # close the loop: a detection naming the launched relationship scores against the orchestrator's
    # truth with NO schema glue — proving the qualification harness feeds the real scorer.
    spec = {"dataset": "rt-qual", "actions": [actions.beacon("10.9.0.6", "203.0.113.10")]}
    labels, _ = orch.run_campaign(spec, tempfile.mkdtemp(), run=_norun, clock=_Clock())
    detection = {"entities": [{"value": "10.9.0.6", "role": "src"}, {"value": "203.0.113.10", "role": "dst"}],
                 "behavior": "c2", "finding_id": "f1"}
    # score the truth in its own (untimed-for-this-check) form: a matching detection surfaces it
    eps = [dict(e, interval=None) for e in labels["episodes"]]     # drop interval for the schema check
    r = ep.score([detection], eps)
    assert r["episode_recall"] == 1.0 and r["false_items"] == 0

    # and a WRONG detection (benign host) does not falsely surface it
    benign = {"entities": [{"value": "10.0.0.99", "role": "src"}], "behavior": "c2"}
    assert ep.score([benign], eps)["episode_recall"] == 0.0


def test_attempted_attack_is_unknown_not_a_detection_obligation():
    # R08/§33.4: a beacon whose listener is absent (0 successful connections) EXECUTED but achieved
    # nothing on the wire; it must be attempted -> unknown (unscored), attacker OUT of the malicious set.
    a = actions.beacon("10.9.0.6", "203.0.113.10", count=5)
    run = lambda _cmd: (0, 'RT-OUTCOME {"attempts":5,"ok":0,"errors":5,"connections":0}')
    r = orch.run_action(a, run=run, clock=_Clock())
    assert r["executed"] and not r["achieved"]
    ep = orch.truth_episode(r)
    assert ep["label"] == "unknown" and ep["status"] == "attempted"
    labels = orch.build_labels([r], "rt")
    assert "10.9.0.6" not in labels["malicious"]
    assert any("achieved nothing" in c for c in labels["caveats"])


def test_achieved_and_partial_transfer_are_distinguished():
    # R08: bytes actually sent => achieved (malicious); the retained outcome shows it was PARTIAL.
    a = actions.exfil("10.9.0.7", "203.0.113.10", mb=80)
    run = lambda _cmd: (0, 'RT-OUTCOME {"connected":1,"bytes":1048576,"target_bytes":83886080}')
    r = orch.run_action(a, run=run, clock=_Clock())
    ep = orch.truth_episode(r)
    assert r["achieved"] and ep["label"] == "malicious"
    assert ep["outcome"]["bytes"] < ep["outcome"]["target_bytes"]        # partial transfer, preserved


def test_failed_command_without_evidence_is_not_achieved():
    # R08: a nonzero exit with no RT-OUTCOME is attempted, never achieved.
    a = actions.scan("10.9.0.8", ["10.0.0.20"])
    r = orch.run_action(a, run=lambda _cmd: (1, ""), clock=_Clock())
    assert not r["achieved"] and orch.truth_episode(r)["label"] == "unknown"


def test_capture_failure_is_recorded_as_a_coverage_caveat():
    # R08: an unverified capture must surface as a caveat, not a silent clean run.
    r = orch.run_action(actions.beacon("10.9.0.6", "c2", count=2),
                        run=lambda _cmd: (0, 'RT-OUTCOME {"ok":2,"connections":2}'), clock=_Clock())
    labels = orch.build_labels([r], "rt", capture_status={"ok": False, "started": False, "packets": None})
    assert any("capture unverified" in c.lower() for c in labels["caveats"])


def test_action_library_builds_real_commands_for_each_behavior():
    assert actions.scan("a", ["b"])["cmd"][0] == "nmap"
    assert actions.beacon("a", "c2")["behavior"] == "c2" and actions.beacon("a", "c2")["cmd"][0] == "python3"
    assert actions.dns_tunnel("a", "r", "evil.example")["behavior"] == "exfil"
    assert actions.lateral("a", ["b", "c"])["targets"] == ["b", "c"]


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok", _n)
    print("all red-team orchestrator tests passed")
