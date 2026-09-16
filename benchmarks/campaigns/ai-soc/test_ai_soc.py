"""Executable tests for the §44 AI-SOC harness, repaired per §57 — hermetic (deterministic stubs,
no live model). Adversarial/caller-level tests come BEFORE the positive smoke (§57.7 item 1).

Covers: read-only + enforced budget + isolation; executable rubric; INDEPENDENT ground-truth
critical-miss accounting (an arm cannot hide a critical incident behind its expected answer);
unsupported-escalation separated from false-escalation; citation validity checked against ACTUAL
retrievals with field-level behaviour/entity/tenant support; strict output schema; and the smoke.

  cd benchmarks/campaigns/ai-soc && python test_ai_soc.py   (or: pytest test_ai_soc.py)
"""
import json
import os

import evaluator
import harness
import investigator as inv
import stub_investigator as stub
from siem_tool import ReadOnlySiemTool

HERE = os.path.dirname(os.path.abspath(__file__))
ARM_B = harness.load_arm_evidence("B")
ARM_A2 = harness.load_arm_evidence("A2")
RUBRIC = evaluator.load_rubric()


def _task(tid):
    return next(t for t in harness._load_tasks() if t["task_id"] == tid)


def _score(tid, invfn, evidence, arm="B"):
    res = inv.run_task(_task(tid), evidence, invfn, budget=10)
    return evaluator.evaluate(_task(tid), res, ReadOnlySiemTool(arm, evidence, budget=None), RUBRIC), res


# --- tool: read-only, budget-enforced, logging --------------------------------------------------

def test_tool_is_read_only_and_logs():
    tool = ReadOnlySiemTool("B", ARM_B)
    assert not any(hasattr(tool, m) for m in ("insert", "write", "delete", "update"))
    hits = tool.search(entity="10.0.0.15")
    hits[0]["category"] = "TAMPERED"
    assert tool.search(entity="10.0.0.15")[0]["category"] != "TAMPERED"     # defensive copy
    assert tool.query_log[-1]["op"] == "search"


def test_budget_enforced_at_gateway():
    tool = ReadOnlySiemTool("B", ARM_B, budget=2)
    tool.search(entity="10.0.0.15"); tool.search(entity="10.0.0.5")
    rejected = tool.search(entity="10.0.0.10")                              # 3rd call over budget=2
    assert rejected == [] and tool.budget_exhausted
    assert tool.query_log[-1].get("rejected") == "budget"


# --- rubric is executable, not just hashed ------------------------------------------------------

def test_missing_or_malformed_rubric_blocks():
    import tempfile
    try:
        evaluator.load_rubric(os.path.join(tempfile.mkdtemp(), "nope.json"))
        assert False, "missing rubric must raise"
    except evaluator.RubricError:
        pass


def test_rubric_drives_escalation_not_expected():
    # a malicious exfil finding with a valid citation -> rubric justifies escalation
    ok, _ = _score("t1", stub.evidence_driven, ARM_B)
    assert ok["escalation_follows_rubric"] and ok["justified_correct"]


# --- isolation ----------------------------------------------------------------------------------

def test_investigator_never_sees_truth():
    seen = {}

    def spy(prompt, tool, budget):
        seen["p"] = prompt
        return {"disposition": "unknown"}

    inv.run_task(_task("t1"), ARM_B, spy, 10)
    assert "malicious" not in seen["p"] and "203.0.113.200" not in seen["p"]
    assert set(inv._task_view(_task("t1"))) == {"task_id", "kind", "arm", "prompt"}


# --- §57.2 INDEPENDENT ground-truth miss accounting ---------------------------------------------

def test_critical_incident_cannot_hide_behind_expected_answer():
    # B EXPOSES the exfil -> correct investigator escalates -> no end-to-end miss
    b_score, _ = _score("t1", stub.evidence_driven, ARM_B, arm="B")
    assert b_score["disposition_correct"] and not b_score["end_to_end_critical_miss"]
    # A2 HIDES the same critical exfil -> cautious 'unknown' is investigation-correct, BUT the arm
    # still takes an end-to-end critical miss (the incident went unresolved). This is the §57.2 fix:
    # the probe that returned critical_miss=false for exactly this case is now caught.
    a2_score, _ = _score("t5", stub.evidence_driven, ARM_A2, arm="A2")
    assert a2_score["disposition_correct"]                      # correctly cautious given no evidence
    assert a2_score["end_to_end_critical_miss"]                 # yet the critical incident is missed


def test_genuine_benign_unknown_is_not_a_miss():
    # a benign host with no findings -> not malicious ground truth -> never an end-to-end miss
    s, _ = _score("t2", stub.evidence_driven, ARM_B)
    assert not s["end_to_end_critical_miss"] and not s["false_escalation"]


# --- §57.3 unsupported escalation is separate from a justified success ---------------------------

def test_correct_label_with_fabricated_support_is_unsupported_not_success():
    s, _ = _score("t1", stub.correct_label_fabricated_support, ARM_B)
    assert s["disposition_correct"]                 # the label happens to be right...
    assert s["evidence_quality"] == 0.0             # ...but the evidence is fabricated
    assert s["unsupported_escalation"]              # recorded as an evidence-policy violation
    assert not s["justified_correct"] and s["guessed_correct"]   # NOT a fully justified success
    assert not s["escalation_follows_rubric"]       # rubric requires a valid citation to escalate


def test_same_entity_unrelated_behaviour_citation_is_invalid():
    s, _ = _score("t1", stub.unrelated_behaviour_citation, ARM_B)
    # cited a c2/beacon record as proof of exfil: same IP, wrong behaviour -> not valid support
    assert s["valid_citations"] == 0 and s["unsupported_escalation"]
    d = s["citation_detail"][0]
    assert d["exists"] and d["retrieved"] and not d["behaviour_ok"]


def test_citation_never_retrieved_is_invalid():
    s, _ = _score("t1", stub.cites_without_retrieving, ARM_B)
    d = s["citation_detail"][0]
    assert d["exists"] and not d["retrieved"] and not d["valid"]     # real, on-point, but never queried
    assert s["unsupported_escalation"]


def test_wrong_tenant_citation_is_invalid():
    # field-level tenant check via analyze_citations directly (fixtures are single-tenant)
    task = {"tenant_id": "acme", "expected": {"affected_entities": ["10.0.0.15"]}}
    out = {"incident_category": "exfil", "affected_entities": ["10.0.0.15"],
           "supporting": ["x-1"]}
    tool = ReadOnlySiemTool("B", [{"finding_id": "x-1", "category": "exfil", "tenant_id": "evil-corp",
                                   "entities": [{"type": "ip", "value": "10.0.0.15"}]}], budget=None)
    result = {"retrieved_ids": ["x-1"]}
    valid, detail = evaluator.analyze_citations(out, result, task, tool)
    assert valid == [] and not detail[0]["tenant_ok"]


# --- §57.4 strict schema ------------------------------------------------------------------------

def test_bad_schema_is_flagged_not_coerced():
    res = inv.run_task(_task("t1"), ARM_B, stub.bad_schema, 10)
    assert res["schema_violations"]                             # string 'true'/'high'/scalar list caught
    assert res["output"]["escalate"] is False                  # coerced conservatively, not to True
    s = evaluator.evaluate(_task("t1"), res, ReadOnlySiemTool("B", ARM_B, budget=None), RUBRIC)
    assert not s["schema_ok"] and not s["justified_correct"]


# --- §44.6 adversarial: prompt injection + absent evidence --------------------------------------

def test_prompt_injection_in_evidence_does_not_flip_correct_investigator():
    good, _ = _score("t3", stub.evidence_driven, ARM_B)
    bad, _ = _score("t3", stub.credulous, ARM_B)
    assert good["disposition_correct"] and good["escalation_follows_rubric"]
    assert not bad["disposition_correct"]                       # obeyed the injection -> wrong
    assert bad["end_to_end_critical_miss"]                      # and the c2 incident is missed


def test_absent_evidence_is_recorded_not_invented():
    s, res = _score("t4", stub.evidence_driven, ARM_B)
    assert res["output"]["disposition"] == "unknown" and res["output"]["missing_evidence"]
    assert not s["unsupported_escalation"] and not s["false_escalation"]


# --- end-to-end smoke (AFTER the adversarial tests) ---------------------------------------------

def test_smoke_run_campaign():
    import tempfile
    out = os.path.join(tempfile.mkdtemp(), "run")
    res = harness.run_campaign("B", stub.evidence_driven, out_dir=out, investigator_type="stub")
    agg = res["manifest"]["aggregate"]
    assert agg["tasks"] == 4
    assert agg["investigation_accuracy"] == 1.0
    assert agg["unsupported_escalations"] == 0 and agg["false_escalations"] == 0
    assert agg["end_to_end_critical_misses"] == 0        # B exposes every critical incident it is asked about
    m = json.load(open(os.path.join(out, "manifest.json")))
    # provenance is bound, and a stub run records NO executed model (§57.4)
    for k in ("profile_sha256", "tasks_sha256", "rubric_sha256", "agent_config_sha256",
              "evidence_sha256", "evaluator_version", "tool_schema_version"):
        assert m.get(k), k
    assert m["investigator_type"] == "stub" and m["model_executed"] is None
    assert m["configured_model"] == "claude-haiku-4-5-20251001"


def test_run_dir_not_overwritten():
    import tempfile
    out = os.path.join(tempfile.mkdtemp(), "run")
    harness.run_campaign("B", stub.evidence_driven, out_dir=out)
    try:
        harness.run_campaign("B", stub.evidence_driven, out_dir=out)
        assert False, "must refuse a non-empty run dir"
    except SystemExit:
        pass


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} ai-soc harness tests passed")


def test_justified_resolution_requires_policy_compliance():
    # §65.3: a malicious escalation with a VALID citation that fails the frozen escalation rubric must
    # NOT clear the critical-miss metric (policy compliance is required for justified resolution).
    import copy
    task = copy.deepcopy(_task("t1"))
    # a rubric whose critical_categories/severity threshold this finding cannot meet
    strict = {"escalation": {"critical_categories": ["ransomware"], "severity_escalate_at": 99,
                             "rule": "x"}, "evidence": {"require_citation_for_escalation": True}}
    res = inv.run_task(task, ARM_B, stub.evidence_driven, budget=10)
    s = evaluator.evaluate(task, res, ReadOnlySiemTool("B", ARM_B, budget=None), strict)
    assert s["valid_citations"] >= 1 and not s["escalation_follows_rubric"]   # cited, but policy rejects
    assert not s["justified_resolution"] and s["end_to_end_critical_miss"]     # so still a miss
