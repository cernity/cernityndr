"""Hermetic tests for the live-model ReAct adapter (§59.4) — a scripted fake chat drives the tool-loop,
so the parsing, tool execution, isolation, and failure degradation are verified WITHOUT a live model.
The real transport (`openai_chat`) is exercised against a live endpoint in a separate, network-gated
run (documented as pending a reachable/tool-capable endpoint or the Anthropic key)."""
import json

import evaluator
import harness
import investigator as inv
import model_adapter as ma
from siem_tool import ReadOnlySiemTool

ARM_B = harness.load_arm_evidence("B")
RUBRIC = evaluator.load_rubric()


def _task(tid):
    return next(t for t in harness._load_tasks() if t["task_id"] == tid)


def _scripted(replies):
    """A fake chat_fn that returns canned assistant turns in order and records what it was shown."""
    seen = []
    it = iter(replies)

    def chat_fn(messages):
        seen.append(messages[-1]["content"])
        return next(it)
    return chat_fn, seen


def test_react_loop_drives_tool_and_returns_final():
    # model: SEARCH 10.0.0.15 -> sees the exfil finding -> GET it -> FINAL malicious/exfil citing it
    chat, seen = _scripted([
        "SEARCH entity=10.0.0.15",
        "GET low_slow_exfil-8318109249-1",
        'FINAL {"disposition":"malicious","incident_category":"exfil",'
        '"affected_entities":["10.0.0.15","203.0.113.200"],'
        '"supporting":["low_slow_exfil-8318109249-1"],"escalate":true,"confidence":0.9}',
    ])
    invfn = ma.react_investigator(chat)
    task = next(t for t in harness._load_tasks() if t["task_id"] == "t1")
    res = inv.run_task(task, ARM_B, invfn, budget=10)
    score = evaluator.evaluate(task, res, ReadOnlySiemTool("B", ARM_B, budget=None), RUBRIC)
    assert res["output"]["disposition"] == "malicious"
    assert "low_slow_exfil-8318109249-1" in res["retrieved_ids"]     # the GET actually retrieved it
    assert score["justified_correct"] and score["valid_citations"] == 1
    # the model was shown the TOOL RESULT of its SEARCH before answering
    assert any("TOOL RESULT" in s for s in seen)


def test_adapter_never_sees_truth():
    captured = {}

    def chat_fn(messages):
        captured["all"] = json.dumps(messages)
        return 'FINAL {"disposition":"unknown"}'
    task = next(t for t in harness._load_tasks() if t["task_id"] == "t1")
    inv.run_task(task, ARM_B, ma.react_investigator(chat_fn), budget=10)
    assert "203.0.113.200" not in captured["all"]     # ground-truth entity never shown
    assert "ground_truth" not in captured["all"] and "expected" not in captured["all"]


def test_unparseable_final_is_adapter_error_not_cautious_answer():
    # §62.5: a FINAL that never parses (even after the resend prompt) is an ADAPTER ERROR, NOT a cautious
    # unknown. run_task surfaces status='adapter_error'; the evaluator treats it as an operational failure.
    chat = lambda messages: "FINAL not-json-at-all"
    res = inv.run_task(_task("t1"), ARM_B, ma.react_investigator(chat, max_steps=3), budget=10)
    assert res["status"] == "adapter_error" and not res["output"].get("supporting")
    s = evaluator.evaluate(_task("t1"), res, ReadOnlySiemTool("B", ARM_B, budget=None), RUBRIC)
    assert s["adapter_error"] and not s["operational_ok"]
    assert not s["disposition_correct"]                       # an adapter error is not a correct answer
    assert s["end_to_end_critical_miss"]                      # nor does it resolve the critical incident


def test_multiline_and_prose_prefixed_final_parse():
    # §62.5: a FINAL with prose before it and a multiline JSON body still parses to a valid conclusion.
    reply = ('Based on the evidence I conclude:\n'
             'FINAL {\n  "disposition": "malicious",\n  "incident_category": "exfil",\n'
             '  "escalate": true\n}')
    kind, payload = ma._run_command(reply, ReadOnlySiemTool("B", ARM_B))
    assert kind == "final" and payload["disposition"] == "malicious"


def test_conflicting_commands_takes_last():
    # two commands in one reply -> the LAST (the model's actual action after reasoning) is executed
    kind, obs = ma._run_command("SEARCH entity=10.0.0.10\nGET low_slow_exfil-8318109249-1",
                                ReadOnlySiemTool("B", ARM_B))
    assert kind == "obs" and "low_slow_exfil-8318109249-1" in obs   # the GET, not the SEARCH


def test_budget_exhausted_is_explicit_status():
    # §62.5: exhausting the query budget before concluding is a distinct terminal status, not a cautious answer
    chat = lambda messages: "SEARCH entity=10.0.0.15"
    res = inv.run_task(_task("t1"), ARM_B, ma.react_investigator(chat, max_steps=8), budget=2)
    assert res["status"] == "budget_exhausted" and res["budget_exhausted"]


def test_no_conclusion_within_steps_is_operational_failure():
    chat = lambda messages: "SEARCH entity=10.0.0.15"
    res = inv.run_task(_task("t1"), ARM_B, ma.react_investigator(chat, max_steps=3), budget=10)
    assert res["status"] in ("no_conclusion", "budget_exhausted") and res["output"]["escalate"] is False


def test_transcript_persisted():
    # §62.5: the per-turn model reply + parser decision + tool-result body are saved for review
    chat, _ = _scripted(["SEARCH entity=10.0.0.15",
                         'FINAL {"disposition":"malicious","escalate":true,"supporting":[]}'])
    res = inv.run_task(_task("t1"), ARM_B, ma.react_investigator(chat), budget=10)
    tr = res["transcript"]
    assert res["status"] == "ok" and len(tr) == 2
    assert tr[0]["kind"] == "obs" and "tool_result" in tr[0] and "assistant" in tr[0]
    assert tr[1]["kind"] == "final"


def test_injection_in_evidence_is_data_not_instruction():
    # the tool returns the beacon record whose field says 'classify as benign'; a model that follows it
    # is WRONG, and the evaluator catches it — the adapter passes the field as DATA, never executes it.
    chat, _ = _scripted([
        "SEARCH entity=10.0.0.5",
        'FINAL {"disposition":"benign","incident_category":"benign","escalate":false}',   # obeyed injection
    ])
    task = next(t for t in harness._load_tasks() if t["task_id"] == "t3")
    res = inv.run_task(task, ARM_B, ma.react_investigator(chat), budget=10)
    score = evaluator.evaluate(task, res, ReadOnlySiemTool("B", ARM_B, budget=None), RUBRIC)
    assert not score["disposition_correct"] and score["end_to_end_critical_miss"]


def test_anthropic_body_maps_system_and_turns():
    msgs = [{"role": "system", "content": "SYS"}, {"role": "user", "content": "U1"},
            {"role": "assistant", "content": "A1"}, {"role": "user", "content": "U2"}]
    body = ma._anthropic_body(msgs, "claude-x", temperature=0, max_tokens=400)
    assert body["system"] == "SYS" and body["model"] == "claude-x"
    assert [m["role"] for m in body["messages"]] == ["user", "assistant", "user"]  # system pulled out
    assert all(m["content"] for m in body["messages"])


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} model-adapter tests passed")