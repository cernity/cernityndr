"""Isolated investigator runner (§44.3). Runs ONE task in a fresh session that can reach only the
task PROMPT and a read-only SIEM tool bound to one arm — never the episode truth, the rubric, other
arms' outputs, or prior task answers. Isolation is enforced by what is passed in, not by a prompt
asking the investigator to ignore labels: this function simply never receives the truth object.

CAVEAT (§57.4): a pluggable in-process Python callable is an INTERFACE boundary, not a security
sandbox — a stub could in principle retain module state or read local files. A live-model adapter must
create a NEW conversation per task, expose only the allowed tool, and keep truth outside its
filesystem/tool scope; `run_task` does not by itself prove a security-enforced fresh session.

The investigator is pluggable `(prompt, tool, budget) -> dict`. CI/smoke passes a deterministic stub;
a real run passes the pinned-model adapter (agent-config.json). The runner captures the full
transcript (every query + the final structured output) and the set of records the investigator
actually retrieved, so the evaluator can check citations against real retrievals."""
from __future__ import annotations

from siem_tool import ReadOnlySiemTool

# The structured output every investigator must return (§44.4).
REQUIRED_FIELDS = ("disposition", "confidence", "affected_entities", "incident_category",
                   "supporting", "missing_evidence", "recommended_action", "escalate",
                   "escalation_rationale")

_DISPOSITIONS = ("malicious", "benign", "unknown")


def _task_view(task: dict) -> dict:
    """The ONLY task fields the investigator may see. `ground_truth`/`expected`/`adversarial` are
    stripped here — the isolation boundary is this projection, so a truth field can never reach the
    investigator even if a task file carries it inline."""
    return {"task_id": task.get("task_id"), "kind": task.get("kind"),
            "arm": task.get("arm"), "prompt": task.get("prompt")}


def validate_output(out: dict) -> tuple[dict, list[str]]:
    """STRICT schema check (§57.4): record every type/enum violation instead of silently coercing a
    string 'true' into an escalation. Returns (normalized, violations). A violation does not crash the
    run — the evaluator treats a schema-invalid result as unqualified — but the value is coerced
    CONSERVATIVELY (unknown/False/empty) so a malformed output cannot score better than a valid one."""
    o = dict(out or {})
    v: list[str] = []

    disp = o.get("disposition")
    if disp not in _DISPOSITIONS:
        v.append(f"disposition {disp!r} not in {_DISPOSITIONS}")
        disp = "unknown"
    o["disposition"] = disp

    esc = o.get("escalate", False)
    if not isinstance(esc, bool):
        v.append(f"escalate {esc!r} is not a bool")
        esc = False
    o["escalate"] = esc

    conf = o.get("confidence", 0.0)
    if not isinstance(conf, (int, float)) or isinstance(conf, bool):
        v.append(f"confidence {conf!r} is not a number")
        conf = 0.0
    o["confidence"] = float(conf)

    for k, default in (("affected_entities", []), ("supporting", []), ("missing_evidence", [])):
        val = o.get(k, default)
        if not isinstance(val, list):
            v.append(f"{k} {val!r} is not a list")
            val = []
        o[k] = [str(x) for x in val]

    o.setdefault("incident_category", "unknown")
    o.setdefault("recommended_action", "")
    o.setdefault("escalation_rationale", "")
    return o, v


def run_task(task: dict, records: list[dict], investigate, budget: int = 10) -> dict:
    """Run one task in isolation. `records` is the arm's exposed evidence; `investigate` is the
    pluggable investigator; `budget` is ENFORCED by the tool. Returns the transcript + strict-validated
    output + the ids the investigator actually retrieved — NO truth is returned from here.

    §62.5: a live adapter may return reserved keys `_status`/`_error`/`_trace`; these are extracted (not
    scored as content). A status other than 'ok' is an OPERATIONAL FAILURE (adapter_error /
    budget_exhausted / no_conclusion) — it is NOT silently accepted as a cautious answer."""
    tool = ReadOnlySiemTool(task.get("arm"), records, budget=budget)
    view = _task_view(task)
    raw = dict(investigate(view["prompt"], tool, budget) or {})
    status = raw.pop("_status", "ok")
    error = raw.pop("_error", None)
    trace = raw.pop("_trace", None)
    output, violations = validate_output(raw)
    return {"task_id": task.get("task_id"), "arm": task.get("arm"),
            "output": output, "schema_violations": violations,
            "status": status, "error": error, "transcript": trace,
            "query_log": tool.query_log, "retrieved_ids": sorted(tool.retrieved_ids),
            "budget_exhausted": tool.budget_exhausted,
            "over_budget": tool.budget_exhausted}
