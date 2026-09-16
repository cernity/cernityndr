"""Independent deterministic evaluator (§44.5, repaired per §57). It holds the hidden per-task truth
and scores an investigator's saved output with factual, reproducible checks — never a narrative grade.

Repairs demanded by §57:
  * §57.2 INDEPENDENT ground-truth accounting: an `end_to_end_critical_miss` is charged whenever a
    CRITICAL ground-truth incident was not resolved (investigator did not conclude malicious AND
    escalate), REGARDLESS of what the arm-specific expected answer was. An arm that exposes no evidence
    can be judged correctly-cautious on `investigation_correct` AND still take the end-to-end miss.
  * §57.3 EXECUTABLE rubric: the frozen rubric.json is parsed and APPLIED (not merely hashed). A
    missing/malformed rubric blocks qualification. Escalation policy is derived from the rubric and the
    investigator's own VALID evidence, not from `expected`.
  * §57.3 EVIDENCE POLICY: `unsupported_escalation` (escalated with zero valid citations) is recorded
    SEPARATELY from `false_escalation` (escalated a case that should not escalate) — a correct label
    with fabricated support is neither a full success nor a benign false escalation.
  * §57.3 CITATION support is checked against the investigator's ACTUAL retrieved-record log and at the
    field level: a citation is valid only if it EXISTS, was RETRIEVED, matches the claimed BEHAVIOUR
    (category), references a claimed ENTITY, and is not a wrong-TENANT record. Same-IP is not proof.

Ground truth (arm-independent) drives end-to-end miss accounting; the arm-expected answer drives
investigation-quality. Missing evidence stays `unknown`; nothing is fabricated to fill a gap."""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
_VALID_RESET = None   # placeholder to keep import symmetry; not used here


class RubricError(RuntimeError):
    pass


def load_rubric(path: str | None = None) -> dict:
    """Parse and VALIDATE the frozen rubric (§57.3). A missing or malformed rubric raises — a run that
    cannot execute its policy is not qualifiable, it does not silently pass."""
    path = path or os.path.join(HERE, "rubric.json")
    if not os.path.isfile(path):
        raise RubricError(f"rubric not found: {path}")
    with open(path) as f:
        r = json.load(f)
    esc = r.get("escalation") or {}
    if not isinstance(esc.get("critical_categories"), list) or not isinstance(
            esc.get("severity_escalate_at"), (int, float)):
        raise RubricError("rubric.escalation missing critical_categories / severity_escalate_at")
    if not isinstance(r.get("evidence"), dict):
        raise RubricError("rubric.evidence missing")
    return r


def _f1(pred, gold) -> float:
    ps, gs = set(pred), set(gold)
    if not ps and not gs:
        return 1.0
    if not ps or not gs:
        return 0.0
    tp = len(ps & gs)
    if tp == 0:
        return 0.0
    prec, rec = tp / len(ps), tp / len(gs)
    return round(2 * prec * rec / (prec + rec), 3)


def _record_entities(rec):
    return {str(e.get("value")) for e in (rec.get("entities") or []) if isinstance(e, dict)}


def analyze_citations(output, result, task, tool):
    """Per-citation field-level validity (§57.3). A citation is valid iff it EXISTS in the arm evidence,
    was actually RETRIEVED by the investigator (present in its retrieval log), matches the claimed
    BEHAVIOUR (record.category == claimed incident_category), references a claimed ENTITY, and is not a
    wrong-TENANT record. Returns (valid_records, detail[])."""
    retrieved = set(result.get("retrieved_ids") or [])
    claimed_cat = output.get("incident_category")
    claimed_entities = set(output.get("affected_entities") or []) or set(
        (task.get("expected") or {}).get("affected_entities") or [])
    want_tenant = task.get("tenant_id")
    valid, detail = [], []
    for fid in output.get("supporting") or []:
        rec = tool.get(fid)
        exists = rec is not None
        was_retrieved = fid in retrieved
        behaviour_ok = bool(rec) and rec.get("category") == claimed_cat
        entity_ok = bool(rec) and (not claimed_entities or (_record_entities(rec) & claimed_entities))
        tenant_ok = (want_tenant is None) or (not rec) or (rec.get("tenant_id") in (None, want_tenant))
        ok = exists and was_retrieved and behaviour_ok and entity_ok and tenant_ok
        detail.append({"finding_id": fid, "exists": exists, "retrieved": was_retrieved,
                       "behaviour_ok": behaviour_ok, "entity_ok": bool(entity_ok),
                       "tenant_ok": bool(tenant_ok), "valid": bool(ok)})
        if ok:
            valid.append(rec)
    return valid, detail


def rubric_justifies_escalation(output, valid_records, rubric) -> bool:
    """Apply the FROZEN rubric to the investigator's own conclusion + its VALID evidence (§57.3).
    Escalation is policy-justified only for a malicious disposition that meets a criticality/severity
    trigger AND (if the rubric requires it) carries at least one valid supporting citation."""
    if output.get("disposition") != "malicious":
        return False
    esc = rubric["escalation"]
    crit = output.get("incident_category") in esc["critical_categories"]
    max_sev = max((int(r.get("severity", 0) or 0) for r in valid_records), default=0)
    trigger = crit or max_sev >= esc["severity_escalate_at"]
    if rubric.get("evidence", {}).get("require_citation_for_escalation") and not valid_records:
        return False
    return bool(trigger)


def evaluate(task: dict, result: dict, tool, rubric: dict) -> dict:
    """Score one task result deterministically. `tool` is a FRESH read-only tool over the same arm
    evidence (unbounded — the evaluator verifies citations without spending the investigator's budget);
    `rubric` is the parsed frozen policy."""
    exp = task.get("expected") or {}
    gt = task.get("ground_truth") or {}
    out = result.get("output") or {}
    schema_ok = not result.get("schema_violations")
    # §62.5: a live adapter reports a terminal status; anything but 'ok' (adapter_error / no_conclusion /
    # budget_exhausted) is an OPERATIONAL FAILURE, not a cautious answer. It cannot score as a correct
    # disposition or a justified resolution — it is preserved in the operational-failure rate.
    status = result.get("status", "ok")
    operational_ok = (status == "ok") and schema_ok

    # --- evidence-conditioned investigation quality (arm-expected) ---
    # §62.4 versioned answer-key: a task may declare `acceptable_dispositions` (e.g. a flagged host with
    # no corroborating evidence may be graded correct as EITHER benign or unknown). Falls back to the
    # single `disposition`. Absence-of-evidence is thus not force-graded to one convention.
    acceptable = exp.get("acceptable_dispositions") or [exp.get("disposition")]
    disposition_correct = operational_ok and out.get("disposition") in acceptable
    category_correct = operational_ok and (
        out.get("incident_category") == exp.get("category")
        if exp.get("category") not in (None, "unknown")
        else out.get("incident_category") in (None, "unknown"))
    scope_f1 = _f1(out.get("affected_entities", []), exp.get("affected_entities", []))

    valid_records, cite_detail = analyze_citations(out, result, task, tool)
    valid_cites = len(valid_records)
    total_cites = len(out.get("supporting") or [])
    # §62.4: report citation validity and abstention SEPARATELY — evidence_quality 1.0 on a no-citation
    # answer means "appropriate abstention under this convention", NOT "strong evidence". `abstained`
    # marks a no-citation outcome so a reader never mistakes it for a complete investigation.
    abstained = total_cites == 0
    evidence_quality = (valid_cites / total_cites) if total_cites else (
        1.0 if not exp.get("supporting_present") else 0.0)

    # --- executable rubric: is the escalation policy-justified? ---
    escalated = bool(out.get("escalate"))
    policy_justifies = rubric_justifies_escalation(out, valid_records, rubric) and operational_ok
    escalation_follows_rubric = (escalated == policy_justifies)

    # --- separated escalation-failure classes (§57.3) ---
    unsupported_escalation = escalated and valid_cites == 0
    false_escalation = escalated and not bool(exp.get("escalate"))

    # correctness split (§57.3): justified vs guessed.
    justified_correct = bool(disposition_correct
                             and (not escalated or (policy_justifies and valid_cites > 0)))
    guessed_correct = bool(disposition_correct and not justified_correct)

    # --- §57.2 + §62.4 + §65.3 INDEPENDENT ground-truth end-to-end miss, requiring JUSTIFIED resolution ---
    # A critical incident is "resolved" only by an operationally-valid, EVIDENCE-BACKED, POLICY-COMPLIANT
    # malicious escalation. §65.3: also require `policy_justifies` (the rubric result) — a malicious
    # escalation with a valid citation that nonetheless FAILS the frozen escalation rubric does not clear
    # the miss. An unsupported/fabricated/schema-invalid/adapter-error/policy-violating guess is still an
    # unresolved critical incident. Raw escalation is kept separately.
    justified_resolution = bool(operational_ok and out.get("disposition") == "malicious"
                                and escalated and valid_cites > 0 and policy_justifies)
    end_to_end_critical_miss = bool(gt.get("critical")) and not justified_resolution

    return {
        "task_id": task.get("task_id"), "arm": task.get("arm"),
        "status": status, "operational_ok": operational_ok, "adapter_error": status != "ok",
        "schema_ok": schema_ok,
        "disposition_correct": disposition_correct,
        "category_correct": category_correct,
        "scope_f1": scope_f1,
        "evidence_quality": round(evidence_quality, 3), "abstained": abstained,
        "valid_citations": valid_cites, "total_citations": total_cites,
        "citation_detail": cite_detail,
        "escalation_follows_rubric": escalation_follows_rubric,
        "unsupported_escalation": unsupported_escalation,
        "false_escalation": false_escalation,
        "raw_escalation": escalated,
        "justified_correct": justified_correct,
        "guessed_correct": guessed_correct,
        "justified_resolution": justified_resolution,
        "end_to_end_critical_miss": end_to_end_critical_miss,
        "over_budget": bool(result.get("over_budget")),
        "adversarial": task.get("adversarial"),
        "ground_truth_label": gt.get("label"), "ground_truth_critical": bool(gt.get("critical")),
    }


def aggregate(scores: list[dict]) -> dict:
    """Roll up per-task scores into separated §44.5/§57 dimensions. Counts, not human-minute
    conversions; the ground-truth miss denominator is arm-independent."""
    n = len(scores) or 1
    critical_total = sum(s["ground_truth_critical"] for s in scores)
    return {
        "tasks": len(scores),
        "operational_failures": sum(s["adapter_error"] for s in scores),   # §62.5 adapter/parse/no-conclusion
        "schema_ok_rate": round(sum(s["schema_ok"] for s in scores) / n, 3),
        "investigation_accuracy": round(sum(s["disposition_correct"] for s in scores) / n, 3),
        "justified_correct": sum(s["justified_correct"] for s in scores),
        "guessed_correct": sum(s["guessed_correct"] for s in scores),
        "abstained": sum(s["abstained"] for s in scores),                  # §62.4 no-citation outcomes
        "mean_scope_f1": round(sum(s["scope_f1"] for s in scores) / n, 3),
        "mean_evidence_quality": round(sum(s["evidence_quality"] for s in scores) / n, 3),
        "raw_escalations": sum(s["raw_escalation"] for s in scores),
        "unsupported_escalations": sum(s["unsupported_escalation"] for s in scores),
        "false_escalations": sum(s["false_escalation"] for s in scores),
        "justified_resolutions": sum(s["justified_resolution"] for s in scores),
        "end_to_end_critical_misses": sum(s["end_to_end_critical_miss"] for s in scores),
        "critical_incidents": critical_total,
        "over_budget": sum(s["over_budget"] for s in scores),
    }
