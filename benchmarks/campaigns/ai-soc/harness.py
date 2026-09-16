"""AI-SOC assessment harness (§44). Wires the pieces: load the frozen profile/tasks/rubric, run each
task through an ISOLATED investigator bound to its arm's read-only evidence, score with the INDEPENDENT
evaluator against hidden truth, and write a run manifest + per-task audit. The investigator is
pluggable so CI runs a deterministic stub and a live run plugs in the pinned model (agent-config.json).

This module builds the harness; it does NOT grade its own narrative (§44.3) — scoring is entirely in
evaluator.py against hidden truth, and the investigator never receives that truth (investigator.py).

CLI:  python harness.py --arm B [--out runs/<id>]   # uses the evidence_driven stub by default
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone

import evaluator
import investigator as inv
import stub_investigator

HERE = os.path.dirname(os.path.abspath(__file__))
_STUBS = {"evidence_driven": stub_investigator.evidence_driven,
          "credulous": stub_investigator.credulous,
          "hallucinating": stub_investigator.hallucinating,
          "correct_label_fabricated_support": stub_investigator.correct_label_fabricated_support,
          "unrelated_behaviour_citation": stub_investigator.unrelated_behaviour_citation,
          "cites_without_retrieving": stub_investigator.cites_without_retrieving,
          "bad_schema": stub_investigator.bad_schema}


def _load_json(name):
    with open(os.path.join(HERE, name)) as f:
        return json.load(f)


def _load_tasks():
    with open(os.path.join(HERE, "tasks.jsonl")) as f:
        return [json.loads(l) for l in f if l.strip()]


def load_arm_evidence(arm: str) -> list[dict]:
    """One arm's exposed findings/alerts. Fixtures back the smoke; a live run points this at the arm's
    actual export (benchmarks/out/<scenario>/output/cernity-findings.jsonl for B, suricata-alerts for A2)."""
    path = os.path.join(HERE, "fixtures", f"arm-{arm.lower()}.jsonl")
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(65536), b""):
            h.update(b)
    return h.hexdigest()


EVALUATOR_VERSION = "2"      # §57 repair: independent GT miss, executable rubric, retrieval-checked citations


def run_campaign(arm: str, investigate, out_dir: str | None = None, budget: int | None = None,
                 investigator_type: str = "stub", model_executed: str | None = None) -> dict:
    """Run every task for one arm, evaluate against the frozen rubric, aggregate, and (if out_dir)
    persist the audit + a provenance-complete manifest. `investigator_type`/`model_executed` are
    recorded SEPARATELY (§57.4): a configured model string in agent-config is NOT a model invocation."""
    profile, agent = _load_json("profile.json"), _load_json("agent-config.json")
    rubric = evaluator.load_rubric()          # §57.3: fails loudly if missing/malformed -> not qualifiable
    tasks = [t for t in _load_tasks() if t.get("arm") == arm]
    evidence = load_arm_evidence(arm)
    budget = budget if budget is not None else int(agent.get("max_queries", 10))

    per_task, scores = [], []
    for task in tasks:
        result = inv.run_task(task, evidence, investigate, budget=budget)
        # evaluator re-binds a FRESH, UNBOUNDED read-only tool to verify citations without spending budget
        score = evaluator.evaluate(task, result, inv.ReadOnlySiemTool(arm, evidence, budget=None), rubric)
        per_task.append({"result": result, "score": score})
        scores.append(score)

    manifest = {
        "campaign": "ai-soc", "arm": arm,
        # §62.3: this run investigates the campaign FIXTURES (curated per-arm evidence), NOT verified
        # product exports. Reserve 'verified-product-evidence' for the bundle-backed export path.
        "evidence_kind": "fixture",
        "profile": profile.get("name"), "profile_kind": profile.get("kind"),
        "profile_sha256": _sha256(os.path.join(HERE, "profile.json")),
        "tasks_sha256": _sha256(os.path.join(HERE, "tasks.jsonl")),
        "rubric_sha256": _sha256(os.path.join(HERE, "rubric.json")),
        "agent_config_sha256": _sha256(os.path.join(HERE, "agent-config.json")),
        "evidence_sha256": _sha256(os.path.join(HERE, "fixtures", f"arm-{arm.lower()}.jsonl")),
        "evaluator_version": EVALUATOR_VERSION,
        "tool_schema_version": inv.ReadOnlySiemTool.SCHEMA_VERSION,
        # §57.4: what was CONFIGURED vs what actually EXECUTED are distinct facts.
        "configured_model": agent.get("investigator_model"),
        "investigator_type": investigator_type,
        "model_executed": model_executed,          # None for a stub run — no model was invoked
        "query_budget": budget, "task_count": len(tasks),
        "run_at": datetime.now(timezone.utc).isoformat(),
        "aggregate": evaluator.aggregate(scores),
    }
    if out_dir:
        # §57.4: unique run dir, never silently overwrite a prior run's evidence.
        if os.path.exists(out_dir) and os.listdir(out_dir):
            raise SystemExit(f"run dir {out_dir} is non-empty — refusing to overwrite (use a fresh dir)")
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)
        with open(os.path.join(out_dir, "audit.jsonl"), "w") as f:
            for pt in per_task:
                f.write(json.dumps(pt) + "\n")
    return {"manifest": manifest, "per_task": per_task}


def _build_live(provider, model_url, model, api_key_env):
    """§59.4: wire the real ReAct model adapter over a live endpoint. `provider` selects the transport:
    'openai' for any OpenAI-compatible /v1/chat/completions (local llama.cpp/oMLX/vLLM), 'anthropic' for
    the Anthropic Messages API. Returns (investigate_fn, model_id). Imported lazily."""
    import os as _os
    import model_adapter
    key = _os.environ.get(api_key_env) if api_key_env else None
    if provider == "anthropic":
        if not key:
            raise SystemExit(f"anthropic provider needs an API key in ${api_key_env}")
        chat = model_adapter.anthropic_chat(model, key)
    else:
        chat = model_adapter.openai_chat(model_url, model, api_key=key)
    return model_adapter.react_investigator(chat), model


def main(argv=None):
    ap = argparse.ArgumentParser(description="AI-SOC assessment harness (§44)")
    ap.add_argument("--arm", default="B", help="arm to assess (A2/A3/B)")
    ap.add_argument("--investigator", default="evidence_driven", choices=sorted(_STUBS),
                    help="stub investigator (a live run uses --model-url instead)")
    ap.add_argument("--provider", default="openai", choices=("openai", "anthropic"),
                    help="live transport: openai (any /v1/chat/completions) or anthropic (Messages API)")
    ap.add_argument("--model-url", help="§59.4 live run: OpenAI-compatible base URL (e.g. http://host:8081)")
    ap.add_argument("--model", help="model id for the live run")
    ap.add_argument("--api-key-env", help="env var holding the API key, if the endpoint requires one")
    ap.add_argument("--out", default=None, help="output dir for manifest + audit")
    a = ap.parse_args(argv)
    if a.model_url or a.provider == "anthropic":     # §59.4 live run: real model, recorded as such
        if not a.model:
            ap.error("--model is required for a live run")
        invfn, model_id = _build_live(a.provider, a.model_url, a.model, a.api_key_env)
        res = run_campaign(a.arm, invfn, out_dir=a.out, investigator_type="live", model_executed=model_id)
    else:
        res = run_campaign(a.arm, _STUBS[a.investigator], out_dir=a.out, investigator_type="stub")
    print(json.dumps(res["manifest"]["aggregate"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
