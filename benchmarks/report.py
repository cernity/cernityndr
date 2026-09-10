"""Benchmark report rendering (pure, stdlib only). A results dict -> a markdown
side-by-side report + JSON. The markdown always carries the honesty and caveats
sections and the paradigm-interpretation note, so a run cannot silently produce a
one-sided 'Cernity wins' artifact.
"""
from __future__ import annotations
import json

ARMS = ("suricata_siem", "cernity_siem", "zeek_ref")
ARM_LABEL = {"suricata_siem": "Suricata -> SIEM",
             "cernity_siem": "Suricata -> Cernity -> SIEM",
             "zeek_ref": "Zeek (reference)"}


def render_markdown(results: dict) -> str:
    meta = results.get("meta", {})
    arms = results.get("arms", {})
    L = [f"# Benchmark: {meta.get('scenario', '(scenario)')}", ""]
    L.append(f"- Dataset: {meta.get('dataset', '?')}")
    L.append(f"- Suricata: {meta.get('suricata_version', '?')} · ET Open: {meta.get('etopen', '?')}")
    L.append(f"- Zeek: {meta.get('zeek_version', '?')} · Cernity: {meta.get('cernity_version', '?')}")
    L.append(f"- Granularity: {meta.get('granularity', 'per-host')} · determinism hash: "
             f"`{meta.get('determinism_hash', '?')}`")

    L += ["", "## Detection accuracy", "",
          "| Arm | Precision | Recall | F1 | TP | FP | FN |",
          "|---|---|---|---|---|---|---|"]
    for a in ARMS:
        if a not in arms:
            continue
        sc = arms[a].get("accuracy", {})
        L.append(f"| {ARM_LABEL[a]} | {sc.get('precision', '-')} | {sc.get('recall', '-')} | "
                 f"{sc.get('f1', '-')} | {sc.get('tp', '-')} | {sc.get('fp', '-')} | {sc.get('fn', '-')} |")

    L += ["", "## Analyst experience (volume & noise)", "",
          "| Arm | Raw events | Alerts/Findings | Delivered | Alerts per true positive | Suppression |",
          "|---|---|---|---|---|---|"]
    for a in ARMS:
        if a not in arms:
            continue
        nz = arms[a].get("noise", {})
        L.append(f"| {ARM_LABEL[a]} | {nz.get('raw_events', '-')} | {nz.get('alerts', '-')} | "
                 f"{nz.get('delivered', '-')} | {nz.get('alerts_per_true_positive', '-')} | "
                 f"{nz.get('suppression_ratio', '-')} |")

    L += ["", "## How to read this", "",
          "These engines are architecturally different — Suricata matches signatures, Zeek "
          "scripts structure, Cernity adds stateful/behavioral analysis and a findings "
          "lifecycle on top. Compare by paradigm, not by one 'winner' number.", "",
          "## Where Cernity does NOT add value", ""]
    for note in results.get("honesty") or ["(record per run: e.g. on a direct signature IOC hit, "
                                           "Cernity adds little over raw Suricata beyond enrichment)"]:
        L.append(f"- {note}")

    L += ["", "## Caveats", ""]
    for c in results.get("caveats") or ["Dataset age: a stale corpus may not trigger current "
                                        "rulesets — a fairness caveat, not a detection failure."]:
        L.append(f"- {c}")
    return "\n".join(L) + "\n"


def render_json(results: dict) -> str:
    return json.dumps(results, indent=2, sort_keys=True)
