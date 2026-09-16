"""Build gate for report (run: `python test_report.py`)."""
import json

import report as r

RESULTS = {
    "meta": {"scenario": "demo", "dataset": "synthetic", "granularity": "per-host",
             "determinism_hash": "abc123"},
    "arms": {
        "suricata_siem": {
            "accuracy": {"precision": 1.0, "recall": 0.4, "f1": 0.5714, "tp": 2, "fp": 0, "fn": 3},
            "noise": {"raw_events": 100000, "alerts": 500, "delivered": 500,
                      "alerts_per_true_positive": 250.0, "suppression_ratio": 0.0}},
        "cernity_siem": {
            "accuracy": {"precision": 0.9, "recall": 0.8, "f1": 0.8471, "tp": 4, "fp": 0, "fn": 1},
            "noise": {"raw_events": 100000, "alerts": 12, "delivered": 6,
                      "alerts_per_true_positive": 3.0, "suppression_ratio": 0.5}},
    },
    "honesty": ["On a direct signature IOC hit, Cernity adds little over raw Suricata."],
    "caveats": ["Synthetic scenario; not a real-world prevalence sample."],
}


def test_markdown_has_both_arms_and_all_sections():
    md = r.render_markdown(RESULTS)
    assert "Suricata -> SIEM" in md and "Suricata -> Cernity -> SIEM" in md
    assert "Detection accuracy" in md and "Volume & noise" in md
    assert "Where Cernity does NOT add value" in md and "## Caveats" in md
    assert "How to read this" in md


def test_missing_zeek_arm_omitted_without_error():
    md = r.render_markdown(RESULTS)
    assert "Zeek (reference)" not in md            # zeek_ref not in arms


def test_honesty_and_caveats_rendered():
    md = r.render_markdown(RESULTS)
    assert "adds little over raw Suricata" in md and "Synthetic scenario" in md


def test_defaults_present_when_sections_empty():
    md = r.render_markdown({"meta": {}, "arms": {}})
    assert "Where Cernity does NOT add value" in md and "## Caveats" in md   # never one-sided


def test_json_round_trips():
    assert json.loads(r.render_json(RESULTS))["meta"]["scenario"] == "demo"


def test_unreconciled_run_renders_diagnostic_not_qualified():
    # R09: an unfinished run must render validity BEFORE metrics and cannot present an unqualified
    # effectiveness table as a verdict.
    unfinished = dict(RESULTS, completion={"state": "inputs_drained",
                                           "unresolved": ["downstream delivery not accounted (R01): ..."],
                                           "delivery": None})
    md = r.render_markdown(unfinished)
    assert "## Run validity" in md
    assert md.index("## Run validity") < md.index("Detection accuracy")     # validity comes first
    assert "DIAGNOSTIC" in md and "diagnostic only" in md
    assert "Unresolved work" in md and "downstream delivery not accounted" in md
    assert not r._qualified(unfinished)


def test_delivery_conflict_run_cannot_render_qualified():
    # §39.5 report-level negative control: a delivery CONFLICT (ledger present but not reconciled) must
    # render DIAGNOSTIC with the disagreement shown, never a qualified effectiveness table.
    conflict = dict(RESULTS, completion={
        "state": "inputs_drained",
        "unresolved": ["downstream delivery CONFLICT — durable ledger present but does not reconcile; NOT overridden by the bus receipt (§39.2): ledger accounts 1 of 100"],
        "delivery": {"source": "obligation-ledger", "delivered": 1, "dead_lettered": 0}})
    md = r.render_markdown(conflict)
    assert not r._qualified(conflict)
    assert "DIAGNOSTIC" in md and "delivery CONFLICT" in md


def test_reconciled_run_is_qualified():
    # R09: a reconciled run with no unresolved work IS a qualified result (no diagnostic banner).
    done = dict(RESULTS, completion={"state": "reconciled", "unresolved": [],
                                     "delivery": {"source": "obligation-ledger", "delivered": 6, "dead_lettered": 0}})
    md = r.render_markdown(done)
    assert r._qualified(done)
    assert "DIAGNOSTIC" not in md
    assert "Qualified effectiveness result: **yes**" in md


def test_unbound_capture_run_is_not_qualified():
    # §49.3: a reconciled run whose capture is NOT hash-bound is diagnostic, not qualified.
    reconciled_unbound = dict(RESULTS, completion={"state": "reconciled", "unresolved": []}, capture_bound=False)
    assert not r._qualified(reconciled_unbound)
    assert "DIAGNOSTIC" in r.render_markdown(reconciled_unbound)
    bound = dict(RESULTS, completion={"state": "reconciled", "unresolved": []}, capture_bound=True)
    assert r._qualified(bound)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"ok {name}")
    print("all ok")
