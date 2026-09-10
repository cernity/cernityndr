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
    assert "Detection accuracy" in md and "Analyst experience" in md
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


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"ok {name}")
    print("all ok")
