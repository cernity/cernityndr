"""Benchmark scoring (pure, stdlib only). Detection-accuracy and alert-noise
metrics from each arm's flagged entities against a ground-truth set. Same
pure-module + assert-test pattern the detectors use.

The caller decides granularity by how it keys the sets: per-host uses attacker
IPs, per-flow uses community-ids. The scorer is agnostic to that choice.
"""
from __future__ import annotations


def score(flagged, truth) -> dict:
    """Precision / recall / F1 for one arm. Empty-set safe: a metric with a zero
    denominator is 0.0, never a ZeroDivisionError."""
    flagged, truth = set(flagged), set(truth)
    tp = len(flagged & truth)
    fp = len(flagged - truth)
    fn = len(truth - flagged)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}


def noise(raw_events: int, alerts: int, true_positives: int, delivered: int) -> dict:
    """Analyst-facing volume. `alerts_per_true_positive` = how many things an analyst
    must triage per real threat (the firehose-vs-findings story). `suppression_ratio`
    = how much of the alert stream Cernity gates away before delivery."""
    return {
        "raw_events": raw_events,
        "alerts": alerts,
        "delivered": delivered,
        "alerts_per_true_positive": round(alerts / true_positives, 2) if true_positives else None,
        "suppression_ratio": round(1 - delivered / alerts, 4) if alerts else 0.0,
    }
