#!/usr/bin/env python3
"""Per-detector precision/recall harness (plan U7).

Replays a LABELED corpus of Suricata flow/DNS events through the real detector
pipeline (app._handle + evaluate on an in-memory store) and scores each detector's
findings against the labels. A corpus line is a normal EVE event with an added
`expect` list naming the detector_ids that SHOULD fire for its entity; lines with
no `expect` are benign (any finding on them is a false positive).

Usage:
  python precision_recall.py --demo                 # synthetic labeled corpus
  python precision_recall.py --corpus labeled.jsonl # your labeled captures

Real labeled sources to point --corpus at (normalize to EVE+expect first): the
CTU-13 / Stratosphere botnet captures and malware-traffic-analysis.net, with
flightsim-generated benign/malicious mixes.
"""
import argparse
import json
import os
import sys
import time

os.environ.setdefault("NDR_STATE_BACKEND", "memory")
os.environ.setdefault("NDR_CONFIG_TOPIC_DISABLE", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app, store                                       # noqa: E402


class _Collector:
    def __init__(self):
        self.out = []

    def send(self, _t, v):
        self.out.append(v)

    def flush(self):
        pass


def _entity_ips(finding):
    try:
        return {e.get("value") for e in json.loads(finding["entities"]) if e.get("type") in ("ip", "domain")}
    except Exception:
        return set()


def run(corpus):
    app._store = store.make_store("memory")
    app._rare_last_eval = 0.0                # rare-dest emits dsts first-seen since last eval (plan 007)
    p = _Collector()
    now = time.time()
    expected = []          # (detector_id, {entity ips})
    for line in corpus:
        exp = line.pop("expect", None)
        if exp:
            ips = {v for v in (line.get("src_ip"), line.get("dest_ip")) if v}
            for d in exp:
                expected.append((d, ips))
        app._handle(line, p, now)
    app.evaluate(p)

    got = [(f["detector_id"], _entity_ips(f)) for f in p.out]
    detectors = sorted({d for d, _ in expected} | {d for d, _ in got})
    print(f"{'detector':<28}{'TP':>4}{'FP':>4}{'FN':>4}{'prec':>8}{'recall':>8}")
    for det_id in detectors:
        exp = [ips for d, ips in expected if d == det_id]
        gt = [ips for d, ips in got if d == det_id]
        tp = sum(1 for e in exp if any(e & g for g in gt))
        fn = len(exp) - tp
        fp = sum(1 for g in gt if not any(g & e for e in exp))
        prec = tp / (tp + fp) if (tp + fp) else 1.0
        rec = tp / (tp + fn) if (tp + fn) else 1.0
        print(f"{det_id:<28}{tp:>4}{fp:>4}{fn:>4}{prec:>8.2f}{rec:>8.2f}")
    return expected, got


def demo():
    """Synthetic labeled corpus: one real beacon, one exfil, plus benign noise.
    Timestamps are relative to now so the planted beacon is always inside the
    rolling window regardless of when/where the harness runs."""
    from datetime import datetime, timezone, timedelta
    c = []
    start = datetime.now(timezone.utc) - timedelta(seconds=550)
    def iso(sec):
        return (start + timedelta(seconds=sec)).isoformat().replace("+00:00", "Z")
    # a real C2 beacon: 12 regular callbacks (every 45s) to a rare external dst
    for i in range(12):
        c.append({"event_type": "flow", "src_ip": "10.0.0.9", "dest_ip": "203.0.113.44",
                  "timestamp": iso(i * 45),
                  "flow": {"bytes_toserver": 300, "bytes_toclient": 300, "age": 1},
                  "expect": ["beacon"]})
    # an exfil: one big upload to an external dst
    c.append({"event_type": "flow", "src_ip": "10.0.0.9", "dest_ip": "198.51.100.7",
              "timestamp": iso(0),
              "flow": {"bytes_toserver": 80_000_000, "bytes_toclient": 100, "age": 5},
              "expect": ["exfil"]})
    # benign noise: one-off external flows (no expect -> any finding is FP)
    for i in range(30):
        c.append({"event_type": "flow", "src_ip": "10.0.0.9", "dest_ip": f"93.184.216.{i}",
                  "timestamp": iso(i),
                  "flow": {"bytes_toserver": 500, "bytes_toclient": 4000, "age": 1}})
    return c


def fingerprint(corpus):
    """Severity-aware equivalence artifact (plan 007 R3). The TP/FP table above
    compares only (detector_id, entity ips); this dumps every finding's
    (detector_id, entities, severity, confidence) sorted, so a diff of
    `--fingerprint` output before vs after a change proves findings were preserved
    INCLUDING severity -- the write-only refactor's hard acceptance gate. (Proven
    on the demo corpus: 19 findings byte-identical pre/post.)"""
    app._store = store.make_store("memory")
    app._rare_last_eval = 0.0                # rare-dest emits dsts first-seen since last eval (plan 007)
    p = _Collector()
    now = time.time()
    for line in corpus:
        line.pop("expect", None)
        app._handle(line, p, now)
    app.evaluate(p)
    for r in sorted((f["detector_id"], f["entities"], f["severity"], f["confidence"]) for f in p.out):
        print(json.dumps(r))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus")
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--fingerprint", action="store_true", help="dump severity-aware finding fingerprint for equivalence diffing")
    a = ap.parse_args()
    corpus = demo() if (a.demo or not a.corpus) else [json.loads(l) for l in open(a.corpus) if l.strip()]
    fingerprint(corpus) if a.fingerprint else run(corpus)
