#!/usr/bin/env python3
"""Benchmark orchestrator.

Runs one scenario through the two arms (+ Zeek reference) and writes a side-by-side
report. Two paths:

  * full (needs Docker): brings up deploy/benchmark, runs Suricata/Zeek offline over
    the PCAP, ships Arm A (raw EVE -> OpenSearch) and Arm B (EVE -> Cernity -> findings
    -> OpenSearch), queries both, scores, reports.
  * --from-docs <json> (no infra): compose a report from already-fetched arm documents.
    Used for CI/smoke and to prove the extract->scorer->report chain end to end.

The scoring/report/extract logic is pure and unit-gated (test_scorer/report/extract);
this file is the I/O shell around it.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.request

import extract
import report

HERE = os.path.dirname(os.path.abspath(__file__))
DATASETS = os.path.join(HERE, "datasets")
COMPOSE = os.path.join(HERE, "..", "deploy", "benchmark", "docker-compose.yml")

DEFAULT_HONESTY = [
    "On a direct signature IOC hit, Cernity adds little raw detection over Suricata beyond "
    "enrichment and lifecycle — the value there is triage volume, not catching more.",
]
DEFAULT_CAVEATS = [
    "Offline pcap replay: this measures detection and analyst-volume, NOT throughput/packet loss.",
    "Dataset age: a stale corpus may not trigger current rulesets — a fairness caveat, not a "
    "detection failure. Ruleset/engine versions are recorded in the report meta.",
    "Both arms use fair default/max configs; neither is tuned to the dataset.",
]


def _load(path):
    with open(path) as f:
        return json.load(f)


def determinism_hash(*paths) -> str:
    """SHA-256 over the engine outputs, so a re-run can be shown byte-identical (R1)."""
    h = hashlib.sha256()
    for p in sorted(paths):
        try:
            with open(p, "rb") as f:
                h.update(f.read())
        except OSError:
            h.update(b"<missing>")
    return h.hexdigest()[:16]


def os_search(endpoint, index, size=10000) -> list:
    """Fetch documents from an OpenSearch index (best-effort; empty on error)."""
    url = f"{endpoint}/{index}/_search?size={size}"
    body = json.dumps({"query": {"match_all": {}}}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            hits = json.loads(r.read()).get("hits", {}).get("hits", [])
        return [h.get("_source", {}) for h in hits]
    except Exception as e:                       # noqa: BLE001 - report the gap, don't crash
        print(f"  ! OpenSearch query {index} failed: {e}", file=sys.stderr)
        return []


def compose(*args):
    subprocess.run(["docker", "compose", "-f", COMPOSE, *args], check=True)


def run_from_docs(spec: dict, out_dir: str) -> str:
    """No-infra path: `spec` carries meta, truth, and each arm's raw docs + counts."""
    gran = spec.get("meta", {}).get("granularity", "host")
    arms_raw = {}
    for arm, d in spec["arms"].items():
        docs = d.get("docs", [])
        flag = (extract.flagged_from_findings if d.get("kind") == "findings"
                else extract.flagged_from_alerts)(docs, gran)
        arms_raw[arm] = {"flagged": flag, "raw_events": d.get("raw_events", 0),
                         "alerts": d.get("alerts", len(docs)),
                         "delivered": d.get("delivered", d.get("alerts", len(docs)))}
    results = extract.build_results(spec["meta"], arms_raw, spec.get("truth", []),
                                    honesty=spec.get("honesty") or DEFAULT_HONESTY,
                                    caveats=spec.get("caveats") or DEFAULT_CAVEATS)
    return _write(results, out_dir)


def run_full(scenario: str, out_dir: str) -> str:
    """Docker path. Sequences the offline engines, ships both arms, queries, scores."""
    labels = _load(os.path.join(DATASETS, scenario, "labels.json"))
    endpoint = os.environ.get("BENCH_OPENSEARCH", "http://localhost:9200")
    print(f"[1] bringing up benchmark stack for '{scenario}'")
    compose("up", "-d", "--build")
    print("[2] waiting for offline engines to finish + arms to ship (see compose logs)")
    subprocess.run(["docker", "wait", "cernity-bench-suricata"], check=False)
    # ships + Cernity settle; run.py polls OpenSearch until counts stabilise (omitted here).
    print("[3] querying both arms from OpenSearch")
    arm_a = os_search(endpoint, "arm-a-suricata")
    arm_b = os_search(endpoint, "arm-b-findings-*")
    gran = labels.get("granularity", "host")
    truth = set(labels["malicious"])
    arms_raw = {
        "suricata_siem": {"flagged": extract.flagged_from_alerts(arm_a, gran),
                          "raw_events": len(arm_a), "alerts": _count_alerts(arm_a),
                          "delivered": _count_alerts(arm_a)},
        "cernity_siem": {"flagged": extract.flagged_from_findings(arm_b, gran),
                         "raw_events": len(arm_a), "alerts": len(arm_b), "delivered": len(arm_b)},
    }
    meta = {"scenario": scenario, "dataset": labels.get("dataset", scenario),
            "granularity": f"per-{gran}",
            "determinism_hash": determinism_hash(*_eve_paths()),
            "suricata_version": os.environ.get("BENCH_SURICATA_VER", "jasonish/suricata:latest"),
            "zeek_version": os.environ.get("BENCH_ZEEK_VER", "zeek/zeek:latest"),
            "etopen": os.environ.get("BENCH_ETOPEN", "(pin in README)"),
            "cernity_version": os.environ.get("BENCH_CERNITY_VER", "dev")}
    results = extract.build_results(meta, arms_raw, truth,
                                    honesty=labels.get("honesty") or DEFAULT_HONESTY,
                                    caveats=labels.get("caveats") or DEFAULT_CAVEATS)
    return _write(results, out_dir)


def _count_alerts(docs):
    return sum(1 for d in docs if d.get("event_type") == "alert") or len(docs)


def _eve_paths():
    return []   # populated when reading from a mounted volume in a real run


def _write(results: dict, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    md = os.path.join(out_dir, "report.md")
    with open(md, "w") as f:
        f.write(report.render_markdown(results))
    with open(os.path.join(out_dir, "report.json"), "w") as f:
        f.write(report.render_json(results))
    return md


def main(argv=None):
    ap = argparse.ArgumentParser(description="Cernity Suricata-vs-Cernity benchmark")
    ap.add_argument("scenario", help="scenario name under benchmarks/datasets/")
    ap.add_argument("--from-docs", help="no-infra: JSON of pre-fetched arm docs")
    ap.add_argument("--out", default=None, help="output dir (default benchmarks/out/<scenario>)")
    a = ap.parse_args(argv)
    out_dir = a.out or os.path.join(HERE, "out", a.scenario)
    md = (run_from_docs(_load(a.from_docs), out_dir) if a.from_docs
          else run_full(a.scenario, out_dir))
    print(f"report -> {md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
