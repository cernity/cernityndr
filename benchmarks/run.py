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
# Dedicated, run-scoped Compose project (M1.1/§3): the network, volumes, state and the
# (auto-named) bench-own containers are namespaced under this and isolated from a production
# 'central' deployment. Override BENCH_PROJECT to keep separate isolations apart. NOTE: the
# INCLUDED central services still carry fixed container_names, so two runs would collide there
# until those are templated — the preflight below aborts on exactly that collision.
PROJECT = os.environ.get("BENCH_PROJECT", "cernity-bench")

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


def _http_fetch(endpoint, index, body):
    url = f"{endpoint}/{index}/_search"
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read()).get("hits", {}).get("hits", [])


def os_search(endpoint, index, page=10000, fetch=None, strict=True) -> list:
    """ALL documents from an index, paginating past the 10k max_result_window via
    search_after (F10: the old `size=10000` SILENTLY TRUNCATED at 10k, so any arm with more
    than 10k docs scored wrong). On a query/engine error, RAISE in strict mode — the
    benchmark must fail loudly, never report a silent empty arm as '0 detections'."""
    fetch = fetch or _http_fetch
    out, after = [], None
    while True:
        body = {"size": page, "sort": [{"_doc": "asc"}], "query": {"match_all": {}}}
        if after is not None:
            body["search_after"] = after
        try:
            hits = fetch(endpoint, index, body)
        except Exception as e:                       # noqa: BLE001
            if strict:
                raise RuntimeError(f"OpenSearch query '{index}' failed: {e}") from e
            print(f"  ! OpenSearch query {index} failed (non-strict): {e}", file=sys.stderr)
            return out
        if not hits:
            break
        out += [h.get("_source", {}) for h in hits]
        after = hits[-1].get("sort")
        if len(hits) < page or not after:
            break
    return out


def wait_for_completion(endpoint, required, optional=(), tries=30, delay=2.0,
                        count=None, sleep=None, min_stable=2, grace=0.0) -> dict:
    """Wait until the arms have SETTLED, then return their doc counts (M1.4/§9 empty-output
    semantics). `required` arms (the baseline telemetry) must reach >=1 AND be stable — an empty
    baseline means telemetry never shipped, i.e. a broken run, so RAISE. `optional` arms (Cernity
    findings, Zeek notices) need only be STABLE: 0 is a VALID result (a benign scenario, or a real
    miss), not a failure — but only because the caller has already waited for the offline producers
    to exit, so 'empty' cannot mean 'still ingesting'. A run that never settles RAISES.

    `grace` waits before the first poll and `min_stable` requires that many CONSECUTIVE equal reads
    before settling — together they stop the optional sink arms from settling at a transient 0 while
    the findings-forwarder's BATCHED OpenSearch write is still in flight after the bus has drained
    (§25.2, the under-count seen in a live run). This is a race-reducer, NOT proof of delivery.

    Residual (§25.2, part-blocked): this verifies production + stability, not per-sink delivery
    HEALTH; a forwarder that silently dead-lettered every finding would still read as valid-empty.
    Proving delivery needs a service-side per-sink receipt/DLQ signal (not harness-verifiable)."""
    import time as _t
    count = count or (lambda idx: len(os_search(endpoint, idx, strict=False)))
    sleep = sleep or _t.sleep
    idx = list(required) + [i for i in optional if i not in required]
    if grace:
        sleep(grace)                       # let a batched sink flush land before trusting an empty arm
    prev, stable = {i: -1 for i in idx}, 0
    for _ in range(tries):
        cur = {i: count(i) for i in idx}
        stable = stable + 1 if cur == prev else 1
        if stable >= min_stable and all(cur[i] >= 1 for i in required):
            return cur
        prev = cur
        sleep(delay)
    raise RuntimeError(f"run did not settle after {tries} tries: {prev} "
                       f"(need {list(required)} >= 1 and every arm stable x{min_stable})")


def compose(*args):
    subprocess.run(["docker", "compose", "-p", PROJECT, "-f", COMPOSE, *args], check=True)


def _fixed_container_names():
    """The explicit container_name values in the resolved compose (the included central
    services still set them). The preflight uses these so the benchmark ABORTS on a real
    collision instead of attaching to / clobbering an existing deployment (§3)."""
    out = subprocess.run(["docker", "compose", "-p", PROJECT, "-f", COMPOSE, "config", "--format", "json"],
                         capture_output=True, text=True)
    if out.returncode != 0:
        return []
    cfg = json.loads(out.stdout or "{}")
    return [s["container_name"] for s in cfg.get("services", {}).values() if s.get("container_name")]


def preflight_no_foreign_containers(names=None, exists=None):
    """After tearing down THIS project's own state, any surviving fixed name belongs to a
    foreign deployment — abort rather than collide (§3 'abort on collisions, never attach')."""
    names = _fixed_container_names() if names is None else names
    exists = exists or (lambda n: subprocess.run(["docker", "inspect", n],
                                                  capture_output=True).returncode == 0)
    clash = [n for n in names if exists(n)]
    if clash:
        raise SystemExit(
            "benchmark abort: container(s) " + ", ".join(clash) + " already exist — a Cernity "
            "deployment is running here and the benchmark's fixed names would collide. Run on an "
            "isolated host or tear that deployment down first (M1.1/§3).")


def svc_container(service):
    """Resolve a bench service to its project-scoped, auto-named container id."""
    out = subprocess.run(["docker", "compose", "-p", PROJECT, "-f", COMPOSE, "ps", "-q", service],
                         capture_output=True, text=True)
    return out.stdout.strip()


def _sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git_provenance():
    """Source revision + dirty flag of the checkout under test (M0.3)."""
    def _g(*args):
        r = subprocess.run(["git", *args], cwd=HERE, capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None
    rev = _g("rev-parse", "HEAD")
    dirty = _g("status", "--porcelain")
    return {"revision": rev, "dirty": None if dirty is None else bool(dirty)}


def running_images(project):
    """service -> {image_ref, image_id, repo_digests} for the project's containers (M0.3). The
    local image_id (content id) and the registry repo_digests are recorded separately because
    they are NOT interchangeable — a pulled tag and a local build can share neither."""
    ids = subprocess.run(["docker", "compose", "-p", project, "-f", COMPOSE, "ps", "-aq"],
                         capture_output=True, text=True).stdout.split()
    out = {}
    for cid in ids:
        info = subprocess.run(
            ["docker", "inspect", cid, "--format",
             '{{index .Config.Labels "com.docker.compose.service"}}\t{{.Config.Image}}\t{{.Image}}'],
            capture_output=True, text=True).stdout.strip()
        if not info:
            continue
        parts = (info.split("\t") + ["", "", ""])[:3]
        svc, ref, image_id = parts
        rd = subprocess.run(["docker", "inspect", image_id, "--format", "{{json .RepoDigests}}"],
                            capture_output=True, text=True).stdout.strip()
        try:
            repo_digests = json.loads(rd) if rd else []
        except ValueError:
            repo_digests = []
        out[svc] = {"image_ref": ref, "image_id": image_id, "repo_digests": repo_digests}
    return out


def build_manifest(scenario, project, input_paths):
    """Provenance manifest (M0.3): source revision, per-service image identity, and input
    hashes, so a run's exact artifacts are recorded and a re-run can be checked against them."""
    import datetime as _dt
    inputs = {}
    for label, p in (input_paths or {}).items():
        if p and os.path.isfile(p):
            inputs[label] = {"file": os.path.basename(p), "sha256": _sha256(p)}
    return {"scenario": scenario, "project": project,
            "created": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "git": git_provenance(), "images": running_images(project), "inputs": inputs}


def manifest_drift(current_images, pinned_manifest):
    """Services whose running image_id differs from a pinned manifest, or are present on only
    one side (M0.4). Empty list = the run matches the pinned artifacts; pure/testable."""
    cur = {s: v.get("image_id") for s, v in (current_images or {}).items()}
    pin = {s: v.get("image_id") for s, v in ((pinned_manifest or {}).get("images") or {}).items()}
    return [{"service": s, "running": cur.get(s), "pinned": pin.get(s)}
            for s in sorted(set(cur) | set(pin)) if cur.get(s) != pin.get(s)]


PRODUCERS = ("suricata-offline", "zeek-offline", "arm-b-feeder")
# The pipeline consumer groups whose drain proves the produced input was consumed (R2/§21.2).
PIPELINE_GROUPS = ("ndr-behavioral-detectors", "ndr-ids-alerts", "ndr-finding-service",
                   "cernity-findings-forwarder", "ndr-dns-detector", "ndr-http-detector",
                   "ndr-protocol-detectors", "ndr-anomaly-detector", "ndr-coverage-detector",
                   "ndr-threat-intel", "ndr-east-west")


def _redpanda_cid(project):
    out = subprocess.run(["docker", "compose", "-p", project, "-f", COMPOSE, "ps", "-q", "redpanda"],
                         capture_output=True, text=True).stdout.split()
    return out[0] if out else ""


def wait_for_producer_exits(producers=PRODUCERS):
    """docker wait each offline producer and RECORD its exit status (R2). A non-zero exit means
    the producer failed — the run is invalid, not a valid-empty result (producer termination is
    not producer success)."""
    exits = {}
    for svc in producers:
        # -aq (not -q): a producer that already exited must still be found so a FAILED fast
        # producer is not silently skipped.
        out = subprocess.run(["docker", "compose", "-p", PROJECT, "-f", COMPOSE, "ps", "-aq", svc],
                             capture_output=True, text=True).stdout.split()
        if not out:
            continue
        rc = subprocess.run(["docker", "wait", out[0]], capture_output=True, text=True).stdout.split()
        exits[svc] = int(rc[-1]) if rc and rc[-1].lstrip("-").isdigit() else None
    return exits


def consumer_group_lag(project, groups=PIPELINE_GROUPS):
    """Total lag per pipeline consumer group via rpk in the redpanda container (R2 drain). Lag 0
    across all groups = the pipeline consumed the produced input. Empty (rpk unavailable, e.g. a
    SASL bus without creds here) => caller treats drain as unverified."""
    cid = _redpanda_cid(project)
    lag = {}
    if not cid:
        return lag
    for g in groups:
        out = subprocess.run(["docker", "exec", cid, "rpk", "group", "describe", g],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            if line.strip().startswith("TOTAL-LAG"):
                try:
                    lag[g] = int(line.split()[-1])
                except (ValueError, IndexError):
                    pass
                break
    return lag


def wait_for_drain(project, tries=25, delay=3.0, sleep=None, lag_fn=None):
    """Poll consumer-group lag until every pipeline group has caught up (total lag 0) and is
    stable across two polls, else return the last observed lag for the caller to classify as
    inconclusive (§21.2 bus drain — never scores a run whose pipeline has not consumed the input)."""
    import time as _t
    sleep = sleep or _t.sleep
    lag_fn = lag_fn or (lambda: consumer_group_lag(project))
    prev = None
    for _ in range(tries):
        lag = lag_fn()
        if lag and all(v == 0 for v in lag.values()) and lag == prev:
            return lag
        prev = lag
        sleep(delay)
    return prev or {}


def classify_completion(producer_exits, group_lag, arm_counts, required=("arm-a-suricata",),
                        expected_producers=PRODUCERS, expected_groups=PIPELINE_GROUPS):
    """Explicit run state (R2/§21.2, §24.2 + §26/§25.2 repair). A valid outcome requires the COMPLETE
    expected inventory to report — an absent, null, or unparsable status is unknown, never success:
      invalid        — an expected producer exited non-zero (a definite product/harness failure).
      inconclusive   — an expected producer is missing/null/unparsable; an expected consumer group is
                       missing/unparsable/not-drained; drain is unverifiable (no readings at all); or a
                       required baseline arm is empty. Attribution is impossible; not a valid zero.
      inputs_drained — every expected producer exited 0 AND every expected group drained to 0 AND the
                       baseline arrived. This proves the produced input was CONSUMED and the baseline
                       shipped; an empty findings arm is then a valid miss/benign. It is deliberately
                       NOT called `reconciled`: a zero-lag group is offset progress, not proof of
                       timer-driven detection / pending-capture / async-publication / per-sink
                       disposition. Full `reconciled` is reserved for when those downstream acks are
                       collected (§25.2) — not yet emitted, so `inputs_drained` is the current best.
    The run is scoreable at `inputs_drained`; the report must label it as inputs-drained (not full
    reconciliation) so the missing downstream evidence stays visible. Pure/testable."""
    unresolved = []
    # Producers: the full expected set must each report a valid exit. non-zero => invalid;
    # missing / None / unparsable => unknown (cannot reconcile).
    failed = {s: producer_exits.get(s) for s in expected_producers
              if isinstance(producer_exits.get(s), int) and producer_exits.get(s) != 0}
    unknown_producers = [s for s in expected_producers
                         if not isinstance(producer_exits.get(s), int)]   # missing or None
    if failed:
        unresolved.append(f"producer non-zero exit: {failed}")
    if unknown_producers:
        unresolved.append(f"producer status unknown (missing/null): {unknown_producers}")
    # Consumer groups: no readings at all => drain unverifiable; otherwise every expected group must
    # have a parseable, zero, drained lag. A missing/unparsable expected group is unknown, not drained.
    if not group_lag:
        unresolved.append("consumer drain unverified (no lag readings)")
        undrained = {}
    else:
        missing_groups = [g for g in expected_groups if not isinstance(group_lag.get(g), int)]
        undrained = {g: group_lag[g] for g in expected_groups
                     if isinstance(group_lag.get(g), int) and group_lag[g] != 0}
        if missing_groups:
            unresolved.append(f"consumer group status unknown (missing/unparsable): {missing_groups}")
        if undrained:
            unresolved.append(f"consumer lag not drained: {undrained}")
    empty_baseline = [i for i in required if arm_counts.get(i, 0) < 1]
    if empty_baseline:
        unresolved.append(f"baseline arm empty: {empty_baseline}")
    state = ("invalid" if failed
             else "inputs_drained" if not unresolved
             else "inconclusive")
    return {"state": state, "producer_exits": producer_exits,
            "consumer_group_lag": group_lag, "unresolved": unresolved}


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
    compose("down", "-v", "--remove-orphans")     # clean THIS project's state (empty-state, §3)
    preflight_no_foreign_containers()             # abort if a real deployment would collide (§3)
    # A pinned run must NOT rebuild: `--build` yields fresh, non-reproducible local image IDs
    # each time (observed: a rebuild drifts nearly every service from the prior manifest), so a
    # pin can only be honoured by reusing the images already present (built once / loaded by
    # digest). Unpinned runs build from source as before.
    compose("up", "-d", *([] if os.environ.get("BENCH_PIN_MANIFEST") else ["--build"]))
    apply_index_template(endpoint)             # M3: type the arm fields before ingestion (best-effort)
    print("[1b] recording provenance manifest (M0.3) + checking artifact drift (M0.4)")
    _bench = os.path.dirname(COMPOSE)
    _pcap = os.environ.get("BENCH_PCAP", "")
    _pcap_dir = os.environ.get("BENCH_PCAP_DIR")
    manifest = build_manifest(scenario, PROJECT, {
        "pcap": os.path.join(_pcap_dir, os.path.basename(_pcap)) if _pcap_dir and _pcap else None,
        "labels": os.path.join(DATASETS, scenario, "labels.json"),
        "suricata_yaml": os.path.join(_bench, "suricata", "suricata.yaml"),
        "zeek_local": os.path.join(_bench, "zeek", "local.zeek"),
        "arm_a_fluentbit": os.path.join(_bench, "arm-a", "fluent-bit.conf"),
        "arm_c_fluentbit": os.path.join(_bench, "zeek", "fluent-bit.conf")})
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "manifest.json"), "w") as _mf:
        json.dump(manifest, _mf, indent=2, sort_keys=True)
    _pin = os.environ.get("BENCH_PIN_MANIFEST")
    if _pin:
        _drift = manifest_drift(manifest["images"], _load(_pin))
        if _drift:
            compose("down", "-v", "--remove-orphans")
            raise SystemExit(f"benchmark abort: running images drift from pinned manifest "
                             f"{os.path.basename(_pin)}: {json.dumps(_drift)} — the run does not "
                             f"match the pinned artifacts (M0.4).")
    print("[2] R2 completion: waiting for producers to exit + checking their exit status")
    producer_exits = wait_for_producer_exits()
    print("[2a] R2 completion: reconciling consumer-group drain (pipeline consumed the input)")
    group_lag = wait_for_drain(PROJECT)
    print("[2b] waiting for the arms to settle (sink grace so a batched forwarder write is not raced)")
    try:
        # §25.2: after drain, allow the forwarder's batched OpenSearch write to land before trusting
        # an empty findings arm, and require a longer consecutive-stable window. BENCH_SINK_GRACE
        # (seconds) tunes the grace to the deployment's forwarder flush interval; a race-reducer.
        arm_counts = wait_for_completion(endpoint, required=["arm-a-suricata"],
                                         optional=["arm-b-findings-*", "arm-c-zeek"],
                                         grace=float(os.environ.get("BENCH_SINK_GRACE", "20") or 0),
                                         min_stable=3)
    except RuntimeError:
        arm_counts = {}                    # never settled -> classified inconclusive below
    completion = classify_completion(producer_exits, group_lag, arm_counts)
    SCOREABLE = ("inputs_drained", "reconciled")   # §25.2: reconciled requires downstream acks (future)
    if completion["state"] not in SCOREABLE:
        # A run whose inputs did not drain is NOT scored (§9/R2/§24.2): a producer failed/was unknown,
        # the pipeline never drained, or the baseline never arrived. Write a failure report with the
        # unresolved-work inventory and stop — never convert an unverified run into zero.
        _write({"meta": {"scenario": scenario, "dataset": labels.get("dataset", scenario)},
                "completion": completion, "arms": {},
                "honesty": [], "caveats": [f"inputs not drained ({completion['state']}); not scored (R2/§9)"]},
               out_dir)
        raise SystemExit(f"benchmark inputs not drained ({completion['state']}): {completion['unresolved']}")
    print("[3] exporting the immutable snapshot, then scoring FROM it (R4)")
    exported, _export_counts = export_arms(endpoint, out_dir, PROJECT)
    arm_a = exported["arm-a-suricata"]           # scored docs ARE the exported files (§20.3)
    arm_b = exported["arm-b-findings-*"]
    arm_c = exported["arm-c-zeek"]
    meta = {"scenario": scenario, "dataset": labels.get("dataset", scenario),
            "granularity": f"per-{labels.get('granularity', 'host')}",
            "determinism_hash": determinism_hash(*_eve_paths()),
            "suricata_version": os.environ.get("BENCH_SURICATA_VER", "jasonish/suricata:latest"),
            "zeek_version": os.environ.get("BENCH_ZEEK_VER", "zeek/zeek:latest"),
            "etopen": os.environ.get("BENCH_ETOPEN", "(pin in README)"),
            "cernity_version": os.environ.get("BENCH_CERNITY_VER", "dev")}
    results = _score_arms(arm_a, arm_b, arm_c, labels, meta,       # R4: score the exported snapshot
                          replay_offset=_replay_offset(out_dir))  # §25.3: map truth -> replay clock
    results["completion"] = completion                             # R2: state + evidence inventory
    if completion["state"] == "inputs_drained":                    # §25.2: be explicit about what is proven
        results.setdefault("caveats", []).append(
            "completion=inputs_drained: inputs consumed + baseline shipped; downstream detector "
            "evaluation / pending-capture / per-sink disposition not yet verified (§25.2)")
    results["exports"] = _export_counts                            # M3/R4: counts from the scored snapshot
    return _write(results, out_dir)


def _count_alerts(docs):
    return sum(1 for d in docs if d.get("event_type") == "alert") or len(docs)


def _eve_paths():
    """Real engine output files to hash for the determinism proof (F10: was [] so the
    hash was over nothing). Set BENCH_EVE_DIR to the mounted volume holding the
    Suricata/Zeek EVE outputs; every file under it is hashed."""
    d = os.environ.get("BENCH_EVE_DIR")
    if not d or not os.path.isdir(d):
        return []
    return [os.path.join(root, f) for root, _dirs, files in os.walk(d) for f in sorted(files)]


def _refresh(endpoint):
    try:
        urllib.request.urlopen(urllib.request.Request(endpoint + "/_refresh", method="POST"),
                               timeout=20).read()
    except Exception:                            # noqa: BLE001
        pass


def apply_index_template(endpoint, tries=15, delay=2.0):
    """Best-effort: install the arm-index template (M3) so Dashboards fields are typed. Racing
    the shippers is acceptable — dynamic mapping still works and the numerical export reads raw
    docs; this only improves the views. Waits briefly for OpenSearch, then PUTs the template."""
    path = os.path.join(HERE, "dashboards", "mappings", "arm-index-template.json")
    if not os.path.isfile(path):
        return
    body = _load(path)
    body.pop("_comment", None)
    import time as _t
    for _ in range(tries):
        try:
            req = urllib.request.Request(endpoint + "/_index_template/cernity-bench-arms",
                                         data=json.dumps(body).encode(), method="PUT",
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10).read()
            return
        except Exception:                        # noqa: BLE001
            _t.sleep(delay)


ARM_EXPORTS = (("arm-a-suricata", "suricata-alerts.jsonl"),
               ("arm-b-findings-*", "cernity-findings.jsonl"),
               ("arm-c-zeek", "zeek-notices.jsonl"))


def export_arms(endpoint, out_dir, project=None):
    """Complete, reproducible export of every arm's docs + the shared source EVE to the
    release-bundle layout (M3/§9.6/§11) — the auditable source for any numerical claim, and the
    data behind the paired SIEM views. Refresh first so the read sees every write, then paginate
    all docs (search_after, no 10k cap). Post-run the arms are static, so this is a complete
    snapshot; a PIT is only needed under concurrent writes (noted). Returns per-file counts."""
    outdir = os.path.join(out_dir, "output")
    os.makedirs(outdir, exist_ok=True)
    _refresh(endpoint)
    counts, docs_by = {}, {}
    for index, fname in ARM_EXPORTS:
        docs = os_search(endpoint, index, strict=False)
        with open(os.path.join(outdir, fname), "w") as f:
            for d in docs:
                f.write(json.dumps(d, sort_keys=True) + "\n")
        counts[fname] = len(docs)
        docs_by[index] = docs
    if project:                                  # the common EVE both arms consumed (fairness anchor)
        vol = f"{project}_cernity-bench-eve"
        try:
            out = subprocess.run(["docker", "run", "--rm", "-v", f"{vol}:/eve:ro", "alpine",
                                  "sh", "-c", "cat /eve/eve-*.json 2>/dev/null"],
                                 capture_output=True, text=True, timeout=60).stdout
            with open(os.path.join(outdir, "source-eve.jsonl"), "w") as f:
                f.write(out)
            counts["source-eve.jsonl"] = sum(1 for _l in out.splitlines() if _l.strip())
            # The single reanchor offset the feeder recorded (§25.3): maps episode truth -> replay clock.
            rep = subprocess.run(["docker", "run", "--rm", "-v", f"{vol}:/eve:ro", "alpine",
                                  "sh", "-c", "cat /eve/replay.json 2>/dev/null"],
                                 capture_output=True, text=True, timeout=60).stdout
            if rep.strip():
                with open(os.path.join(outdir, "replay.json"), "w") as f:
                    f.write(rep)
        except Exception:                        # noqa: BLE001
            pass
    return docs_by, counts


def _replay_offset(out_dir):
    """The recorded reanchor offset (seconds) from a run's export, or 0.0 (untimed comparison) when
    none was recorded — an old export or a no-anchor run. §25.3."""
    rep = _read_jsonl_or_json(os.path.join(out_dir, "output", "replay.json"))
    return float(rep.get("replay_offset_seconds", 0.0)) if isinstance(rep, dict) else 0.0


def _read_jsonl_or_json(path):
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        return json.load(f)


def _score_arms(arm_a, arm_b, arm_c, labels, meta, replay_offset=0.0):
    """Compose the report from the three arms' documents + frozen labels (R4). The SAME function
    scores a live run (fed the exported snapshot) and a file-only recompute, so a report is
    reproducible from out/<scenario>/output/*.jsonl. `replay_offset` maps episode truth onto the
    replay clock the delivered detections carry (§25.3). Pure over its inputs."""
    gran = labels.get("granularity", "host")
    truth = set(labels.get("malicious", []))
    arms_raw = {
        "suricata_siem": {"flagged": extract.flagged_from_alerts(arm_a, gran),
                          "raw_events": len(arm_a), "alerts": _count_alerts(arm_a),
                          "delivered": _count_alerts(arm_a)},
        "cernity_siem": {"flagged": extract.flagged_from_findings(arm_b, gran),
                         "raw_events": len(arm_a), "alerts": len(arm_b), "delivered": len(arm_b)},
        "zeek_reference": {"flagged": extract.flagged_from_notices(arm_c, gran),
                           "raw_events": len(arm_c), "alerts": len(arm_c), "delivered": len(arm_c)},
    }
    results = extract.build_results(meta, arms_raw, truth,
                                    honesty=labels.get("honesty") or DEFAULT_HONESTY,
                                    caveats=labels.get("caveats") or DEFAULT_CAVEATS)
    truth_eps = labels.get("episodes")
    if truth_eps:
        import episodes as _epmod
        # deadline=None: the latest revision per logical finding is selected deterministically
        # (order-independent), but deadline-GATING of late revisions is deferred until the product
        # exposes reliable delivery timing (§25.2/§25.3) — recency is only a proxy for delivery.
        deadline = labels.get("eval_deadline")
        results["episode_scoring"] = {
            "suricata_siem": _epmod.score(extract.detections_from_alerts(arm_a), truth_eps, replay_offset=replay_offset, deadline=deadline),
            "cernity_siem": _epmod.score(extract.detections_from_findings(arm_b), truth_eps, replay_offset=replay_offset, deadline=deadline),
            "zeek_reference": _epmod.score(extract.detections_from_notices(arm_c), truth_eps, replay_offset=replay_offset, deadline=deadline),
        }
        results["replay_offset_seconds"] = replay_offset
    return results


def _read_jsonl(path):
    if not os.path.isfile(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def score_from_export(out_dir, scenario):
    """Recompute the report from ONLY the exported files + frozen labels (R4/§21.4 file-only
    recomputation): every metric must reconcile with out/<scenario>/output/*.jsonl."""
    labels = _load(os.path.join(DATASETS, scenario, "labels.json"))
    od = os.path.join(out_dir, "output")
    arm_a = _read_jsonl(os.path.join(od, "suricata-alerts.jsonl"))
    arm_b = _read_jsonl(os.path.join(od, "cernity-findings.jsonl"))
    arm_c = _read_jsonl(os.path.join(od, "zeek-notices.jsonl"))
    meta = {"scenario": scenario, "dataset": labels.get("dataset", scenario),
            "granularity": f"per-{labels.get('granularity', 'host')}", "source": "file-only recompute"}
    return _score_arms(arm_a, arm_b, arm_c, labels, meta, replay_offset=_replay_offset(out_dir))


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
    ap.add_argument("--score-export", action="store_true",
                    help="R4: recompute the report from out/<scenario>/output/*.jsonl only (no infra)")
    a = ap.parse_args(argv)
    out_dir = a.out or os.path.join(HERE, "out", a.scenario)
    if a.score_export:
        results = score_from_export(out_dir, a.scenario)
        md = _write(results, os.path.join(out_dir, "recompute"))
        print(f"file-only recompute -> {md}")
        return 0
    md = (run_from_docs(_load(a.from_docs), out_dir) if a.from_docs
          else run_full(a.scenario, out_dir))
    print(f"report -> {md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
