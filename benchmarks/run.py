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


# The offline PRODUCERS (read the pcap / feed the bus). Verification runs while the rest of the
# stack is up but BEFORE these start, so a drifted image, bad input, or reused output aborts the
# run before any data is produced (§25.1 verify-before-feeder). Compose service names.
PRODUCER_SERVICES = ("suricata-offline", "zeek-offline", "arm-b-feeder")


def _all_services():
    out = subprocess.run(["docker", "compose", "-p", PROJECT, "-f", COMPOSE, "config", "--services"],
                         capture_output=True, text=True)
    return [s for s in out.stdout.split() if s]


def _running_services():
    out = subprocess.run(["docker", "compose", "-p", PROJECT, "-f", COMPOSE, "ps", "--services",
                          "--status", "running"], capture_output=True, text=True)
    return [s for s in out.stdout.split() if s]


def _run_id():
    import datetime as _dt
    import uuid
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]


def build_run_spec(scenario, run_id, manifest, required_services, required_groups, deadline=None):
    """The frozen experiment spec archived with each run (§25.1): what identity/inputs/topology this
    result is attributable to. Required components are listed EXPLICITLY so a missing one is a
    failure, never a silent optional. `replay_mapping` is filled after the feeder records it."""
    return {
        "run_id": run_id, "scenario": scenario,
        "target_images": manifest.get("images", {}),          # per-service revision identity
        "inputs": manifest.get("inputs", {}),                 # pcap/labels/config hashes (fairness anchor)
        "required_services": list(required_services),
        "required_groups": list(required_groups),
        "optional_arms": ["arm-b-findings-*", "arm-c-zeek"],  # a valid-empty result, not required
        "replay_mapping": None,
        "eval_deadline": deadline,
        "scoring_policy": {"identity": "(tenant, finding_id)", "temporal": "in/out/ambiguous/untimed",
                           "precision": "adjudicable-only", "revision": "max-rank, deadline-aware"},
    }


def preflight_run_spec(spec, running_services, output_exists=False, overwrite=False):
    """Gate scenario execution on an explicit successful preflight BEFORE the feeder is released
    (§25.1). Fails on: an empty required set (would silently accept any topology), a required
    service not running, or a populated output dir (reused run id / overlapping path — refuse to
    overwrite existing evidence). Pure/testable."""
    problems = []
    if not spec.get("required_services"):
        problems.append("run-spec declares no required services (would silently accept any topology)")
    missing = [s for s in spec.get("required_services", []) if s not in set(running_services)]
    if missing:
        problems.append(f"required services not running: {missing}")
    if output_exists and not overwrite:
        problems.append(f"output already holds a scored run (reused run dir / id {spec.get('run_id')}); "
                        f"refusing to overwrite evidence — set BENCH_OVERWRITE=1 for a new attempt")
    if problems:
        raise SystemExit("run-spec preflight FAILED (before any production): " + "; ".join(problems))
    return spec


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


def _bundle_digest(files) -> str:
    """One digest pinning the whole export bundle: sha256 over the sorted (filename, per-file sha256)
    pairs (§stage4). Recorded with the result and publishable as the immutable release record, so a
    jointly-altered bundle+manifest is caught by comparing to the externally-published value."""
    canon = json.dumps(sorted((name, rec.get("sha256")) for name, rec in (files or {}).items()),
                       sort_keys=True).encode()
    return hashlib.sha256(canon).hexdigest()


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
# The TIMER-DRIVEN detectors whose evaluation is decoupled from consumption: they must ack an
# evaluate pass past the drain instant (§stage3 gate). Per-record detectors (anomaly/protocol/http/
# ids) evaluate on consume, so consumer-group drain already proves their evaluation. These `svc`
# names match the eval-ack `svc` field emitted by ndr_runtime.EvalAckEmitter.
EXPECTED_EVAL_DETECTORS = ("behavioral-detectors", "dns-detector", "east-west-detectors")


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


def read_sink_receipts(project, topic="ndr.sink.receipt.v1", limit=2000, timeout=12):
    """ALL findings-forwarder receipts on the bus (Rec-D/§stage3), read via rpk. Returns the raw list;
    the caller aggregates the latest PER WORKER — trusting one recent message drops a second worker's
    counts or accepts a stale one. rpk tails after end-of-topic, so a bounded timeout stops it."""
    cid = _redpanda_cid(project)
    if not cid:
        return []
    p = subprocess.Popen(["docker", "exec", cid, "rpk", "topic", "consume", topic,
                          "-o", "start", "-n", str(limit), "-f", "%v\n"],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
    receipts = []
    for line in (out or "").splitlines():
        line = line.strip()
        if line:
            try:
                receipts.append(json.loads(line))
            except ValueError:
                pass
    return receipts


def read_obligations(project):
    """The findings-forwarder's DURABLE obligation ledger(s), read off the persistent cernity-out
    volume (§stage2/3 fix). This is the AUTHORITATIVE, synchronously-written delivery record — unlike
    the bus receipt it cannot race the deliveries it describes. Returns (records, available): available
    is False only when the volume/ledger could not be read (then the caller falls back to the receipt)."""
    vol = f"{project}_cernity-out"
    try:
        out = subprocess.run(["docker", "run", "--rm", "-v", f"{vol}:/out:ro", "alpine",
                              "sh", "-c", "cat /out/dlq/obligations-*.jsonl 2>/dev/null"],
                             capture_output=True, text=True, timeout=60)
    except Exception:                                # noqa: BLE001
        return [], False
    if out.returncode != 0:
        return [], False
    records = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if line:
            try:
                records.append(json.loads(line))
            except ValueError:
                pass
    return records, True                             # readable (possibly empty = a benign no-delivery run)


def ledger_disposition(records):
    """Authoritative delivery disposition from the obligation ledger: distinct delivered / dead-lettered
    obligations per destination (deduped by finding_id+revision+dest — a record appears once even if the
    ledger was appended to across restarts). dead_lettered>0 is a recorded delivery FAILURE (valid
    negative), still accounted."""
    seen, sinks = set(), {}
    for r in records or []:
        if not isinstance(r, dict):
            continue
        key = (r.get("finding_id"), r.get("revision"), r.get("dest"))
        if key in seen:
            continue
        seen.add(key)
        s = sinks.setdefault(r.get("dest"), {"name": r.get("dest"), "delivered": 0, "dead_lettered": 0})
        if r.get("outcome") == "delivered":
            s["delivered"] += 1
        elif r.get("outcome") == "dead_lettered":
            s["dead_lettered"] += 1
    return {"sinks": list(sinks.values()),
            "delivered": sum(s["delivered"] for s in sinks.values()),
            "dead_lettered": sum(s["dead_lettered"] for s in sinks.values())}


def read_eval_acks(project, topic="ndr.eval.ack.v1", limit=5000, timeout=12):
    """All detector evaluation-completion acks on the bus (§stage3), read via rpk. A detector emits
    one per assigned partition after each evaluate() pass; the harness confirms evaluation covered the
    input horizon, not just that offsets progressed. Returns the raw list ([] if absent)."""
    return read_sink_receipts(project, topic=topic, limit=limit, timeout=timeout)


def eval_horizon_ok(acks, expected_detectors, deadline_wall, default_horizon=0.0):
    """PURE (§stage3): every expected detector must have an ack whose evaluate() ran at/after the
    deadline (last input time + the detector's horizon) — proving a post-drain, horizon-covering
    evaluation pass, not just consumed offsets. Returns (ok, unresolved[]). An empty expected set
    means the gate is not armed yet (not all detectors emit acks) -> ok=True with a note, so this is
    evidence-only until the full rollout."""
    if not expected_detectors:
        return True, ["eval-ack gate not armed (no expected detectors declared)"]
    latest = {}                                       # svc -> max evaluated_wall seen (over its acks)
    horizon = {}
    for a in acks or []:
        if not isinstance(a, dict):
            continue
        svc = a.get("svc")
        ew = a.get("evaluated_wall")
        if svc is None or not isinstance(ew, (int, float)):
            continue
        latest[svc] = max(ew, latest.get(svc, float("-inf")))
        horizon[svc] = max(a.get("horizon_secs") or default_horizon, horizon.get(svc, 0.0))
    unresolved = []
    for svc in expected_detectors:
        if svc not in latest:
            unresolved.append(f"{svc}: no evaluation ack")
        elif latest[svc] < deadline_wall + horizon.get(svc, default_horizon):
            unresolved.append(f"{svc}: last evaluate {latest[svc]} < deadline+horizon "
                              f"{deadline_wall + horizon.get(svc, default_horizon)}")
    return (not unresolved), unresolved


def read_lifecycle_acks(project, topic="ndr.lifecycle.ack.v1", limit=5000, timeout=12):
    """finding-service lifecycle disposition acks (§stage3): delivered-now / capture-requested /
    pending / finalized. Read via rpk. Returns the raw list ([] if absent)."""
    return read_sink_receipts(project, topic=topic, limit=limit, timeout=timeout)


def lifecycle_disposition(acks):
    """Aggregate the latest finding-service lifecycle ack PER worker and sum. None when no acks exist
    (not armed / disabled). `pending`>0 means capture-bound findings were never finalized — undisposed
    lifecycle work that producer exit + offset progress cannot reveal (§stage3)."""
    latest = {}
    for a in acks or []:
        if not isinstance(a, dict):
            continue
        w = a.get("worker")
        if w not in latest or a.get("seq", 0) > latest[w].get("seq", 0):
            latest[w] = a
    if not latest:
        return None
    return {"delivered_now": sum(a.get("delivered_now", 0) for a in latest.values()),
            "capture_requested": sum(a.get("capture_requested", 0) for a in latest.values()),
            "pending": sum(a.get("pending", 0) for a in latest.values()),
            "finalized": sum(a.get("finalized", 0) for a in latest.values()),
            "workers": len(latest)}


def _summarize_eval_acks(acks):
    """Per-detector evaluation evidence for the completion record: latest evaluate() wall time,
    records seen, horizon, ack count. Evidence, not yet a gate."""
    by = {}
    for a in acks or []:
        if not isinstance(a, dict) or a.get("svc") is None:
            continue
        s = by.setdefault(a["svc"], {"acks": 0, "latest_evaluated_wall": None,
                                     "records_seen": 0, "horizon_secs": a.get("horizon_secs")})
        s["acks"] += 1
        ew = a.get("evaluated_wall")
        if isinstance(ew, (int, float)):
            s["latest_evaluated_wall"] = max(ew, s["latest_evaluated_wall"] or ew)
        s["records_seen"] = max(a.get("records_seen") or 0, s["records_seen"])
    return by


def _is_count(v):
    """A valid count: an int that is not a bool, and nonnegative (§stage3 type validation)."""
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def aggregate_receipts(receipts):
    """Fold the forwarder receipts into ONE accountable disposition (§stage3): keep the latest (max
    seq) receipt per worker, VALIDATE each (schema, int-not-bool nonnegative counts, the internal
    invariants consumed==suppressed+delivered_live and per-sink delivered+dead_lettered==delivered_live),
    then SUM across workers (per-sink by name). Returns (aggregate|None, problems[]). Any validation
    problem -> aggregate is None so the run cannot reconcile on a malformed/partial receipt."""
    latest = {}
    for r in receipts or []:
        if not isinstance(r, dict):
            continue
        w = r.get("worker")
        if w not in latest or r.get("seq", 0) > latest[w].get("seq", 0):
            latest[w] = r
    if not latest:
        return None, ["no receipts"]
    problems, consumed, suppressed, live = [], 0, 0, 0
    sinks = {}
    for w, r in latest.items():
        for k in ("consumed", "suppressed", "delivered_live"):
            if not _is_count(r.get(k)):
                problems.append(f"worker {w}: bad {k}={r.get(k)!r}")
        if problems:
            continue
        if r["consumed"] != r["suppressed"] + r["delivered_live"]:
            problems.append(f"worker {w}: consumed != suppressed + delivered_live")
        rs = r.get("sinks")
        if not isinstance(rs, list) or not rs:
            problems.append(f"worker {w}: no sinks")
            continue
        for s in rs:
            d, x = s.get("delivered"), s.get("dead_lettered")
            if not (_is_count(d) and _is_count(x)):
                problems.append(f"worker {w}/{s.get('name')}: bad sink counts")
                continue
            if d + x != r["delivered_live"]:
                problems.append(f"worker {w}/{s.get('name')}: delivered+dead_lettered != delivered_live")
            agg = sinks.setdefault(s.get("name"), {"name": s.get("name"), "delivered": 0, "dead_lettered": 0})
            agg["delivered"] += d
            agg["dead_lettered"] += x
        consumed += r["consumed"]
        suppressed += r["suppressed"]
        live += r["delivered_live"]
    if problems:
        return None, problems
    return ({"consumed": consumed, "suppressed": suppressed, "delivered_live": live,
             "sinks": list(sinks.values()), "workers": len(latest)}, [])


def _receipt_accounted(aggregate):
    """The aggregated disposition (from aggregate_receipts) is 'accounted' when every consumed finding
    is accounted downstream — each sink's delivered + dead_lettered equals the aggregate live count,
    with at least one sink. dead_lettered>0 is a recorded delivery FAILURE (valid negative), still
    accounted, so it does not block reconciliation — it is surfaced separately."""
    if not aggregate or not aggregate.get("sinks"):
        return False
    live = aggregate.get("delivered_live")
    if not _is_count(live):
        return False
    return all(s.get("delivered", 0) + s.get("dead_lettered", 0) == live for s in aggregate["sinks"])


def classify_completion(producer_exits, group_lag, arm_counts, required=("arm-a-suricata",),
                        expected_producers=PRODUCERS, expected_groups=PIPELINE_GROUPS, sink_receipt=None,
                        ledger=None, eval_ok=None, lifecycle_ok=None):
    """Explicit run state (R2/§21.2, §24.2 + §25.2/Rec-D + §stage3 fix). A valid outcome requires the
    COMPLETE expected inventory to report — an absent/null/unparsable status is unknown, never success:
      invalid        — an expected producer exited non-zero (a definite product/harness failure).
      inconclusive   — an expected producer is missing/null/unparsable; an expected consumer group is
                       missing/unparsable/not-drained; drain is unverifiable; or the baseline is empty.
      inputs_drained — producers exited 0, groups drained to 0, baseline arrived, but downstream
                       delivery is NOT authoritatively accounted (no ledger, and no accountable receipt).
      reconciled     — inputs_drained AND downstream delivery is accounted. The AUTHORITATIVE source is
                       the forwarder's durable obligation `ledger` (read off the persistent volume,
                       written synchronously at delivery) — used when present so a run reconciles on the
                       real record, not the async bus receipt which can race the deliveries (§stage3
                       run8 finding). The bus `sink_receipt` is the fallback when the ledger is
                       unreadable. dead_lettered>0 is a recorded delivery failure, still accounted.
    Scoreable at inputs_drained or reconciled. Pure/testable."""
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
    # Delivery is accounted authoritatively by the durable ledger when it could be read (present even
    # if empty = a benign no-delivery run); the bus receipt is the fallback. Either one accounts for
    # downstream delivery -> reconciled (§stage3 fix: the ledger cannot race its own deliveries).
    delivery_accounted = ledger is not None or _receipt_accounted(sink_receipt)
    # §stage3 gate: the timer-driven detectors must have evaluated PAST the drained input (eval acks),
    # not merely progressed offsets. eval_ok=None = gate not armed (evidence-only); False = detectors
    # did not evaluate through the horizon -> not reconciled (the run is inputs_drained, still
    # scoreable, with the reason recorded). Input DID drain, so this is never inconclusive/invalid.
    if failed:
        state = "invalid"
    elif unresolved:
        state = "inconclusive"
    elif delivery_accounted and eval_ok is not False and lifecycle_ok is not False:
        state = "reconciled"
    else:
        state = "inputs_drained"                   # consumed + baseline, but delivery/eval/lifecycle unconfirmed
        if eval_ok is False:
            unresolved.append("detectors have not acked evaluation through the input horizon (§stage3)")
        if lifecycle_ok is False:
            unresolved.append("finding lifecycle has capture-bound findings still pending disposition (§stage3)")
    delivery = None
    if ledger is not None:                          # authoritative
        delivery = {"source": "obligation-ledger", "sinks": ledger.get("sinks"),
                    "delivered": ledger.get("delivered", 0), "dead_lettered": ledger.get("dead_lettered", 0),
                    "receipt": ({"consumed": sink_receipt.get("consumed"),
                                 "suppressed": sink_receipt.get("suppressed")} if sink_receipt else None)}
    elif sink_receipt:
        delivery = {"source": "bus-receipt", "consumed": sink_receipt.get("consumed"),
                    "suppressed": sink_receipt.get("suppressed"), "sinks": sink_receipt.get("sinks"),
                    "dead_lettered": sum(s.get("dead_lettered", 0) for s in sink_receipt.get("sinks", []))}
    return {"state": state, "producer_exits": producer_exits,
            "consumer_group_lag": group_lag, "unresolved": unresolved, "delivery": delivery}


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
    run_id = _run_id()
    overwrite = os.environ.get("BENCH_OVERWRITE", "").strip() not in ("", "0", "false", "no")
    if os.path.isfile(os.path.join(out_dir, "report.json")) and not overwrite:
        raise SystemExit(f"benchmark abort: {out_dir} already holds a scored run — refusing to "
                         f"overwrite evidence (§25.1). Set BENCH_OVERWRITE=1 or use a fresh --out.")
    print(f"[1] bringing up benchmark stack for '{scenario}' (run {run_id}), producers held")
    compose("down", "-v", "--remove-orphans")     # clean THIS project's state (empty-state, §3)
    preflight_no_foreign_containers()             # abort if a real deployment would collide (§3)
    # Verify-before-feeder (§25.1): bring up everything EXCEPT the offline producers, verify the
    # topology/images/inputs, and only release the producers once preflight passes — so a drifted
    # image / bad input / reused output aborts BEFORE any data is produced. A pinned run must NOT
    # rebuild (`--build` yields fresh, non-reproducible local image IDs); unpinned builds from source.
    # Load the pin BEFORE mutating any output, and refuse pin/output aliasing regardless of
    # overwrite so a run can never destroy its own reference (§28 Major-2).
    _pin = os.environ.get("BENCH_PIN_MANIFEST")
    if _pin and os.path.abspath(_pin).startswith(os.path.abspath(out_dir) + os.sep):
        raise SystemExit(f"benchmark abort: pinned manifest {_pin} lives inside the output dir "
                         f"{out_dir} (aliasing) — a run would overwrite its own reference (§28).")
    _pinned = _load(_pin) if _pin else None
    _infra = [s for s in _all_services() if s not in PRODUCER_SERVICES]
    compose("up", "-d", *([] if _pin else ["--build"]), *_infra)
    # CREATE (do not start) the producers so their image identities/mounts are captured and verified
    # before release — Suricata+rules and the feeder are essential artifacts (§28 Major-1). ps -aq
    # (used by running_images) includes created-but-unstarted containers.
    compose("create", *PRODUCER_SERVICES)
    apply_index_template(endpoint)             # M3: type the arm fields before ingestion (best-effort)
    print("[1b] recording provenance manifest (M0.3) + run-spec preflight (M0.4/§25.1)")
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
    if _pinned is not None:
        _drift = manifest_drift(manifest["images"], _pinned)
        # Verify the COMPLETE mandatory input set the pin declares: a required input MISSING from the
        # current run (not just changed) is a failure, never silently dropped (§28 Major-2).
        _cur_in, _pin_in = manifest.get("inputs", {}), _pinned.get("inputs", {})
        _input_drift = {k: {"pinned": pv.get("sha256"), "current": _cur_in.get(k, {}).get("sha256")}
                        for k, pv in _pin_in.items() if _cur_in.get(k, {}).get("sha256") != pv.get("sha256")}
        if _drift or _input_drift:
            compose("down", "-v", "--remove-orphans")
            raise SystemExit(f"benchmark abort: run drifts from pinned manifest "
                             f"{os.path.basename(_pin)}: images={json.dumps(_drift)} "
                             f"inputs={json.dumps(_input_drift)} — does not match pinned artifacts (M0.4).")
    os.makedirs(out_dir, exist_ok=True)        # write evidence only AFTER the pin check passes
    with open(os.path.join(out_dir, "manifest.json"), "w") as _mf:
        json.dump(manifest, _mf, indent=2, sort_keys=True)
    # The pipeline (detectors/forwarder/shippers/bus/store) must be up to RECEIVE production; verify
    # that before releasing producers, else findings are lost to the offset race. dashboards is not
    # essential to scoring, so it is not required.
    _required = [s for s in _infra if s != "dashboards"]
    spec = build_run_spec(scenario, run_id, manifest, required_services=_required,
                          required_groups=PIPELINE_GROUPS, deadline=labels.get("eval_deadline"))
    preflight_run_spec(spec, running_services=_running_services(), output_exists=False, overwrite=overwrite)
    with open(os.path.join(out_dir, "run-spec.json"), "w") as _sf:
        json.dump(spec, _sf, indent=2, sort_keys=True)
    print("[1c] preflight passed — starting the held offline producers")
    compose("start", *PRODUCER_SERVICES)          # release the already-created, already-verified producers
    print("[2] R2 completion: waiting for producers to exit + checking their exit status")
    producer_exits = wait_for_producer_exits()
    print("[2a] R2 completion: reconciling consumer-group drain (pipeline consumed the input)")
    group_lag = wait_for_drain(PROJECT)
    import time as _time
    drain_wall = _time.time()                    # §stage3: detectors must evaluate PAST this instant
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
    _receipts = read_sink_receipts(PROJECT)     # Rec-D/§stage3: the bus receipt (fallback / live signal)
    sink_disposition, _receipt_problems = aggregate_receipts(_receipts)
    if _receipt_problems:
        print(f"  ! sink receipts not accountable: {_receipt_problems}", file=sys.stderr)
    _obl, _obl_ok = read_obligations(PROJECT)    # §stage3 fix: the durable ledger is authoritative
    ledger = ledger_disposition(_obl) if _obl_ok else None
    _acks = read_eval_acks(PROJECT)
    # §stage3 gate ARMED: the timer-driven detectors (evaluation decoupled from consumption) must have
    # acked an evaluate pass past the drain instant. Per-record detectors are covered by offset-drain.
    eval_ok, eval_unresolved = eval_horizon_ok(_acks, EXPECTED_EVAL_DETECTORS, drain_wall)
    if not eval_ok:
        print(f"  ! detector evaluation not confirmed through horizon: {eval_unresolved}", file=sys.stderr)
    _lifecycle = lifecycle_disposition(read_lifecycle_acks(PROJECT))   # §stage3: pending capture disposition
    lifecycle_ok = None if _lifecycle is None else (_lifecycle.get("pending", 0) == 0)
    if lifecycle_ok is False:
        print(f"  ! finding lifecycle has {_lifecycle['pending']} pending capture disposition(s)", file=sys.stderr)
    completion = classify_completion(producer_exits, group_lag, arm_counts,
                                     sink_receipt=sink_disposition, ledger=ledger,
                                     eval_ok=eval_ok, lifecycle_ok=lifecycle_ok)
    completion["eval_acks"] = _summarize_eval_acks(_acks)          # §stage3 per-detector evidence
    completion["lifecycle"] = _lifecycle                           # §stage3 finding-lifecycle disposition
    SCOREABLE = ("inputs_drained", "reconciled")   # reconciled needs an accountable sink receipt (Rec-D)
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
    exported, _export_counts = export_arms(endpoint, out_dir, PROJECT,
                                           labels_path=os.path.join(DATASETS, scenario, "labels.json"))
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
    results["run_id"] = run_id                                     # §25.1: link the result to its (immutable) spec
    _mf = os.path.join(out_dir, "output", "export-manifest.json")  # §stage4: publish the bundle digest with the result
    if os.path.isfile(_mf):
        results["bundle_digest"] = _load(_mf).get("bundle_digest")
    # The frozen run-spec is NOT mutated post-run (§28 Major-2): the measured replay mapping is a
    # runtime OBSERVATION, recorded in the result (report.json) + output/replay.json, linked by run_id.
    md = _write(results, out_dir)
    _release_record(out_dir, run_id, results.get("bundle_digest"))   # §stage4: immutable release record
    return md


def _release_record(out_dir, run_id, bundle_digest):
    """The immutable release record (§stage4): pins the run to its evidence — run_id, the export
    bundle_digest, and the sha256 of the scored report — in one small file that lands in version
    control. Comparing these to a later re-export/re-score proves the published numbers came from
    exactly this bundle (completion evidence lives in report.json, hashed here)."""
    import datetime as _dt
    report = os.path.join(out_dir, "report.json")
    rec = {"run_id": run_id, "bundle_digest": bundle_digest,
           "report_sha256": _sha256(report) if os.path.isfile(report) else None,
           "created": _dt.datetime.now(_dt.timezone.utc).isoformat()}
    with open(os.path.join(out_dir, "release.json"), "w") as f:
        json.dump(rec, f, indent=2, sort_keys=True)
    return rec


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


def export_arms(endpoint, out_dir, project=None, labels_path=None):
    """Complete, reproducible export of every arm's docs + the shared source EVE to the
    release-bundle layout (M3/§9.6/§11) — the auditable source for any numerical claim, and the
    data behind the paired SIEM views. Refresh first so the read sees every write, then paginate
    all docs (search_after, no 10k cap). Post-run the arms are static, so this is a complete
    snapshot; a PIT is only needed under concurrent writes (noted). Returns per-file counts."""
    outdir = os.path.join(out_dir, "output")
    os.makedirs(outdir, exist_ok=True)
    _refresh(endpoint)
    counts, docs_by, files = {}, {}, {}
    for index, fname in ARM_EXPORTS:
        # The baseline arm is exported STRICT: a query/engine error must FAIL the export, never write
        # an apparently-valid empty dataset (§25.4). Optional arms tolerate a missing index (empty).
        strict = index == "arm-a-suricata"
        docs = os_search(endpoint, index, strict=strict)
        path = os.path.join(outdir, fname)
        with open(path, "w") as f:
            for d in docs:
                f.write(json.dumps(d, sort_keys=True) + "\n")
        counts[fname] = len(docs)
        docs_by[index] = docs
        files[fname] = {"sha256": _sha256(path), "doc_count": len(docs)}
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
                rpath = os.path.join(outdir, "replay.json")
                with open(rpath, "w") as f:
                    f.write(rep)
                files["replay.json"] = {"sha256": _sha256(rpath)}
            spath = os.path.join(outdir, "source-eve.jsonl")
            if os.path.isfile(spath):
                files["source-eve.jsonl"] = {"sha256": _sha256(spath),
                                             "doc_count": counts.get("source-eve.jsonl", 0)}
        except Exception:                        # noqa: BLE001
            pass
    # Freeze the ground TRUTH inside the bundle (§stage4): the file-only scorer reads labels from
    # here, hashed, NOT from the repo datasets dir — so a recompute needs only the bundle and can't
    # be silently rescored against a changed answer key.
    if labels_path and os.path.isfile(labels_path):
        lpath = os.path.join(outdir, "labels.json")
        with open(labels_path) as _src, open(lpath, "w") as _dst:
            _dst.write(_src.read())
        files["labels.json"] = {"sha256": _sha256(lpath)}
    # Per-file integrity manifest (§25.4/Rec-E): the file-only scorer verifies these before scoring,
    # so a mutated / truncated / missing export fails visibly. consistency_basis records WHY the
    # snapshot is coherent — the completion gate proved the writers exited and the bus/sink settled
    # (a proven post-reconciliation write-freeze), which is Codex's accepted alternative to a PIT.
    manifest = {"consistency_basis": "post-reconciliation write-freeze (producers exited, groups "
                "drained, sink settled)", "files": files, "bundle_digest": _bundle_digest(files)}
    with open(os.path.join(outdir, "export-manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
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


def verify_export_manifest(out_dir):
    """Recompute each exported file's hash + line count and check them against export-manifest.json
    (§25.4/Rec-E). A mutated, truncated, or missing exported file must FAIL visibly before any score
    is recomputed from it. Returns the manifest; raises SystemExit on drift."""
    od = os.path.join(out_dir, "output")
    mpath = os.path.join(od, "export-manifest.json")
    if not os.path.isfile(mpath):
        raise SystemExit(f"benchmark abort: no export-manifest.json in {od} — cannot verify the "
                         f"exported evidence before recomputing (§25.4).")
    manifest = _load(mpath)
    files = manifest.get("files", {})
    drift = []
    for fname, rec in files.items():
        if fname != os.path.basename(fname) or fname in ("", ".", ".."):
            drift.append(f"{fname}: unsafe manifest path (traversal)")   # §stage4: resolve inside the bundle only
            continue
        fpath = os.path.join(od, fname)
        if not os.path.isfile(fpath):
            drift.append(f"{fname}: missing")
            continue
        if _sha256(fpath) != rec.get("sha256"):
            drift.append(f"{fname}: sha256 mismatch (mutated/truncated)")
            continue
        if "doc_count" in rec and sum(1 for _l in open(fpath) if _l.strip()) != rec["doc_count"]:
            drift.append(f"{fname}: doc_count mismatch")
    # §stage4: the manifest's own file-list must match its published bundle_digest — catches a
    # manifest whose file list was edited (added/removed/renamed) to hide a change. The digest is
    # recorded with the result (report.json) so a jointly-altered bundle+manifest is caught by
    # comparing to the externally-published value.
    if "bundle_digest" in manifest and manifest["bundle_digest"] != _bundle_digest(files):
        drift.append("bundle_digest mismatch (manifest file list altered)")
    if drift:
        raise SystemExit("benchmark abort: exported evidence fails manifest verification (§25.4): "
                         + "; ".join(drift))
    return manifest


def score_from_export(out_dir, scenario):
    """Recompute the report from ONLY the verified bundle (R4/§21.4 + §stage4): the manifest is
    verified first, then truth is read from the HASHED bundle copy (out/<scenario>/output/labels.json),
    NOT the repo datasets dir — a recompute needs only the bundle and cannot be rescored against a
    changed answer key. Fails if the bundle carries no frozen truth."""
    verify_export_manifest(out_dir)                    # refuse to score mutated/truncated evidence
    od = os.path.join(out_dir, "output")
    labels_path = os.path.join(od, "labels.json")
    if not os.path.isfile(labels_path):
        raise SystemExit(f"benchmark abort: bundle {od} has no frozen labels.json — cannot recompute "
                         f"from a self-contained bundle (§stage4). Re-export with truth frozen in.")
    labels = _load(labels_path)
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
