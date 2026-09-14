"""Stage-5 AI-red-team qualification orchestrator.

Runs real attack tooling to emit REAL protocol traffic and derives GROUND TRUTH from the
orchestrator's OWN launch log — independent of Cernity's output (the detector never grades itself,
which is the independence the review requires). It produces a scenario the existing benchmark
consumes unchanged: `labels.json` (episodes + malicious set, from the launch record) plus a captured
PCAP fed through the normal paced replay.

Purpose (stage 5): qualify that the measurement system correctly attributes KNOWN incidents end to
end — not a corpus-scale effectiveness claim. Truth is known by construction because the orchestrator
launched the attack; it is not inferred from what Cernity reported.

Pure core: `run` (execute a command), `clock` (epoch source) and `capture` (pcap) are injected, so
the truth-emission logic is unit-tested without the tools or a live wire. Live mode wires the real
subprocess/tcpdump. stdlib only.
"""
import json
import os
import subprocess
import time
from datetime import datetime, timezone


def _now():
    return time.time()


def _default_run(cmd):
    """Execute a command; return (returncode, stdout_text). stdout carries any RT-OUTCOME line an
    attack script prints so run_action can record ACHIEVED vs merely attempted (R08)."""
    r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True)
    return r.returncode, r.stdout


def _parse_outcome(stdout):
    """The RT-OUTCOME json an attack script printed (attempts/ok/errors/bytes/connected), or None. This
    is the ACTUAL on-wire evidence that distinguishes an attempted attack from an achieved callback or
    completed transfer (R08/§33.4)."""
    for line in (stdout or "").splitlines():
        if line.startswith("RT-OUTCOME "):
            try:
                return json.loads(line[len("RT-OUTCOME "):])
            except ValueError:
                return None
    return None


def _achieved(rc, outcome):
    """Did the malicious BEHAVIOUR actually reach the wire? A scripted action reports it (ok>0, or bytes
    sent, or a connection established); an external tool with no outcome falls back to a clean exit.
    Zero successful connections / zero bytes = attempted, NOT achieved."""
    if outcome is not None:
        return bool(outcome.get("ok", 0) or outcome.get("bytes", 0) or outcome.get("connected", 0))
    return rc == 0


def run_action(action, run=None, clock=None):
    """Execute ONE attack action and record its independent truth.

    An action = {id, behavior, attacker, targets:[...], cmd}. `behavior` is the scorer's taxonomy
    class (recon/c2/exfil/lateral/...). We stamp the wall interval around the command and record who
    attacked whom FROM THE ACTION SPEC — never from any detector output. `run(cmd)->(rc, stdout)` (an
    int rc or None is also accepted for fakes/dry-run) and `clock()->epoch` are injected. We parse the
    script's RT-OUTCOME to record whether the behaviour was EXECUTED and ACHIEVED (R08)."""
    run = run or _default_run
    clock = clock or _now
    start = clock()
    res = run(action["cmd"]) if action.get("cmd") else None
    end = clock()
    rc, stdout = res if isinstance(res, tuple) else (res, "")
    outcome = _parse_outcome(stdout)
    executed = rc is not None                              # dry-run (rc None) = truth-schema only, no traffic
    achieved = executed and _achieved(rc, outcome)
    return {"id": action["id"], "behavior": action["behavior"], "attacker": action["attacker"],
            "targets": list(action.get("targets") or []), "start": start, "end": end,
            "rc": rc, "cmd": action.get("cmd"), "match_requires": action.get("match_requires"),
            "outcome": outcome, "executed": executed, "achieved": achieved}


def _status(result):
    """not-executed (dry-run, no traffic) | achieved (behaviour on the wire) | attempted (ran but no
    successful connection/transfer). Attempted actions are scored under a different scope (R08)."""
    if not result.get("executed"):
        return "not-executed"
    return "achieved" if result.get("achieved") else "attempted"


def truth_episode(result):
    """One labelled episode from an action result: entities from the LAUNCH record (attacker as
    initiator, each target as target), the behaviour class, and the wall interval. LABEL reflects
    ACHIEVEMENT (R08/§33.4): an achieved (or not-yet-executed dry-run) action is `malicious`; an action
    that ran but achieved nothing on the wire is `unknown` — preserved and reported, but UNSCORED so a
    detector is neither credited nor penalised for an attack that never actually happened. The factual
    behaviour taxonomy stays independent of any detector output."""
    ents = [{"value": result["attacker"], "role": "initiator"}]
    ents += [{"value": t, "role": "target"} for t in result["targets"] if t]
    status = _status(result)
    label = "unknown" if status == "attempted" else "malicious"
    ep = {"id": result["id"], "label": label, "behavior": result["behavior"], "entities": ents,
          "status": status}
    if result.get("outcome") is not None:
        ep["outcome"] = result["outcome"]                 # the ACTUAL execution facts, retained
    # A fan-out (scan/lateral) is identified by the INITIATOR — a real fan-out finding names the
    # source and an aggregate ("-> 12 hosts"), not every dst — so the truth keys on the attacker and
    # treats the targets as evidence (§stage5, matching the synthetic-scan precedent). Set via the
    # action's match_requires; other behaviours require their full relationship.
    if result.get("match_requires"):
        ep["match_requires"] = list(result["match_requires"])
    if result.get("start") is not None and result.get("end") is not None:
        ep["interval"] = {"start": result["start"], "end": result["end"]}
    return ep


def build_labels(results, dataset, granularity="host", capture_status=None):
    """The scenario truth the benchmark scores against — episodes + malicious host set, all from the
    orchestrator's launch record (independent of Cernity). Only ACHIEVED episodes put their attacker in
    the malicious set (an attempted-only action does not obligate a detection). Capture status, when
    known, is recorded so unverified telemetry coverage is visible rather than a silent false miss."""
    episodes = [truth_episode(r) for r in results]
    malicious = sorted({e["entities"][0]["value"] for e in episodes
                        if e["label"] == "malicious" and e.get("entities")})
    attempted = [e["id"] for e in episodes if e.get("status") == "attempted"]
    honesty = [
        "Traffic is generated by REAL attack tooling; ground truth comes from the orchestrator's own "
        "launch log (who attacked whom, when) AND the scripts' reported execution facts (connections "
        "made, bytes sent) — independent of Cernity's output. Emulated adversary actions, not a "
        "field-prevalence sample."]
    caveats = [
        "Stage-5 qualification: verifies the measurement system attributes known incidents end to end; "
        "it is NOT a corpus-scale effectiveness or SOC-value claim."]
    if attempted:
        caveats.append(
            f"Actions {attempted} executed but achieved nothing on the wire (no successful "
            "connection/transfer); scored as unknown (unscored), not a detection obligation.")
    if capture_status is not None and not capture_status.get("ok", True):
        caveats.append(
            f"Packet capture unverified ({capture_status}); telemetry coverage is not established, so "
            "a detector miss cannot be distinguished from missing sensor input.")
    return {"dataset": dataset, "granularity": granularity, "malicious": malicious,
            "episodes": episodes, "capture": capture_status, "honesty": honesty, "caveats": caveats}


def run_campaign(spec, out_dir, run=None, clock=None, capture=None):
    """Run every action (optionally wrapping the whole campaign in a pcap capture), then write
    `labels.json` (scenario truth) and `run-log.json` (the immutable, independent truth record with
    per-action start/end/attacker/targets/rc/cmd/outcome/achieved). Returns (labels, results).

    `capture(path) -> handle` starts packet capture; `handle.stop() -> {ok, started, packets, ...}`
    ends it and REPORTS coverage (live: tcpdump on the sensor interface). None skips capture."""
    os.makedirs(out_dir, exist_ok=True)
    cap = capture(os.path.join(out_dir, f"{spec['dataset']}.pcap")) if capture else None
    cap_status = None
    try:
        results = [run_action(a, run, clock) for a in spec["actions"]]
    finally:
        if cap is not None:
            cap_status = cap.stop()
    labels = build_labels(results, spec["dataset"], spec.get("granularity", "host"), cap_status)
    with open(os.path.join(out_dir, "labels.json"), "w") as f:
        json.dump(labels, f, indent=2, sort_keys=True)
    with open(os.path.join(out_dir, "run-log.json"), "w") as f:
        json.dump({"dataset": spec["dataset"], "actions": results, "capture": cap_status,
                   "created": datetime.now(timezone.utc).isoformat()}, f, indent=2, sort_keys=True)
    return labels, results
