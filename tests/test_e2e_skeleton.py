"""End-to-end walking skeleton: a replayed beacon capture must surface as a
final beacon finding in the file sink, through the full central pipeline
(feeder -> behavioral-detectors -> finding-service -> findings-forwarder).

Requires Docker. Run from the repo root:  python tests/test_e2e_skeleton.py
"""
import json
import subprocess
import time

QUICK = ["docker", "compose", "-f", "deploy/quickstart/docker-compose.yml"]
CENTRAL = ["docker", "compose", "-f", "deploy/central/docker-compose.yml"]


def _run(*args):
    subprocess.run(list(args), check=True)


def _sink():
    out = subprocess.run(
        CENTRAL + ["exec", "-T", "findings-forwarder", "cat", "/out/findings.jsonl"],
        capture_output=True, text=True).stdout.strip()
    return [json.loads(l) for l in out.splitlines() if l.strip()] if out else []


def test_beacon_becomes_finding():
    _run(*QUICK, "down", "-v")
    _run(*QUICK, "up", "-d", "--build")
    try:
        findings = []
        for _ in range(24):                       # up to ~3 min: feed(8s)+eval(30s)+margin
            time.sleep(8)
            findings = _sink()
            if findings:
                break
        assert findings, "no finding written to the file sink"
        beacons = [f for f in findings if f.get("detector_id") == "beacon"]
        assert beacons, f"expected a beacon finding, got {[f.get('detector_id') for f in findings]}"
        f = beacons[0]
        assert f["category"] == "c2"
        assert f["state"] == "FINAL"
    finally:
        _run(*QUICK, "down", "-v")


if __name__ == "__main__":
    test_beacon_becomes_finding()
    print("ok test_e2e_skeleton")
