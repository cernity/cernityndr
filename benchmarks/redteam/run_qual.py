"""CLI: run a Stage-5 qualification campaign.

Dry-run (default) emits TRUTH ONLY (no traffic) so the labels/episodes path can be validated without
tools or a wire. `--live` executes the real attack tooling on an ISOLATED range and captures a pcap
(tcpdump) for the full paired run; feed that pcap to the benchmark via BENCH_PCAP. The ground truth
is written from the orchestrator's launch log — independent of Cernity.

  # validate the truth path (no traffic):
  python3 run_qual.py --out /tmp/rtqual --dataset rt-qualification
  # real run on the isolated range (needs nmap/python3/tcpdump + targets you own):
  sudo python3 run_qual.py --live --iface eth0 --attacker 10.9.0.5 --c2 203.0.113.10 \
       --resolver 10.0.0.53 --targets 10.0.0.20 10.0.0.21 --out /out/rtqual
"""
import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
import orchestrator as orch          # noqa: E402
import actions                       # noqa: E402


def default_spec(attacker, c2, resolver, targets, dataset):
    """A first qualification batch spanning the behaviour classes the scorer knows and that capture
    reliably on a bridged range: recon (scan), c2 (beacon), exfil (large transfer to c2). DNS-tunnel
    is available in the library but omitted here — a container's DNS goes to the embedded resolver
    (127.0.0.11), off the captured interface, so it would be a false miss on a docker range. Add
    dns_tunnel/lateral once the range has an on-wire resolver / AD targets. attacker+targets ARE truth."""
    return {"dataset": dataset, "actions": [
        actions.scan(attacker, targets, ports="445,3389,22,80"),        # one src -> many dsts = internal scan
        actions.beacon(attacker, c2, interval=5, count=30, port=4444),  # clean port: beaconing, not proto-mismatch
        actions.exfil(attacker, c2, mb=80, port=5555),                  # clean port: large transfer
    ]}


def _tcpdump_capture(iface):
    """Wrap the campaign in a full-packet capture on the sensor interface (live mode). The handle
    verifies tcpdump actually STARTED and reports the packet count on stop (R08: capture readiness +
    coverage), so an unverified capture is recorded rather than mistaken for a clean run."""
    import re
    import time

    def cap(path):
        p = subprocess.Popen(["tcpdump", "-i", iface, "-w", path, "-U", "-s", "0"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        time.sleep(0.5)                                   # give it a moment to bind or die
        started = p.poll() is None                        # still alive => it opened the interface

        class _H:
            def stop(self):
                if p.poll() is not None:                  # already exited (failed to start / died)
                    err = (p.stderr.read() if p.stderr else "") or ""
                    return {"ok": False, "started": False, "packets": None,
                            "path": path, "error": err.strip()[:200]}
                p.terminate()
                try:
                    _o, err = p.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    p.kill(); _o, err = p.communicate()
                m = re.search(r"(\d+) packets captured", err or "")
                packets = int(m.group(1)) if m else None
                ok = started and (packets is None or packets > 0)
                return {"ok": ok, "started": started, "packets": packets,
                        "path": path, "size": os.path.getsize(path) if os.path.exists(path) else 0}
        return _H()
    return cap


def main(argv=None):
    ap = argparse.ArgumentParser(description="Stage-5 AI-red-team qualification campaign")
    ap.add_argument("--out", required=True, help="output dir for labels.json + run-log.json (+ pcap in --live)")
    ap.add_argument("--dataset", default="rt-qualification")
    ap.add_argument("--attacker", default="10.9.0.5")
    ap.add_argument("--c2", default="203.0.113.10")
    ap.add_argument("--resolver", default="10.0.0.53")
    ap.add_argument("--targets", nargs="*", default=["10.0.0.20", "10.0.0.21", "10.0.0.22"])
    ap.add_argument("--live", action="store_true", help="EXECUTE the real tools + capture a pcap (isolated range only)")
    ap.add_argument("--iface", default="eth0", help="capture interface (live)")
    a = ap.parse_args(argv)
    spec = default_spec(a.attacker, a.c2, a.resolver, a.targets, a.dataset)
    run = None if a.live else (lambda _cmd: None)      # dry-run: record intent + real wall interval, no exec
    capture = _tcpdump_capture(a.iface) if a.live else None
    labels, results = orch.run_campaign(spec, a.out, run=run, capture=capture)
    tail = " + pcap" if a.live else " (dry-run: truth only, no traffic)"
    print(f"campaign {a.dataset}: {len(results)} actions, malicious={labels['malicious']} -> "
          f"{os.path.join(a.out, 'labels.json')}{tail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
