# Stage-5 AI-red-team qualification harness

Qualifies that the (now hardened) measurement system attributes **known** incidents end to end —
Suricata → SIEM (Arm A) vs Suricata → Cernity → SIEM (Arm B) — on **real** attack traffic whose
**ground truth is independent of Cernity**. This is the gate that turns the measurement contract into
an actual paired result; it is *not* a corpus-scale effectiveness or SOC-value claim.

## Why the truth is independent
The orchestrator (`orchestrator.py`) *launches* the attacks, so it knows who attacked whom and when
from its **own launch log** (`run-log.json`) — the ground truth (`labels.json` episodes) is derived
from that record, never from what Cernity reported. The detector never grades itself. That is the
independence the review requires.

## Pieces
- `actions.py` — the attack-action library. Each builder returns `{id, behavior, attacker, targets,
  cmd}`: the behaviour CLASS matches the scorer taxonomy (recon/c2/exfil/lateral), attacker+targets
  are the truth entities, and `cmd` is the REAL command that puts traffic on the wire (nmap, a scripted
  beacon, a DNS-tunnel client, a large transfer, crackmapexec).
- `orchestrator.py` — runs each action, stamps the wall interval, and writes `labels.json` +
  `run-log.json`. Pure core (`run`/`clock`/`capture` injected) so truth emission is unit-tested with
  no tools or wire.
- `run_qual.py` — CLI. **Dry-run** (default) emits truth only (validates the labels path). **`--live`**
  executes the tools on an ISOLATED range and captures a pcap.

## Run it
```bash
# 1) validate the truth/labels path with no traffic:
python3 run_qual.py --out /tmp/rtqual --dataset rt-qualification

# 2) real run on an ISOLATED range (needs nmap / python3 / tcpdump + targets you OWN):
sudo python3 run_qual.py --live --iface <sensor-iface> \
     --attacker 10.9.0.5 --c2 203.0.113.10 --resolver 10.0.0.53 \
     --targets 10.0.0.20 10.0.0.21 10.0.0.22 --out /out/rtqual
#    -> /out/rtqual/rt-qualification.pcap + labels.json + run-log.json

# 3) feed the captured pcap through the benchmark (both arms) and score against the emitted truth:
cp /out/rtqual/labels.json benchmarks/datasets/rt-qualification/labels.json
env NDR_OFFSET_RESET=earliest CERNITY_FEED_PACED=1 BENCH_SINK_GRACE=45 \
    BENCH_PCAP=/out/rtqual/rt-qualification.pcap BENCH_PCAP_DIR=/out/rtqual \
    BENCH_OPENSEARCH=http://localhost:9200 python3 benchmarks/run.py rt-qualification
```
The run reconciles under the full stage-1–4 contract (ledger delivery + detector evaluation + zero
pending lifecycle) and is pinned by the bundle digest + release record, so the AI-driven run cannot
fool itself. Compare Arm A vs Arm B episode recall/precision against the independent truth.

## Safety
`--live` runs real offensive tooling. Only ever point it at hosts/networks you own in an isolated lab
(the throwaway VM range). Dry-run executes nothing.

## Scope
Emulated adversary actions across the behaviour classes the scorer knows — a *qualification* of the
measurement system, honest about not being field prevalence. Extend `default_spec` with `lateral()` /
`exfil()` once the range has AD / large-transfer targets; add public-corpus replay for stage 6.
