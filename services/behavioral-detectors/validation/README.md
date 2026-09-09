# validation harness (U7)

Measurement tools for the behavioral detectors. Not feature code; runtime/dataset
verification.

## precision / recall

```bash
python precision_recall.py --demo                 # synthetic labeled corpus
python precision_recall.py --corpus labeled.jsonl # your labeled captures
```
Replays a labeled EVE corpus through the real detector pipeline and prints
per-detector TP/FP/FN + precision/recall. A corpus line is a normal flow/DNS event
plus an `expect` list of detector_ids that should fire; unlabeled lines are benign
(any finding is a false positive). Point `--corpus` at normalized CTU-13 /
Stratosphere botnet captures and malware-traffic-analysis.net for real numbers.

## RITA oracle

```bash
python rita_oracle_compare.py --ours findings.jsonl --rita rita_beacons.json
```
Diffs our beacon/long-conn verdicts against a RITA export on the same traffic and
reports agreement. RITA is the FOSS oracle; running it over the Zeek logs is an
operator/CI step (not bundled).

## load test

```bash
python loadtest.py --n 50000                                   # memory backend
python loadtest.py --n 50000 --backend redis --redis redis://localhost:6399/0
```
Drives N synthetic flows and reports ingest records/sec, evaluate() latency, and
(redis) key count — the per-replica throughput ceiling and store pressure.

## CI

Run `test_validation.py` (a smoke over the demo corpus + a small load test) in the
build gate; run the full labeled-dataset precision/recall and RITA comparison as a
scheduled/nightly job (they need external datasets and a RITA runtime).


## Single-server ceiling harness (plan 003 U7)

`loadtest.py` measures how much one processing box holds before adding sensors:

```
python loadtest.py --n 50000 --partitions 32 --replicas 8      # in-process shape
python loadtest.py --backend redis --redis unix:///sock/redis.sock?db=0 ...
python loadtest.py --selfcheck                                  # classifier + tiny run (CI)
```

It reports **per-core ingest rate**, **per-partition skew** (a hot `src_ip` makes a
hot partition -> one replica saturates while others idle; do not read aggregate
rate as the ceiling when skew is >~1.5x), and **per-replica scoped evaluate() vs
scan-all** (scoped ~ scan-all / replicas -- the U4 partition-scoping win). The full
run is `docker compose up -d --scale behavioral-detectors=R` against one local
Redis and a 32-partition topic (partitions >= replicas); this harness shows the
per-core and per-replica shape in one process. `classify_ceiling()` names the
bottleneck (cpu / bus / redis / headroom) from CPU, lag, and Redis saturation.
