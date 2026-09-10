# Cernity benchmark — Suricata → SIEM vs Suricata → Cernity → SIEM

A **reproducible, honest** comparison: run the same traffic through raw Suricata → SIEM and
through Suricata → Cernity → SIEM (plus Zeek as a reference), and get a detailed side-by-side
report — detection accuracy *and* analyst-facing noise. It's meant to help you decide whether
Cernity is worth it **for your network**, not to declare a winner.

## What it measures

- **Detection accuracy** — precision / recall / F1 vs a ground-truth label set, at a fixed
  granularity (per-host by default), infra notices excluded.
- **Analyst experience** — raw event volume, alerts-per-true-positive, and how much Cernity
  suppresses/dedups before delivery (the firehose-vs-findings story).
- **Zeek parity** — a capability map ([../docs/suricata-zeek-parity.md](../docs/suricata-zeek-parity.md))
  plus a Zeek reference arm, so "Suricata logs as richly as Zeek" is *shown*, not asserted.

## Fair by construction

- **Offline PCAP replay** — deterministic, no packet loss; re-runs are byte-identical (a hash
  is recorded in every report).
- **Same corpus, same hardware, both arms**; current ET Open rules, versions pinned in the
  report.
- **Both arms configured to their strengths** (max-fidelity Suricata EVE; full Cernity stack).
- **Interpret by paradigm** — signature vs scripted-behavioral vs Cernity's stateful+ML. The
  report always carries a "where Cernity does NOT add value" section and the dataset-age caveat.

## Run it

**Smoke (no infrastructure)** — proves the scoring→report chain on a built-in scenario:

```bash
python benchmarks/run.py synthetic-beacon \
  --from-docs benchmarks/datasets/synthetic-beacon/from-docs.json
# -> benchmarks/out/synthetic-beacon/report.md
```

**Full (Docker)** — real Suricata/Zeek/OpenSearch over a PCAP:

```bash
BENCH_PCAP=/pcaps/friday.pcap python benchmarks/run.py cic-ids-2017-friday
```

Add a dataset by editing `datasets/registry.json` and dropping a `labels.json` under
`datasets/<name>/`. **PCAPs are referenced/downloaded, never committed** (license + size) —
see each registry entry for the source and citation.

## Layout

- `scorer.py` / `report.py` / `parity.py` / `extract.py` — pure, unit-gated logic
  (`test_*.py`, run with `python test_*.py`, same gate style as the services).
- `run.py` — orchestrator (Docker + OpenSearch shell around the pure logic).
- `datasets/` — the registry, per-scenario ground-truth labels, and the built-in scenario.
- `../deploy/benchmark/` — the compose stack (OpenSearch, offline Suricata/Zeek, Arm A shipper)
  and the max-fidelity engine configs.
