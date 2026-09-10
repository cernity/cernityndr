# deploy/benchmark — the comparison stack

Infrastructure for the [Suricata-vs-Cernity benchmark](../../benchmarks/README.md). Driven by
`benchmarks/run.py`, not brought up by hand in normal use.

## Services

| Service | Role |
|---|---|
| `opensearch` | shared SIEM both arms ship to (single-node, security off — **test only**) |
| `suricata-offline` | runs `suricata -r <pcap>` with the max-fidelity config → split EVE on a shared volume |
| `zeek-offline` | runs `zeek -r <pcap>` (reference arm) → JSON logs |
| `arm-a-shipper` | Fluent Bit: raw Suricata EVE → OpenSearch `arm-a-suricata` (no Cernity) |
| `arm-b-feeder` | replays the same EVE onto the Cernity bus (via `tools/eve-feeder`) |
| *(from `../central`)* | the full Cernity stack turns Arm B's EVE into findings |

Both arms read the **same** EVE the one offline Suricata run produced — the fairness anchor.

## Arm B → OpenSearch

Point `findings-forwarder` (from the central include) at this OpenSearch in `.env`:

```bash
CERNITY_SINK=opensearch
ES_ENDPOINT=http://opensearch:9200
ES_INDEX_PREFIX=arm-b-findings
```

## Configs

- `suricata/suricata.yaml` — max-fidelity offline config (split EVE, community-id, nDPI,
  JA3/JA4, krb5/smb/dcerpc, file hashing). Mirrors [docs/suricata-config.md](../../docs/suricata-config.md).
- `zeek/local.zeek` — default Zeek analysis + JSON logs (a fair default-vs-default reference).
- `arm-a/fluent-bit.conf` — the raw-EVE → OpenSearch shipper for Arm A.

Pin the ET Open ruleset version you test with and record it (it lands in the report meta). These
configs are validated by the benchmark smoke run, not unit tests.

> **Not for production.** OpenSearch here has security disabled and is single-node for a
> throwaway, deterministic test.
