# Replay fixtures — see detectors fire without live traffic

`eve-feeder` replays recorded Suricata **EVE JSONL** through the whole Cernity pipeline, so you
can watch findings appear on demand — including detections your own network never generates.

| Fixture | Trips |
|---|---|
| `beacon-eve.jsonl` | the C2 **beaconing** detector (the default quickstart demo) |
| `east-west-eve.jsonl` | **east-west** detectors that need Windows/AD traffic: LLMNR poisoning, kerberoasting, password spraying, lateral-exec (named pipe) |
| `modbus-ot-eve.jsonl` | **ot-detectors** (Modbus): unauthorized write/control, new master→outstation pairing, function-code enumeration, illegal-function bursts, Modbus-off-502, program/mode transfer |

## Why east-west and OT need this

The east-west detectors (SMB/RDP/Kerberos/LLMNR/lateral-exec) only fire on internal
Windows/AD traffic. A flat homelab with none will **never** trip them from real traffic — that's
correct behavior, not a fault. Replaying `east-west-eve.jsonl` injects a synthetic AD-attack
burst so you can confirm the detectors and the findings pipeline work end to end.

The same is true for `ot-detectors`: Modbus findings need a sensor tapped on an **OT segment**
with the Suricata Modbus parser enabled. Replaying `modbus-ot-eve.jsonl` injects a synthetic
Modbus session (benign master baseline + unauthorized control, recon, and program-transfer) so
you can confirm the OT detections and pipeline without an OT network.

## Run it

Point the quickstart feeder at a fixture with `CERNITY_FEED_FIXTURE`:

```bash
CERNITY_FEED_FIXTURE=fixtures/east-west-eve.jsonl \
  docker compose --env-file .env -f deploy/quickstart/docker-compose.yml up -d
```

Within a minute (a detector eval cycle) you'll see `llmnr_poison`, `kerberoasting`,
`password_spraying`, and `lateral_exec` findings reach your sink — the same path a real sensor
would produce them on. Or run the feeder directly against a live bus:
`python feeder.py fixtures/east-west-eve.jsonl`.
