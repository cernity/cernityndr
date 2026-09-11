# Replay fixtures — see detectors fire without live traffic

`eve-feeder` replays recorded Suricata **EVE JSONL** through the whole Cernity pipeline, so you
can watch findings appear on demand — including detections your own network never generates.

| Fixture | Trips |
|---|---|
| `beacon-eve.jsonl` | the C2 **beaconing** detector (the default quickstart demo) |
| `east-west-eve.jsonl` | **east-west** detectors that need Windows/AD traffic: LLMNR poisoning, kerberoasting, password spraying, lateral-exec (named pipe) |

## Why east-west needs this

The east-west detectors (SMB/RDP/Kerberos/LLMNR/lateral-exec) only fire on internal
Windows/AD traffic. A flat homelab with none will **never** trip them from real traffic — that's
correct behavior, not a fault. Replaying `east-west-eve.jsonl` injects a synthetic AD-attack
burst so you can confirm the detectors and the findings pipeline work end to end.

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
