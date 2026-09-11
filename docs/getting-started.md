# Get started — add Cernity to your Suricata sensor

**Goal of this guide:** you already run a Suricata sensor. By the end of this page you'll
have Cernity turning its telemetry into security **findings** and delivering them to your
SIEM. Every step is copy-paste, and each one ends with a quick "did it work?" check.

You don't need to understand the internals to follow this — if you want them, read
[how-it-works.md](how-it-works.md). If you just want it running, start here.

```
   YOUR SENSOR                     ONE NEW HOST (Cernity)              YOUR SIEM
   ----------                      --------------------                ---------
   Suricata  ─ eve logs ─►  shipper ─►  bus ─► detectors ─► findings ─►  (Splunk,
   (you have this)          (you add both of these, one command each)    Elastic,
                                                                         Devo, …)
```

You add two things: the **Cernity central stack** (on any spare Docker host) and a tiny
**shipper** on the sensor. Then you point Cernity at your SIEM. That's the whole job.

---

## Before you start

You need:

1. **A Suricata sensor** you can edit the config on and restart (you have this).
2. **One Docker host for Cernity** — a VM/LXC/box with **Docker + Docker Compose v2**,
   ~4 CPU / 8 GB RAM to start, reachable from the sensor on **TCP 19092** (the bus's
   external listener). This is *not* the sensor — keep the heavy analytics off the sensor.
3. **Your SIEM's connection details** (endpoint + credentials). Cernity ships to
   Elasticsearch/OpenSearch, Splunk, Devo, syslog/CEF, or a webhook.
4. Git + this repo checked out on the Cernity host:
   ```bash
   git clone https://github.com/cernity/cernityndr.git && cd cernityndr
   cp cernity.env.example .env      # every setting has a working default
   ```

Throughout, `CENTRAL_HOST` = the IP/hostname of your Cernity host.

---

## Step 1 — Stand up the Cernity central stack

On the **Cernity host**, first tell the bus this host's reachable address so the remote
sensor can connect — edit `.env` and set:

```bash
CERNITY_ADVERTISE_HOST=CENTRAL_HOST     # this host's LAN IP or DNS name
```

The external bus listener (`:19092`, the port your remote sensor connects to) is
**SASL/SCRAM-SHA-512 over TLS by default** — an unauthenticated client is refused. Generate
the CA, broker cert, and a SCRAM credential:

```bash
CERNITY_ADVERTISE_HOST=CENTRAL_HOST ./deploy/security/gen-bus-certs.sh
```

It prints the `CERNITY_BUS_USER` / `CERNITY_BUS_PASSWORD` to add to `.env` (and the `ca.crt`
you'll copy to each sensor in Step 3). For a throwaway single-host demo with no remote sensor,
you can skip this and set `CERNITY_INSECURE_BUS=1` (plaintext external listener; warns loudly —
never on an untrusted network).

Then bring it up (Compose reads `.env` automatically):

```bash
docker compose -f deploy/central/docker-compose.yml up -d
```

That starts the bus (Redpanda), the detectors, `finding-service`, and
`findings-forwarder`. Give it ~30 seconds.

**Check it worked:**
```bash
docker compose -f deploy/central/docker-compose.yml ps
```
All services should show `Up` (Redpanda shows `Up (healthy)`). If anything is restarting,
see [Troubleshooting](#troubleshooting).

> By default findings are written to a local file (the `file` sink) so you can verify the
> pipeline before wiring your SIEM. You'll switch that to your SIEM in Step 4.

---

## Step 2 — Configure your Suricata to feed Cernity

Cernity reads Suricata's **EVE** telemetry. Suricata needs two things: split its EVE
output into an **alerts** file and a **network-telemetry** file, and turn on
**community-id**. Add this to your `suricata.yaml` under `outputs:`:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filename: eve-alerts.json          # signature alerts
      community-id: true
      types:
        - alert
  - eve-log:
      enabled: yes
      filename: eve-nsm.json             # network telemetry (the detectors' fuel)
      community-id: true
      types:
        - flow
        - dns: { version: 3 }
        - tls: { extended: yes }
        - http: { extended: yes }
        - ssh
        - files
        - anomaly
```

Then restart Suricata and confirm both files are being written:

```bash
sudo systemctl restart suricata        # or however you run it
ls -la /var/log/suricata/eve-alerts.json /var/log/suricata/eve-nsm.json
```

Both should exist and be growing.

> This is the **minimum**. To get the most out of Cernity — nDPI application/risk
> detection, JA3/JA4 fingerprints, file hashing — follow the full, copy-paste
> best-results config in **[suricata-config.md](suricata-config.md)**. You can do that
> later; the minimum above is enough to start seeing findings.

---

## Step 3 — Run the shipper on the sensor

The shipper is a tiny Fluent Bit container that tails those two EVE files and forwards
them to Cernity. It runs **on the sensor** (it's the one piece that must be where the logs
are) and uses almost nothing.

First copy the `ca.crt` generated in Step 1 from the Cernity host to this sensor. Then, on
the **sensor**, from a checkout of this repo (the shipper authenticates to the secure bus with
the SCRAM credential + CA):

```bash
REDPANDA_BOOTSTRAP=CENTRAL_HOST:19092 \
SURICATA_LOG_DIR=/var/log/suricata \
CERNITY_BUS_USER=cernity-sensor \
CERNITY_BUS_PASSWORD=<from Step 1> \
CERNITY_BUS_CA=/path/to/ca.crt \
docker compose -f deploy/sensor/docker-compose.yml up -d
```

(Only if the central host runs with `CERNITY_INSECURE_BUS=1`: skip the CA/creds and remove the
`rdkafka.sasl.*`/`ssl.*` lines from `deploy/fluent-bit/fluent-bit.conf` so the shipper connects
plaintext.)

(Replace `CENTRAL_HOST` with your Cernity host. If your EVE files live elsewhere, set
`SURICATA_EVE_ALERTS` / `SURICATA_EVE_NSM` — see [deploy-sensor.md](deploy-sensor.md).)

**Check it worked** — on the sensor:
```bash
docker logs cernity-fluent-bit 2>&1 | tail -5
```
You want to see it tailing the files and forwarding, with no connection errors to
`CENTRAL_HOST:19092`. If it can't connect, the Cernity host's firewall is blocking 19092,
or `CERNITY_ADVERTISE_HOST` isn't set to an address the sensor can reach.

---

## Step 4 — Connect Cernity to your SIEM

By default Cernity writes findings to a file. Now point it at your SIEM. On the **Cernity
host**, edit `.env` and set the sink. Pick your SIEM:

**Elasticsearch / OpenSearch**
```bash
CERNITY_SINK=elasticsearch
ES_ENDPOINT=https://your-es:9200
ES_USER=elastic
ES_PASSWORD=your-password
ES_INDEX_PREFIX=ndr-findings
```

**Splunk (HTTP Event Collector)**
```bash
CERNITY_SINK=splunk
SPLUNK_HEC_URL=https://your-splunk:8088/services/collector
SPLUNK_HEC_TOKEN=your-hec-token
```

**Syslog / CEF (QRadar, ArcSight, most on-prem SIEMs)**
```bash
CERNITY_SINK=syslog
SYSLOG_HOST=your-siem
SYSLOG_PORT=514
```

**Webhook (Slack, ticketing, custom)**
```bash
CERNITY_SINK=webhook
WEBHOOK_URL=https://your-endpoint/hook
```

(Devo and multi-SIEM fan-out — set `CERNITY_SINK` to a comma list — are in
**[siem-integrations.md](siem-integrations.md)**.)

Then re-create just the forwarder so it picks up the new sink:

```bash
docker compose -f deploy/central/docker-compose.yml up -d findings-forwarder
```

**Check it worked:**
```bash
docker logs cernity-findings-forwarder 2>&1 | tail -5
```
You want a line like `indexed N finding(s) -> ...` (or your sink's equivalent), and no
auth/connection errors.

---

## Step 5 — Verify the whole pipeline end to end

Findings appear when Suricata sees something worth flagging. To confirm the pipeline
*without waiting for real traffic*, replay the built-in beacon fixture on the Cernity host:

```bash
docker compose -f deploy/quickstart/docker-compose.yml up -d eve-feeder
```

Within ~a minute a `beacon` / C2 finding should reach your SIEM (or, if you're still on the
file sink, read it directly):

```bash
docker compose -f deploy/central/docker-compose.yml exec findings-forwarder \
  cat /out/findings.jsonl
```

If you see a finding with `"category": "c2"` and `"state": "FINAL"`, **you're done** —
Cernity is live: your sensor's telemetry is becoming findings and landing in your SIEM.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| A central service keeps restarting | `docker compose -f deploy/central/docker-compose.yml logs <svc>` — usually a missing `.env` value (e.g. an unset `CLICKHOUSE_PASSWORD` while ClickHouse is enabled; leave it empty to run without ClickHouse). |
| Shipper can't reach `CENTRAL_HOST:19092` | Open TCP 19092 on the Cernity host's firewall, and set `CERNITY_ADVERTISE_HOST` to a name/IP the sensor can reach; confirm `REDPANDA_BOOTSTRAP` points at the right host. The port is auth+TLS by default — it *should* refuse unauthenticated clients. |
| Shipper connects but the bus rejects it (auth/TLS errors) | The secure bus needs the SCRAM creds + CA on the sensor: `CERNITY_BUS_USER`/`CERNITY_BUS_PASSWORD` (from `gen-bus-certs.sh`) and `CERNITY_BUS_CA` pointing at the `ca.crt` copied from the central host. The cert's SAN must include `CERNITY_ADVERTISE_HOST`. |
| No findings arrive | Confirm both EVE files are growing (Step 2), the shipper shows no errors (Step 3), and `finding-service` logs show `FINAL` lines: `docker compose -f deploy/central/docker-compose.yml logs finding-service`. |
| SIEM shows nothing | Check `findings-forwarder` logs for auth/endpoint errors (Step 4); verify the credentials and that the index/HEC token exists. |

---

## Next steps

- **Get more detections:** apply the full [Suricata best-results config](suricata-config.md)
  (nDPI, JA3/JA4, file hashing) — each unlocks more detectors.
- **Richer findings:** turn on [enrichment](enrichment.md) — GeoIP/ASN, reverse DNS,
  domain age, IP reputation.
- **Grow past one sensor:** the [scale guide](placement.md) covers many sensors and
  splitting Cernity across hosts.
- **Understand what you built:** [how-it-works.md](how-it-works.md) and
  [how Cernity completes Suricata into an NDR](ndr-coverage.md).
