# Sensor agent (U2)

Mandatory sensor health daemon, separate from the optional capture agent. It
emits `sensor-health.v1` on `ndr.sensor.health.v1` immediately, then every
`SENSOR_HEARTBEAT_SECONDS` (default 30). Scheduling uses a monotonic clock;
missed intervals are skipped. Delivery failures are logged and retried on the
next interval. A heartbeat waits for the broker acknowledgement. Connectivity
reports the **previous** publish result; the first report says `unknown`.

## Sensor deployment

The normal `deploy/sensor/docker-compose.yml` includes this agent without a
profile or capture dependency. Set a persistent `NDR_SENSOR_UUID` (UUID),
`NDR_TENANT`, `NDR_SITE`, and `REDPANDA_BOOTSTRAP` to the central external broker
address. Empty UUID/site fails startup rather than inventing an identity. UUID
provisioning/enrollment and the legacy `NDR_SENSOR` mapping belong to U3; this
service does not rewrite existing EVE sensor IDs.

The image contains a chronyc client. The Linux **host** must run chronyd with
its localhost monitoring endpoint enabled (default UDP 323). Host networking
lets the unprivileged client query this read-only endpoint. The agent does not
start a second chronyd or change the host clock. `/proc` and the Suricata log
directory are mounted read-only; CPU and memory describe the host, and disk
free space describes the log filesystem. It needs no PCAP or Suricata command
socket. Ensure logs are readable by the container's `nobody` user.

Secure Kafka settings reuse `shared/ndr_runtime.py`. The central bootstrap adds
only write/describe/create on the literal `ndr.sensor.health.v1` topic to the
sensor principal. Existing deployed brokers must apply that same ACL before
starting the agent. No read permission or general `ndr.*` write is granted.
Topic keys are UTF-8 JSON `[tenant, sensor_uuid]`. As with existing sensor bus
credentials, payload identity is an assertion, not an authenticated per-sensor
binding; a registry consumer must enforce that binding at trusted ingress.

## Measurements and unknown values

All metric fields are present. `null` means unavailable, not zero. Versions
always includes this agent's build version. Additional installed versions can
be supplied by deployment inventory using `SENSOR_VERSIONS` JSON; the daemon
does not guess them.

* CPU is the host `/proc/stat` delta; its first sample is unknown. Memory uses
  `/proc/meminfo` available/total, disk uses filesystem free bytes.
* EVE rates count complete lines and their bytes appended to the comma-separated
  `SENSOR_EVE_PATHS` files. These files must contain one EVE event per line.
  The default is the existing alerts/NSM split. Startup, rotation, unreadable
  files or more than 4 MiB appended per file per interval produce null rates.
  Reads are bounded; this is not an unbounded second ingestion pipeline.
* Capture drop counters and shipper backlog are read from an **optional host
  metrics exporter snapshot**, `SENSOR_METRICS_PATH`. No such exporter is added
  by U2. Without it these fields remain unknown; capture capability is not
  inferred from nulls. The snapshot must be written atomically, be at most
  16 KiB and no more than 60 seconds old, and contain actual measured values:

```json
{
  "observed_at_unix": 1790553600,
  "capture": {"kernel_drops_total": 12, "suricata_capture_drops_total": 8},
  "shipper": {"queue_depth": 1024, "oldest_unsent_age_s": 2.1}
}
```

The compose default path is `/var/log/suricata/sensor-metrics.json`.

`clock_offset_ms` is **system clock minus the chrony NTP clock**. Positive means
sensor ahead. The daemon reads `chronyc -c -h 127.0.0.1 tracking` each heartbeat,
negates the signed current correction (CSV field 5), and converts seconds to
milliseconds. It uses the current system correction, not the last frequency
update's offset. `time_source` is the selected source from the same report.
Missing chrony, timeout, malformed/nonfinite data, local-reference mode and
unsynchronized state yield null offset/source and `clock_status=unavailable`.
This is chrony's measured estimate, not an independent accuracy guarantee.

Semantics verified against the [chronyc monitoring manual](https://chrony-project.org/doc/4.6/chronyc.html)
and [chrony 4.6 CSV formatter/tracking source](https://github.com/mlichvar/chrony/blob/4.6/client.c)
(`process_cmd_tracking`, `print_report`).

## Verification

```sh
.venv/bin/python -m pytest contracts services/sensor-agent/test_agent.py
NDR_SENSOR_UUID=e04b79e4-6d53-4303-8183-382410120cc6 NDR_SITE=dc1 docker compose -f deploy/sensor/docker-compose.yml config --quiet
```

For a real bus smoke, configure the above identity, chronyd and bus credentials,
apply the health-topic ACL, then start **only** the mandatory agent:

```sh
docker compose -f deploy/sensor/docker-compose.yml up -d --build sensor-agent
```

Use an authenticated central consumer to retrieve at least two records from
`ndr.sensor.health.v1`. Validate them against the schema; verify their sensor
UUID, tenant, interval, and nonnull measured offset/source against the host's
`chronyc -c tracking` report. Capture need not be running. Run
`deploy/security/test_bus_acls.sh` against its disposable broker to check the
exact-topic permission and continued denial of capture/findings writes.

The implementation environment denied Docker daemon access, so neither image
build nor compose delivery/ACL smoke was observed there. Unit tests cover
measured chrony report parsing and the Kafka publication/acknowledgement wiring
with substitutes; they do not prove live delivery.
