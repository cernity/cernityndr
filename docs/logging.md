# Logging and health

Every Cernity service logs the same way and exposes the same health surface, so you
can tell at a glance whether it's working — and feed its logs into your own platform.

## Format: JSON or text

Set `LOG_FORMAT`:

- `json` (default) — one JSON object per line with standard fields. Machine-parseable;
  ingest it into Loki/Elastic/your SIEM and query by service or tenant.
  ```json
  {"ts":"2026-09-09T13:33:59Z","level":"INFO","svc":"behavioral-detectors","tenant":"acme","event":"beacon","src":"10.0.0.5","dst":"203.0.113.10","score":1.0,"msg":"beacon src=10.0.0.5 dst=203.0.113.10 score=1.0"}
  ```
- `text` — human-readable for `docker logs` and the quickstart (which sets it):
  ```
  2026-09-09 13:33:59 INFO [behavioral-detectors] beacon src=10.0.0.5 dst=203.0.113.10 score=1.0
  ```

Every line — including logs from underlying libraries — carries `ts`, `level`, `svc`,
and `tenant`, because the shared setup configures the root logger.

## Levels

Set `LOG_LEVEL` (default `INFO`):

| Level | What you see |
|---|---|
| `ERROR` | something is broken and needs attention |
| `WARNING` | degraded but recovering (a retryable send, a dropped malformed record) |
| `INFO` | lifecycle (startup, ready, config), **each finding/detection**, and the heartbeat |
| `DEBUG` | per-record detail — off by default |

**Per-record detail is never logged above DEBUG.** That's the rule that keeps logs
from filling a disk: findings are rare and log at INFO; individual flow/DNS records
only appear at DEBUG.

## Heartbeat — "is it alive?"

Each service logs a heartbeat every `HEARTBEAT_SECS` (default 300) at INFO:

```json
{"ts":"…","level":"INFO","svc":"dns-detector","tenant":"acme","event":"heartbeat","uptime_s":300}
```

So `docker logs cernity-<svc>` always shows recent activity. It's infrequent by design
and never a disk concern.

## Health and metrics

Services expose (on `NDR_METRICS_PORT`, default 9108):

- `GET /healthz` — process is up (liveness).
- `GET /readyz` — dependencies (bus, state) are reachable (readiness). An orchestrator
  should only route work to a service that is ready.
- `GET /metrics` — Prometheus metrics (events processed, findings emitted, errors,
  evaluation duration), labeled by service.

Point Prometheus at `/metrics` and use `/healthz` / `/readyz` for container/k8s probes.

## Not filling the disk

- Logs go to **stdout** — Docker/Kubernetes capture and rotate them. The bundled
  compose caps container logs (`max-size`/`max-file`); nothing writes log files.
- The heartbeat is low-frequency; per-record logging is DEBUG-only.

## Settings summary

| Variable | Default | Meaning |
|---|---|---|
| `LOG_FORMAT` | `json` | `json` or `text` |
| `LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |
| `HEARTBEAT_SECS` | `300` | seconds between heartbeat log lines |
| `NDR_METRICS_PORT` | `9108` | port for `/healthz` `/readyz` `/metrics` |
