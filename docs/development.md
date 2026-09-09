# Development guide

How Cernity is built, tested, and extended. Plain and practical.

## Layout

```
contracts/          the public API: JSON schemas + the topic list
shared/             the shared library every service uses:
                      ndr_runtime.py  tuned Kafka consumer/producer + health/metrics
                      store.py        the window store (in-memory or Redis, sharded)
                      metrics.py      Prometheus metrics helpers
services/<name>/    one folder per service: its code, tests, and Dockerfile
deploy/             how to run it: sensor, central, overlays, scale, helm, fluent-bit
docs/               these docs
tools/, tests/      dev tooling and the end-to-end test
```

## How a service is built

Every service is small and single-purpose:
- **Pure logic** lives in its own module (e.g. `detectors.py`, `state_machine.py`,
  `adapters.py`) and is unit-tested without a broker.
- **`app.py`** is the thin I/O shell: build a consumer/producer via `ndr_runtime`,
  poll the bus, call the pure logic, publish results.
- Config comes from environment variables (with sane defaults). No hardcoded IPs,
  hostnames, or secrets.

## Tests

Tests are plain assert-based scripts named `test_*.py` — no framework, run directly:

```bash
python services/behavioral-detectors/test_detectors.py
```

Each service's Docker image **runs its tests as a build gate** (`RUN python test_*.py`
in the Dockerfile), so an image cannot be built if its tests fail.

Run the whole unit suite (uses a local interpreter via `PYBIN`, puts `shared/` on the
path automatically):

```bash
PYBIN=.venv/bin/python ./run-tests.sh
```

Run the end-to-end walking skeleton (needs Docker — builds the stack, replays a beacon,
asserts a finding appears):

```bash
python tests/test_e2e_skeleton.py
```

## Building images

Every service builds from the repo root so it can copy the shared library:

```bash
docker build -t cernity/behavioral-detectors -f services/behavioral-detectors/Dockerfile .
```

CI (`.github/workflows/ci.yml`) runs the unit gate on every push; the e2e is on-demand.
`publish.yml` builds and pushes multi-arch images to Docker Hub on version tags or a
manual run (needs `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` secrets).

### The `shared/` library is copied flat into every image

Each service image `COPY`s the shared modules (`ndr_runtime.py`, `metrics.py`,
`store.py`) in flat — there is no shared base image. Two consequences that will bite you:

- **A change under `shared/` means rebuilding *every* service image**, not just the one
  you're working on. A stale service running the old shared code is a classic
  "works in tests, breaks in the stack" bug.
- **`metrics` is imported lazily** (it needs `prometheus_client`, which the light
  self-contained images don't all carry). `setup_logging` — used by every service — stays
  dependency-free. A service that runs its own metrics server reaches it as
  `ndr_runtime.metrics`; that attribute is resolved lazily via a module `__getattr__`, so
  don't assume `import metrics` has happened at module load.

### Rebuild gotcha: build through Compose, and verify what's actually running

When you rebuild after editing `shared/` (or anything), two things can silently serve you
a **stale image**, so the container keeps running old code even though your rebuild
"succeeded":

1. **Docker layer cache** can reuse the `COPY shared/…` layer. Force it with
   `docker compose build --no-cache <svc>` when in doubt.
2. **buildx builder stores differ.** A bare `docker build -t cernity/foo:latest …` may
   land the image in a *different* builder's store (e.g. `desktop-linux`) than the one
   Compose resolves the tag from — so Compose recreates the container from an *older*
   image with the same tag. Building **through Compose**
   (`docker compose -f deploy/quickstart/docker-compose.yml build <svc>`) avoids this
   because Compose builds and runs from the same store.

Verify the container is really on your new image:

```bash
# these two IDs must match
docker inspect cernity-<svc> -f '{{.Image}}'
docker image inspect cernity/<svc>:latest -f '{{.Id}}'
```

**Always run the quickstart e2e (`tests/test_e2e_skeleton.py`) before shipping.** It replays
a beacon through the whole pipeline and catches integration regressions the unit gate
can't see — a shared-module change that crash-loops a detector shows up here immediately.

## Adding a detector

1. Create `services/<name>/` with a pure module + `app.py` that consumes the topic(s)
   it needs and publishes `ndr.finding.candidate.v1`. Mirror an existing detector.
2. Add `test_<name>.py` covering the detection logic (happy path, edges, no-fire cases).
3. Add a Dockerfile that copies `shared/` + your files and runs your tests as the gate.
4. Register it in `deploy/central/docker-compose.yml`, the `deploy/scale` and Helm
   detector lists, and the publish matrix.
5. Keep to the contract: don't change a schema without updating `contracts/` and its
   test (`contracts/test_contracts.py`).

## Adding a SIEM sink

Add an adapter class to `services/findings-forwarder/adapters.py` exposing
`emit_batch(findings)`, register it in `_make()`, and add a unit test that asserts the
payload/format it builds (no live SIEM needed). Use `cef.py` for syslog-family targets.
See `docs/siem-integrations.md`.

## Conventions

- Small, focused files; one responsibility each.
- `:latest` image tags by default; pin only with a concrete reason.
- Health-level logging (INFO = startup + heartbeat, DEBUG = detail); never flood.
- Every non-trivial change leaves a runnable test behind.
