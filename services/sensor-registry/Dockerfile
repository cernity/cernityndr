FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/sensor-registry/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ndr_runtime.py shared/metrics.py ./
COPY services/sensor-registry/store.py services/sensor-registry/app.py services/sensor-registry/enrollment.py ./
# test_registry.py spans services (loads the sensor-agent + contracts) so it runs
# in the repo-wide CI gate (PYTHONPATH=shared pytest), not this single-service build.
# SQLite lives on a mounted volume (KTD3) — no relational-DB overlay. Create /data
# owned by the runtime user BEFORE declaring the volume: a fresh NAMED volume
# inherits this dir's ownership, so `nobody` can open /data/registry.db on first
# boot. NOTE for a BIND mount: host dir ownership wins, so the operator must
# `chown 65534:65534` (nobody:nogroup) the bind target or nobody cannot write.
RUN mkdir -p /data && chown nobody:nogroup /data
VOLUME ["/data"]
USER nobody
EXPOSE 8091
ENTRYPOINT ["python", "app.py"]
