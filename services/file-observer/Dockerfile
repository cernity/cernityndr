FROM python:3.12-slim
WORKDIR /app
# libsnappy for python-snappy so the consumer can decode ANY producer's codec
# (Vector uses lz4; rpk/other producers may use snappy/zstd).
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev \
 && rm -rf /var/lib/apt/lists/*
COPY services/file-observer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# shared runtime (plan 003 U6 rollout)
COPY shared/ndr_runtime.py shared/metrics.py ./
# EVERY module app.py imports, flat in /app: the service code AND the lifted
# file-threat capture-completeness helper (observe.py imports `filematch`). Do not
# rely on PYTHONPATH — copy the file the code imports.
COPY services/file-threat/filematch.py ./filematch.py
# observe.py validates every row against the pinned contract before insertion, so the
# schemas are RUNTIME inputs — COPY them beside the module (the loader resolves them
# here first, then contracts/ in the repo layout). file_observation $refs observation.
COPY contracts/observation.schema.json contracts/file_observation.schema.json ./
COPY services/file-observer/observe.py services/file-observer/app.py ./
USER nobody
ENTRYPOINT ["python", "app.py"]
