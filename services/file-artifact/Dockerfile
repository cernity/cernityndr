FROM python:3.14.7-slim
WORKDIR /app
# libsnappy for python-snappy so the consumer can decode ANY producer's codec.
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev \
 && rm -rf /var/lib/apt/lists/*
COPY services/file-artifact/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# EVERY module app.py imports, flat in /app: the shared runtime + metrics (ndr_runtime
# lazily imports metrics in start_health) + the shared tenant-safe key discipline
# (store.py imports object_keys), then the service code. No PYTHONPATH shortcut.
COPY shared/ndr_runtime.py shared/metrics.py shared/object_keys.py ./
COPY services/file-artifact/store.py services/file-artifact/app.py ./
USER nobody
ENTRYPOINT ["python", "app.py"]
