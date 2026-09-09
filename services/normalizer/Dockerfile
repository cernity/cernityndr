FROM python:3.12-slim
WORKDIR /app
# libsnappy for python-snappy so the consumer can decode ANY producer's codec
# (Vector uses lz4; rpk/other producers may use snappy/zstd).
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev \
 && rm -rf /var/lib/apt/lists/*
COPY services/normalizer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# shared runtime (plan 003 U6 rollout)
COPY shared/ndr_runtime.py shared/metrics.py ./
COPY services/normalizer/models.py services/normalizer/app.py services/normalizer/test_normalize.py ./
RUN python test_normalize.py            # fail the build if transforms regress
USER nobody
ENTRYPOINT ["python", "app.py"]
