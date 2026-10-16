FROM python:3.14.7-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/anomaly-detector/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# shared runtime (plan 003 U5/U6)
COPY shared/ndr_runtime.py shared/metrics.py shared/store.py ./
COPY services/anomaly-detector/features.py services/anomaly-detector/anomaly.py services/anomaly-detector/app.py ./
COPY services/anomaly-detector/test_anomaly.py ./services/anomaly-detector/test_anomaly.py
COPY contracts/finding.schema.json ./contracts/finding.schema.json
RUN pip install --no-cache-dir --target /tmp/test-deps jsonschema && \
    PYTHONPATH=/app:/tmp/test-deps python services/anomaly-detector/test_anomaly.py && rm -rf /tmp/test-deps
USER nobody
ENTRYPOINT ["python", "app.py"]
