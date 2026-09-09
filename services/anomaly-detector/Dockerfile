FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/anomaly-detector/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# shared runtime (plan 003 U5/U6)
COPY shared/ndr_runtime.py shared/metrics.py ./
COPY services/anomaly-detector/anomaly.py services/anomaly-detector/app.py services/anomaly-detector/test_anomaly.py ./
RUN python test_anomaly.py
USER nobody
ENTRYPOINT ["python", "app.py"]
