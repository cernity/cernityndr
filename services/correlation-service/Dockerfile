FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev \
    && rm -rf /var/lib/apt/lists/*
COPY services/correlation-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# shared runtime (plan 003 U6 rollout)
COPY shared/ndr_runtime.py shared/metrics.py ./
COPY services/correlation-service/correlate.py services/correlation-service/app.py services/correlation-service/test_correlate.py ./
RUN python test_correlate.py
USER nobody
ENTRYPOINT ["python", "app.py"]
