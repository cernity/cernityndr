FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/ids-alerts/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# shared runtime (plan 003 U6 rollout)
COPY shared/ndr_runtime.py shared/metrics.py ./
COPY services/ids-alerts/promote.py services/ids-alerts/app.py services/ids-alerts/test_promote.py ./
RUN python test_promote.py
USER nobody
ENTRYPOINT ["python", "app.py"]
