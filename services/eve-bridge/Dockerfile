FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/eve-bridge/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ndr_runtime.py shared/metrics.py ./
COPY services/eve-bridge/bridge.py services/eve-bridge/app.py services/eve-bridge/test_bridge.py ./
RUN python test_bridge.py
USER nobody
ENTRYPOINT ["python", "app.py"]
