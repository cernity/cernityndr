FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/capture-orchestrator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ndr_runtime.py ./
COPY services/capture-orchestrator/gates.py services/capture-orchestrator/app.py services/capture-orchestrator/test_gates.py ./
RUN python test_gates.py
USER nobody
ENTRYPOINT ["python", "app.py"]
