FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends chrony && rm -rf /var/lib/apt/lists/*
COPY services/sensor-agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ndr_runtime.py ./
COPY services/sensor-agent/agent.py services/sensor-agent/app.py ./
USER nobody
CMD ["python", "app.py"]
