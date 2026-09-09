FROM python:3.12-slim
WORKDIR /app
# tcpdump: carve the finding's connection out of the rolling-ring look-back slice
# by BPF (plan 2026-08-25-002, U2).
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump && rm -rf /var/lib/apt/lists/*
COPY services/capture-agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/capture-agent/suricata_socket.py services/capture-agent/agent.py services/capture-agent/app.py services/capture-agent/test_agent.py ./
RUN python test_agent.py
# Note: no USER nobody and CMD (not ENTRYPOINT) are deliberate here — this agent
# runs ON the sensor and needs the root-owned Suricata command socket and the
# file-store dir, unlike the central USER-nobody services.
CMD ["python", "app.py"]
