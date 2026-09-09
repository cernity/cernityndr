FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/soar-forwarder/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# shared runtime (plan 003 U6 rollout)
COPY shared/ndr_runtime.py shared/metrics.py ./
COPY services/soar-forwarder/playbook.py services/soar-forwarder/app.py services/soar-forwarder/test_playbook.py ./
RUN python test_playbook.py
USER nobody
ENTRYPOINT ["python", "app.py"]
