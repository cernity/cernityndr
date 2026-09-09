FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev ca-certificates && rm -rf /var/lib/apt/lists/*
COPY services/threat-intel/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# shared runtime (plan 003 U5/U6)
COPY shared/ndr_runtime.py shared/metrics.py ./
COPY services/threat-intel/ti.py services/threat-intel/app.py services/threat-intel/test_ti.py ./
RUN python test_ti.py
USER nobody
ENTRYPOINT ["python", "app.py"]
