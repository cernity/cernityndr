FROM python:3.14.7-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev ca-certificates && rm -rf /var/lib/apt/lists/*
COPY services/threat-intel/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# shared runtime (plan 003 U5/U6)
COPY shared/ndr_runtime.py shared/metrics.py ./
# service-local modules (U1 lifecycle: store/lifecycle/feeds imported by the U2 matcher);
# COPY every module the service owns so the image is complete (not a PYTHONPATH shortcut).
COPY services/threat-intel/ti.py services/threat-intel/app.py services/threat-intel/test_ti.py ./
COPY services/threat-intel/store.py services/threat-intel/lifecycle.py services/threat-intel/feeds.py services/threat-intel/test_lifecycle.py ./
RUN python test_ti.py && python test_lifecycle.py
USER nobody
ENTRYPOINT ["python", "app.py"]
