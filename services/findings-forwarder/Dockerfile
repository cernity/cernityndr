# build context = repo root
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/findings-forwarder/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ndr_runtime.py shared/metrics.py ./
COPY services/findings-forwarder/adapters.py services/findings-forwarder/cef.py services/findings-forwarder/forwarder.py services/findings-forwarder/app.py \
     services/findings-forwarder/test_adapters.py services/findings-forwarder/test_forwarder.py services/findings-forwarder/test_cef.py ./
RUN python test_adapters.py && python test_forwarder.py && python test_cef.py
# Own the default sink directory so the unprivileged user can write findings.
# A fresh named volume mounted here inherits this ownership on first use.
RUN mkdir -p /out && chown nobody:nogroup /out
USER nobody
ENTRYPOINT ["python", "app.py"]
