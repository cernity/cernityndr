FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/file-threat/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# shared runtime (plan 003 U6 rollout)
COPY shared/ndr_runtime.py shared/metrics.py ./
COPY services/file-threat/filematch.py services/file-threat/app.py services/file-threat/test_filematch.py ./
RUN python test_filematch.py
USER nobody
ENTRYPOINT ["python", "app.py"]
