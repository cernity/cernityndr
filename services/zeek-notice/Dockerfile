FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/zeek-notice/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# shared runtime (plan 003 U6 rollout)
COPY shared/ndr_runtime.py shared/metrics.py ./
COPY services/zeek-notice/promote_notice.py services/zeek-notice/app.py services/zeek-notice/test_promote_notice.py ./
RUN python test_promote_notice.py
USER nobody
ENTRYPOINT ["python", "app.py"]
