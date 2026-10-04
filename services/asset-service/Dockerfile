# build context = repo root
FROM python:3.14.7-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/asset-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ndr_runtime.py ./
COPY services/asset-service/resolution.py services/asset-service/relationships.py services/asset-service/app.py ./
# Build smoke: the runtime module imports cleanly. (test_resolution.py is a repo-level
# integration test — it cross-loads normalizer/models.py and reads deploy/clickhouse SQL,
# neither present in this flat image — so it runs in CI from the repo, not the image gate.)
RUN python -c "import app"
USER nobody
ENTRYPOINT ["python", "app.py"]
