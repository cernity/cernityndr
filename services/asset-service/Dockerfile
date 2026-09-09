# build context = repo root
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/asset-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/asset-service/resolution.py services/asset-service/app.py services/asset-service/test_resolution.py ./
RUN python test_resolution.py
USER nobody
ENTRYPOINT ["python", "app.py"]
