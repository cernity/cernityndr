FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/coverage-detector/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# shared runtime (plan 003 U5/U6)
COPY shared/ndr_runtime.py shared/metrics.py ./
COPY services/coverage-detector/coverage.py services/coverage-detector/app.py services/coverage-detector/test_coverage.py ./
RUN python test_coverage.py
USER nobody
ENTRYPOINT ["python", "app.py"]
