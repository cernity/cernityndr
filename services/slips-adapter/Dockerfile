FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/slips-adapter/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ndr_runtime.py shared/metrics.py ./
COPY services/slips-adapter/slips_map.py services/slips-adapter/app.py services/slips-adapter/test_slips_map.py ./
RUN python test_slips_map.py
USER nobody
ENTRYPOINT ["python", "app.py"]
