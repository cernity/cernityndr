FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/east-west-detectors/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# shared runtime (plan 003 U5/U6)
COPY shared/ndr_runtime.py shared/metrics.py shared/store.py ./
COPY services/east-west-detectors/ew.py services/east-west-detectors/app.py services/east-west-detectors/test_ew.py services/east-west-detectors/test_ew_state.py ./
RUN python test_ew.py && python test_ew_state.py
USER nobody
ENTRYPOINT ["python", "app.py"]
