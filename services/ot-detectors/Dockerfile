FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/ot-detectors/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# shared runtime (plan 003 U5/U6)
COPY shared/ndr_runtime.py shared/metrics.py shared/store.py ./
COPY services/ot-detectors/ot.py services/ot-detectors/app.py services/ot-detectors/test_ot.py services/ot-detectors/test_ot_state.py ./
RUN python test_ot.py && python test_ot_state.py
USER nobody
ENTRYPOINT ["python", "app.py"]
