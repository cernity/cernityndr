FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/protocol-detectors/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# shared runtime (plan 003 U5/U6)
COPY shared/ndr_runtime.py shared/metrics.py shared/store.py ./
COPY services/protocol-detectors/proto.py services/protocol-detectors/app.py services/protocol-detectors/test_proto.py services/protocol-detectors/test_proto_state.py ./
RUN python test_proto.py && python test_proto_state.py
USER nobody
ENTRYPOINT ["python", "app.py"]
