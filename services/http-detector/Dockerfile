FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/http-detector/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# shared runtime (plan 003 U5/U6)
COPY shared/ndr_runtime.py shared/metrics.py shared/store.py ./
COPY services/http-detector/http_detect.py services/http-detector/app.py services/http-detector/test_http_detect.py services/http-detector/test_http_state.py ./
RUN python test_http_detect.py && python test_http_state.py
USER nobody
ENTRYPOINT ["python", "app.py"]
