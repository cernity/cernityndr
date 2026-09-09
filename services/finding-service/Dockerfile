# build context = repo root
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/finding-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ndr_runtime.py shared/metrics.py shared/store.py shared/test_store.py shared/test_ndr_runtime.py ./
COPY services/finding-service/state_machine.py services/finding-service/app.py services/finding-service/geoenrich.py \
     services/finding-service/intel.py services/finding-service/fingerprints.json \
     services/finding-service/test_state_machine.py services/finding-service/test_ch_optional.py \
     services/finding-service/test_geoenrich.py services/finding-service/test_intel.py ./
RUN python test_state_machine.py && python test_ch_optional.py && python test_geoenrich.py && python test_intel.py && python test_store.py && python test_ndr_runtime.py
USER nobody
ENTRYPOINT ["python", "app.py"]
