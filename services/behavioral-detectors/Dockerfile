# build context = repo root
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/behavioral-detectors/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ndr_runtime.py shared/metrics.py shared/store.py shared/test_store.py shared/test_ndr_runtime.py ./
COPY services/behavioral-detectors/detectors.py services/behavioral-detectors/config_source.py services/behavioral-detectors/app.py \
     services/behavioral-detectors/test_detectors.py services/behavioral-detectors/test_metrics.py \
     services/behavioral-detectors/test_contract.py services/behavioral-detectors/test_config_source.py \
     services/behavioral-detectors/test_partition_scope.py services/behavioral-detectors/test_ndpi.py services/behavioral-detectors/test_timing.py ./
COPY services/behavioral-detectors/validation ./validation
RUN python test_detectors.py && python test_store.py && python test_metrics.py && python test_ndr_runtime.py && python test_partition_scope.py && python test_contract.py && python test_config_source.py && python test_ndpi.py && python test_timing.py && (cd validation && python test_validation.py)
USER nobody
ENTRYPOINT ["python", "app.py"]
