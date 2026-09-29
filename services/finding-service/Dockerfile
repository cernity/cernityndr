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
# U7 case model. The service-local store.py (CaseStore) MUST NOT overwrite
# shared/store.py (WindowStore) already at /app/store.py, so the U7 modules are
# copied UNDER their repo-relative path (not flattened into /app) — which also lets
# test_cases.py's HERE/ROOT resolve its modules + contracts unchanged.
COPY services/finding-service/cases.py services/finding-service/store.py \
     services/finding-service/state_machine.py services/finding-service/test_cases.py \
     services/finding-service/
COPY contracts/case.schema.json contracts/disposition.schema.json contracts/
# Verify the U7 modules import in the image AND shared/store.py stays unshadowed.
RUN python -c "import importlib.util as u,sys;\
load=lambda n,p:(sys.modules.__setitem__(n,(m:=u.module_from_spec(s:=u.spec_from_file_location(n,p)))) or s.loader.exec_module(m) or m);\
load('state_machine','services/finding-service/state_machine.py');\
c=load('cases','services/finding-service/cases.py');\
st=load('finding_case_store','services/finding-service/store.py');\
import store as sh;\
assert st.CaseStore and c.new_case and sh.WindowStore;\
print('U7 imports OK: CaseStore + shared WindowStore both resolve')"
USER nobody
ENTRYPOINT ["python", "app.py"]
