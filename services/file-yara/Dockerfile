FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY services/file-yara/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ndr_runtime.py ./
COPY services/file-yara/scan.py services/file-yara/rules_refresh.py services/file-yara/fileforensics.py services/file-yara/app.py services/file-yara/test_scan.py services/file-yara/test_fileforensics.py ./
COPY services/file-yara/rules/ ./rules/
RUN python test_scan.py && python test_fileforensics.py
USER nobody
ENTRYPOINT ["python", "app.py"]
