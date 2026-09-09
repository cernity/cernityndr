FROM zeek/zeek:latest
RUN apt-get update && apt-get install -y --no-install-recommends python3-pip python3-venv libsnappy-dev gcc git \
 && rm -rf /var/lib/apt/lists/*
# JA3/JA4 TLS fingerprint packages (best-effort; auto-loaded via zkg on `zeek -r`).
# Wholly non-fatal: Zeek still enriches without them, and zkg needs network/config
# that a clean build may lack.
RUN (zkg autoconfig && zkg install --force salesforce/ja3 && zkg install --force FoxIO-LLC/ja4) 2>/dev/null || true
RUN python3 -m venv /venv && /venv/bin/pip install --no-cache-dir kafka-python-ng boto3 lz4 python-snappy zstandard
ENV PATH="/venv/bin:/opt/zeek/bin:${PATH}"
WORKDIR /app
COPY services/zeek-central/enrich.py services/zeek-central/test_enrich.py ./
RUN python3 test_enrich.py
ENTRYPOINT ["python3", "enrich.py"]
