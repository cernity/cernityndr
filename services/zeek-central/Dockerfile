FROM zeek/zeek:latest
RUN apt-get update && apt-get install -y --no-install-recommends python3-pip python3-venv libsnappy-dev gcc git \
 && rm -rf /var/lib/apt/lists/*
# JA3/JA4 TLS fingerprint packages (auto-loaded via zkg on `zeek -r`). Best-effort by
# default because zkg needs network/config a clean build may lack and Zeek still enriches
# without them — but the outcome is VISIBLE, not a silent `|| true` that hides a missing
# capability (F15). Build with --build-arg ZEEK_REQUIRE_FINGERPRINTS=1 to fail the build
# when JA3/JA4 are unavailable (a deployment that requires them).
ARG ZEEK_REQUIRE_FINGERPRINTS=0
RUN if zkg autoconfig && zkg install --force salesforce/ja3 && zkg install --force FoxIO-LLC/ja4; then \
        echo "zeek-central: JA3/JA4 fingerprint packages installed"; \
    elif [ "$ZEEK_REQUIRE_FINGERPRINTS" = "1" ]; then \
        echo "zeek-central: ERROR JA3/JA4 fingerprint packages REQUIRED but unavailable" >&2; exit 1; \
    else \
        echo "zeek-central: WARNING JA3/JA4 fingerprint packages unavailable — continuing without them" >&2; \
    fi
RUN python3 -m venv /venv && /venv/bin/pip install --no-cache-dir kafka-python-ng boto3 lz4 python-snappy zstandard
ENV PATH="/venv/bin:/opt/zeek/bin:${PATH}"
WORKDIR /app
COPY services/zeek-central/enrich.py services/zeek-central/test_enrich.py ./
RUN python3 test_enrich.py
ENTRYPOINT ["python3", "enrich.py"]
