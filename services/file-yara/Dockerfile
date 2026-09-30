FROM python:3.14.7-slim
WORKDIR /app
# yara-python compiles its bundled libyara from sdist on 3.14 (no prebuilt wheel yet), so it needs
# the full autotools/compiler toolchain, not just gcc.
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc make libtool automake pkg-config flex bison libssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY services/file-yara/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ndr_runtime.py ./
COPY services/file-yara/scan.py services/file-yara/rules_refresh.py services/file-yara/registry.py services/file-yara/fileforensics.py services/file-yara/app.py services/file-yara/test_scan.py services/file-yara/test_fileforensics.py ./
COPY services/file-yara/rules/ ./rules/
RUN python test_scan.py && python test_fileforensics.py
# Persistent, service-writable registry store. A named volume mounts here at runtime
# (deploy/overlays/forensics.yml) under the read-only root fs; created + chowned so
# the fresh volume inherits nobody ownership on first mount.
RUN mkdir -p /var/lib/file-yara && chown nobody:nogroup /var/lib/file-yara
USER nobody
# Smoke test under the deployed user: the entrypoint's imports resolve (registry.py
# is shipped) and nobody can initialise + write the registry in its deployed dir.
# Leaves the dir empty so the runtime volume starts clean.
RUN python -c "import app" \
    && python -c "import registry; registry.RulesetRegistry('/var/lib/file-yara/registry.db').register_draft('smoke', '0', b'rule s { condition: true }', 'build-smoke')" \
    && rm -f /var/lib/file-yara/registry.db
ENTRYPOINT ["python", "app.py"]
