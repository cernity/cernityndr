# build context = repo root
FROM python:3.14.7-slim
WORKDIR /app
COPY services/connector-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ndr_runtime.py ./
COPY services/connector-service/netbox.py services/connector-service/app.py ./
# Build smoke: the entrypoint (and the connector mapping it drives) import cleanly.
RUN python -c "import app"
USER nobody
ENTRYPOINT ["python", "app.py"]
