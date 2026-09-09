FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libsnappy-dev && rm -rf /var/lib/apt/lists/*
COPY services/reconstruction/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ndr_runtime.py ./
COPY services/reconstruction/reconstruct.py services/reconstruction/app.py services/reconstruction/test_reconstruct.py ./
RUN python test_reconstruct.py
USER nobody
EXPOSE 8090
ENTRYPOINT ["python", "app.py"]
