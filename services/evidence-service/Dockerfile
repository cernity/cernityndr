FROM python:3.14.7-slim
WORKDIR /app
COPY services/evidence-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ndr_runtime.py ./
COPY services/evidence-service/query.py services/evidence-service/app.py services/evidence-service/test_query.py ./
RUN python test_query.py
USER nobody
EXPOSE 8092
ENTRYPOINT ["python", "app.py"]
