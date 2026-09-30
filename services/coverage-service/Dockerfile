FROM python:3.14.7-slim
WORKDIR /app
COPY services/coverage-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/coverage-service/coverage.py services/coverage-service/app.py services/coverage-service/test_coverage.py ./
RUN python test_coverage.py
USER nobody
EXPOSE 8095
ENTRYPOINT ["python", "app.py"]
