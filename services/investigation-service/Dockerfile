FROM python:3.14.7-slim
WORKDIR /app
COPY services/investigation-service/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY services/investigation-service /app/services/investigation-service
COPY services/evidence-service/query.py /app/services/evidence-service/query.py
USER nobody
EXPOSE 8097
ENTRYPOINT ["python", "/app/services/investigation-service/app.py"]
