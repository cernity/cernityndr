FROM python:3.14.7-slim
WORKDIR /app
COPY services/feedback-service/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY contracts/disposition.schema.json /app/contracts/disposition.schema.json
COPY services/feedback-service/app.py services/feedback-service/router.py services/feedback-service/quality.py /app/services/feedback-service/
RUN mkdir /data && chown nobody:nogroup /data
USER nobody
EXPOSE 8094
ENTRYPOINT ["python", "/app/services/feedback-service/app.py"]
