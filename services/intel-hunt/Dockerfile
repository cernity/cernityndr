FROM python:3.14-slim
WORKDIR /app
COPY services/intel-hunt/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY services/intel-hunt/ ./services/intel-hunt/
COPY services/evidence-service/query.py ./services/evidence-service/query.py
COPY services/threat-intel/lifecycle.py services/threat-intel/ti.py ./services/threat-intel/
COPY contracts/hunt.schema.json ./contracts/hunt.schema.json
RUN mkdir /data && chown nobody:nogroup /data
USER nobody
EXPOSE 8096
ENTRYPOINT ["python", "services/intel-hunt/app.py"]
