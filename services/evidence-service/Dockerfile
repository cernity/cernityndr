FROM python:3.14.7-slim
WORKDIR /app
COPY services/evidence-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ndr_runtime.py ./
COPY services/evidence-service/query.py services/evidence-service/app.py services/evidence-service/test_query.py ./
# test_query.py uses pytest (importorskip for the live-ClickHouse cases); install it for the
# build-gate run, then drop it so it isn't in the runtime image.
RUN pip install --no-cache-dir pytest && python -m pytest test_query.py -q && pip uninstall -y pytest
USER nobody
EXPOSE 8092
ENTRYPOINT ["python", "app.py"]
