FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY scripts ./scripts
COPY trusttunnel_endpoint /opt/trusttunnel/trusttunnel_endpoint
ENV DATA_DIR=/data ENDPOINT_BIN=/opt/trusttunnel/trusttunnel_endpoint ENDPOINT_WORKDIR=/data/runtime CERT_DIR=/certs
USER 10001:10001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
