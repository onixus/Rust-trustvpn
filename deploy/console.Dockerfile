# Additive sidecar; VPN endpoint in the existing container is untouched.
ARG BASE_IMAGE=trusttunnel-web:profiles-20260930
FROM ${BASE_IMAGE}
USER root
COPY server/console /console
WORKDIR /app
ENV PYTHONPATH=/app:/console
USER 10001:10001
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:8000/console/healthz',timeout=3).status == 200"
CMD ["uvicorn", "console_app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
