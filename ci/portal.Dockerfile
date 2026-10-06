FROM rust:1.98.1-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv libdbus-1-dev pkg-config openssl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/portal-venv && /opt/portal-venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt
RUN mkdir /build-target /cargo-cache && chown 1000:1000 /build-target /cargo-cache
ENV PATH=/opt/portal-venv/bin:$PATH CARGO_HOME=/cargo-cache CARGO_TARGET_DIR=/build-target HOME=/tmp/portal-home PYTHONDONTWRITEBYTECODE=1
USER 1000:1000
WORKDIR /src
