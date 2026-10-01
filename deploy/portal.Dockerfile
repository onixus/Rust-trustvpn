# Build on the server's native architecture; runtime inherits the exact live image.
FROM rust:1.98.1-bookworm AS codec
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p rtrust-codec
FROM trusttunnel-web:dns-20260929
USER root
RUN pip install --no-cache-dir cryptography==50.0.2
COPY --from=codec /src/target/release/rtrust-codec /usr/local/bin/rtrust-codec
COPY server/overlay/app/ /app/app/
COPY deploy/portal_patch.py /tmp/portal_patch.py
RUN python /tmp/portal_patch.py && rm /tmp/portal_patch.py
USER 10001:10001
