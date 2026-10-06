# Layer the exchange API/UI onto the exact installed portal OR console image.
# The existing codec, endpoint, console modules and entrypoint stay in the base.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
COPY server/overlay/app/ /app/app/
COPY deploy/portal_patch.py /tmp/rtrust-portal-patch.py
RUN python /tmp/rtrust-portal-patch.py && rm /tmp/rtrust-portal-patch.py
USER 10001:10001
