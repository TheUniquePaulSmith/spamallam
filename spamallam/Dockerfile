FROM python:3.12-slim

# Release identifier shown in the admin UI footer. Pass the git tag / short
# hash at build time; docker-compose wires this from ${SPAMALLAM_VERSION}.
# Left unset, app/version.py falls back to the packaged pyproject version.
ARG SPAMALLAM_VERSION=""

# curl is used by the web_fetch tool's default backend
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --create-home --shell /usr/sbin/nologin spamallam

WORKDIR /opt/spamallam
COPY pyproject.toml README.md ./
COPY app ./app
COPY templates ./templates
COPY static ./static
RUN pip install --no-cache-dir .

# /data: declarative file-based config, users, logs (the only writable volume)
# /run/spamallam: tmpfs scratch (compose mounts it; decrypted mTLS material only)
ENV PYTHONUNBUFFERED=1 \
    SPAMALLAM_DATA=/data \
    SPAMALLAM_TEMPLATES=/opt/spamallam/templates \
    SPAMALLAM_STATIC=/opt/spamallam/static \
    SPAMALLAM_VERSION=${SPAMALLAM_VERSION} \
    TMPDIR=/run/spamallam

EXPOSE 10026 8443

# Pre-create /data owned by spamallam so a fresh named volume mounted here
# inherits this ownership on first creation (container never runs as root).
# Also normalize app source permissions: COPY preserves build-context file
# modes verbatim, so a restrictive host umask (e.g. files copied at 600)
# would otherwise leave spamallam unable to read its own source at runtime.
RUN mkdir -p /data && chown spamallam:spamallam /data \
    && chmod -R a+rX /opt/spamallam

USER spamallam

CMD ["python", "-m", "app.main"]
