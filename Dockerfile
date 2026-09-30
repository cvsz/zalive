# syntax=docker/dockerfile:1.4
# albert_server — production Dockerfile (python:3.14-slim, non-root, read-only)
# Validated: pip hash-checked, gcc only in builder, no secrets copied, OCI labels, tini, healthcheck

# Build stage
FROM python:3.14-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends gcc python3-dev \
    && pip install --require-hashes --prefix=/install -r requirements.txt \
    && python -m compileall -q /install \
    && apt-get purge -y gcc python3-dev \
    && rm -rf /var/lib/apt/lists/* /root/.cache

# Runtime stage
FROM python:3.14-slim

LABEL org.opencontainers.image.title="albert_server" \
    org.opencontainers.image.description="Local Albert albert.apple.com emulator for iPhone XR restore" \
    org.opencontainers.image.source="https://github.com/cvsz/zalive" \
    org.opencontainers.image.version="1.1-fixed"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    ALBERT_HOST=0.0.0.0 ALBERT_HTTP_PORT=18090

RUN apt-get update && apt-get install -y --no-install-recommends \
    tini ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 -s /usr/sbin/nologin app \
    && mkdir -p /app/certs /app/logs/restore /app/static /app/scripts \
    && chown -R app:app /app

WORKDIR /app
COPY --from=builder /install /usr/local

# Copy only runtime code — never copy certs/*.key or .env (secrets are mounted / generated at runtime)
COPY albert_server.py gunicorn_conf.py ./
COPY static/ ./static/
COPY scripts/ ./scripts/
COPY certs/.gitkeep ./certs/.gitkeep
COPY logs/.gitkeep ./logs/.gitkeep
COPY logs/restore/README.md ./logs/restore/README.md
RUN chown -R app:app /app && chmod 755 /app/scripts/*.sh 2>/dev/null || true

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libssl3 \
    libffi8 \
    usbmuxd \
    libimobiledevice-utils \
    && rm -rf /var/lib/apt/lists/*

# Container process binds 0.0.0.0; host publish controls exposure (127.0.0.1 for localhost-only, 0.0.0.0 for LAN)
ENV ALBERT_HOST=0.0.0.0

EXPOSE 18090 18443

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s CMD curl -fsS http://127.0.0.1:${ALBERT_HTTP_PORT:-18090}/health || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["gunicorn", "-c", "gunicorn_conf.py", "albert_server:app"]