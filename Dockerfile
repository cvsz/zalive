# syntax=docker/dockerfile:1.4
FROM python:3.13-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends gcc python3-dev && \
    pip install --no-cache-dir --no-require-hashes --prefix=/install -r requirements.txt \
    && python -m compileall -q /install \
    && apt-get purge -y gcc python3-dev && rm -rf /var/lib/apt/lists/*

FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 -s /usr/sbin/nologin app
WORKDIR /app
COPY --from=builder /install /usr/local
COPY albert_server.py gunicorn_conf.py ./
COPY static/ ./static/
COPY certs/ ./certs/
COPY logs/.gitkeep logs/.gitkeep
COPY logs/restore/README.md logs/restore/README.md
COPY scripts/ ./scripts/
USER app
EXPOSE 18090 18443
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s CMD curl -fsS http://127.0.0.1:${ALBERT_HTTP_PORT:-18090}/health || exit 1
ENTRYPOINT ["tini", "--"]
CMD ["gunicorn", "-c", "gunicorn_conf.py", "albert_server:app"]
