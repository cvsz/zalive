FROM python:3.13-slim

# tini for PID 1, curl for HEALTHCHECK, ca-certificates for Apple TLS
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# non-root user (uid 10001 matches docker-compose read_only needs)
RUN useradd -m -u 10001 -s /usr/sbin/nologin app

WORKDIR /app

# deps first for layer cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m compileall -q .

# source (respect .dockerignore)
COPY albert_server.py gunicorn_conf.py ./
COPY static/ ./static/
COPY certs/ ./certs/
COPY logs/.gitkeep logs/.gitkeep
COPY logs/restore/README.md logs/restore/README.md

# drop privileges, read-only root compatible
USER app

# gunicorn via tini, binds ALBERT_HOST:ALBERT_HTTP_PORT (default 0.0.0.0:18090 via gunicorn_conf.py)
EXPOSE 18090 18443
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s CMD curl -fsS http://127.0.0.1:${ALBERT_HTTP_PORT:-18090}/health || exit 1
ENTRYPOINT ["tini", "--"]
CMD ["gunicorn", "-c", "gunicorn_conf.py", "albert_server:app"]
