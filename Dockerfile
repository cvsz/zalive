FROM python:3.14-slim

# Security: non-root, pinned OS packages, tini for PID1 handling
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    libimobiledevice6 libimobiledevice-utils \
    libplist3 libusbmuxd6 usbmuxd \
    libcurl4-openssl-dev libssl-dev openssl curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 app

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY albert_server.py gunicorn_conf.py firmware_restore_proxy.py activate_device.py ./
RUN mkdir -p certs logs && chown -R app:app /app

USER app
EXPOSE 18090 18443
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:${ALBERT_HTTP_PORT:-18090}/health || curl -f http://127.0.0.1:18090/health || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["gunicorn", "-c", "gunicorn_conf.py", "albert_server:app"]
