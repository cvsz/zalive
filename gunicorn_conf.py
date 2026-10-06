"""Production gunicorn config for albert_server.

The WSGI service is plain HTTP. Keep its host listener loopback-only and use a
TLS reverse proxy for remote browser access.
"""
import ipaddress
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / ".env", override=False)
except Exception:
    pass


def _is_loopback_host(host):
    value = str(host or "").strip().lower()
    if value in ("localhost", "localhost.localdomain"):
        return True
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def on_starting(server):
    if os.environ.get("ALBERT_ACCEPT_RISK") != "1":
        raise RuntimeError("ALBERT_ACCEPT_RISK=1 is required to start the activation server.")
    if os.environ.get("ALBERT_IN_DOCKER") == "1":
        public_host = os.environ.get("ALBERT_BIND_ADDRESS", "127.0.0.1")
    else:
        public_host = os.environ.get("ALBERT_HOST", "127.0.0.1")
    if not _is_loopback_host(public_host):
        raise RuntimeError("Gunicorn serves plain HTTP; bind it to loopback and use a TLS-terminating reverse proxy for remote access.")
    ca = os.environ.get("ALBERT_MTLS_CA", "").strip()
    if ca and not Path(ca).is_file():
        raise RuntimeError("ALBERT_MTLS_CA is configured but the CA file is missing.")
    token = os.environ.get("ALBERT_MTLS_TOKEN", "").strip()
    if token and len(token) < 32:
        raise RuntimeError("ALBERT_MTLS_TOKEN must contain at least 32 characters.")
    if os.environ.get("ALBERT_IN_DOCKER") == "1" and len(token) < 32:
        raise RuntimeError("Compose requires ALBERT_MTLS_TOKEN with at least 32 characters.")
    if token:
        os.environ["ALBERT_REQUIRE_DEVICE_TOKEN"] = "1"
    workers_configured = int(os.environ.get("GUNICORN_WORKERS", "1"))
    if workers_configured > 1:
        if not os.environ.get("ALBERT_REDIS_URL", "").strip():
            raise RuntimeError("Multiple Gunicorn workers require ALBERT_REDIS_URL for shared rate limits.")
        if os.environ.get("ALBERT_REDIS_FAIL_CLOSED", "0").strip() != "1":
            raise RuntimeError("Multiple Gunicorn workers require ALBERT_REDIS_FAIL_CLOSED=1.")


def post_fork(server, worker):
    ca = os.environ.get("ALBERT_MTLS_CA", "").strip()
    token = os.environ.get("ALBERT_MTLS_TOKEN", "").strip()
    if ca:
        server.log.info("mTLS gate configured against CA=%s", ca)
    elif token:
        server.log.info("device-route shared-token authentication enabled")
    else:
        server.log.warning("No device-route auth configured; keep the listener loopback-only.")


bind = f"{os.environ.get('ALBERT_HOST', '127.0.0.1')}:{os.environ.get('ALBERT_HTTP_PORT', '18090')}"
workers = int(os.environ.get('GUNICORN_WORKERS', '1'))
threads = int(os.environ.get('GUNICORN_THREADS', '4'))
worker_class = "gthread"
timeout = 30
graceful_timeout = 10
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get('LOG_LEVEL', 'info')
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(m)s %(U)s %(H)s" %(s)s %(b)s "%(f)s" "%(a)s" request_id="%({X-Request-ID}i)s"'
limit_request_line = 4096
limit_request_fields = 50
limit_request_field_size = 8190
