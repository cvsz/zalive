"""Production gunicorn config for albert_server"""
import os
import logging as _logging
# mTLS toggle for proxy→Albert (env ALBERT_MTLS_CA)
# If ALBERT_MTLS_CA is set, require client cert for incoming connections (mitmproxy must present ALBERT_MTLS_CERT/KEY).
# If not set, warn that proxy→Albert is unauthenticated.
_mtls_ca = os.environ.get("ALBERT_MTLS_CA", "").strip()
if _mtls_ca:
    ca_certs = _mtls_ca
    cert_reqs = 2  # ssl.CERT_REQUIRED
else:
    # No mTLS — will warn at worker startup via hook
    pass

def on_starting(server):
    ca = os.environ.get("ALBERT_MTLS_CA", "").strip()
    if ca:
        server.log.info(f"mTLS enabled — proxy→Albert requires client cert (CA={ca})")
        # verify CA file exists
        import pathlib
        if not pathlib.Path(ca).exists():
            server.log.warning(f"ALBERT_MTLS_CA={ca} not found — client cert verification will fail")
    else:
        server.log.warning("ALBERT_MTLS_CA not set — proxy→Albert mTLS disabled (unauthenticated). Set ALBERT_MTLS_CA to require client cert.")

def post_fork(server, worker):
    ca = os.environ.get("ALBERT_MTLS_CA", "").strip()
    if not ca:
        server.log.warning("ALBERT_MTLS_CA not set — proxy→Albert mTLS disabled (unauthenticated).")
bind = f"{os.environ.get('ALBERT_HOST','0.0.0.0')}:{os.environ.get('ALBERT_HTTP_PORT','18090')}"
workers = int(os.environ.get('GUNICORN_WORKERS','2'))
threads = int(os.environ.get('GUNICORN_THREADS','4'))
worker_class = "gthread"
timeout = 30
graceful_timeout = 10
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get('LOG_LEVEL','info')
# Access log format with request_id (X-Request-ID header)
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" request_id="%({X-Request-ID}i)s"'
# Security: limit request size at proxy layer too
limit_request_line = 4096
limit_request_fields = 50
limit_request_field_size = 8190
