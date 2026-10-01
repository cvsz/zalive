"""Production gunicorn config for albert_server"""
import os
import logging as _logging
# mTLS toggle for proxy→Albert (env ALBERT_MTLS_CA)
# NOTE: Changing ALBERT_MTLS_CA requires gunicorn restart — TLS config is evaluated at import (cert_reqs=2). See docs/RUNBOOK.md mTLS section.
# If ALBERT_MTLS_CA is set, require client cert for incoming connections (mitmproxy must present ALBERT_MTLS_CERT/KEY).
# If not set, warn that proxy→Albert is unauthenticated.
_mtls_ca = os.environ.get("ALBERT_MTLS_CA", "").strip()
if _mtls_ca:
    ca_certs = _mtls_ca
    cert_reqs = 2  # ssl.CERT_REQUIRED
    # cert_reqs only takes effect once gunicorn is actually serving TLS, and
    # gunicorn decides that from certfile/keyfile alone (Config.is_ssl is
    # `return self.certfile or self.keyfile`). Without these two the CA was
    # loaded and then ignored, no TLS listener was opened, and the
    # SSL_CLIENT_VERIFY branch in albert_server.py could never fire -- the mTLS
    # gate silently fell back to the forgeable header path.
    _tls_cert = os.environ.get("ALBERT_TLS_CERT", "certs/server.crt").strip()
    _tls_key = os.environ.get("ALBERT_TLS_KEY", "certs/server.key").strip()
    import pathlib as _pathlib
    if _pathlib.Path(_tls_cert).exists() and _pathlib.Path(_tls_key).exists():
        certfile = _tls_cert
        keyfile = _tls_key
    else:
        # Fail loudly rather than pretending mTLS is on: without a server
        # certificate gunicorn would serve plain HTTP and every client-cert
        # check would be decided by a header.
        _missing = [p for p in (_tls_cert, _tls_key) if not _pathlib.Path(p).exists()]
        raise SystemExit(
            f"ALBERT_MTLS_CA is set ({_mtls_ca}) but the server certificate is missing: "
            f"{', '.join(_missing)}. Generate certs/server.crt and certs/server.key, or "
            f"unset ALBERT_MTLS_CA to run without mTLS deliberately."
        )
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
