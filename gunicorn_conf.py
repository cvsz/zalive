"""Production gunicorn config for albert_server"""
import os
import logging as _logging
# mTLS toggle for proxy→Albert (env ALBERT_MTLS_CA)
#
# This worker serves PLAIN HTTP on ALBERT_HTTP_PORT. It does not terminate TLS,
# so the `ca_certs`/`cert_reqs` pair that used to live here was a no-op: gunicorn
# decides whether to open a TLS listener from certfile/keyfile alone
# (Config.is_ssl is `return self.certfile or self.keyfile`), and neither was
# ever set. The CA was loaded at import and then ignored.
#
# The proxy→Albert gate is enforced in albert_server.py instead, in this order:
#   1. SSL_CLIENT_VERIFY      — only if something upstream already did the TLS
#   2. X-MTLS-Token          — shared secret, compare_digest
#   3. X-Client-Cert (PEM)   — parsed and signature-verified against ALBERT_MTLS_CA
#   4. bare "present"/"mtls" — spoofable; needs ALBERT_MTLS_ALLOW_HEADER_FALLBACK=1
#                             AND a localhost peer
# To terminate TLS here instead, set certfile/keyfile as well — see docs/RUNBOOK.md.
_mtls_ca = os.environ.get("ALBERT_MTLS_CA", "").strip()

def on_starting(server):
    ca = _mtls_ca
    if ca:
        server.log.info(f"mTLS gate active in albert_server.py — client cert verified against CA={ca}")
        # verify CA file exists
        import pathlib
        if not pathlib.Path(ca).exists():
            server.log.warning(f"ALBERT_MTLS_CA={ca} not found — client cert verification will fail")
    else:
        server.log.warning("ALBERT_MTLS_CA not set — proxy→Albert mTLS disabled (unauthenticated). Set ALBERT_MTLS_CA to require client cert.")

def post_fork(server, worker):
    ca = _mtls_ca
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
