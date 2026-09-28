"""Production gunicorn config for albert_server"""
import os
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
