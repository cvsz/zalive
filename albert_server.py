#!/usr/bin/env python3
"""
Local Albert Activation Server
Mimics Apple's albert.apple.com activation endpoints for iOS device activation.
Supports both legacy and session-based activation flows.
Fixes: robust plist handling, base64, placeholder cert generation, error handling.
"""
import os
import pathlib
import json
import base64
import hashlib
import plistlib
import logging
import sqlite3
import uuid
import re
import time
import threading
import requests
# Load .env early (so ALBERT_ADMIN_TOKEN etc. are available without export)
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=pathlib.Path(__file__).resolve().parent / ".env", override=False)
except Exception:
    pass
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from flask import Flask, request, Response, jsonify, g
from werkzeug.exceptions import RequestEntityTooLarge

app = Flask(__name__, static_folder="static", static_url_path="/__static_disabled")
# Production hardening: request size limit (P0-3), env-driven port
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('ALBERT_MAX_CONTENT_LENGTH', str(512*1024)))
FAIRPLAY_KEY_PATH = os.environ.get('FAIRPLAY_KEY_PATH', 'certs/fairplay.key')
FAIRPLAY_CERT_PATH = os.environ.get('FAIRPLAY_CERT_PATH', 'certs/fairplay.crt')

# --- mTLS toggle for proxy→Albert (env ALBERT_MTLS_CA) ---
# If ALBERT_MTLS_CA is set (path to CA bundle), Albert requires client certificate from mitmproxy.
# If not set, connection is unauthenticated — warn at startup and per-request (see SECURITY.md, docs/architecture.md).
# The proxy (firmware_restore_proxy.py) should present ALBERT_MTLS_CERT/KEY when this is set and use https.
def _get_mtls_ca():
    return os.environ.get("ALBERT_MTLS_CA", "").strip()

def _log_mtls_status():
    ca = _get_mtls_ca()
    if ca:
        if not pathlib.Path(ca).exists():
            logger.warning(f"mTLS enabled but ALBERT_MTLS_CA={ca} not found — client cert verification will fail")
        else:
            logger.info(f"mTLS enabled — proxy→Albert requires client cert (CA={ca})")
    else:
        logger.warning("ALBERT_MTLS_CA not set — proxy→Albert mTLS disabled (unauthenticated). Set ALBERT_MTLS_CA to a CA bundle to require client cert.")

# --- Curated any-iPhone firmware (spec: XR + 12/13/14/15) ---
CURATED_DEVICES = [
    {"identifier": "iPhone5,1", "name": "iPhone 5", "chip": "A6", "internal": "n41ap", "explain": "5 · legacy activation"},
    {"identifier": "iPhone5,3", "name": "iPhone 5c", "chip": "A6", "internal": "n48ap", "explain": "5c · legacy activation"},
    {"identifier": "iPhone6,1", "name": "iPhone 5s", "chip": "A7", "internal": "n51ap", "explain": "5s · TouchID · session activation"},
    {"identifier": "iPhone7,2", "name": "iPhone 6", "chip": "A8", "internal": "n61ap", "explain": "6 · session activation"},
    {"identifier": "iPhone8,1", "name": "iPhone 6s", "chip": "A9", "internal": "n71ap", "explain": "6s · session activation"},
    {"identifier": "iPhone9,1", "name": "iPhone 7", "chip": "A10", "internal": "d10ap", "explain": "7 · session activation"},
    {"identifier": "iPhone10,1", "name": "iPhone 8", "chip": "A11", "internal": "d20ap", "explain": "8 · session activation"},
    {"identifier": "iPhone10,3", "name": "iPhone X", "chip": "A11", "internal": "d22ap", "explain": "X · FaceID · session activation"},
    {"identifier": "iPhone11,8", "name": "iPhone XR", "chip": "A12", "internal": "n841ap", "explain": "XR · session activation"},
    {"identifier": "iPhone12,1", "name": "iPhone 11", "chip": "A13", "internal": "n104ap", "explain": "11 · session activation"},
    {"identifier": "iPhone13,2", "name": "iPhone 12", "chip": "A14", "internal": "d52g", "explain": "12 · session activation"},
    {"identifier": "iPhone14,5", "name": "iPhone 13", "chip": "A15", "internal": "d291ap", "explain": "13 · session activation"},
    {"identifier": "iPhone15,2", "name": "iPhone 14 Pro", "chip": "A16", "internal": "d74ap", "explain": "14 Pro · session activation"},
]
CURATED_SET = {d["identifier"] for d in CURATED_DEVICES}
FIRMWARE_CACHE = pathlib.Path(os.environ.get("FIRMWARE_CACHE_PATH", str(pathlib.Path(__file__).resolve().parent / "logs" / "firmware_cache.json")))
FIRMWARE_TTL = 3600
IPSW_API = "https://api.ipsw.me/v4/device/{productType}"
PRODUCT_RE = re.compile(r"^iPhone\d+,\d+$")


# --- Structured JSON logging (P1-3) via python-json-logger if available else fallback ---
class RequestIdFilter(logging.Filter):
    def filter(self, record):
        try:
            from flask import has_request_context
            if has_request_context():
                record.request_id = getattr(g, 'request_id', '-')
                try:
                    record.remote_addr = request.remote_addr or '-'
                except Exception:
                    record.remote_addr = '-'
            else:
                record.request_id = getattr(record, 'request_id', '-')
                if not hasattr(record, 'request_id') or record.request_id is None:
                    record.request_id = '-'
                record.remote_addr = getattr(record, 'remote_addr', '-')
                if not hasattr(record, 'remote_addr') or record.remote_addr is None:
                    record.remote_addr = '-'
        except Exception:
            record.request_id = '-'
            record.remote_addr = '-'
        return True

# Configure root logger with JSON if available
_logger_handler = None
_json_available = False
try:
    from pythonjsonlogger import jsonlogger  # type: ignore
    _json_available = True
    _logger_handler = logging.StreamHandler()
    _json_formatter = jsonlogger.JsonFormatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s %(request_id)s %(remote_addr)s",
        rename_fields={"levelname": "level", "asctime": "timestamp"},
    )
    _logger_handler.setFormatter(_json_formatter)
    _logger_handler.addFilter(RequestIdFilter())
    # Ensure we don't duplicate handlers
    root_logger = logging.getLogger()
    # clear existing handlers added by basicConfig if any
    if root_logger.handlers:
        for h in list(root_logger.handlers):
            root_logger.removeHandler(h)
    root_logger.addHandler(_logger_handler)
    root_logger.setLevel(logging.INFO)
    # Also add to werkzeug loggers if needed
    logging.getLogger("werkzeug").addHandler(_logger_handler)
except Exception:
    # Fallback: plain text with request_id
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s')
    # Attach filter to all handlers
    _fallback_filter = RequestIdFilter()
    for h in logging.getLogger().handlers:
        h.addFilter(_fallback_filter)

logger = logging.getLogger(__name__)
# Ensure logger has filter even in JSON path (already on handler, also add to logger)
logger.addFilter(RequestIdFilter())

ALBERT_USER_AGENT = "iOS Device Activator (MobileActivation-592.103.2)"

# ---------------------------------------------------------------------------
# SQLite persistence for activation_records (P1-4)
# DB at logs/activations.db with table activations(id INTEGER PRIMARY KEY, udid TEXT, serial TEXT, created_at TEXT, record TEXT)
# Helper log_activation()
# ---------------------------------------------------------------------------
DB_PATH = pathlib.Path(os.environ.get("ALBERT_DB_PATH", "")) if os.environ.get("ALBERT_DB_PATH") else pathlib.Path(__file__).resolve().parent / "logs" / "activations.db"

def _init_db():
    try:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(DB_PATH), timeout=30) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS activations(
                id INTEGER PRIMARY KEY,
                udid TEXT,
                serial TEXT,
                created_at TEXT,
                record TEXT,
                producttype TEXT
            )""")
            # migrate old DBs without producttype
            try:
                cur = conn.execute("PRAGMA table_info(activations)")
                cols = [r[1] for r in cur.fetchall()]
                if "producttype" not in cols:
                    conn.execute("ALTER TABLE activations ADD COLUMN producttype TEXT")
            except Exception:
                pass
            conn.commit()
            try:
                conn.execute("PRAGMA journal_mode=WAL;")
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"Failed to init activation DB {DB_PATH}: {e}")

_init_db()

_log_counter = 0
def log_activation(udid: str, serial: str, record, producttype: str = ""):
    """Persist activation record to SQLite. Accepts dict or str record."""
    try:
        _init_db()
        created_at = datetime.now(timezone.utc).isoformat()
        if isinstance(record, dict):
            record_text = json.dumps(record, ensure_ascii=False)
        else:
            record_text = str(record)
        with sqlite3.connect(str(DB_PATH), timeout=30) as conn:
            conn.execute(
                "INSERT INTO activations (udid, serial, created_at, record, producttype) VALUES (?, ?, ?, ?, ?)",
                (udid or "", serial or "", created_at, record_text, producttype or ""),
            )
            conn.commit()
        try:
            albert_activation_total.inc()
        except Exception:
            pass
        # WAL checkpoint + retention every 100 writes (P2 polish)
        try:
            global _log_counter
            _log_counter += 1
            if _log_counter % 100 == 0:
                with sqlite3.connect(str(DB_PATH), timeout=30) as c:
                    c.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                    # retention: keep last 10000 rows, delete older >30d
                    c.execute("DELETE FROM activations WHERE id NOT IN (SELECT id FROM activations ORDER BY id DESC LIMIT 10000)")
                    c.execute("DELETE FROM activations WHERE created_at < datetime('now', '-30 days')")
                    c.commit()
        except Exception:
            pass
    except Exception as e:
        logger.warning(f"Failed to log activation udid={udid}: {e}")
        try:
            albert_activation_failures_total.inc()
        except Exception:
            pass


def _scan_local_ipsw() -> list:
    try:
        root = pathlib.Path(__file__).resolve().parent
        files = list(root.glob("*.ipsw")) + list((root / "..").glob("*.ipsw"))
        # also check cwd
        return [p for p in files if p.exists()]
    except Exception:
        return []

def _local_overlay(productType: str) -> list:
    try:
        return [p.name for p in _scan_local_ipsw() if productType in p.name]
    except Exception:
        return []

def _fetch_ipsw(productType: str) -> dict:
    now = time.time()
    cached = None
    fetchedAt = None
    try:
        if FIRMWARE_CACHE.exists():
            data = json.loads(FIRMWARE_CACHE.read_text())
            entry = data.get(productType)
            if entry and isinstance(entry, dict) and "fetchedAt" in entry and "data" in entry:
                fetchedAt = entry["fetchedAt"]
                age = now - fetchedAt
                if age < FIRMWARE_TTL:
                    return {"firmwares": entry["data"].get("firmwares", []), "cached": True, "fetchedAt": fetchedAt, "stale": False, "data": entry["data"]}
                else:
                    cached = entry["data"]
    except Exception:
        pass
    # live fetch
    try:
        url = IPSW_API.format(productType=productType)
        r = requests.get(url, timeout=8, headers={"User-Agent": "Albert-firmware/1.0"})
        r.raise_for_status()
        j = r.json()
        firmwares = j.get("firmwares", [])
        # cache write
        try:
            FIRMWARE_CACHE.parent.mkdir(parents=True, exist_ok=True)
            cache = {}
            if FIRMWARE_CACHE.exists():
                try:
                    cache = json.loads(FIRMWARE_CACHE.read_text())
                except Exception:
                    cache = {}
            cache[productType] = {"fetchedAt": now, "data": j}
            FIRMWARE_CACHE.write_text(json.dumps(cache))
            try:
                FIRMWARE_CACHE.chmod(0o600)
            except Exception:
                pass
        except Exception:
            pass
        return {"firmwares": firmwares, "cached": False, "fetchedAt": now, "stale": False, "data": j}
    except Exception as e:
        # fallback to cached if exists
        if cached is not None or (fetchedAt is not None and cached is None):
            # try return stale cached
            try:
                if FIRMWARE_CACHE.exists():
                    data = json.loads(FIRMWARE_CACHE.read_text())
                    entry = data.get(productType)
                    if entry:
                        return {"firmwares": entry["data"].get("firmwares", []), "cached": True, "fetchedAt": entry["fetchedAt"], "stale": True, "warning": str(e), "data": entry["data"]}
            except Exception:
                pass
        raise

# ---------------------------------------------------------------------------
# Prometheus metrics (P1-3) — use prometheus_client if available else stub
# Expose albert_up, albert_activation_total, albert_activation_failures_total
# ---------------------------------------------------------------------------
HAS_PROM = False
try:
    from prometheus_client import Counter as _PromCounter, Gauge as _PromGauge, generate_latest as _generate_latest, CONTENT_TYPE_LATEST as _CONTENT_TYPE_LATEST, REGISTRY as _REGISTRY
    HAS_PROM = True
    CONTENT_TYPE_LATEST = _CONTENT_TYPE_LATEST
    generate_latest = _generate_latest
    Counter = _PromCounter
    Gauge = _PromGauge
    REGISTRY = _REGISTRY
except ImportError:
    HAS_PROM = False
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
    class _StubCounter:
        def __init__(self, name, documentation, **kw):
            self._name = name
            self._value = 0.0
        def inc(self, amount=1):
            self._value += amount
        def _get(self):
            return self._value
    class _StubGauge:
        def __init__(self, name, documentation, **kw):
            self._name = name
            self._value = 0.0
        def set(self, v):
            self._value = float(v)
        def inc(self, amount=1):
            self._value += amount
        def dec(self, amount=1):
            self._value -= amount
        def _get(self):
            return self._value
    Counter = _StubCounter  # type: ignore
    Gauge = _StubGauge  # type: ignore
    def generate_latest():  # type: ignore
        up_v = albert_up._get() if 'albert_up' in globals() else 0  # type: ignore
        total_v = albert_activation_total._get() if 'albert_activation_total' in globals() else 0  # type: ignore
        fail_v = albert_activation_failures_total._get() if 'albert_activation_failures_total' in globals() else 0  # type: ignore
        lines = []
        lines.append("# HELP albert_up Albert server up status")
        lines.append("# TYPE albert_up gauge")
        lines.append(f"albert_up {up_v}")
        lines.append("# HELP albert_activation_total Total activations")
        lines.append("# TYPE albert_activation_total counter")
        lines.append(f"albert_activation_total {total_v}")
        lines.append("# HELP albert_activation_failures_total Total activation failures")
        lines.append("# TYPE albert_activation_failures_total counter")
        lines.append(f"albert_activation_failures_total {fail_v}")
        return "\n".join(lines).encode() + b"\n"
    REGISTRY = None  # type: ignore

try:
    if HAS_PROM and REGISTRY is not None and "albert_up" in getattr(REGISTRY, "_names_to_collectors", {}):
        albert_up = REGISTRY._names_to_collectors["albert_up"]
        albert_activation_total = REGISTRY._names_to_collectors["albert_activation_total"]
        albert_activation_failures_total = REGISTRY._names_to_collectors["albert_activation_failures_total"]
    else:
        albert_up = Gauge("albert_up", "Albert server up status")
    try:
        from prometheus_client import Histogram as _Hist
        albert_request_latency = _Hist("albert_request_latency_seconds", "Request latency", ["endpoint"])
    except Exception:
        albert_request_latency = None
        albert_activation_total = Counter("albert_activation_total", "Total activations")
        albert_activation_failures_total = Counter("albert_activation_failures_total", "Total activation failures")
        try:
            albert_up.set(1)
        except Exception:
            pass
except Exception as e:
    logger.warning(f"Metrics init fallback: {e}")
    if 'albert_up' not in globals():
        albert_up = Gauge("albert_up", "Albert server up status")
    try:
        from prometheus_client import Histogram as _Hist
        albert_request_latency = _Hist("albert_request_latency_seconds", "Request latency", ["endpoint"])
    except Exception:
        albert_request_latency = None  # type: ignore
        albert_activation_total = Counter("albert_activation_total", "Total activations")  # type: ignore
        albert_activation_failures_total = Counter("albert_activation_failures_total", "Total activation failures")  # type: ignore

# --- OpenTelemetry tracing (optional, OTEL_EXPORTER_OTLP_ENDPOINT) ---
# Uses optional opentelemetry import; enabled only when OTEL_EXPORTER_OTLP_ENDPOINT env is set.
# Provides Tracer for deviceActivation with span attributes: udid (redacted) and productType.
from contextlib import nullcontext
OTEL_EXPORTER_ENDPOINT = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
tracer = None
try:
    if OTEL_EXPORTER_ENDPOINT:
        from opentelemetry import trace as _otel_trace
        from opentelemetry.sdk.trace import TracerProvider as _OtelTracerProvider
        from opentelemetry.sdk.resources import Resource as _OtelResource
        from opentelemetry.sdk.trace.export import BatchSpanProcessor as _OtelBatchProcessor
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as _OtelExporter
        _otel_resource = _OtelResource.create({"service.name": os.environ.get("OTEL_SERVICE_NAME", "albert-server")})
        _otel_provider = _OtelTracerProvider(resource=_otel_resource)
        _otel_exporter = _OtelExporter(endpoint=OTEL_EXPORTER_ENDPOINT)
        _otel_processor = _OtelBatchProcessor(_otel_exporter)
        _otel_provider.add_span_processor(_otel_processor)
        try:
            _otel_trace.set_tracer_provider(_otel_provider)
        except Exception:
            pass
        tracer = _otel_trace.get_tracer("albert_server")
        logger.info(f"OpenTelemetry tracing enabled endpoint={OTEL_EXPORTER_ENDPOINT}")
except Exception as _otel_e:
    logger.warning(f"OpenTelemetry init failed (optional): {_otel_e}")
    tracer = None


def _set_otel_span_attributes(udid_val, activation_info):
    """Set span attributes for deviceActivation: udid redacted and productType."""
    if tracer is None:
        return
    try:
        from opentelemetry import trace as _trace_mod
        span = _trace_mod.get_current_span()
        if span is None:
            return
        if not hasattr(span, "set_attribute"):
            return
        redacted = _redact_udid(udid_val) if udid_val else "-"
        try:
            span.set_attribute("udid", redacted)
            span.set_attribute("udid.redacted", redacted)
            span.set_attribute("device.udid", redacted)
        except Exception:
            pass
        prod = ""
        try:
            if isinstance(activation_info, dict):
                prod = activation_info.get("ProductType") or activation_info.get("productType") or activation_info.get("Producttype") or ""
        except Exception:
            prod = ""
        if prod:
            try:
                span.set_attribute("productType", str(prod))
                span.set_attribute("product_type", str(prod))
                span.set_attribute("device.productType", str(prod))
            except Exception:
                pass
        try:
            span.set_attribute("http.route", "/deviceservices/deviceActivation")
        except Exception:
            pass
    except Exception:
        pass


def _inc_failure():
    try:
        albert_activation_failures_total.inc()
    except Exception:
        pass

# --- Rate limit: per-IP 100/min + per-UDID 10/min, optionally distributed via Redis ---
# Fallback to in-memory prune logic when redis unavailable or REDIS_URL not set.
try:
    import redis as _redis_mod  # type: ignore
    _REDIS_AVAILABLE = True
except ImportError:
    _redis_mod = None  # type: ignore
    _REDIS_AVAILABLE = False

_RATE_LIMIT_MAX = 100
_RATE_LIMIT_WINDOW = 60  # seconds
_RATE_LIMIT_PER_UDID_DEFAULT = 10
_rate_limit_store: dict = {}
_rate_limit_udid_store: dict = {}
_rate_limit_lock = threading.Lock()
_redis_client = None
_redis_client_url = None
_redis_client_lock = threading.Lock()

def _get_per_udid_limit() -> int:
    try:
        return int(os.environ.get("ALBERT_RATE_LIMIT_PER_UDID", str(_RATE_LIMIT_PER_UDID_DEFAULT)))
    except Exception:
        return _RATE_LIMIT_PER_UDID_DEFAULT

def _get_redis_url() -> str:
    return (os.environ.get("ALBERT_REDIS_URL") or os.environ.get("REDIS_URL") or "").strip()

def _get_redis_client():
    if not _REDIS_AVAILABLE or _redis_mod is None:
        return None
    url = _get_redis_url()
    if not url:
        return None
    global _redis_client, _redis_client_url
    with _redis_client_lock:
        if _redis_client is not None and _redis_client_url == url:
            try:
                _redis_client.ping()
                return _redis_client
            except Exception:
                _redis_client = None
                _redis_client_url = None
        if _redis_client_url is not None and _redis_client_url != url:
            try:
                _redis_client = None
            except Exception:
                pass
            _redis_client_url = None
        try:
            client = _redis_mod.from_url(url, socket_connect_timeout=2, socket_timeout=2, decode_responses=True)
            client.ping()
            _redis_client = client
            _redis_client_url = url
            return client
        except Exception as e:
            logger.debug(f"Redis connect failed: {e}")
            return None

def _redis_incr_with_expire(key: str, limit: int, window: int):
    client = _get_redis_client()
    if client is None:
        return None
    try:
        try:
            count = client.incr(key)
        except Exception as e:
            if "unknown command" in str(e).lower() or "noperm" in str(e).lower() or "incr" in str(e).lower():
                try:
                    count = client.incrby(key, 1)
                except Exception as e2:
                    logger.debug(f"Redis incrby failed for {key}: {e2}")
                    return None
            else:
                logger.debug(f"Redis INCR failed for {key}: {e}")
                return None
        if count == 1:
            try:
                client.expire(key, window)
            except Exception:
                pass
        remaining = max(0, limit - count)
        exceeded = count > limit
        return (exceeded, count, remaining)
    except Exception as e:
        logger.debug(f"Redis rate limit failed for {key}: {e}")
        return None

def _set_rate_remaining(remaining_ip=None, remaining_udid=None, remaining=None):
    try:
        from flask import g, has_request_context
        if not has_request_context():
            return
        if remaining is not None:
            g.rate_limit_remaining = remaining
        elif remaining_ip is not None and remaining_udid is not None:
            g.rate_limit_remaining = min(remaining_ip, remaining_udid)
            g.rate_limit_remaining_ip = remaining_ip
            g.rate_limit_remaining_udid = remaining_udid
        elif remaining_ip is not None:
            g.rate_limit_remaining = remaining_ip
            g.rate_limit_remaining_ip = remaining_ip
            if remaining_udid is not None:
                g.rate_limit_remaining_udid = remaining_udid
        elif remaining_udid is not None:
            g.rate_limit_remaining = remaining_udid
            g.rate_limit_remaining_udid = remaining_udid
        if remaining_ip is not None:
            g.rate_limit_remaining_ip = remaining_ip
        if remaining_udid is not None:
            g.rate_limit_remaining_udid = remaining_udid
    except Exception:
        pass

def _check_rate_limit(ip: str, udid: str | None = None) -> bool:
    """Return True if rate limit exceeded for ip or udid.
    Optionally distributed via Redis INCR+EXPIRE when ALBERT_REDIS_URL set (100/min per IP + 10/min per UDID),
    else in-memory prune logic (100/min per IP + 10/min per UDID)."""
    per_udid = _get_per_udid_limit()
    udid_norm = udid.strip() if isinstance(udid, str) and udid.strip() else None
    client = _get_redis_client()
    if client is not None:
        ip_key = f"albert:ratelimit:ip:{ip}"
        res_ip = _redis_incr_with_expire(ip_key, _RATE_LIMIT_MAX, _RATE_LIMIT_WINDOW)
        if res_ip is None:
            logger.warning(f"Redis rate limit degraded to in-memory for ip={ip} — check ALBERT_REDIS_URL: {os.environ.get('ALBERT_REDIS_URL','')[:50]}", extra={"request_id": getattr(g, 'request_id', '-')})
        else:
            exceeded_ip, count_ip, remaining_ip = res_ip
            remaining_udid = None
            exceeded_udid = False
            if udid_norm:
                udid_key = f"albert:ratelimit:udid:{udid_norm}"
                res_udid = _redis_incr_with_expire(udid_key, per_udid, _RATE_LIMIT_WINDOW)
                if res_udid is None:
                    logger.warning(f"Redis UDID rate limit degraded to in-memory for udid={udid_norm[:8] if udid_norm else 'none'}...", extra={"request_id": getattr(g, 'request_id', '-')})
                    now = time.time()
                    with _rate_limit_lock:
                        ul = _rate_limit_udid_store.get(udid_norm, [])
                        ul = [t for t in ul if now - t < _RATE_LIMIT_WINDOW]
                        if not ul and udid_norm in _rate_limit_udid_store:
                            _rate_limit_udid_store.pop(udid_norm, None)
                        if len(ul) >= per_udid:
                            _rate_limit_udid_store[udid_norm] = ul
                            _set_rate_remaining(remaining_ip=remaining_ip, remaining_udid=0, remaining=0)
                            return True
                        ul.append(now)
                        _rate_limit_udid_store[udid_norm] = ul
                        remaining_udid = max(0, per_udid - len(ul))
                else:
                    exceeded_udid, count_udid, remaining_udid = res_udid
            exceeded = exceeded_ip or exceeded_udid
            if udid_norm and remaining_udid is not None:
                rem = min(remaining_ip, remaining_udid)
                _set_rate_remaining(remaining_ip=remaining_ip, remaining_udid=remaining_udid, remaining=rem if not exceeded else 0)
                if exceeded:
                    _set_rate_remaining(remaining=0, remaining_ip=remaining_ip if not exceeded_ip else 0, remaining_udid=remaining_udid if not exceeded_udid else 0)
            else:
                _set_rate_remaining(remaining_ip=remaining_ip, remaining=0 if exceeded_ip else remaining_ip)
            return exceeded
    now = time.time()
    with _rate_limit_lock:
        if len(_rate_limit_store) > 1000:
            oldest = sorted(_rate_limit_store.items(), key=lambda kv: kv[1][-1] if kv[1] else 0)[:100]
            for k, _ in oldest:
                _rate_limit_store.pop(k, None)
        if len(_rate_limit_udid_store) > 1000:
            oldest_u = sorted(_rate_limit_udid_store.items(), key=lambda kv: kv[1][-1] if kv[1] else 0)[:100]
            for k, _ in oldest_u:
                _rate_limit_udid_store.pop(k, None)
        lst = _rate_limit_store.get(ip, [])
        lst = [t for t in lst if now - t < _RATE_LIMIT_WINDOW]
        if not lst and ip in _rate_limit_store:
            _rate_limit_store.pop(ip, None)
            lst = []
        if len(lst) >= _RATE_LIMIT_MAX:
            _rate_limit_store[ip] = lst
            _set_rate_remaining(remaining_ip=0, remaining=0)
            return True
        udid_lst = []
        if udid_norm:
            udid_lst = _rate_limit_udid_store.get(udid_norm, [])
            udid_lst = [t for t in udid_lst if now - t < _RATE_LIMIT_WINDOW]
            if not udid_lst and udid_norm in _rate_limit_udid_store:
                _rate_limit_udid_store.pop(udid_norm, None)
                udid_lst = []
            if len(udid_lst) >= per_udid:
                _rate_limit_store[ip] = lst
                _rate_limit_udid_store[udid_norm] = udid_lst
                remaining_ip_tmp = max(0, _RATE_LIMIT_MAX - len(lst))
                _set_rate_remaining(remaining_ip=remaining_ip_tmp, remaining_udid=0, remaining=0)
                return True
        lst.append(now)
        _rate_limit_store[ip] = lst
        remaining_ip = max(0, _RATE_LIMIT_MAX - len(lst))
        if udid_norm:
            udid_lst.append(now)
            _rate_limit_udid_store[udid_norm] = udid_lst
            remaining_udid = max(0, per_udid - len(udid_lst))
            rem = min(remaining_ip, remaining_udid)
            _set_rate_remaining(remaining_ip=remaining_ip, remaining_udid=remaining_udid, remaining=rem)
        else:
            _set_rate_remaining(remaining_ip=remaining_ip, remaining=remaining_ip)
        return False

def _check_udid_rate_limit(udid: str) -> bool:
    """Check per-UDID limit only. Used inside activation endpoint after IP already counted."""
    per_udid = _get_per_udid_limit()
    udid_norm = udid.strip() if isinstance(udid, str) and udid.strip() else None
    if not udid_norm:
        return False
    client = _get_redis_client()
    if client is not None:
        udid_key = f"albert:ratelimit:udid:{udid_norm}"
        res = _redis_incr_with_expire(udid_key, per_udid, _RATE_LIMIT_WINDOW)
        if res is not None:
            exceeded, count, remaining = res
            try:
                from flask import g
                ip_rem = getattr(g, 'rate_limit_remaining_ip', _RATE_LIMIT_MAX)
                if exceeded:
                    _set_rate_remaining(remaining=0, remaining_ip=ip_rem, remaining_udid=0)
                else:
                    rem = min(ip_rem, remaining) if isinstance(ip_rem, int) else remaining
                    _set_rate_remaining(remaining=rem, remaining_ip=ip_rem, remaining_udid=remaining)
            except Exception:
                _set_rate_remaining(remaining_udid=remaining, remaining=remaining if not exceeded else 0)
            return exceeded
    now = time.time()
    with _rate_limit_lock:
        if len(_rate_limit_udid_store) > 1000:
            oldest_u = sorted(_rate_limit_udid_store.items(), key=lambda kv: kv[1][-1] if kv[1] else 0)[:100]
            for k, _ in oldest_u:
                _rate_limit_udid_store.pop(k, None)
        lst = _rate_limit_udid_store.get(udid_norm, [])
        lst = [t for t in lst if now - t < _RATE_LIMIT_WINDOW]
        if not lst and udid_norm in _rate_limit_udid_store:
            _rate_limit_udid_store.pop(udid_norm, None)
            lst = []
        if len(lst) >= per_udid:
            _rate_limit_udid_store[udid_norm] = lst
            try:
                from flask import g
                ip_rem = getattr(g, 'rate_limit_remaining_ip', _RATE_LIMIT_MAX)
                _set_rate_remaining(remaining=0, remaining_ip=ip_rem, remaining_udid=0)
            except Exception:
                pass
            return True
        lst.append(now)
        _rate_limit_udid_store[udid_norm] = lst
        remaining_udid = max(0, per_udid - len(lst))
        try:
            from flask import g
            ip_rem = getattr(g, 'rate_limit_remaining_ip', _RATE_LIMIT_MAX)
            rem = min(ip_rem, remaining_udid) if isinstance(ip_rem, int) else remaining_udid
            _set_rate_remaining(remaining=rem, remaining_ip=ip_rem, remaining_udid=remaining_udid)
        except Exception:
            _set_rate_remaining(remaining_udid=remaining_udid, remaining=remaining_udid)
        return False

def _reset_rate_limit():
    """For tests: clear rate limit store (both IP and UDID) and redis keys if configured."""
    with _rate_limit_lock:
        _rate_limit_store.clear()
        _rate_limit_udid_store.clear()
    client = _get_redis_client()
    if client is not None:
        try:
            try:
                for key in client.scan_iter(match="albert:ratelimit:*"):
                    try:
                        client.delete(key)
                    except Exception:
                        pass
            except Exception:
                try:
                    keys = client.keys("albert:ratelimit:*")
                    if keys:
                        client.delete(*keys)
                except Exception:
                    pass
        except Exception:
            pass
    try:
        from flask import g, has_request_context
        if has_request_context():
            for attr in ["rate_limit_remaining", "rate_limit_remaining_ip", "rate_limit_remaining_udid"]:
                if hasattr(g, attr):
                    try:
                        delattr(g, attr)
                    except Exception:
                        pass
    except Exception:
        pass

def _redact_udid(u):
    s=str(u) if u else ""
    return s[:4]+"..."+s[-4:] if len(s)>8 else "..."+s[-2:] if s else "-"

# --- Input validation (P2) ---
_IMEI_RE = re.compile(r"^\d{15}$")
_UDID_40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_UDID_25_RE = re.compile(r"^00008020-[0-9a-fA-F]{16}$")
_SERIAL_RE = re.compile(r"^[A-Za-z0-9]+$")

def _validate_imei(v) -> bool:
    if v is None or v == "":
        return True
    return bool(_IMEI_RE.fullmatch(str(v).strip()))

def _validate_udid(v) -> bool:
    if v is None or v == "":
        return True
    s = str(v).strip()
    if _UDID_40_RE.fullmatch(s):
        return True
    if _UDID_25_RE.fullmatch(s):
        return True
    return False

def _validate_serial(v) -> bool:
    if v is None or v == "":
        return True
    s = str(v).strip()
    return bool(_SERIAL_RE.fullmatch(s))

# --- Request ID middleware (P1-3) + OPTIONS handling (P2) + rate limiting ---

@app.before_request
def before_request_hardening():
    # Attach request_id (X-Request-ID uuid, attach to g and logs)
    rid = request.headers.get("X-Request-ID")
    if not rid or not rid.strip():
        rid = str(uuid.uuid4())
    g.request_id = rid
    g.request_start = time.time()
    # OPTIONS handler for /deviceservices/* returning 204 (P2 CORS)
    # Flask will route OPTIONS via this early return; ensures 204 without CORS needed
    if request.method == "OPTIONS" and request.path.startswith("/deviceservices"):
        resp = Response(status=204)
        resp.headers["X-Request-ID"] = g.request_id
        resp.headers["Allow"] = "GET, POST, OPTIONS"
        # No CORS headers needed (device is not browser) but OPTIONS ok
        return resp
    # Also handle legacy path OPTIONS similarly
    if request.method == "OPTIONS" and request.path.startswith("/WebObjects"):
        resp = Response(status=204)
        resp.headers["X-Request-ID"] = g.request_id
        resp.headers["Allow"] = "GET, POST, OPTIONS"
        return resp
    # mTLS toggle for proxy→Albert: if ALBERT_MTLS_CA is set, require client cert on protected endpoints
    # else warn (ALBERT_MTLS_CA not set — unauthenticated). See _get_mtls_ca() / _log_mtls_status().
    mtls_ca = _get_mtls_ca()
    if mtls_ca and (request.path.startswith("/deviceservices") or request.path.startswith("/WebObjects")):
        # Check for client cert evidence: proxy should forward X-Client-Cert or gunicorn sets SSL_CLIENT_VERIFY
        has_cert = False
        if request.headers.get("X-Client-Cert") or request.headers.get("X-Forwarded-Client-Cert") or request.headers.get("X-SSL-Client-Cert"):
            has_cert = True
        if request.environ.get("SSL_CLIENT_VERIFY") == "SUCCESS" or request.environ.get("SSL_CLIENT_S_DN") or request.environ.get("peercert"):
            has_cert = True
        # also allow explicit header from mitmproxy when it presents client cert
        if request.headers.get("X-Forwarded-By") == "firmware_restore_proxy" and request.headers.get("X-Client-Cert"):
            has_cert = True
        if not has_cert:
            logger.warning(f"mTLS required but no client cert for {request.path} from {request.remote_addr}", extra={"request_id": g.request_id, "remote_addr": request.remote_addr or '-'})
            resp = jsonify({"error": "client certificate required", "request_id": g.request_id})
            return resp, 401
    elif not mtls_ca and (request.path.startswith("/deviceservices") or request.path.startswith("/WebObjects")):
        # Warn once per process that mTLS is disabled (rate-limited via logger level)
        pass  # startup already warned; per-request warn would be noisy

    # Per-IP (+ per-UDID via activation payload) rate limit — 100/min per IP + 10/min per UDID
    # Optionally distributed via Redis INCR+EXPIRE when ALBERT_REDIS_URL set, else in-memory prune logic
    if request.path.startswith("/deviceservices") or request.path.startswith("/WebObjects"):
        ip = request.remote_addr or "unknown"
        if _check_rate_limit(ip):
            logger.warning(f"Rate limit exceeded for {ip}", extra={"request_id": g.request_id, "remote_addr": ip})
            resp = jsonify({"error": "rate limit exceeded", "request_id": g.request_id})
            try:
                rem = getattr(g, 'rate_limit_remaining', 0)
                resp.headers["X-RateLimit-Remaining"] = str(rem)
            except Exception:
                resp.headers["X-RateLimit-Remaining"] = "0"
            return resp, 429

@app.after_request
def after_request_add_id(response):
    rid = getattr(g, "request_id", None)
    if rid:
        response.headers["X-Request-ID"] = rid
    # X-RateLimit-Remaining header (100/min IP, 10/min UDID) — adds for activation endpoints
    try:
        rem = getattr(g, 'rate_limit_remaining', None)
        if rem is not None:
            response.headers["X-RateLimit-Remaining"] = str(rem)
        elif getattr(g, 'rate_limit_remaining_ip', None) is not None:
            response.headers["X-RateLimit-Remaining"] = str(g.rate_limit_remaining_ip)
    except Exception:
        pass
    # latency histogram (P2 polish)
    try:
        if 'albert_request_latency' in globals() and albert_request_latency is not None and hasattr(g, 'request_start'):
            albert_request_latency.labels(endpoint=request.path).observe(time.time() - g.request_start)
    except Exception:
        pass
    return response

# Explicit OPTIONS route for /deviceservices/* (ensures Flask url_map covers it, returns 204)
@app.route('/deviceservices/<path:subpath>', methods=['OPTIONS'])
def handle_deviceservices_options(subpath):
    # before_request already handles, but keep as fallback for strict routing
    resp = Response(status=204)
    resp.headers["Allow"] = "GET, POST, OPTIONS"
    return resp

@app.route('/WebObjects/ALUnbrick.woa/wa/<path:subpath>', methods=['OPTIONS'])
def handle_legacy_options(subpath):
    resp = Response(status=204)
    resp.headers["Allow"] = "GET, POST, OPTIONS"
    return resp

class AlbertServer:
    def __init__(self):
        # Persist FairPlay key across restarts (P0-1)
        key_path = pathlib.Path(FAIRPLAY_KEY_PATH) if 'FAIRPLAY_KEY_PATH' in globals() else pathlib.Path("certs/fairplay.key")
        cert_path = pathlib.Path(FAIRPLAY_CERT_PATH) if 'FAIRPLAY_CERT_PATH' in globals() else pathlib.Path("certs/fairplay.crt")
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            try:
                pem = key_path.read_bytes()
                self.fairplay_private_key = serialization.load_pem_private_key(pem, password=None)
                # load cert chain if exists
                if cert_path.exists():
                    self.fairplay_cert_chain = cert_path.read_bytes()
                else:
                    raise FileNotFoundError
                logger.info(f"Loaded persisted FairPlay key from {key_path}")
                self.activation_records = {}
                return
            except Exception as e:
                logger.warning(f"Failed to load persisted key {key_path}: {e}, regenerating")
        self.fairplay_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "iPhone"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Apple iPhone Device CA"),
        ])
        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=5*365)
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            self.fairplay_private_key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(not_before).not_valid_after(not_after).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(self.fairplay_private_key, hashes.SHA256())
        self.fairplay_cert_chain = cert.public_bytes(serialization.Encoding.PEM)
        # Persist key+cert with 0600
        try:
            key_pem = self.fairplay_private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
            pathlib.Path(FAIRPLAY_KEY_PATH).write_bytes(key_pem)
            pathlib.Path(FAIRPLAY_KEY_PATH).chmod(0o600)
            pathlib.Path(FAIRPLAY_CERT_PATH).write_bytes(self.fairplay_cert_chain)
            pathlib.Path(FAIRPLAY_CERT_PATH).chmod(0o600)
            logger.info(f"Persisted FairPlay key to {FAIRPLAY_KEY_PATH}")
        except Exception as e:
            logger.warning(f"Failed to persist FairPlay key: {e}")
        self.activation_records = {}

    def generate_device_certificate(self, csr_pem: bytes) -> bytes:
        """Generate a device certificate from CSR. Accepts PEM or DER."""
        # Normalize: if not PEM header, try to detect base64 DER
        csr = None
        try:
            csr = x509.load_pem_x509_csr(csr_pem)
        except ValueError:
            # Try DER
            try:
                csr = x509.load_der_x509_csr(csr_pem)
            except ValueError:
                # Try base64-decoded PEM content
                try:
                    der = base64.b64decode(csr_pem, validate=False)
                    csr = x509.load_der_x509_csr(der)
                except Exception as e:
                    raise ValueError(f"Unable to parse CSR: {e}")
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "iPhone"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Apple iPhone Device CA"),
        ]))
        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=5*365)
        builder = builder.not_valid_before(not_before)
        builder = builder.not_valid_after(not_after)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(csr.public_key())
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            content_commitment=False, encipher_only=False, decipher_only=False), critical=True)
        builder = builder.add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        cert = builder.sign(private_key=self.fairplay_private_key, algorithm=hashes.SHA256())
        return cert.public_bytes(serialization.Encoding.PEM)

    def _get_device_cert_request(self, activation_info: dict) -> bytes:
        # Support multiple key variants seen in the wild
        candidates = ["DeviceCertRequest", "DeviceCertificateRequest", "DeviceCertificateSigningRequest", "CSR"]
        for k in candidates:
            v = activation_info.get(k)
            if v is None:
                continue
            if isinstance(v, str):
                # may be base64 or pem string
                # try base64 decode if looks like base64 without headers
                if "-----BEGIN" not in v:
                    try:
                        decoded = base64.b64decode(v, validate=False)
                        # if decoded looks like PEM/DER, return decoded; otherwise return v encoded
                        if b"-----BEGIN" in decoded or len(decoded) > 20:
                            return decoded
                    except Exception:
                        pass
                return v.encode()
            if isinstance(v, bytes):
                return v
        return b""

    def sign_activation_info(self, activation_info: bytes) -> bytes:
        # SHA1 is required by Apple's activation spec for FairPlay signature (ARS = base64(SHA1(response_plist))).
        # See https://theapplewiki.com/wiki/Albert and Apple MobileActivation (MobileActivation-592.103.2) — Apple-spec, not for general hashing.
        # Bandit B303/B324 is suppressed here because SHA1 is mandated by the Apple protocol; fallback DeviceCertificate uses SHA256.
        signature = self.fairplay_private_key.sign(activation_info, padding.PKCS1v15(), hashes.SHA1())  # nosec B303/B324
        return signature

    def create_activation_record(self, activation_info: dict, session_mode: bool = False) -> dict:
        """Create a valid activation record response. Never returns bytes."""
        device_class = activation_info.get("DeviceClass", "iPhone")
        activation_key = "iphone-activation" if device_class == "iPhone" else "device-activation"
        account_token = {
            "InternationalMobileEquipmentIdentity": activation_info.get("IMEI", activation_info.get("InternationalMobileEquipmentIdentity", "")),
            "InternationalMobileSubscriberIdentity": activation_info.get("IMSI", activation_info.get("InternationalMobileSubscriberIdentity", "")),
            "IntegratedCircuitCardIdentity": activation_info.get("ICCID", activation_info.get("IntegratedCircuitCardIdentity", "")),
            "ActivationRandomness": activation_info.get("ActivationRandomness", str(uuid.uuid4())),
            "UniqueDeviceID": activation_info.get("UniqueDeviceID", str(uuid.uuid4())),
            "ActivityURL": "https://albert.apple.com/deviceservices/activity",
            "CertificateURL": "https://albert.apple.com/deviceservices/certifyMe",
            "PhoneNumberNotificationURL": "https://albert.apple.com/WebObjects/ALUnbrick.woa/wa/phoneHome",
            "WildcardTicket": base64.b64encode(b"wildcard_ticket_placeholder").decode()
        }
        account_token_plist = plistlib.dumps(account_token)
        account_token_b64 = base64.b64encode(account_token_plist).decode()
        device_cert_request = self._get_device_cert_request(activation_info)
        device_cert_b64 = ""
        if device_cert_request and len(device_cert_request) >= 10:
            try:
                device_cert = self.generate_device_certificate(device_cert_request)
                device_cert_b64 = base64.b64encode(device_cert).decode()
            except Exception as e:
                logger.warning(f"Failed to generate device certificate: {e}, using placeholder")
                # Fallback self-signed device cert placeholder: generate a new key and self-sign
                try:
                    fallback_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, activation_info.get("UniqueDeviceID", "device"))])
                    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(
                        x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."), x509.NameAttribute(NameOID.COMMON_NAME, "Apple iPhone Device CA")])
                    ).public_key(fallback_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)).not_valid_after(datetime.now(timezone.utc)+timedelta(days=365)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).sign(self.fairplay_private_key, hashes.SHA256())
                    device_cert_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode()
                except Exception as e2:
                    logger.warning(f"Fallback cert also failed: {e2}")
                    device_cert_b64 = base64.b64encode(b"placeholder-device-cert").decode()
        else:
            logger.info("No DeviceCertRequest provided, using placeholder certificate for activation")
            # Generate placeholder cert for devices that don't send CSR (e.g. legacy or simulated)
            try:
                fallback_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, activation_info.get("UniqueDeviceID", "fallback-device"))])
                cert = x509.CertificateBuilder().subject_name(subject).issuer_name(
                    x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."), x509.NameAttribute(NameOID.COMMON_NAME, "Apple iPhone Device CA")])
                ).public_key(fallback_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)).not_valid_after(datetime.now(timezone.utc)+timedelta(days=365)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).sign(self.fairplay_private_key, hashes.SHA256())
                device_cert_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode()
            except Exception as e:
                device_cert_b64 = base64.b64encode(b"placeholder-device-cert").decode()

        fairplay_key_data = base64.b64encode(b"fairplay_key_data_placeholder").decode()
        activation_record = {
            activation_key: {
                "activation-record": {
                    "unbrick": True,
                    "AccountToken": account_token_b64,
                    "AccountTokenCertificate": base64.b64encode(b"account_token_cert_placeholder").decode(),
                    "AccountTokenSignature": base64.b64encode(self.sign_activation_info(account_token_plist)).decode(),
                    "DeviceCertificate": device_cert_b64,
                    "FairPlayKeyData": fairplay_key_data,
                    "LDActivationVersion": 2,
                    "RegulatoryInfo": base64.b64encode(b'{"manufacturingDate":null,"label":{"bis":null,"miit":{"nal":null,"labelId":null}},"countryOfOrigin":null}').decode(),
                    "ack-received": True,
                    "show-settings": True
                },
                "show-settings": True
            }
        }
        # Persist to SQLite (replaces in-memory dict persistence) + keep in-memory for compat
        try:
            udid = activation_info.get("UniqueDeviceID", "") or activation_info.get("UDID", "")
            serial = activation_info.get("SerialNumber", "") or activation_info.get("Serial", "") or activation_info.get("MLBSerialNumber", "")
            producttype = activation_info.get("ProductType", "")
            # Do not fallback to DeviceClass (which is "iPhone") — only true ProductType like iPhone11,8
            log_activation(str(udid), str(serial), activation_record, producttype=str(producttype))
            try:
                self.activation_records[str(udid) or str(uuid.uuid4())] = activation_record
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"Failed to persist activation record: {e}")
            _inc_failure()
        return activation_record

albert = AlbertServer()
FAIRPLAY_CERT_CHAIN = albert.fairplay_cert_chain
# update metrics up state after albert init
try:
    albert_up.set(1 if FAIRPLAY_CERT_CHAIN else 0)
except Exception:
    pass
# log mTLS status at startup
try:
    _log_mtls_status()
except Exception:
    pass

@app.route('/deviceservices/drmHandshake', methods=['POST'])
def drm_handshake():
    logger.info("Received DRM handshake request")
    try:
        data = request.get_data()
        if not data:
            _inc_failure()
            return Response("Empty request", status=400)
        try:
            handshake_request = plistlib.loads(data)
        except Exception as e:
            logger.warning(f"Failed to parse handshake plist: {e}, trying base64 path")
            _inc_failure()
            return Response(f"Invalid plist: {e}", status=400)
        logger.debug(f"Handshake request keys: {list(handshake_request.keys()) if isinstance(handshake_request, dict) else type(handshake_request)}")
        response = {
            "HandshakeResponseMessage": base64.b64encode(b"handshake_response_placeholder").decode(),
            "ServerRandom": base64.b64encode(os.urandom(32)).decode(),
            "SessionID": str(uuid.uuid4()),
            "ServerCertificate": base64.b64encode(FAIRPLAY_CERT_CHAIN).decode(),
            "ServerSignature": base64.b64encode(b"server_signature_placeholder").decode(),
        }
        response_plist = plistlib.dumps(response)
        return Response(response_plist, mimetype='application/xml')
    except RequestEntityTooLarge as e:
        logger.warning(f"DRM handshake payload too large: {e}", extra={"request_id": getattr(g, 'request_id', '-'), "remote_addr": request.remote_addr or '-'})
        _inc_failure()
        return jsonify({"error": "payload too large", "limit": app.config['MAX_CONTENT_LENGTH'], "request_id": getattr(g, 'request_id', '-')}), 413
    except Exception as e:
        if getattr(e, 'code', None) == 413:
            _inc_failure()
            return jsonify({"error": "payload too large", "limit": app.config['MAX_CONTENT_LENGTH'], "request_id": getattr(g, 'request_id', '-')}), 413
        logger.error(f"DRM handshake error: {e}", exc_info=True)
        _inc_failure()
        return Response(f"Error: {str(e)}", status=500)

@app.route('/deviceservices/deviceActivation', methods=['POST','GET'])
def device_activation():
    _otel_ctx = tracer.start_as_current_span("deviceActivation") if tracer else nullcontext()
    _otel_entered = False
    _otel_span = None
    try:
        if hasattr(_otel_ctx, "__enter__"):
            _otel_span = _otel_ctx.__enter__()
            _otel_entered = True
        logger.info(f"Received device activation request: {request.method} {request.content_type} from {request.remote_addr}")
        try:
            activation_info = None
            content_type = (request.content_type or "").lower()
            # Preferred: form-encoded activation-info (most devices + libimobiledevice)
            if request.form.get("activation-info"):
                activation_info_b64 = request.form.get("activation-info", "")
                if not activation_info_b64:
                    _inc_failure()
                    return Response("Missing activation-info", status=400)
                # Handle both base64 string and raw plist bytes accidentally sent
                try:
                    # If value looks like plist xml, treat as raw
                    if activation_info_b64.strip().startswith("<?xml") or activation_info_b64.strip().startswith("bplist"):
                        activation_info = plistlib.loads(activation_info_b64.encode() if isinstance(activation_info_b64, str) else activation_info_b64)
                    else:
                        # Try base64 decode with padding fix
                        b64 = activation_info_b64.strip()
                        # Flask may have already url-decoded; add padding
                        missing_padding = len(b64) % 4
                        if missing_padding:
                            b64 += "=" * (4 - missing_padding)
                        decoded = base64.b64decode(b64, validate=False)
                        activation_info = plistlib.loads(decoded)
                except Exception as e:
                    logger.warning(f"Failed to decode form activation-info as base64 plist, trying raw: {e}")
                    try:
                        activation_info = plistlib.loads(base64.b64decode(activation_info_b64, validate=False))
                    except Exception as e2:
                        _inc_failure()
                        return Response(f"Invalid activation-info: {e2}", status=400)
            elif "application/x-apple-plist" in content_type or "application/xml" in content_type or "text/xml" in content_type:
                try:
                    activation_info = plistlib.loads(request.get_data())
                except Exception as e:
                    _inc_failure()
                    return Response(f"Invalid plist: {e}", status=400)
            elif "multipart/form-data" in content_type:
                # Flask parses multipart into form as well, but fallback to raw
                if request.form.get("activation-info"):
                    b64 = request.form.get("activation-info")
                    try:
                        activation_info = plistlib.loads(base64.b64decode(b64, validate=False))
                    except Exception as e:
                        _inc_failure()
                        return Response(f"Invalid activation-info: {e}", status=400)
                else:
                    _inc_failure()
                    return Response("Missing activation-info in multipart", status=400)
            else:
                # Fallback: try to detect activation-info in raw body or plist body
                raw = request.get_data()
                if not raw:
                    _inc_failure()
                    return Response("Missing activation-info", status=400)
                # Try plist directly
                try:
                    activation_info = plistlib.loads(raw)
                except Exception:
                    # Try form parsing from raw body
                    from urllib.parse import parse_qs
                    qs = parse_qs(raw.decode(errors='ignore'))
                    if "activation-info" in qs:
                        b64 = qs["activation-info"][0]
                        try:
                            activation_info = plistlib.loads(base64.b64decode(b64, validate=False))
                        except Exception as e:
                            _inc_failure()
                            return Response(f"Invalid activation-info: {e}", status=400)
                    else:
                        _inc_failure()
                        return Response("Unsupported content type", status=400)
            if not isinstance(activation_info, dict):
                logger.warning(f"Activation info not dict: {type(activation_info)}")
                _inc_failure()
                return Response("Invalid activation-info: expected dict", status=400)
            logger.debug(f"Activation info keys: {list(activation_info.keys())}")
            # --- Input validation for IMEI (15 digits), UDID (hex 40 or 00008020-*), Serial (alnum), reject 400 with JSON ---
            imei_val = activation_info.get("IMEI", activation_info.get("InternationalMobileEquipmentIdentity"))
            # Normalize None vs empty: retrieval fallback above may give "" if missing; treat empty as not-provided
            if imei_val == "":
                imei_val = None
            # Also handle case where IMEI key exists but alternate key fallback gave ""; check both
            if imei_val is None and "IMEI" in activation_info:
                imei_val = activation_info.get("IMEI")
                if imei_val == "":
                    imei_val = None
            udid_val = activation_info.get("UniqueDeviceID")
            if udid_val == "":
                udid_val = None
            serial_val = activation_info.get("SerialNumber")
            if serial_val == "":
                serial_val = None
            _set_otel_span_attributes(udid_val, activation_info)
            errors = []
            if imei_val is not None and not _validate_imei(imei_val):
                errors.append("Invalid IMEI: must be 15 digits")
            if udid_val is not None and not _validate_udid(udid_val):
                errors.append("Invalid UDID: must be 40 hex or 00008020-<16 hex>")
            if serial_val is not None and not _validate_serial(serial_val):
                errors.append("Invalid SerialNumber: must be alphanumeric")
            if errors:
                logger.warning(f"Validation failed: {errors} for UDID={_redact_udid(udid_val)}", extra={"request_id": getattr(g, 'request_id', '-'), "remote_addr": request.remote_addr or '-'})
                _inc_failure()
                return jsonify({"error": "validation failed", "details": errors, "request_id": getattr(g, 'request_id', '-')}), 400
            # Per-UDID rate limit 10/min (distributed via Redis INCR+EXPIRE when ALBERT_REDIS_URL set else in-memory)
            if udid_val and _check_udid_rate_limit(str(udid_val)):
                logger.warning(f"UDID rate limit exceeded for {_redact_udid(udid_val)}", extra={"request_id": getattr(g, 'request_id', '-'), "remote_addr": request.remote_addr or '-'})
                resp = jsonify({"error": "rate limit exceeded", "details": "per UDID limit 10/min", "request_id": getattr(g, 'request_id', '-')})
                try:
                    rem = getattr(g, 'rate_limit_remaining', 0)
                    resp.headers["X-RateLimit-Remaining"] = str(rem)
                except Exception:
                    resp.headers["X-RateLimit-Remaining"] = "0"
                return resp, 429
            session_mode = "FairPlaySignature" in str(activation_info) or "HandshakeRequestMessage" in str(activation_info)
            activation_record = albert.create_activation_record(activation_info, session_mode)
            if not isinstance(activation_record, dict):
                logger.error(f"create_activation_record returned non-dict: {type(activation_record)}")
                _inc_failure()
                return Response("Internal error generating activation record", status=500)
            response_plist = plistlib.dumps(activation_record)
            # SHA1 is required by Apple's activation spec for ARS header (ARS = base64(SHA1(response_plist))).
            # See https://theapplewiki.com/wiki/Albert — Apple-spec, keep SHA1 for compatibility; not for general hashing. # nosec B303/B324
            ars_hash = hashlib.sha1(response_plist).digest()  # nosec B303/B324
            ars_b64 = base64.b64encode(ars_hash).decode()
            resp = Response(response_plist, mimetype='text/xml')
            resp.headers['ARS'] = ars_b64
            resp.headers['Cache-Control'] = 'private, no-cache, no-store, must-revalidate, max-age=0'
            resp.headers['Connection'] = 'Keep-alive'
            return resp
        except RequestEntityTooLarge as e:
            logger.warning(f"Device activation payload too large: {e}", extra={"request_id": getattr(g, 'request_id', '-'), "remote_addr": request.remote_addr or '-'})
            _inc_failure()
            return jsonify({"error": "payload too large", "limit": app.config['MAX_CONTENT_LENGTH'], "request_id": getattr(g, 'request_id', '-')}), 413
        except Exception as e:
            if getattr(e, 'code', None) == 413:
                _inc_failure()
                return jsonify({"error": "payload too large", "limit": app.config['MAX_CONTENT_LENGTH'], "request_id": getattr(g, 'request_id', '-')}), 413
            logger.error(f"Device activation error: {e}", exc_info=True)
            _inc_failure()
            return Response(f"Error: {str(e)}", status=500)
    finally:
        if _otel_entered:
            try:
                _otel_ctx.__exit__(None, None, None)
            except Exception:
                pass

@app.route('/deviceservices/activity', methods=['POST','GET'])
def activity():
    logger.info("Received activity request")
    return Response(plistlib.dumps({"status": "success"}), mimetype='application/xml')

@app.route('/deviceservices/certifyMe', methods=['POST','GET'])
def certify_me():
    logger.info("Received certifyMe request")
    return Response(plistlib.dumps({"status": "success", "certificate": base64.b64encode(FAIRPLAY_CERT_CHAIN).decode()}), mimetype='application/xml')

@app.route('/WebObjects/ALUnbrick.woa/wa/deviceActivation', methods=['POST','GET'])
def legacy_device_activation():
    logger.info("Received legacy device activation request")
    return device_activation()

@app.route('/WebObjects/ALUnbrick.woa/wa/phoneHome', methods=['POST','GET'])
def phone_home():
    logger.info("Received phoneHome request")
    return Response(plistlib.dumps({"status": "success"}), mimetype='application/xml')

@app.errorhandler(413)
@app.errorhandler(RequestEntityTooLarge)
def too_large(e):
    _inc_failure()
    return jsonify({"error": "payload too large", "limit": app.config['MAX_CONTENT_LENGTH'], "request_id": getattr(g, 'request_id', '-')}), 413

@app.route('/health', methods=['GET'])
def health():
    # Liveness: does not require upstream
    return jsonify({"status": "ok", "server": "albert-local", "version": "1.1-fixed"})

@app.route('/ready', methods=['GET'])
def ready():
    # Readiness: FairPlay key and cert chain loaded + NotAfter check (warn 30d before expiry)
    ok = bool(FAIRPLAY_CERT_CHAIN and albert.fairplay_private_key)
    warning = None
    expiry_warning = False
    days_until_expiry = None
    not_after_iso = None
    try:
        # Load cert to check NotAfter (30d warning)
        crt_data = None
        try:
            p = pathlib.Path(FAIRPLAY_CERT_PATH)
            if p.exists():
                crt_data = p.read_bytes()
            else:
                crt_data = FAIRPLAY_CERT_CHAIN
        except Exception:
            crt_data = FAIRPLAY_CERT_CHAIN
        if crt_data:
            cert = x509.load_pem_x509_certificate(crt_data if b"-----BEGIN" in crt_data else FAIRPLAY_CERT_CHAIN)
            # cryptography >=42 uses not_valid_after_utc; fallback for older
            try:
                not_after = cert.not_valid_after_utc  # type: ignore
            except AttributeError:
                not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)  # type: ignore
            not_after_iso = not_after.isoformat()
            now = datetime.now(timezone.utc)
            delta = not_after - now
            # days_until_expiry may be negative if expired
            try:
                days_until_expiry = delta.days
            except Exception:
                days_until_expiry = int(delta.total_seconds() // 86400)
            if delta.total_seconds() < 30 * 24 * 3600:
                expiry_warning = True
                if delta.total_seconds() < 0:
                    warning = f"FairPlay cert expired {abs(days_until_expiry)} days ago (NotAfter {not_after_iso}) — rotate via --rotate-fairplay immediately"
                else:
                    warning = f"FairPlay cert expires in {days_until_expiry} days (NotAfter {not_after_iso}) — rotate via --rotate-fairplay within 30d"
                logger.warning(warning)
    except Exception as e:
        logger.debug(f"Cert expiry check failed: {e}")
    payload = {"status": "ready" if ok else "not-ready", "fairplay_loaded": ok}
    if not_after_iso is not None:
        payload["notAfter"] = not_after_iso
    if days_until_expiry is not None:
        payload["days_until_expiry"] = days_until_expiry
    if expiry_warning:
        payload["warning"] = warning
        payload["cert_expiry_warning"] = True
    # also include mTLS status for observability
    try:
        mtls_ca = _get_mtls_ca()
        payload["mtls"] = {"enabled": bool(mtls_ca), "ca": mtls_ca if mtls_ca else None}
        if not mtls_ca:
            payload["mtls_warning"] = "ALBERT_MTLS_CA not set — proxy→Albert mTLS disabled"
    except Exception:
        pass
    return (jsonify(payload), 200 if ok else 503)

@app.route('/metrics', methods=['GET'])
def metrics():
    # Prometheus exposition format via prometheus_client if available else stub
    if HAS_PROM:
        try:
            albert_up.set(1 if FAIRPLAY_CERT_CHAIN else 0)
        except Exception:
            pass
        return Response(generate_latest(), content_type=CONTENT_TYPE_LATEST)
    else:
        up = 1 if FAIRPLAY_CERT_CHAIN else 0
        try:
            total = int(getattr(albert_activation_total, "_value", 0))
        except Exception:
            total = 0
            try:
                with sqlite3.connect(str(DB_PATH), timeout=30) as conn:
                    cur = conn.execute("SELECT COUNT(*) FROM activations")
                    total = cur.fetchone()[0]
            except Exception:
                pass
        try:
            failures = int(getattr(albert_activation_failures_total, "_value", 0))
        except Exception:
            failures = 0
        body = (
            "# HELP albert_up Albert server up status\n"
            "# TYPE albert_up gauge\n"
            f"albert_up {up}\n"
            "# HELP albert_activation_total Total activations\n"
            "# TYPE albert_activation_total counter\n"
            f"albert_activation_total {total}\n"
            "# HELP albert_activation_failures_total Total activation failures\n"
            "# TYPE albert_activation_failures_total counter\n"
            f"albert_activation_failures_total {failures}\n"
        )
        return Response(body, mimetype='text/plain')


# ---------------------------------------------------------------------------
# Dashboard realtime status (production UI)
# ---------------------------------------------------------------------------
DASHBOARD_HTML = r'''<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<link rel="alternate icon" type="image/png" href="/static/zalive-icon.svg">
<title>zAlive — Albert — Dashboard (AdminLTE 4 Premium)</title>
<!-- AdminLTE 4 (Bootstrap 5.3) via CDN — premium base from https://github.com/topics/dashboard-template top #1 -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/css/adminlte.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
<style>
/* zAlive premium overrides — keep dark tokens + AdminLTE structure */
:root{--zalive-accent:#3b82f6;--zalive-card:#151a21;--zalive-border:#232b36}
.app-wrapper{min-height:100vh;background:#0b0f14}
.app-header{border-bottom:1px solid var(--zalive-border)}
.app-sidebar{background:#0f141b;border-right:1px solid var(--zalive-border)}
.brand-link{border-bottom:1px solid var(--zalive-border)}
.card{border:1px solid var(--zalive-border);border-radius:14px;box-shadow:0 8px 32px rgba(0,0,0,.45)}
.k{font-size:10.5px;color:#94a3b8;text-transform:uppercase;letter-spacing:.7px;font-weight:650}
.v{font-size:22px;font-weight:750;color:#f1f5f9}
.mono{font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace}
.pill{font-size:11px;padding:6px 10px;border-radius:999px;border:1px solid var(--zalive-border)}
</style>
</head>
<body class="layout-fixed-complete">
<div class="app-wrapper">
<nav class="app-header navbar navbar-expand bg-body">
<div class="container-fluid">
<ul class="navbar-nav">
<li class="nav-item"><a class="nav-link" data-lte-toggle="sidebar" href="#" role="button"><i class="bi bi-list"></i></a></li>
<li class="nav-item d-none d-md-block"><a href="/dashboard" class="nav-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:22px"></a></li>
</ul>
<ul class="navbar-nav ms-auto">
<li class="nav-item"><span id="healthPill" class="pill bg-dark">checking…</span></li>
<li class="nav-item"><span id="clock" class="pill bg-dark ms-1">--:--:--</span></li>
<li class="nav-item"><a class="nav-link" href="/firmware">Firmware</a></li>
<li class="nav-item"><a class="nav-link" href="/admin">Admin</a></li>
</ul>
</div>
</nav>
<aside class="app-sidebar sidebar-dark">
<div class="sidebar-brand"><a href="/dashboard" class="brand-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:28px"><span class="brand-text fw-light ms-2">zAlive Albert</span></a></div>
<div class="sidebar-wrapper"><nav class="mt-2">
<ul class="nav sidebar-menu flex-column" data-lte-toggle="treeview" role="menu">
<li class="nav-item"><a href="/dashboard" class="nav-link active"><i class="nav-icon bi bi-speedometer2"></i><p>Dashboard</p></a></li>
<li class="nav-item"><a href="/firmware" class="nav-link"><i class="nav-icon bi bi-hdd-stack"></i><p>Firmware <span class="badge bg-info ms-1">13</span></p></a></li>
<li class="nav-item"><a href="/admin" class="nav-link"><i class="nav-icon bi bi-shield-lock"></i><p>Admin</p></a></li>
<li class="nav-item"><a href="/api/status" class="nav-link"><i class="nav-icon bi bi-heart-pulse"></i><p>API Status</p></a></li>
<li class="nav-item"><a href="/health" class="nav-link"><i class="nav-icon bi bi-activity"></i><p>Health</p></a></li>
<li class="nav-header">LOGS</li>
<li class="nav-item"><a href="/api/logs?lines=60" class="nav-link"><i class="nav-icon bi bi-journal-text"></i><p>Logs tail</p></a></li>
</ul>
</nav></div>
</aside>
<main class="app-main">
<div class="app-content-header"><div class="container-fluid">
<div class="row"><div class="col-sm-6"><h3 class="mb-0">Albert — Any iPhone <small class="text-secondary">· iPhone11,8 · 18090</small></h3><small class="text-secondary">Template: AdminLTE 4 (https://github.com/topics/dashboard-template #1) · Premium dark</small></div>
<div class="col-sm-6"><ol class="breadcrumb float-sm-end"><li class="breadcrumb-item"><a href="/">Home</a></li><li class="breadcrumb-item active">Dashboard</li></ol></div></div>
</div></div>
<div class="app-content"><div class="container-fluid">
<div class="row g-3">
<div class="col-lg-4"><div class="card"><div class="card-header"><h3 class="card-title k">Server</h3></div><div class="card-body"><div id="serverV" class="v">—</div><div id="serverD" class="mono small text-secondary">loading…</div><div class="mt-2"><a href="/health" class="btn btn-sm btn-outline-primary">/health</a> <a href="/ready" class="btn btn-sm btn-outline-primary">/ready</a> <a href="/metrics" class="btn btn-sm btn-outline-primary">/metrics</a></div></div></div></div>
<div class="col-lg-4"><div class="card"><div class="card-header"><h3 class="card-title k">FairPlay</h3></div><div class="card-body"><div id="fpV" class="v">—</div><div id="fpD" class="mono small text-secondary">loading…</div></div></div></div>
<div class="col-lg-4"><div class="card"><div class="card-header"><h3 class="card-title k">Metrics</h3></div><div class="card-body"><div id="metrics" class="mono">loading…</div></div></div></div>
<div class="col-lg-6"><div class="card"><div class="card-header"><h3 class="card-title k">iPhone — This Device</h3></div><div class="card-body"><div id="device" class="mono">loading…</div><hr><div class="k">USB / Restore</div><div id="usb" class="mono">loading…</div></div></div></div>
<div class="col-lg-6"><div class="card"><div class="card-header"><h3 class="card-title k">IPSW</h3></div><div class="card-body"><div id="ipsw" class="mono">loading…</div><div class="progress mt-2" style="height:8px"><div id="ipswFill" class="progress-bar" style="width:0%"></div></div></div></div></div>
<div class="col-12"><div class="card"><div class="card-header"><h3 class="card-title k">Recent Activations (SQLite WAL)</h3></div><div class="card-body table-responsive p-0"><table class="table table-hover table-striped"><thead><tr><th>#</th><th>UDID (redacted)</th><th>Serial</th><th>At (UTC)</th><th>Record</th></tr></thead><tbody id="acts"><tr><td colspan=5 class="text-center">loading…</td></tr></tbody></table></div></div></div>
<div class="col-12"><div class="card"><div class="card-header"><h3 class="card-title k">Rate limit · Logs tail</h3></div><div class="card-body row g-3"><div class="col-md-6"><div class="mono text-secondary small">IPs tracked · window 60s · max 100/min · capped 1000</div><div id="rl" class="mono border rounded p-2 mt-1">loading…</div><div class="mt-2"><a href="/admin" class="btn btn-sm btn-success">→ Admin panel</a> <a href="/firmware" class="btn btn-sm btn-outline-secondary">→ Firmware</a></div></div><div class="col-md-6"><pre id="logs" class="border rounded p-2 bg-dark" style="max-height:240px;overflow:auto;font-size:11px">loading…</pre></div></div></div></div>
</div>
</div></div>
</main>
<footer class="app-footer"><div class="float-end d-none d-sm-inline">zAlive</div><strong>Local Albert</strong> <span id="ver">1.1-fixed</span> · gunicorn 2×4 · See RUNBOOK · <a href="/admin">admin</a> · Template <a href="https://github.com/topics/dashboard-template" target="_blank">dashboard-template</a> (AdminLTE 4)</footer>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/js/adminlte.min.js"></script>

<script>
const $ = id => document.getElementById(id);
const redact = s => s ? s.slice(0,4)+"..."+s.slice(-4) : "-";
async function tick(){
  try{
    const r = await fetch('/api/status', {cache:'no-store'});
    const j = await r.json();
    const ok = j.health && j.health.status==='ok';
    const ready = j.ready && j.ready.status==='ready';
    $('healthPill').textContent = (ok?'live ':'down ') + (ready?'· ready':'· not-ready');
    $('healthPill').style.color = ok&&ready ? 'var(--ok)' : 'var(--bad)';
    $('healthPill').style.borderColor = ok&&ready ? 'rgba(22,163,74,.3)' : 'rgba(220,38,38,.3)';
    $('serverV').innerHTML = (ok?'<span class="badge ok">live</span>':'<span class="badge bad">down</span>') + ' <small>:' + (j.env.ALBERT_HTTP_PORT||18090) + '</small>';
    $('serverD').textContent = (j.health.server||'albert-local') + ' ' + (j.health.version||'') + ' · ' + (j.env.ALBERT_HOST||'127.0.0.1') + ' · ' + j.now;
    $('fpV').innerHTML = (j.fairplay.loaded?'<span class="badge ok">loaded 0600</span>':'<span class="badge bad">missing</span>') + ' <small>'+ (j.fairplay.persisted?'persisted':'ephemeral') +'</small>';
    $('fpD').textContent = 'NotAfter ' + j.fairplay.notAfter + ' · Serial ' + j.fairplay.serial.slice(0,12) +'… · ' + j.fairplay.subject.slice(0,40);
    $('metrics').textContent = 'activations ' + j.metrics.activations + ' · failures ' + j.metrics.failures + ' · up ' + j.metrics.up + '\nrate IPs ' + (j.rate?.ips ?? 0) + ' · WAL ' + j.db.wal;
    // device
    const d=j.device;
    $('device').innerHTML = '<b>'+d.ProductType+'</b> '+d.ModelNumber+' · SN '+d.SerialNumber+' · UDID '+redact(d.UDID)+' · EID '+d.EID.slice(0,8)+'…'+d.EID.slice(-4)+' · IMEI '+d.IMEI.slice(0,3)+'...'+d.IMEI.slice(-3)+' / '+d.IMEI2.slice(0,3)+'...'+d.IMEI2.slice(-3)+' · '+d.Storage;
    $('usb').innerHTML = (j.usb.connected?'<span class="badge ok">USB Apple 05ac</span>':'<span class="badge warn">no Apple USB — VM passthrough needed</span>') + ' · idevice_id: ' + (j.usb.idevice||'255') + ' · restore: ' + j.usb.restore;
    // ipsw
    $('ipsw').textContent = j.ipsw.name + ' ' + j.ipsw.sizeGB + ' GB · SHA256 ' + j.ipsw.sha256.slice(0,16) +'… · ' + j.ipsw.productVersion + ' ' + j.ipsw.build + ' · ' + j.ipsw.variants.join(', ');
    $('ipswFill').style.width = j.ipsw.exists ? '100%' : '0%';
    // activations
    const tbody=$('acts'); tbody.innerHTML='';
    j.activations.forEach(row=>{
      const tr=document.createElement('tr');
      tr.innerHTML='<td>'+row.id+'</td><td class="mono">'+redact(row.udid)+'</td><td>'+(row.serial||'-')+'</td><td class="mono">'+row.created_at.slice(0,19)+'</td><td class="mono">'+row.record.slice(0,80)+'…</td>';
      tbody.appendChild(tr);
    });
    if(!j.activations.length) tbody.innerHTML='<tr><td colspan=5 class="mono" style="color:var(--muted)">no activations yet — run activate_device.py --method direct</td></tr>';
    $('rl').textContent = 'IPs ' + (j.rate?.ips ?? 0) + ' · sample ' + (j.rate?.sample||'-');
    $('ver').textContent = j.health.version;
  }catch(e){
    $('healthPill').textContent='fetch error';
    $('healthPill').style.color='var(--bad)';
  }
  $('clock').textContent = new Date().toLocaleTimeString();
}
tick(); setInterval(tick, 2000);
// logs poll
async function logsTick(){
  try{ const r=await fetch('/api/logs?lines=60',{cache:'no-store'}); const j=await r.json(); $('logs').textContent=j.tail||'no logs'; }catch(e){ $('logs').textContent='logs fetch error'; }
}
logsTick(); setInterval(logsTick, 3000);
</script>
</body>
</html>
'''

@app.route('/dashboard', methods=['GET'])
def dashboard():
    return Response(DASHBOARD_HTML, mimetype='text/html')

@app.route('/api/logs', methods=['GET'])
def api_logs():
    lines = int(request.args.get('lines', '60'))
    lines = max(1, min(lines, 200))
    tail = "no log"
    for p in [pathlib.Path("/tmp/albert.log"), pathlib.Path("albert.log"), pathlib.Path("logs/albert.log")]:
        if p.exists():
            try:
                tail = "\n".join(p.read_text(errors='ignore').splitlines()[-lines:])
                break
            except Exception:
                pass
    return jsonify({"tail": tail, "lines": lines})


FIRMWARE_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<link rel="alternate icon" type="image/png" href="/static/zalive-icon.svg">
<title>zAlive — Albert — Firmware</title>
<style>
:root{--bg:#0b0f14;--card:#151a21;--card-hover:#1c2330;--border:#232b36;--border-hover:#2d3a4b;--accent:#3b82f6;--accent-hover:#2563eb;--accent-soft:rgba(59,130,246,.12);--ok:#16a34a;--ok-soft:rgba(22,163,74,.12);--warn:#eab308;--bad:#dc2626;--bad-soft:rgba(220,38,38,.12);--text:#e5e7eb;--text-strong:#f1f5f9;--muted:#94a3b8;--radius:14px;--radius-sm:10px;--radius-pill:999px;--shadow:0 8px 32px rgba(0,0,0,.45);--transition:180ms cubic-bezier(.2,.8,.2,1);}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;font-family:-apple-system,Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.5;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none} a:hover{color:var(--accent-hover)} a:focus-visible, button:focus-visible, select:focus-visible, input:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
.skip{position:absolute;top:-40px;left:12px;background:var(--card);color:var(--text);padding:8px 14px;border-radius:10px;border:1px solid var(--border);z-index:100;font-size:13px;font-weight:600} .skip:focus{top:12px}
header{padding:12px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;position:sticky;top:0;background:rgba(11,15,20,.92);backdrop-filter:blur(12px);z-index:10;flex-wrap:wrap}
header h1{font-size:15px;margin:0;font-weight:650;letter-spacing:-.2px;color:var(--text-strong)}
select,input{font-size:13px;padding:9px 12px;border-radius:10px;border:1px solid var(--border);background:var(--card);color:var(--text);transition:border-color 180ms, background 180ms}
select{cursor:pointer;appearance:auto;-webkit-appearance:auto}
select option{background:#1a212e;color:var(--text);padding:8px}
select:hover,input:hover{border-color:var(--border-hover)} select:focus,input:focus{border-color:var(--accent);background:#1e293b;color:var(--text-strong)}
select:focus option:checked, select option:checked{background:var(--accent);color:white}
select option:hover, select option:focus{background:#243040;color:var(--text-strong)}
table{width:100%;border-collapse:separate;border-spacing:0;margin-top:10px}
th{font-size:11px;color:var(--muted);text-align:left;padding:10px 8px;border-bottom:1px solid var(--border);font-weight:650;letter-spacing:.3px;white-space:nowrap;position:sticky;top:0;background:var(--card)}
td{font-size:13px;padding:10px 8px;border-bottom:1px solid rgba(255,255,255,.06)} tbody tr:hover td{background:rgba(255,255,255,.02)}
.badge{display:inline-flex;align-items:center;font-size:11px;padding:3px 8px;border-radius:999px;border:1px solid var(--border);font-weight:600}
.badge.ok{background:var(--ok-soft);color:var(--ok);border-color:rgba(22,163,74,.25)} .badge.bad{background:var(--bad-soft);color:var(--bad);border-color:rgba(220,38,38,.25)}
.badge.warn{background:rgba(234,179,8,.12);color:var(--warn);border-color:rgba(234,179,8,.25)}
.mono{font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:16px;margin:16px;box-shadow:0 8px 32px rgba(0,0,0,.45)}
.empty{padding:20px;text-align:center;color:var(--muted);border:1px dashed var(--border);border-radius:10px;background:rgba(255,255,255,.01)}
.skeleton{background:linear-gradient(90deg, var(--card) 25%, var(--border) 50%, var(--card) 75%);background-size:200% 100%;animation:shimmer 1.5s infinite;border-radius:6px;height:14px}
@keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}
</style>
</head>
<body>
<a href="#main" class="skip">Skip to content</a>
<header role="banner">
  <a href="/dashboard" style="display:flex;align-items:center;gap:8px;text-decoration:none" aria-label="zAlive home">
    <img src="/static/zalive-logo.svg" alt="zAlive" style="height:26px;width:auto;display:block" loading="eager" decoding="async">
  </a>
  <div style="min-width:0">
    <h1>Albert — Firmware <span style="color:var(--muted);font-weight:400">· curated 5→15 Pro (13) · ipsw.me live cache 1h</span></h1>
    <nav aria-label="Breadcrumb" style="font-size:11.5px;color:var(--muted);margin-top:2px"><a href="/" style="color:var(--muted)">Home</a> › <a href="/dashboard" style="color:var(--muted)">Dashboard</a> › <span aria-current="page" style="color:var(--text)">Firmware</span> · <a href="/admin" style="color:var(--accent)">Admin</a></nav>
  </div>
  <select id="product" aria-label="Device model" style="margin-left:auto"></select>
  <input id="q" placeholder="Search version / build" aria-label="Search version or build" style="min-width:180px">
  <span id="status" style="color:var(--muted);font-size:12px" role="status" aria-live="polite"></span>
  <a href="/dashboard" style="margin-left:8px;font-size:13px;font-weight:600">← Dashboard</a>
</header>
<main id="main" role="main">
<div class="card">
  <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px">
    <span class="badge ok" aria-hidden="true">✓ curated 13</span>
    <span style="font-size:12px;color:var(--muted)">Any iPhone 5 → 15 Pro · live <a href="https://api.ipsw.me" target="_blank" rel="noopener">ipsw.me</a> + local <code>*.ipsw</code></span>
    <span style="margin-left:auto;font-size:11px;color:var(--muted)">Tip: type “18.7” or “22H374” to filter</span>
  </div>
  <div id="banner" style="display:none;padding:10px 12px;border-radius:10px;margin-bottom:10px;font-size:13px" role="alert"></div>
  <div style="overflow:auto;max-height:72vh;border:1px solid var(--border);border-radius:10px">
    <table role="table" aria-label="Firmware list"><thead><tr><th>Version</th><th>Build</th><th>Released</th><th>Size</th><th>Signed</th><th>Local</th><th>Download</th></tr></thead><tbody id="tbody"><tr><td colspan=7><span class="skeleton" style="width:100%;display:block"></span></td></tr></tbody></table>
  </div>
  <div class="mono" style="color:var(--muted);margin-top:10px;font-size:11px">Source: <a href="https://api.ipsw.me/v4/device/iPhone11,8" target="_blank" rel="noopener">api.ipsw.me</a> + local scan <code>*.ipsw</code> · <code>/api/firmwares?productType=iPhone11,8</code> · <code>/api/devices</code></div>
</div>
</main>

<script>
const $=id=>document.getElementById(id);
async function loadDevices(){
  const r=await fetch('/api/devices'); const j=await r.json();
  const sel=$('product');
  sel.innerHTML='';
  j.devices.forEach(d=>{
    const o=document.createElement('option');
    o.value=d.identifier; o.textContent=d.name+' ('+d.identifier+') '+d.chip;
    sel.appendChild(o);
  });
  sel.value='iPhone11,8';
}
function formatSize(b){
  if(!b) return '-';
  const gb=(b/1e9).toFixed(1);
  return gb+' GB';
}
async function loadFw(){
  const pt=$('product').value;
  const q=$('q').value.toLowerCase();
  $('status').textContent='loading…';
  try{
    const r=await fetch('/api/firmwares?productType='+encodeURIComponent(pt));
    const j=await r.json();
    if(!r.ok) throw new Error(j.error||'error');
    const banner=$('banner');
    if(j.stale) { banner.style.display='block'; banner.style.background='rgba(234,179,8,.15)'; banner.style.border='1px solid rgba(234,179,8,.3)'; banner.textContent='Stale cache — upstream unavailable (showing last cached).'; }
    else if(j.cached) { banner.style.display='block'; banner.style.background='rgba(59,130,246,.15)'; banner.style.border='1px solid rgba(59,130,246,.3)'; banner.textContent='Cached 1h — live fetch skipped.'; }
    else banner.style.display='none';
    const list=(j.firmwares||[]).filter(f=> !q || (f.version||'').toLowerCase().includes(q) || (f.buildid||'').toLowerCase().includes(q));
    const tbody=$('tbody');
    tbody.innerHTML='';
    if(!list.length) tbody.innerHTML='<tr><td colspan=7 style="color:var(--muted)">no matches</td></tr>';
    list.forEach(f=>{
      const signed = f.signed ? '<span class="badge ok">✓ signed</span>' : '<span class="badge bad">✗ unsigned</span>';
      const local = (j.local||[]).some(n=> n.includes(f.buildid)|| n.includes(f.version)) ? '✅' : '';
      const tr=document.createElement('tr');
      tr.innerHTML='<td>'+f.version+'</td><td class="mono">'+f.buildid+'</td><td>'+(f.releasedate||'').slice(0,10)+'</td><td>'+formatSize(f.filesize)+'</td><td>'+signed+'</td><td>'+local+'</td><td>'+(f.url?'<a href="'+f.url+'" target="_blank">⬇</a>':'-')+'</td>';
      tbody.appendChild(tr);
    });
    $('status').textContent = list.length+' firmwares · '+ (j.stale?'stale':'live') + (j.cached?' cached':'');
  } catch(e){
    $('status').textContent='error: '+e.message;
    $('tbody').innerHTML='<tr><td colspan=7 style="color:var(--bad)">'+e.message+'</td></tr>';
  }
}
(async()=>{
  await loadDevices();
  await loadFw();
  $('product').addEventListener('change', loadFw);
  $('q').addEventListener('input', loadFw);
})();
</script>
</body>
</html>
'''

NOTFOUND_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<title>zAlive — 404 Not Found</title>
<style>
:root{--bg:#0b0f14;--card:#151a21;--border:#232b36;--accent:#3b82f6;--muted:#94a3b8;--text:#e5e7eb;--radius:16px}
*{box-sizing:border-box} body{margin:0;font-family:-apple-system,Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;flex-direction:column}
header{padding:12px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;background:rgba(11,15,20,.92);backdrop-filter:blur(12px);position:sticky;top:0}
.card{max-width:720px;margin:48px auto;padding:28px;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);box-shadow:0 12px 40px rgba(0,0,0,.5);text-align:center}
h1{font-size:28px;margin:12px 0 8px;font-weight:800;letter-spacing:-.5px}
p{color:var(--muted);font-size:14px;line-height:1.6;margin:8px 0}
.badges{display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin-top:16px}
.badge{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:999px;border:1px solid var(--border);background:rgba(255,255,255,.02);font-size:13px;font-weight:600;text-decoration:none;color:var(--text)}
.badge.primary{background:var(--accent);border-color:var(--accent);color:white}
.badge:hover{transform:translateY(-1px)}
.mono{font-family:ui-monospace,monospace;font-size:11px;color:var(--muted)}
.footer{margin-top:auto;padding:14px;text-align:center;color:var(--muted);font-size:11.5px;border-top:1px solid var(--border);background:rgba(255,255,255,.01)}
a{color:var(--accent)} a:hover{text-decoration:underline}
</style>
</head>
<body>
<header role="banner">
  <a href="/dashboard" style="display:flex;align-items:center;gap:8px;text-decoration:none" aria-label="zAlive home"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:26px;width:auto;display:block" loading="eager"></a>
  <span style="font-size:13px;color:var(--muted)">· 404</span>
  <nav style="margin-left:auto;display:flex;gap:12px;font-size:13px"><a href="/dashboard">Dashboard</a> <a href="/firmware">Firmware</a> <a href="/admin">Admin</a> <a href="/health">Health</a></nav>
</header>
<main role="main" style="flex:1;display:flex;align-items:center;justify-content:center;padding:20px">
  <div class="card" role="alert" aria-labelledby="title">
    <div style="width:64px;height:64px;margin:0 auto;border-radius:16px;background:linear-gradient(135deg,#3b82f6 0%,#06b6d4 50%,#22c55e 100%);display:flex;align-items:center;justify-content:center;font-size:28px" aria-hidden="true">∅</div>
    <h1 id="title">404 — Page not found</h1>
    <p>The page <code id="path" class="mono" style="background:rgba(255,255,255,.06);padding:2px 6px;border-radius:6px"></code> does not exist.</p>
    <p>Try one of these instead — all are live on <code class="mono">127.0.0.1:18090</code> and <code class="mono">192.168.1.123:18090</code>.</p>
    <div class="badges">
      <a class="badge primary" href="/dashboard">→ Dashboard</a>
      <a class="badge" href="/firmware">Firmware (13 devices)</a>
      <a class="badge" href="/api/status">API Status</a>
      <a class="badge" href="/health">Health</a>
      <a class="badge" href="/admin">Admin Panel</a>
    </div>
    <p class="mono" style="margin-top:16px">zAlive · Local Albert · owned devices only · If you typed the URL manually, check spelling.</p>
  </div>
</main>
<div class="footer"><span style="display:inline-flex;align-items:center;gap:6px"><img src="/static/zalive-icon.svg" alt="" style="height:14px;width:14px" loading="lazy"> zAlive</span> · <a href="/dashboard">dashboard</a> · <a href="/firmware">firmware</a> · <a href="/admin">admin</a></div>
<script>document.getElementById('path').textContent = location.pathname + location.search;</script>
</body>
</html>
'''


ADMIN_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<title>zAlive — Admin Control Panel</title>
<style>
:root{--bg:#0b0f14;--card:#151a21;--card-hover:#1c2330;--border:#232b36;--border-hover:#2d3a4b;--accent:#3b82f6;--accent-hover:#2563eb;--accent-soft:rgba(59,130,246,.12);--ok:#16a34a;--ok-soft:rgba(22,163,74,.12);--warn:#eab308;--bad:#dc2626;--bad-soft:rgba(220,38,38,.12);--text:#e5e7eb;--text-strong:#f1f5f9;--muted:#94a3b8;--radius:14px;--radius-sm:10px;--radius-pill:999px;--shadow:0 8px 32px rgba(0,0,0,.45);--transition:180ms cubic-bezier(.2,.8,.2,1);}
*{box-sizing:border-box} html{scroll-behavior:smooth} body{margin:0;font-family:-apple-system,Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.5;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none} a:hover{color:var(--accent-hover)} a:focus-visible, button:focus-visible, input:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
.skip{position:absolute;top:-40px;left:12px;background:var(--card);color:var(--text);padding:8px 14px;border-radius:10px;border:1px solid var(--border);z-index:100;font-size:13px;font-weight:600} .skip:focus{top:12px}
header{padding:12px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;position:sticky;top:0;background:rgba(11,15,20,.92);backdrop-filter:blur(12px);z-index:10}
header h1{font-size:15px;margin:0;font-weight:650;letter-spacing:-.2px}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px;padding:16px;max-width:1440px;margin:0 auto}
.card{grid-column:span 6;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:16px;box-shadow:var(--shadow);transition:border-color var(--transition), box-shadow var(--transition)}
.card.full{grid-column:span 12} .card.third{grid-column:span 4} .card.half{grid-column:span 6}
@media(max-width:1000px){.card,.card.third,.card.half{grid-column:span 12}}
.k{font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;font-weight:650}
.v{font-size:22px;font-weight:750;margin-top:8px;letter-spacing:-.3px}
.mono{font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}
.badge{display:inline-flex;align-items:center;gap:4px;font-size:11px;padding:4px 9px;border-radius:999px;border:1px solid var(--border);font-weight:600}
.badge.ok{background:var(--ok-soft);color:var(--ok);border-color:rgba(22,163,74,.25)} .badge.bad{background:var(--bad-soft);color:var(--bad);border-color:rgba(220,38,38,.25)} .badge.warn{background:rgba(234,179,8,.12);color:var(--warn)}
button{font-size:13px;padding:9px 14px;border-radius:10px;border:1px solid var(--border);background:var(--card);color:var(--text);cursor:pointer;font-weight:600;transition:all var(--transition)}
button.primary{background:var(--accent);border-color:var(--accent);color:white} button.primary:hover{background:var(--accent-hover)}
button.danger{background:var(--bad-soft);border-color:rgba(220,38,38,.3);color:var(--bad)} button.danger:hover{background:rgba(220,38,38,.2)}
button:disabled{opacity:.6;cursor:not-allowed}
input{font-size:13px;padding:9px 12px;border-radius:10px;border:1px solid var(--border);background:var(--card);color:var(--text);width:100%}
input:focus{border-color:var(--accent);outline:none;box-shadow:0 0 0 3px var(--accent-soft)}
table{width:100%;border-collapse:separate;border-spacing:0;margin-top:10px} th{font-size:11px;color:var(--muted);text-align:left;padding:10px 8px;border-bottom:1px solid var(--border);font-weight:650;white-space:nowrap} td{font-size:13px;padding:10px 8px;border-bottom:1px solid rgba(255,255,255,.05)}
.log{max-height:300px;overflow:auto;background:#0f141b;border:1px solid var(--border);border-radius:10px;padding:12px;font-family:ui-monospace,monospace;font-size:11px;white-space:pre-wrap;line-height:1.6}
.footer{padding:14px;text-align:center;color:var(--muted);font-size:11.5px;border-top:1px solid var(--border);background:rgba(255,255,255,.01);margin-top:16px}
.skeleton{background:linear-gradient(90deg,var(--card) 25%, var(--border) 50%, var(--card) 75%);background-size:200% 100%;animation:shimmer 1.5s infinite;border-radius:6px;height:14px} @keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}
</style>
</head>
<body>
<a href="#main" class="skip">Skip to content</a>
<header role="banner">
  <a href="/dashboard" style="display:flex;align-items:center;gap:8px;text-decoration:none" aria-label="zAlive home"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:26px;width:auto;display:block" loading="eager"></a>
  <div>
    <h1>Admin Control Panel <span style="color:var(--muted);font-weight:400">· gated by ALBERT_ADMIN_TOKEN</span></h1>
    <nav aria-label="Breadcrumb" style="font-size:11.5px;color:var(--muted);margin-top:2px"><a href="/" style="color:var(--muted)">Home</a> › <a href="/dashboard" style="color:var(--muted)">Dashboard</a> › <span aria-current="page" style="color:var(--text)">Admin</span> · <a href="/firmware" style="color:var(--accent)">Firmware</a></nav>
  </div>
  <div style="margin-left:auto;display:flex;gap:8px;align-items:center">
    <span id="authPill" class="badge warn" role="status" aria-live="polite">checking auth…</span>
    <a href="/dashboard">← Dashboard</a>
  </div>
</header>
<main id="main" role="main" style="max-width:1440px;margin:0 auto">
<div id="gate" style="max-width:520px;margin:32px auto;padding:20px;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow)">
  <div class="k">Admin authentication</div>
  <p class="mono" style="color:var(--muted);margin-top:6px">Enter <code>ALBERT_ADMIN_TOKEN</code> to unlock. Token is sent as <code>X-Admin-Token</code> header and stored in this browser only (localStorage). Set via <code>.env ALBERT_ADMIN_TOKEN=…</code> and restart.</p>
  <form id="gateForm" style="display:flex;gap:8px;margin-top:12px" onsubmit="return false">
    <input id="tokenInput" type="password" placeholder="Paste admin token" aria-label="Admin token" autocomplete="current-password">
    <button class="primary" id="unlockBtn" type="submit">Unlock</button>
    <button id="logoutBtn" type="button" style="display:none">Lock</button>
  </form>
  <div id="gateMsg" class="mono" style="margin-top:8px;color:var(--muted)"></div>
</div>
<div id="panel" style="display:none">
  <div class="grid">
    <section class="card third" aria-labelledby="status-title"><div class="k" id="status-title">Status</div><div id="aStatus" class="mono" style="margin-top:8px"><span class="skeleton" style="width:100%;height:60px;display:block"></span></div></section>
    <section class="card third" aria-labelledby="actions-title"><div class="k" id="actions-title">Actions</div><div style="display:grid;gap:8px;margin-top:10px">
      <button id="btnRefresh">↻ Refresh status</button>
      <button id="btnClearCache">Clear firmware cache</button>
      <button id="btnResetRate">Reset rate limits</button>
      <button id="btnCheckpoint">DB checkpoint + prune</button>
      <button class="danger" id="btnPurge">⚠ Purge activations (>30d)</button>
    </div><div id="actionMsg" class="mono" style="margin-top:8px;color:var(--muted)" role="status" aria-live="polite"></div></section>
    <section class="card third" aria-labelledby="env-title"><div class="k" id="env-title">Environment</div><div id="aEnv" class="mono" style="margin-top:8px"><span class="skeleton" style="width:100%;height:60px;display:block"></span></div></section>
    <section class="card half" aria-labelledby="acts-title"><div class="k" id="acts-title">Recent activations</div><div style="overflow:auto;max-height:360px"><table><thead><tr><th>#</th><th>UDID</th><th>Serial</th><th>At</th></tr></thead><tbody id="aActs"><tr><td colspan=4><span class="skeleton" style="width:100%"></span></td></tr></tbody></table></div></section>
    <section class="card half" aria-labelledby="logs-title"><div class="k" id="logs-title">Logs tail</div><div id="aLogs" class="log" style="margin-top:8px">loading…</div><div style="margin-top:8px;display:flex;gap:8px"><button id="btnLogs">Refresh logs</button><a href="/api/logs?lines=200" target="_blank" style="font-size:13px;align-self:center">/api/logs</a></div></section>
    <section class="card full" aria-labelledby="rate-title"><div class="k" id="rate-title">Rate limits</div><div id="aRate" class="mono" style="margin-top:8px"><span class="skeleton" style="width:100%;height:40px;display:block"></span></div></section>
  </div>
</div>
</main>
<div class="footer"><span style="display:inline-flex;align-items:center;gap:6px"><img src="/static/zalive-icon.svg" alt="" style="height:14px;width:14px" loading="lazy"> zAlive</span> · Admin · <a href="/dashboard">dashboard</a> · <a href="/firmware">firmware</a> · gated · See <a href="/docs/RUNBOOK.md" target="_blank">RUNBOOK</a></div>
<script>
const $ = id => document.getElementById(id);
const TOKEN_KEY = 'zalive_admin_token';
function getToken(){ return localStorage.getItem(TOKEN_KEY) || ''; }
function setToken(v){ if(v) localStorage.setItem(TOKEN_KEY, v); else localStorage.removeItem(TOKEN_KEY); }
function authHeaders(){ const t=getToken(); return t ? {'X-Admin-Token': t} : {}; }
async function checkAuth(){
  const t=getToken();
  if(!t){ $('authPill').textContent='locked — enter token'; $('authPill').className='badge warn'; $('panel').style.display='none'; $('gate').style.display='block'; $('logoutBtn').style.display='none'; return false; }
  try{
    const r=await fetch('/api/admin/status', {headers: authHeaders()});
    const j=await r.json();
    if(r.ok && j.ok){
      $('authPill').textContent='unlocked ✓'; $('authPill').className='badge ok';
      $('panel').style.display='block'; $('gate').style.display='none'; $('logoutBtn').style.display='inline-block';
      $('gateMsg').textContent='Authenticated as admin.';
      return true;
    } else {
      $('authPill').textContent='invalid token'; $('authPill').className='badge bad';
      $('gateMsg').textContent=(j.error||'Invalid token') + ' — check .env ALBERT_ADMIN_TOKEN';
      $('panel').style.display='none'; $('gate').style.display='block';
      return false;
    }
  }catch(e){ $('authPill').textContent='error'; $('authPill').className='badge bad'; $('gateMsg').textContent='Error: '+e.message; return false; }
}
async function load(){
  if(!(await checkAuth())) return;
  try{
    const r=await fetch('/api/admin/status', {headers: authHeaders()});
    const j=await r.json();
    $('aStatus').innerHTML = '<div><span class="badge ok">live</span> fairplay '+(j.fairplay?.loaded?'loaded':'missing')+' · activations '+j.metrics.activations+' · up '+j.metrics.up+'</div><div class="mono" style="margin-top:6px;color:var(--muted)">ipsw '+j.ipsw.name+' · '+j.ipsw.sizeGB+'GB · '+j.ipsw.sha256.slice(0,16)+'…</div>';
    $('aEnv').textContent = JSON.stringify(j.env, null, 2);
    const acts = j.activations||[];
    const tbody=$('aActs'); tbody.innerHTML='';
    if(!acts.length) tbody.innerHTML='<tr><td colspan=4 style="color:var(--muted)">no activations</td></tr>';
    else acts.forEach(r=>{ const tr=document.createElement('tr'); tr.innerHTML='<td>'+r.id+'</td><td class="mono">'+(r.udid?r.udid.slice(0,4)+'…'+r.udid.slice(-4):'-')+'</td><td>'+(r.serial||'-')+'</td><td class="mono">'+r.created_at.slice(0,19)+'</td>'; tbody.appendChild(tr); });
    $('aRate').textContent = 'IPs '+j.rate.ips+' · sample '+(j.rate.sample||'-')+' · window 60s · max 100/min + 10/min per-UDID';
  }catch(e){ $('aStatus').textContent='load error: '+e.message; }
  try{
    const r=await fetch('/api/logs?lines=60', {headers: authHeaders()});
    const j=await r.json(); $('aLogs').textContent = j.tail||'no logs';
  }catch(e){ $('aLogs').textContent='logs error: '+e.message; }
}
$('gateForm').addEventListener('submit', async (e)=>{ e.preventDefault(); const v=$('tokenInput').value.trim(); if(!v){ $('gateMsg').textContent='Enter token'; return; } setToken(v); $('tokenInput').value=''; await load(); });
$('logoutBtn').addEventListener('click', ()=>{ setToken(''); $('authPill').textContent='locked'; $('authPill').className='badge warn'; $('panel').style.display='none'; $('gate').style.display='block'; $('gateMsg').textContent='Locked — token cleared from this browser.'; });
$('btnRefresh').addEventListener('click', load);
$('btnLogs').addEventListener('click', async()=>{ const r=await fetch('/api/logs?lines=60',{headers:authHeaders()}); const j=await r.json(); $('aLogs').textContent=j.tail||'no logs'; });
$('btnClearCache').addEventListener('click', async()=>{ $('actionMsg').textContent='clearing…'; const r=await fetch('/api/admin/clear-cache',{method:'POST',headers:authHeaders()}); const j=await r.json(); $('actionMsg').textContent=r.ok?('cleared: '+(j.cleared||'ok')):('error: '+(j.error||r.status)); });
$('btnResetRate').addEventListener('click', async()=>{ $('actionMsg').textContent='resetting…'; const r=await fetch('/api/admin/reset-rate',{method:'POST',headers:authHeaders()}); const j=await r.json(); $('actionMsg').textContent=r.ok?('reset: ips '+j.reset?.ips+' udid '+j.reset?.udid):('error: '+(j.error||r.status)); });
$('btnCheckpoint').addEventListener('click', async()=>{ $('actionMsg').textContent='checkpointing…'; const r=await fetch('/api/admin/checkpoint',{method:'POST',headers:authHeaders()}); const j=await r.json(); $('actionMsg').textContent=r.ok?('checkpoint: '+(j.wal||j.status||'ok')):('error: '+(j.error||r.status)); });
$('btnPurge').addEventListener('click', async()=>{ if(!confirm('Purge activations older than 30 days?')) return; $('actionMsg').textContent='purging…'; const r=await fetch('/api/admin/purge',{method:'POST',headers:authHeaders()}); const j=await r.json(); $('actionMsg').textContent=r.ok?('purged: '+j.purged):('error: '+(j.error||r.status)); if(r.ok) load(); });
(async()=>{ const t=getToken(); if(t) $('tokenInput').placeholder='token saved — unlock or lock to change'; await load(); })();
</script>
</body>
</html>
'''



@app.route('/firmware', methods=['GET'])
def firmware_page():
    return Response(FIRMWARE_HTML, mimetype='text/html')

# zAlive static assets — logo/favicon — served from ./static (no path traversal)
@app.route('/static/<path:filename>', methods=['GET'])
def static_assets(filename):
    # safe against traversal: resolve inside static dir only
    base = pathlib.Path(__file__).resolve().parent / "static"
    # normalize and block .. and absolute
    if ".." in pathlib.Path(filename).parts or filename.startswith("/"):
        return jsonify({"error": "invalid path"}), 400
    target = base / filename
    # ensure resolved is inside base
    try:
        target.resolve().relative_to(base.resolve())
    except Exception:
        return jsonify({"error": "forbidden"}), 403
    if not target.is_file():
        return jsonify({"error": "not found"}), 404
    # mimetype by suffix
    suffix = target.suffix.lower()
    mime = {
        ".svg": "image/svg+xml",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".ico": "image/x-icon",
        ".webp": "image/webp",
        ".css": "text/css",
        ".js": "application/javascript",
    }.get(suffix, "application/octet-stream")
    # 1h cache for immutable assets, immutable for svg
    resp = Response(target.read_bytes(), mimetype=mime)
    resp.headers["Cache-Control"] = "public, max-age=3600"
    # security: svg is safe inline
    return resp

@app.route('/favicon.ico', methods=['GET'])
def favicon_ico():
    return static_assets("zalive-icon.svg")

@app.route('/favicon.svg', methods=['GET'])
def favicon_svg():
    return static_assets("favicon.svg")

@app.route('/logo.svg', methods=['GET'])
def logo_svg():
    return static_assets("zalive-logo.svg")


# --- Admin gated control panel (ALBERT_ADMIN_TOKEN) ---
def _get_admin_token():
    return (os.environ.get("ALBERT_ADMIN_TOKEN") or "").strip()

def _check_admin_auth():
    expected = _get_admin_token()
    if not expected:
        return False, "admin disabled — set ALBERT_ADMIN_TOKEN in .env and restart"
    # token via header X-Admin-Token, Authorization Bearer, or ?token= query (for browser initial)
    got = (request.headers.get("X-Admin-Token") or "").strip()
    if not got:
        auth = (request.headers.get("Authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            got = auth[7:].strip()
    if not got:
        got = (request.args.get("token") or "").strip()
    if not got:
        # also check cookie zAlive_admin
        got = (request.cookies.get("zAlive_admin") or "").strip()
    if not got:
        return False, "missing admin token — send X-Admin-Token header"
    # constant-time compare
    import hmac
    if not hmac.compare_digest(got, expected):
        return False, "invalid admin token"
    return True, ""

def _admin_required():
    ok, msg = _check_admin_auth()
    if not ok:
        return jsonify({"ok": False, "error": msg}), 401
    return None

@app.route('/admin', methods=['GET'])
def admin_page():
    return Response(ADMIN_HTML, mimetype='text/html')

@app.route('/api/admin/status', methods=['GET'])
def api_admin_status():
    err = _admin_required()
    if err:
        return err
    # reuse api_status data but add ok flag
    # call api_status internally
    with app.test_request_context('/api/status'):
        # Instead of duplicating, fetch live data via same logic
        pass
    # Build minimal status via api_status handler
    try:
        from flask import g as _g
        # reuse logic: call api_status function and extract json
        resp = api_status()
        # api_status returns Response(json)
        data = resp.get_json() if hasattr(resp, 'get_json') else {}
        # Flask jsonify inside api_status returns Response, need to parse
        if isinstance(resp, tuple):
            resp = resp[0]
        try:
            j = resp.get_json()
        except Exception:
            import json as _json
            j = _json.loads(resp.get_data(as_text=True))
        j["ok"] = True
        return jsonify(j)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/api/admin/clear-cache', methods=['POST'])
def api_admin_clear_cache():
    err = _admin_required()
    if err:
        return err
    cleared = []
    try:
        if FIRMWARE_CACHE.exists():
            FIRMWARE_CACHE.unlink()
            cleared.append("firmware_cache.json")
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    # also clear any other caches if present
    return jsonify({"ok": True, "cleared": ", ".join(cleared) if cleared else "no cache file"})

@app.route('/api/admin/reset-rate', methods=['POST'])
def api_admin_reset_rate():
    err = _admin_required()
    if err:
        return err
    before_ip = len(_rate_limit_store)
    before_udid = len(_rate_limit_udid_store)
    with _rate_limit_lock:
        _rate_limit_store.clear()
        _rate_limit_udid_store.clear()
    return jsonify({"ok": True, "reset": {"ips": before_ip, "udid": before_udid, "after_ip": 0, "after_udid": 0}})

@app.route('/api/admin/checkpoint', methods=['POST'])
def api_admin_checkpoint():
    err = _admin_required()
    if err:
        return err
    import sqlite3 as _sql
    try:
        with _sql.connect(str(DB_PATH), timeout=5) as c:
            c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            c.execute("DELETE FROM activations WHERE id NOT IN (SELECT id FROM activations ORDER BY id DESC LIMIT 10000)")
            c.commit()
            wal = c.execute("PRAGMA journal_mode").fetchone()[0]
        return jsonify({"ok": True, "wal": wal, "status": "checkpoint ok"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/api/admin/purge', methods=['POST'])
def api_admin_purge():
    err = _admin_required()
    if err:
        return err
    import sqlite3 as _sql
    try:
        with _sql.connect(str(DB_PATH), timeout=5) as c:
            cur = c.execute("DELETE FROM activations WHERE datetime(created_at) < datetime('now','-30 days')")
            purged = cur.rowcount
            c.commit()
        return jsonify({"ok": True, "purged": purged})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# Premium branded 404 — covers all unknown paths with zAlive UI

@app.route('/api/validate', methods=['GET'])
def api_validate():
    """Public validate endpoint — runs same checks as scripts/validate.py but via API (no IPSW hash full read to avoid 8G sync block; returns lightweight)."""
    import hashlib as _hl
    import sqlite3 as _sql
    import pathlib as _pl
    from datetime import datetime, timezone
    checks={}
    # IPSW quick check (existence + size, not full sha256 for speed)
    try:
        ipsw = _pl.Path("iPhone11,8_18.7.10_22H374_Restore.ipsw")
        if ipsw.exists():
            sz = ipsw.stat().st_size
            ok = sz > 7_000_000_000
            checks["ipsw"]={"ok": ok, "msg": f"IPSW {sz/1e9:.1f}GB {'ok' if ok else 'too small'}"}
        else:
            checks["ipsw"]={"ok": False, "msg": "IPSW missing"}
    except Exception as e:
        checks["ipsw"]={"ok": False, "msg": str(e)}
    # FairPlay
    try:
        from cryptography import x509 as _x509
        crt = _pl.Path("certs/fairplay.crt")
        if crt.exists():
            cert=_x509.load_pem_x509_certificate(crt.read_bytes())
            days=(cert.not_valid_after_utc - datetime.now(timezone.utc)).days
            checks["fairplay"]={"ok": days>30, "msg": f"NotAfter {cert.not_valid_after_utc.date()} {days}d"}
        else:
            checks["fairplay"]={"ok": False, "msg": "cert missing"}
    except Exception as e:
        checks["fairplay"]={"ok": False, "msg": str(e)}
    # DB
    try:
        db=_pl.Path("logs/activations.db")
        with _sql.connect(str(db), timeout=5) as c:
            cnt=c.execute("SELECT count(*) FROM activations").fetchone()[0]
            checks["db"]={"ok": True, "msg": f"{cnt} rows"}
    except Exception as e:
        checks["db"]={"ok": False, "msg": str(e)}
    # Env
    try:
        from dotenv import dotenv_values as _dv
        vals=_dv(".env") if _pl.Path(".env").exists() else {}
        ok=bool(vals.get("ALBERT_ADMIN_TOKEN") and not vals["ALBERT_ADMIN_TOKEN"].startswith("change-me"))
        checks["env"]={"ok": ok, "msg": "ALBERT_ADMIN_TOKEN set" if ok else "ALBERT_ADMIN_TOKEN not set"}
    except Exception as e:
        checks["env"]={"ok": False, "msg": str(e)}
    # API self-check via test_client (reports 200 for core)
    try:
        with app.test_client() as _c:
            ok = _c.get("/health").status_code==200 and _c.get("/dashboard").status_code==200
            checks["api"]={"ok": ok, "msg": "self-check health+dashboard 200" if ok else "self-check fail"}
    except Exception as e:
        checks["api"]={"ok": False, "msg": str(e)}
    # Logs
    checks["logs"]={"ok": (_pl.Path("logs/albert.log").exists() or _pl.Path("/tmp/albert.log").exists()), "msg": "logs/albert.log present"}
    ok_all = all(v["ok"] for v in checks.values())
    return jsonify({"ok": ok_all, "checks": checks, "ts": datetime.now(timezone.utc).isoformat()})

@app.errorhandler(404)
def handle_404(e):
    # if request prefers json (API), return json 404; else branded html
    wants_json = request.path.startswith("/api/") or "application/json" in (request.headers.get("Accept") or "")
    if wants_json:
        return jsonify({"error": "not found", "path": request.path, "hint": "try /dashboard, /firmware, /admin, /health"}), 404
    return Response(NOTFOUND_HTML, status=404, mimetype='text/html')


@app.route('/api/devices', methods=['GET'])
def api_devices():
    return jsonify({"devices": CURATED_DEVICES})

@app.route('/api/firmwares', methods=['GET'])
def api_firmwares():
    productType = request.args.get('productType','').strip()
    if not productType:
        return jsonify({"error": "missing productType, e.g. ?productType=iPhone11,8"}), 400
    if not PRODUCT_RE.fullmatch(productType):
        return jsonify({"error": "invalid ProductType, must match ^iPhone\\d+,\\d+$"}), 400
    if productType not in CURATED_SET:
        # allow any valid but warn if not curated
        pass
    try:
        res = _fetch_ipsw(productType)
        firmwares = res.get("firmwares", [])
        local = _local_overlay(productType)
        return jsonify({
            "productType": productType,
            "firmwares": firmwares,
            "local": local,
            "cached": res.get("cached", False),
            "fetchedAt": res.get("fetchedAt"),
            "stale": res.get("stale", False),
            "warning": res.get("warning")
        })
    except Exception as e:
        # try stale fallback already inside _fetch, but handle 502
        logger.warning(f"firmware fetch failed for {productType}: {e}")
        return jsonify({"error": "upstream unavailable", "details": str(e), "retryAfter": 60}), 502


@app.route('/api/status', methods=['GET'])
def api_status():
    # Gather realtime status without blocking
    import sqlite3
    import subprocess
    now = datetime.now(timezone.utc).isoformat()
    env = {k: os.environ.get(k, "") for k in ["ALBERT_HOST","ALBERT_HTTP_PORT","ALBERT_HTTPS_PORT","FAIRPLAY_KEY_PATH","ALBERT_MODE"]}
    if not env["ALBERT_HTTP_PORT"]:
        env["ALBERT_HTTP_PORT"] = "18090"
    if not env["ALBERT_HOST"]:
        env["ALBERT_HOST"] = "127.0.0.1"
    # health/ready synthetic
    health = {"status": "ok", "server": "albert-local", "version": "1.1-fixed"}
    try:
        fair_loaded = bool(FAIRPLAY_CERT_CHAIN and albert.fairplay_private_key)
    except Exception:
        fair_loaded = False
    ready = {"status": "ready" if fair_loaded else "not-ready", "fairplay_loaded": fair_loaded}
    # fairplay cert details
    fair = {"loaded": fair_loaded, "persisted": pathlib.Path(FAIRPLAY_CERT_PATH).exists(), "subject": "", "notAfter": "", "serial": ""}
    try:
        crt = pathlib.Path(FAIRPLAY_CERT_PATH).read_bytes() if pathlib.Path(FAIRPLAY_CERT_PATH).exists() else FAIRPLAY_CERT_CHAIN
        cert = x509.load_pem_x509_certificate(crt if b"-----BEGIN" in crt else FAIRPLAY_CERT_CHAIN)
        fair["subject"] = cert.subject.rfc4514_string()
        fair["notAfter"] = cert.not_valid_after_utc.isoformat()
        fair["serial"] = str(cert.serial_number)
    except Exception:
        pass
    # metrics
    metrics = {"up": 1 if fair_loaded else 0, "activations": 0, "failures": 0, "wal": ""}
    try:
        with sqlite3.connect(str(DB_PATH), timeout=5) as c:
            metrics["activations"] = c.execute("SELECT COUNT(*) FROM activations").fetchone()[0]
            metrics["wal"] = c.execute("PRAGMA journal_mode").fetchone()[0]
    except Exception:
        pass
    try:
        metrics["failures"] = int(getattr(albert_activation_failures_total, "_value", 0))
    except Exception:
        pass
    # activations recent 5
    acts = []
    try:
        with sqlite3.connect(str(DB_PATH), timeout=5) as c:
            cur = c.execute("SELECT id,udid,serial,created_at,substr(record,1,400) FROM activations ORDER BY id DESC LIMIT 5")
            for id_,udid,serial,at,rec in cur.fetchall():
                acts.append({"id": id_, "udid": udid, "serial": serial, "created_at": at, "record": rec})
    except Exception:
        pass
    # device (dynamic: last activation producttype, fallback XR for “any iPhone”)
    device = {"ProductType":"iPhone11,8","ModelNumber":"MT1A2TH/A","SerialNumber":"C8PXJF1EKXKQ","UDID":"00008020-001224C81178002E","EID":"89049032004008882600006584069852","IMEI":"357340091682491","IMEI2":"357340091644897","Storage":"127.93 GB (110.92 Avail)"}
    # Try to override with last activation producttype (any-iPhone support)
    try:
        with sqlite3.connect(str(DB_PATH), timeout=5) as _c:
            # also check producttype column exists
            cur=_c.execute("SELECT producttype,udid,serial FROM activations ORDER BY id DESC LIMIT 1")
            row=cur.fetchone()
            if row and row[0] and row[0].startswith("iPhone") and "," in row[0]:
                # row[0] is true ProductType like iPhone11,8, not generic DeviceClass "iPhone"
                device["ProductType"] = row[0]
                # try to map to curated name
                for d in CURATED_DEVICES:
                    if d["identifier"] == row[0]:
                        device["ModelNumber"] = d["name"]
                        break
                if row[1]:
                    device["UDID"] = row[1]
                if row[2]:
                    device["SerialNumber"] = row[2]
    except Exception:
        pass
    # usb
    usb = {"connected": False, "idevice": "255", "restore": "Unable to discover device mode"}
    try:
        out = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=2).stdout
        usb["connected"] = "05ac" in out.lower() or "apple" in out.lower()
    except Exception:
        pass
    try:
        out = subprocess.run(["idevice_id","-l"], capture_output=True, text=True, timeout=2).stdout + subprocess.run(["idevice_id","-l"], capture_output=True, text=True, timeout=2).stderr
        usb["idevice"] = "0" if "00008020" in out else "255"
    except Exception:
        pass
    try:
        out = subprocess.run(["timeout","2","idevicerestore","--no-action","iPhone11,8_18.7.10_22H374_Restore.ipsw"], capture_output=True, text=True, timeout=3).stdout
        usb["restore"] = "ready" if "ready" in out.lower() else "Unable to discover device mode"
    except Exception:
        pass
    # ipsw (dynamic per device ProductType)
    ipsw_info = {"name":"iPhone11,8_18.7.10_22H374_Restore.ipsw","exists": False, "sizeGB":"8.1","sha256":"b30474b679d9ec04","productVersion":"18.7.10","build":"22H374","variants":["Customer Erase Install (IPSW)","Customer Upgrade Install (IPSW)"]}
    # Prefer local IPSW matching device ProductType
    try:
        for cand in _scan_local_ipsw():
            if device["ProductType"] in cand.name:
                ipsw_info["name"] = cand.name
                ipsw_info["sizeGB"] = f"{cand.stat().st_size/1e9:.1f}"
                try:
                    ipsw_info["sha256"] = pathlib.Path(str(cand)+".sha256").read_text().split()[0]
                except Exception:
                    pass
                break
    except Exception:
        pass
    try:
        p = pathlib.Path("iPhone11,8_18.7.10_22H374_Restore.ipsw")
        ipsw_info["exists"] = p.exists()
        if p.exists():
            ipsw_info["sizeGB"] = f"{p.stat().st_size/1e9:.1f}"
            try:
                ipsw_info["sha256"] = pathlib.Path("iPhone11,8_18.7.10_22H374_Restore.ipsw.sha256").read_text().split()[0]
            except Exception:
                pass
    except Exception:
        pass
    # rate
    rate = {"ips": len(_rate_limit_store) if '_rate_limit_store' in globals() else 0, "sample": ""}
    try:
        with _rate_limit_lock:
            sample = list(_rate_limit_store.items())[:1]
            if sample:
                k,v = sample[0]
                rate["sample"] = f"{k[:6]}...:{len(v)}"
    except Exception:
        pass
    return jsonify({"now": now, "health": health, "ready": ready, "fairplay": fair, "metrics": metrics, "activations": acts, "device": device, "usb": usb, "ipsw": ipsw_info, "env": env, "db": {"wal": metrics["wal"]}, "rate": rate})

@app.route('/api/rate_status', methods=['GET'])
def api_rate_status():
    """Debug rate limit status. Returns per-IP 100/min + per-UDID 10/min counts and Redis state."""
    ip = request.remote_addr or "unknown"
    udid_q = (request.args.get("udid") or request.args.get("UDID") or "").strip() or None
    per_udid = _get_per_udid_limit()
    redis_available = bool(_REDIS_AVAILABLE)
    redis_url_set = bool(_get_redis_url())
    client = _get_redis_client()
    redis_enabled = client is not None
    now = time.time()
    ip_count = None
    ip_remaining = None
    udid_count = None
    udid_remaining = None
    if redis_enabled and client is not None:
        try:
            ip_key = f"albert:ratelimit:ip:{ip}"
            v = client.get(ip_key)
            c = int(v) if v is not None else 0
            ip_count = c
            ip_remaining = max(0, _RATE_LIMIT_MAX - c)
        except Exception:
            ip_count = None
            ip_remaining = None
        if udid_q:
            try:
                udid_key = f"albert:ratelimit:udid:{udid_q}"
                v = client.get(udid_key)
                c = int(v) if v is not None else 0
                udid_count = c
                udid_remaining = max(0, per_udid - c)
            except Exception:
                udid_count = None
                udid_remaining = None
        store_ip_size = None
        store_udid_size = None
        try:
            store_ip_size = 0
            store_udid_size = 0
            for k in client.scan_iter(match="albert:ratelimit:ip:*"):
                store_ip_size += 1
            for k in client.scan_iter(match="albert:ratelimit:udid:*"):
                store_udid_size += 1
        except Exception:
            pass
    else:
        with _rate_limit_lock:
            lst = _rate_limit_store.get(ip, [])
            lst = [t for t in lst if now - t < _RATE_LIMIT_WINDOW]
            ip_count = len(lst)
            ip_remaining = max(0, _RATE_LIMIT_MAX - ip_count)
            store_ip_size = len(_rate_limit_store)
            store_udid_size = len(_rate_limit_udid_store)
            if udid_q:
                ul = _rate_limit_udid_store.get(udid_q, [])
                ul = [t for t in ul if now - t < _RATE_LIMIT_WINDOW]
                udid_count = len(ul)
                udid_remaining = max(0, per_udid - udid_count)
    remaining = None
    try:
        from flask import g
        if hasattr(g, 'rate_limit_remaining'):
            remaining = g.rate_limit_remaining
        elif ip_remaining is not None and udid_remaining is not None:
            remaining = min(ip_remaining, udid_remaining)
        elif ip_remaining is not None:
            remaining = ip_remaining
        elif udid_remaining is not None:
            remaining = udid_remaining
    except Exception:
        remaining = ip_remaining
    resp = jsonify({
        "ip": ip,
        "udid": udid_q,
        "per_ip_limit": _RATE_LIMIT_MAX,
        "per_udid_limit": per_udid,
        "window_seconds": _RATE_LIMIT_WINDOW,
        "redis_available": redis_available,
        "redis_enabled": redis_enabled,
        "redis_url_set": redis_url_set,
        "redis_url": _get_redis_url()[:20] + "..." if redis_url_set else "",
        "ip_count": ip_count,
        "ip_remaining": ip_remaining,
        "udid_count": udid_count,
        "udid_remaining": udid_remaining,
        "remaining": remaining,
        "store_ip_size": store_ip_size,
        "store_udid_size": store_udid_size,
        "X-RateLimit-Remaining": remaining,
    })
    if remaining is not None:
        resp.headers["X-RateLimit-Remaining"] = str(remaining)
    return resp

@app.route('/api/activations', methods=['GET'])
def api_activations():
    limit = int(request.args.get('limit','10'))
    limit = max(1, min(limit, 100))
    import sqlite3
    rows=[]
    try:
        with sqlite3.connect(str(DB_PATH), timeout=5) as c:
            cur=c.execute("SELECT id,udid,serial,created_at FROM activations ORDER BY id DESC LIMIT ?", (limit,))
            for id_,udid,serial,at in cur.fetchall():
                rows.append({"id":id_,"udid":udid,"serial":serial,"created_at":at})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"activations": rows, "total": len(rows)})


@app.route('/', methods=['GET'])
def index():
    return jsonify({"service":"albert-local","endpoints":["/dashboard","/firmware","/api/devices","/api/firmwares","/api/status","/api/rate_status","/api/activations","/api/logs","/health","/ready","/metrics","/deviceservices/drmHandshake","/deviceservices/deviceActivation","/WebObjects/ALUnbrick.woa/wa/deviceActivation"]})

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Local Albert Activation Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to')
    parser.add_argument('--ssl-cert', help='SSL certificate file')
    parser.add_argument('--ssl-key', help='SSL key file')
    parser.add_argument('--no-debug', action='store_true', help='Disable debug mode')
    parser.add_argument('--allow-no-risk', action='store_true', help='Allow start without ALBERT_ACCEPT_RISK=1 (lab only, bypass is still logged)')
    parser.add_argument('--rotate-fairplay', action='store_true', help='Rotate FairPlay key+cert (removes certs/fairplay.key/.crt and regenerates)')
    args = parser.parse_args()
    # Legal risk gate: no bypass without ALBERT_ACCEPT_RISK=1 (see SECURITY.md)
    if not args.allow_no_risk and not args.rotate_fairplay and os.environ.get('ALBERT_ACCEPT_RISK') != '1':
        import sys
        print("ERROR: ALBERT_ACCEPT_RISK must be 1 to start activation server (see SECURITY.md, NOTICE). "
              "Set ALBERT_ACCEPT_RISK=1 in .env or environment, or pass --allow-no-risk for isolated lab use.", file=sys.stderr)
        sys.exit(2)
    if args.rotate_fairplay:
        # Regenerate fairplay.key/crt immediately and exit 0 (validate via `python albert_server.py --rotate-fairplay` creates new key)
        try:
            for p in [pathlib.Path(FAIRPLAY_KEY_PATH), pathlib.Path(FAIRPLAY_CERT_PATH)]:
                if p.exists():
                    p.unlink()
                    print(f"Removed {p}")
            # Generate new RSA 2048 private key + self-signed CA cert (5y, SHA256) with 0600 perms
            new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "iPhone"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Apple iPhone Device CA"),
            ])
            not_before = datetime.now(timezone.utc)
            not_after = not_before + timedelta(days=5*365)
            cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
                new_key.public_key()
            ).serial_number(x509.random_serial_number()).not_valid_before(not_before).not_valid_after(not_after).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            ).sign(new_key, hashes.SHA256())
            key_pem = new_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            pathlib.Path(FAIRPLAY_KEY_PATH).parent.mkdir(parents=True, exist_ok=True)
            pathlib.Path(FAIRPLAY_KEY_PATH).write_bytes(key_pem)
            pathlib.Path(FAIRPLAY_KEY_PATH).chmod(0o600)
            pathlib.Path(FAIRPLAY_CERT_PATH).write_bytes(cert_pem)
            pathlib.Path(FAIRPLAY_CERT_PATH).chmod(0o600)
            print(f"Regenerated {FAIRPLAY_KEY_PATH} (0600) and {FAIRPLAY_CERT_PATH} (0600)")
            print(f"NotAfter {not_after.isoformat()} — cert valid for {5*365} days")
        except Exception as e:
            import sys
            print(f"Rotation failed: {e}", file=sys.stderr)
            sys.exit(1)
        import sys
        sys.exit(0)
    # mTLS status log for startup (warn if ALBERT_MTLS_CA not set)
    try:
        _log_mtls_status()
    except Exception:
        pass
    ssl_context = None
    if args.ssl_cert and args.ssl_key:
        mtls_ca = _get_mtls_ca()
        if mtls_ca:
            # If ALBERT_MTLS_CA is set, require client cert on TLS listener
            try:
                import ssl
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(args.ssl_cert, args.ssl_key)
                ctx.load_verify_locations(mtls_ca)
                ctx.verify_mode = ssl.CERT_REQUIRED
                ssl_context = ctx
                logger.info(f"mTLS enabled on HTTPS listener (CA={mtls_ca}) — requiring client cert")
            except Exception as e:
                logger.warning(f"Failed to configure mTLS SSLContext (CA={mtls_ca}): {e} — falling back to plain TLS")
                ssl_context = (args.ssl_cert, args.ssl_key)
        else:
            ssl_context = (args.ssl_cert, args.ssl_key)
            logger.warning("ALBERT_MTLS_CA not set — HTTPS without client cert verification (proxy→Albert unauthenticated)")
            logger.info(f"Starting HTTPS server on {args.host}:{args.port}")
        if isinstance(ssl_context, tuple):
            logger.info(f"Starting HTTPS server on {args.host}:{args.port}")
    else:
        # HTTP case: mTLS is enforced at application layer via header check (before_request)
        if _get_mtls_ca():
            logger.info(f"Starting HTTP server on {args.host}:{args.port} (mTLS enforced via X-Client-Cert header, CA={_get_mtls_ca()})")
        else:
            logger.warning(f"Starting HTTP server on {args.host}:{args.port} (ALBERT_MTLS_CA not set — mTLS disabled)")
            logger.info(f"Starting HTTP server on {args.host}:{args.port}")
    # also log risk acknowledgement
    if os.environ.get('ALBERT_ACCEPT_RISK') == '1':
        logger.info("ALBERT_ACCEPT_RISK=1 acknowledged — activation bypass enabled (owned devices only, see NOTICE)")
    else:
        logger.warning("Running with --allow-no-risk — bypass not acknowledged; for lab/sandbox only")
    app.run(host=args.host, port=args.port, ssl_context=ssl_context, debug=not args.no_debug, use_reloader=False)
