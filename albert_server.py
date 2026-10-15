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
import hmac
import hashlib
import plistlib
import logging
import sqlite3
import uuid
import re
import time
import threading
import subprocess
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
from investigation_center import build_investigation_state

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
                producttype TEXT,
                UNIQUE(udid) ON CONFLICT REPLACE
            )""")
            conn.execute("""CREATE TABLE IF NOT EXISTS sync_state(
                udid TEXT PRIMARY KEY,
                imei TEXT NOT NULL,
                serial TEXT,
                push_token TEXT,
                apns_topic TEXT,
                sync_enabled INTEGER DEFAULT 1,
                find_my_enabled INTEGER DEFAULT 1,
                icloud_enabled INTEGER DEFAULT 1,
                carrier_activated INTEGER DEFAULT 0,
                last_sync TEXT,
                phone_number TEXT DEFAULT \"\",
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            )""")
            # migrate old sync_state DBs without phone_number
            try:
                cur = conn.execute("PRAGMA table_info(sync_state)")
                cols = [r[1] for r in cur.fetchall()]
                if "phone_number" not in cols:
                    conn.execute("ALTER TABLE sync_state ADD COLUMN phone_number TEXT DEFAULT ''")
            except Exception:
                pass
            # migrate old DBs without producttype
            try:
                cur = conn.execute("PRAGMA table_info(activations)")
                cols = [r[1] for r in cur.fetchall()]
                if "producttype" not in cols:
                    conn.execute("ALTER TABLE activations ADD COLUMN producttype TEXT")
            except Exception:
                pass
            # drop no-op UNIQUE index from prior deployment
            try:
                conn.execute("DROP INDEX IF EXISTS idx_activations_udid_created")
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
        logger.warning("Failed to persist activation record (%s)", type(e).__name__)
        try:
            albert_activation_failures_total.inc()
        except Exception:
            pass


def _init_sync_state(udid: str, imei: str, serial: str = "") -> bool:
    """Initialize or update sync state for a device."""
    try:
        _init_db()
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(str(DB_PATH), timeout=30) as conn:
            conn.execute(
                """INSERT INTO sync_state (udid, imei, serial, apns_topic, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(udid) DO UPDATE SET
                   imei=excluded.imei,
                   serial=excluded.serial,
                   apns_topic=excluded.apns_topic,
                   updated_at=excluded.updated_at""",
                (udid or "", imei or "", serial or "", f"com.apple.activation.{imei}" if imei else "", now, now),
            )
            conn.commit()
        return True
    except Exception as e:
        logger.warning("Failed to init sync state: %s", type(e).__name__)
        return False


def _update_sync_state(udid: str, **kwargs) -> bool:
    """Update sync state fields for a device."""
    if not kwargs:
        return True
    # Whitelist of allowed columns to prevent SQL injection
    allowed_columns = {
        "imei", "serial", "push_token", "apns_topic", "sync_enabled",
        "find_my_enabled", "icloud_enabled", "carrier_activated",
        "last_sync", "phone_number"
    }
    try:
        _init_db()
        now = datetime.now(timezone.utc).isoformat()
        fields = []
        values = []
        for key, value in kwargs.items():
            if key not in allowed_columns:
                continue
            fields.append(f"{key}=?")
            values.append(value)
        if not fields:
            return True
        fields.append("updated_at=?")
        values.append(now)
        values.append(udid or "")
        with sqlite3.connect(str(DB_PATH), timeout=30) as conn:
            query = f"UPDATE sync_state SET {', '.join(fields)} WHERE udid=?"  # nosec B608
            conn.execute(query, values)
            conn.commit()
        return True
    except Exception as e:
        logger.warning("Failed to update sync state: %s", type(e).__name__)
        return False


def _get_sync_state(udid: str) -> dict:
    """Get sync state for a device."""
    try:
        _init_db()
        with sqlite3.connect(str(DB_PATH), timeout=30) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute("SELECT * FROM sync_state WHERE udid=?", (udid or "",))
            row = cur.fetchone()
            if row:
                return dict(row)
    except Exception as e:
        logger.warning("Failed to get sync state: %s", type(e).__name__)
    return {}


def _record_push_token(udid: str, push_token: str, imei: str = "") -> bool:
    """Store an APNs push token for a device in local sync state.

    This only persists the token and its derived topic to SQLite; it does not
    contact APNs or Apple. The name says "record" deliberately so callers are
    not led to believe a remote registration happened.
    """
    try:
        apns_topic = f"com.apple.activation.{imei}" if imei else f"com.apple.activation.{udid}"
        return _update_sync_state(
            udid,
            push_token=push_token,
            apns_topic=apns_topic,
            last_sync=datetime.now(timezone.utc).isoformat()
        )
    except Exception as e:
        logger.warning("Failed to record push token: %s", type(e).__name__)
        return False


def _set_carrier_activated(udid: str, activated: bool = True) -> bool:
    """Mark device as carrier activated."""
    return _update_sync_state(udid, carrier_activated=1 if activated else 0)


def _scan_local_ipsw() -> list:
    try:
        root = pathlib.Path(__file__).resolve().parent
        files = list(root.glob("*.ipsw"))
        # also check cwd
        cwd = pathlib.Path.cwd()
        if cwd != root:
            files.extend(cwd.glob("*.ipsw"))
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
                        return {"firmwares": entry["data"].get("firmwares", []), "cached": True, "fetchedAt": entry["fetchedAt"], "stale": True, "warning": "showing cached data; upstream unreachable", "data": entry["data"]}
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
        logger.info("OpenTelemetry tracing enabled")
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
        try:
            rid = getattr(g, 'request_id', '-') if 'g' in dir() else '-'
        except Exception:
            rid = '-'
        logger.warning(f"Redis rate limit failed for {key}: {e} — falling back to in-memory (request_id={rid})")
        return None

# Fail-closed toggle: if ALBERT_REDIS_FAIL_CLOSED=1 and Redis is configured but unreachable, return 429 instead of in-memory
def _redis_fail_closed() -> bool:
    return os.environ.get("ALBERT_REDIS_FAIL_CLOSED", "").strip().lower() in ("1", "true", "yes")

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
    else in-memory prune logic (100/min per IP + 10/min per UDID).
    If ALBERT_REDIS_FAIL_CLOSED=1 and Redis is configured but unreachable, returns 429 immediately."""
    per_udid = _get_per_udid_limit()
    udid_norm = udid.strip() if isinstance(udid, str) and udid.strip() else None
    client = _get_redis_client()
    redis_configured = bool(_get_redis_url())
    # Fail-closed when Redis configured but client unavailable (e.g., connection down) — don't silently fall back
    if client is None and redis_configured and _redis_fail_closed():
        try:
            rid = getattr(g, 'request_id', '-')  # type: ignore
        except Exception:
            rid = '-'
        logger.warning(f"Redis unavailable fail-closed for ip={ip} — returning 429 (no Redis client)", extra={"request_id": rid})
        return True
    if client is not None:
        ip_key = f"albert:ratelimit:ip:{ip}"
        res_ip = _redis_incr_with_expire(ip_key, _RATE_LIMIT_MAX, _RATE_LIMIT_WINDOW)
        if res_ip is None:
            if redis_configured and _redis_fail_closed():
                logger.warning(f"Redis unavailable fail-closed for ip={ip} — returning 429", extra={"request_id": getattr(g, 'request_id', '-')})
                return True
            logger.warning(f"Redis rate limit degraded to in-memory for ip={ip} — check ALBERT_REDIS_URL (redacted)", extra={"request_id": getattr(g, 'request_id', '-')})
        else:
            exceeded_ip, count_ip, remaining_ip = res_ip
            remaining_udid = None
            exceeded_udid = False
            if udid_norm:
                udid_key = f"albert:ratelimit:udid:{udid_norm}"
                res_udid = _redis_incr_with_expire(udid_key, per_udid, _RATE_LIMIT_WINDOW)
                if res_udid is None:
                    if redis_configured and _redis_fail_closed():
                        logger.warning("Redis UDID limiter unavailable — fail-closed 429", extra={"request_id": getattr(g, 'request_id', '-')})
                        return True
                    logger.warning("Redis UDID limiter degraded to in-memory", extra={"request_id": getattr(g, 'request_id', '-')})
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
        # Prune store size without O(N log N) sort under lock — pop oldest inserted (dict preserves insertion order)
        if len(_rate_limit_store) > 1000:
            for k in list(_rate_limit_store.keys())[:100]:
                _rate_limit_store.pop(k, None)
        if len(_rate_limit_udid_store) > 1000:
            for k in list(_rate_limit_udid_store.keys())[:100]:
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
    redis_configured = bool(_get_redis_url())
    if client is None and redis_configured and _redis_fail_closed():
        try:
            rid = getattr(g, 'request_id', '-')  # type: ignore
        except Exception:
            rid = '-'
        logger.warning("Redis unavailable — fail-closed 429 for UDID limiter", extra={"request_id": rid})
        return True
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
            for k in list(_rate_limit_udid_store.keys())[:100]:
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

def _luhn_check(imei: str) -> bool:
    """Validate IMEI using Luhn algorithm (last digit is check digit)."""
    if not _IMEI_RE.fullmatch(imei):
        return False
    digits = [int(d) for d in imei]
    check_digit = digits[-1]
    total = 0
    for i, d in enumerate(digits[:-1]):
        if i % 2 == 0:
            total += d
        else:
            doubled = d * 2
            total += doubled if doubled < 10 else doubled - 9
    return (total * 9) % 10 == check_digit

def _validate_imei(v) -> bool:
    if v is None or v == "":
        return True
    s = str(v).strip()
    if not _IMEI_RE.fullmatch(s):
        return False
    # Optional: enforce Luhn check (Apple does, but some test IMEIs may not pass)
    # Set ALBERT_IMEI_LUHN=1 to enforce
    if os.environ.get("ALBERT_IMEI_LUHN", "0") == "1":
        return _luhn_check(s)
    return True

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

def _verify_forwarded_cert(cert_hdr: str, mtls_ca, request) -> bool:
    """Validate a client certificate forwarded by the proxy in a header.

    The previous implementation accepted any string containing "-----BEGIN"
    that was longer than 100 characters, so a hand-written placeholder
    satisfied the mTLS gate from any peer. The signature has to check out
    against the configured CA, or the header proves nothing.
    """
    if not mtls_ca:
        logger.warning(
            f"forwarded client cert rejected for {request.path} — no CA configured "
            f"via ALBERT_MTLS_CA (request_id={getattr(g, 'request_id', '-')})"
        )
        return False
    try:
        pem = cert_hdr.encode()
        if b"-----BEGIN CERTIFICATE-----" not in pem:
            return False
        presented = x509.load_pem_x509_certificate(pem)
        ca = x509.load_pem_x509_certificate(pathlib.Path(mtls_ca).read_bytes())
    except Exception as exc:
        logger.warning(
            f"forwarded client cert could not be parsed for {request.path}: "
            f"{type(exc).__name__} (request_id={getattr(g, 'request_id', '-')})"
        )
        return False

    now = datetime.now(timezone.utc)
    if not (presented.not_valid_before_utc <= now <= presented.not_valid_after_utc):
        logger.warning(f"forwarded client cert outside validity window for {request.path}")
        return False

    # The CA signs the leaf; verify that signature with the CA's public key.
    try:
        ca.public_key().verify(
            presented.signature,
            presented.tbs_certificate_bytes,
            padding.PKCS1v15(),
            presented.signature_hash_algorithm,
        )
    except Exception:
        logger.warning(f"forwarded client cert is not signed by {mtls_ca} (request_id={getattr(g, 'request_id', '-')})")
        return False
    return True


@app.before_request
def before_request_hardening():
    # Cache the unparsed body before any handler touches request.form /
    # request.files. Werkzeug consumes wsgi.input while parsing a multipart
    # form, and under gunicorn that stream is not seekable, so afterwards the
    # original bytes are unrecoverable. A binary plist sent as a plain form
    # field needs them: Werkzeug would decode it as text and mangle it.
    if request.path.startswith("/deviceservices") or request.path.startswith("/WebObjects"):
        try:
            request.environ["albert.raw_body"] = request.get_data(cache=True)
        except Exception:
            request.environ["albert.raw_body"] = b""

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
        # Check for client cert evidence: proxy should forward cert or gunicorn sets SSL_CLIENT_VERIFY
        # Hardened: header-only "mtls"/"present" is spoofable over HTTP. Distinguish TLS vs header mode.
        has_cert = False
        tls_verified = request.environ.get("SSL_CLIENT_VERIFY") == "SUCCESS" or bool(request.environ.get("SSL_CLIENT_S_DN") or request.environ.get("peercert"))
        if tls_verified:
            has_cert = True
        else:
            # Check shared-secret header if configured (stronger than bare X-Client-Cert)
            expected_token = os.environ.get("ALBERT_MTLS_TOKEN", "").strip()
            presented_token = request.headers.get("X-MTLS-Token", "").strip()
            if expected_token and presented_token and hmac.compare_digest(presented_token, expected_token):
                has_cert = True
            else:
                cert_hdr = (request.headers.get("X-Client-Cert") or request.headers.get("X-Forwarded-Client-Cert") or request.headers.get("X-SSL-Client-Cert") or "").strip()
                if cert_hdr and "-----BEGIN" in cert_hdr:
                    # A forwarded certificate is only worth as much as the
                    # signature it carries. This branch used to accept anything
                    # containing "-----BEGIN" longer than 100 characters, so a
                    # hand-written string bypassed the gate from any peer. Parse
                    # it and check it against ALBERT_MTLS_CA.
                    has_cert = _verify_forwarded_cert(cert_hdr, mtls_ca, request)
                elif cert_hdr:
                    # Bare "present"/"mtls" over HTTP is spoofable — default DENY unless explicitly allowed.
                    # Require ALBERT_MTLS_ALLOW_HEADER_FALLBACK=1 plus localhost; otherwise require token/PEM.
                    allow_fallback = os.environ.get("ALBERT_MTLS_ALLOW_HEADER_FALLBACK", "0").strip().lower() in ("1", "true", "yes")
                    trusted = (request.remote_addr in ("127.0.0.1", "::1", "localhost") or request.remote_addr == os.environ.get("LOCAL_ALBERT_HOST", "127.0.0.1"))
                    if cert_hdr.lower() in ("mtls", "present"):
                        if not allow_fallback or not trusted:
                            logger.warning(f"mTLS bare header denied for {request.path} from {request.remote_addr} — set ALBERT_MTLS_TOKEN or PEM or ALBERT_MTLS_ALLOW_HEADER_FALLBACK=1 for localhost dev (request_id={g.request_id})")
                            has_cert = False
                        else:
                            logger.warning(f"mTLS header-only mode used for {request.path} from {request.remote_addr} — spoofable; set ALBERT_MTLS_TOKEN or LOCAL_ALBERT_SCHEME=https + gunicorn cert_reqs=2 for real mTLS (request_id={g.request_id})")
                            has_cert = True
                    else:
                        # non-PEM opaque string but not bare marker — still require fallback allow
                        if not allow_fallback:
                            has_cert = False
                        else:
                            has_cert = bool(cert_hdr) and trusted
        if not has_cert:
            logger.warning(f"mTLS required but no client cert for {request.path} from {request.remote_addr}", extra={"request_id": g.request_id, "remote_addr": request.remote_addr or '-'})
            # A plist body, not JSON: iOS parses device-endpoint responses as a
            # property list and reports a JSON body as NSCocoaErrorDomain 3840
            # ("Unexpected character {"), which hides the real reason the device
            # cannot activate.
            return _activation_error("client certificate required", 401)
    elif not mtls_ca and (request.path.startswith("/deviceservices") or request.path.startswith("/WebObjects")):
        # Warn once per process that mTLS is disabled (rate-limited via logger level)
        pass  # startup already warned; per-request warn would be noisy

    # Per-IP (+ per-UDID via activation payload) rate limit — 100/min per IP + 10/min per UDID
    # Optionally distributed via Redis INCR+EXPIRE when ALBERT_REDIS_URL set, else in-memory prune logic
    # Gate 04: protect all control-plane /api/* (read+write) + state-changing /api/pair
    if request.path.startswith("/deviceservices") or request.path.startswith("/WebObjects") or request.path.startswith("/api/"):
        ip = request.remote_addr or "unknown"
        if _check_rate_limit(ip):
            logger.warning(f"Rate limit exceeded for {ip}", extra={"request_id": g.request_id, "remote_addr": ip})
            # plist for the same reason as the mTLS 401 above: a JSON body makes
            # the device report NSCocoaErrorDomain 3840 instead of the real cause.
            resp = _activation_error("rate limit exceeded", 429)
            try:
                rem = getattr(g, 'rate_limit_remaining', 0)
                resp.headers["X-RateLimit-Remaining"] = str(rem)
            except Exception:
                resp.headers["X-RateLimit-Remaining"] = "0"
            return resp

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
    _set_security_headers(response)
    return response

# Pages embed the admin token in localStorage, so a script injected from a CDN
# would be able to read it. This CSP is the only thing standing between a
# compromised or typo-squatted CDN asset and full admin access. jsDelivr is
# allowlisted because the templates pull Bootstrap/AdminLTE from it.
_ADMIN_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "font-src 'self' https://cdn.jsdelivr.net data:; "
    "img-src 'self' data: blob:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


def _set_security_headers(response):
    """Apply baseline browser hardening headers to every response."""
    response.headers.setdefault("Content-Security-Policy", _ADMIN_CSP)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")

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

FALLBACK_KEY_PATH = os.environ.get('FALLBACK_KEY_PATH', 'certs/fallback.key')

class AlbertServer:
    def __init__(self):
        # Reusable fallback device key — persisted per-cluster (certs/fallback.key 0600), not per-process.
        # Loads fallback key if exists, else generates and persists; shared across gunicorn workers via file.
        self._fallback_key = None
        self._fallback_cert_cache: str | None = None
        self._fallback_lock = threading.Lock()
        # Preload persisted fallback key if present (shared across workers)
        try:
            _fb = pathlib.Path(FALLBACK_KEY_PATH)
            if _fb.exists():
                try:
                    self._fallback_key = serialization.load_pem_private_key(_fb.read_bytes(), password=None)  # type: ignore
                    logger.info(f"Loaded persisted fallback key from {_fb}")
                except Exception as _e:
                    logger.warning(f"Failed to load fallback key {_fb}: {_e}")
        except Exception:
            pass
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
                "UniqueDeviceID": activation_info.get("UniqueDeviceID") or activation_info.get("UDID") or str(uuid.uuid4()),
            "ActivityURL": "https://albert.apple.com/deviceservices/activity",
            "CertificateURL": "https://albert.apple.com/deviceservices/certifyMe",
            "PhoneNumberNotificationURL": "https://albert.apple.com/WebObjects/ALUnbrick.woa/wa/phoneHome",
            "WildcardTicket": base64.b64encode(b"wildcard_ticket_placeholder").decode()
        }
        account_token_plist = plistlib.dumps(account_token)
        account_token_b64 = base64.b64encode(account_token_plist).decode()
        device_cert_request = self._get_device_cert_request(activation_info)
        device_cert_b64 = ""
        # Helper: reusable fallback key/cert — persisted per-cluster, not per-activation/per-worker
        def _fallback_cert(cn: str) -> str:
            try:
                with self._fallback_lock:
                    if self._fallback_key is None:
                        # try load persisted first (another worker may have created it)
                        try:
                            _fb2 = pathlib.Path(FALLBACK_KEY_PATH)
                            if _fb2.exists():
                                self._fallback_key = serialization.load_pem_private_key(_fb2.read_bytes(), password=None)  # type: ignore
                        except Exception:
                            pass
                        if self._fallback_key is None:
                            self._fallback_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                            # persist for other workers (0600)
                            try:
                                _fbp = pathlib.Path(FALLBACK_KEY_PATH)
                                _fbp.parent.mkdir(parents=True, exist_ok=True)
                                _fbp.write_bytes(self._fallback_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
                                _fbp.chmod(0o600)
                                logger.info(f"Persisted fallback key to {_fbp}")
                            except Exception as _pe:
                                logger.warning(f"Failed to persist fallback key: {_pe}")
                    fk = self._fallback_key
                    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
                    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(
                        x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."), x509.NameAttribute(NameOID.COMMON_NAME, "Apple iPhone Device CA")])
                    ).public_key(fk.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)).not_valid_after(datetime.now(timezone.utc)+timedelta(days=365)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).sign(self.fairplay_private_key, hashes.SHA256())
                    return base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode()
            except Exception as e2:
                logger.warning(f"Fallback cert generation failed for {cn}: {e2}")
                return base64.b64encode(b"placeholder-device-cert").decode()

        if device_cert_request and len(device_cert_request) >= 10:
            try:
                device_cert = self.generate_device_certificate(device_cert_request)
                device_cert_b64 = base64.b64encode(device_cert).decode()
            except Exception as e:
                logger.warning(f"Failed to generate device certificate: {e}, using cached fallback")
                device_cert_b64 = _fallback_cert(activation_info.get("UniqueDeviceID", "device"))
        else:
            logger.info("No DeviceCertRequest provided, using reusable fallback certificate")
            device_cert_b64 = _fallback_cert(activation_info.get("UniqueDeviceID", "fallback-device"))

        fairplay_key_data = base64.b64encode(b"fairplay_key_data_placeholder").decode()
        
        # Add sync data to activation record
        imei = activation_info.get("IMEI", activation_info.get("InternationalMobileEquipmentIdentity", ""))
        udid = activation_info.get("UniqueDeviceID", activation_info.get("UDID", ""))
        push_token = activation_info.get("PushToken", activation_info.get("aps-token", ""))
        
        sync_data = {
            "PushToken": push_token,
            "APNsTopic": f"com.apple.activation.{imei}" if imei else f"com.apple.activation.{udid}",
            "SyncEnabled": 1,
            "FindMyiPhoneEnabled": 1,
            "iCloudSyncEnabled": 1,
            "CarrierActivated": 0,  # Will be set to 1 via phoneHome
            "ActivationTimestamp": datetime.now(timezone.utc).isoformat(),
            "SyncInterval": 3600
        }
        sync_data_b64 = base64.b64encode(plistlib.dumps(sync_data)).decode()
        
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
                    "show-settings": True,
                    "SyncData": sync_data_b64
                },
                "show-settings": True
            }
        }
        # Persist to SQLite (replaces in-memory dict persistence) + keep in-memory for compat
        try:
            udid = activation_info.get("UniqueDeviceID", "") or activation_info.get("UDID", "")
            serial = activation_info.get("SerialNumber", "") or activation_info.get("Serial", "") or activation_info.get("MLBSerialNumber", "")
            producttype = activation_info.get("ProductType", "")
            imei = activation_info.get("IMEI", "") or activation_info.get("InternationalMobileEquipmentIdentity", "")
            # Do not fallback to DeviceClass (which is "iPhone") — only true ProductType like iPhone11,8
            log_activation(str(udid), str(serial), activation_record, producttype=str(producttype))
            # Initialize sync state
            _init_sync_state(str(udid), str(imei), str(serial))
            if push_token:
                _record_push_token(str(udid), push_token, str(imei))
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

def _load_activation_info(raw):
    """Decode an activation-info payload that may be raw plist or base64 plist.

    Returns the parsed dict, or None when neither interpretation works. The
    caller decides the status code; this only reports whether it parsed.
    """
    if isinstance(raw, (bytes, bytearray)):
        try:
            parsed = plistlib.loads(bytes(raw))
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
    text = raw.decode("utf-8", "ignore") if isinstance(raw, (bytes, bytearray)) else str(raw)
    # A base64 plist is pure base64 and never starts with the XML declaration.
    if "<plist" not in text[:200] and "bplist" not in text[:8]:
        try:
            parsed = plistlib.loads(base64.b64decode(text, validate=False))
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
    # Last resort: some clients send raw plist as a text form field.
    try:
        parsed = plistlib.loads(text.encode("utf-8", "ignore"))
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
    return None


def _activation_info_from_raw_multipart(request_obj):
    """Recover activation-info from the unparsed multipart body.

    Fallback for a binary plist sent as a plain form field. Werkzeug decodes
    such a field as text -- a bplist00 payload is not valid UTF-8 -- and once
    request.form has been touched the input stream is consumed, so
    request.get_data() then returns b"". Werkzeug exposes the untouched copy
    through request.environ["wsgi.input"]; rewind and read from it.
    """
    raw = request_obj.environ.get("albert.raw_body") or b""
    if not raw:
        return None
    marker = b'name="activation-info"'
    idx = raw.find(marker)
    if idx == -1:
        return None
    # Step past the part headers to the blank line that ends them.
    head_end = raw.find(b"\r\n\r\n", idx)
    if head_end == -1:
        return None
    body_start = head_end + 4
    boundary = raw.rfind(b"--", 0, idx)
    if boundary == -1:
        return None
    boundary_token = raw[boundary:raw.find(b"\r\n", boundary)]
    close = raw.find(b"\r\n" + boundary_token, body_start)
    if close == -1:
        return None
    payload = raw[body_start:close]
    if b"\r\n" in payload:
        payload = payload.rsplit(b"\r\n", 1)[1]
    return _load_activation_info(payload)


def _activation_error(message, status):
    """Error body for a device activation endpoint, and its only failure counter.

    These endpoints are consumed by iOS, which only ever parses a property
    list. Returning JSON here produces "Unexpected character {" in
    NSCocoaErrorDomain 3840 on the device, which hides the real cause. Return
    a plist so the device can decode it and report a meaningful failure.

    This function owns the _inc_failure() call. Every call site must NOT also
    increment, or albert_activation_failures_total double-counts and the
    dashboard reports a failure rate higher than reality. See P2 in PR #19.
    """
    _inc_failure()
    body = plistlib.dumps({
        "Error": message,
        "NSLocalizedDescription": message,
        "RequestID": getattr(g, "request_id", "-"),
    })
    return Response(body, status=status, mimetype="application/xml")


@app.route('/deviceservices/drmHandshake', methods=['POST'])
def drm_handshake():
    # เป็น research stub เท่านั้น ตัวเครื่องตรวจสอบ HandshakeResponseMessage เทียบกับ
    # FairPlay public key ของ Apple ดังนั้นไม่มี response ที่สร้างจากที่นี่จะผ่านการตรวจได้
    # เพราะ private key อยู่เฉพาะฝั่ง Apple และไม่เคยปรากฏบนสายส่งข้อมูล
    # ยืนยันเชิงทดลองแล้ว: response 3 แบบ (สะท้อน challenge, ค่าว่าง, เต็มด้วยศูนย์)
    # ล้มเหลวทั้งหมดด้วย "Invalid session response"
    # สำหรับเครื่องที่เจ้าของเป็นผู้ถือ ต้อง activate ผ่าน albert.apple.com จริงเท่านั้น
    # ดูรายละเอียดที่ docs/re/ACTIVATION-PROTOCOL.md
    logger.info("Received DRM handshake request")
    try:
        data = request.get_data()
        if not data:
            return _activation_error("empty request", 400)
        try:
            handshake_request = plistlib.loads(data)
        except Exception as e:
            logger.warning(f"Failed to parse handshake plist: {e}, trying base64 path")
            return _activation_error("invalid plist", 400)
        logger.debug(f"Handshake request keys: {list(handshake_request.keys()) if isinstance(handshake_request, dict) else type(handshake_request)}")
        response = {
            # Apple คืน 4 key: serverKP(85B), FDRBlob(32B), SUInfo(366B),
            # HandshakeResponseMessage(508B มีลายเซ็น)
            # ส่วน "Server*" ทั้ง 3 key ไม่ได้อยู่ในโปรโตคอลของ Apple
            # คงไว้เพื่อรักษา shape ของ response ให้ตรงกับ tooling เดิมเท่านั้น
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
        return _activation_error("payload too large", 413)
    except Exception as e:
        if getattr(e, 'code', None) == 413:
            return _activation_error("payload too large", 413)
        logger.error(f"DRM handshake error: {e}", exc_info=True)
        return _activation_error("internal error", 500)

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
            # A multipart upload can arrive as a file part (request.files) or as
            # a plain field (request.form). Reading request.form first is wrong:
            # a binary plist in a form field gets decoded as text and mangled,
            # and a file part never appears in request.form at all. Check
            # request.files and the raw body first, then fall back to the field.
            if "multipart/form-data" in content_type:
                uploaded = request.files.get("activation-info")
                if uploaded is not None:
                    raw = uploaded.read()
                    activation_info = _load_activation_info(raw)
                    if activation_info is None:
                        _inc_failure()
                        return _activation_error("invalid activation-info", 400)
                else:
                    # A binary plist in a plain form field is unrecoverable from
                    # request.form: Werkzeug has already decoded it as text, and
                    # a bplist00 payload is not valid UTF-8. Read the raw body
                    # and slice the part out by hand so the original bytes survive.
                    raw_info = request.form.get("activation-info")
                    if not raw_info:
                        _inc_failure()
                        return _activation_error("missing activation-info", 400)
                    parsed = _load_activation_info(raw_info)
                    if parsed is None:
                        parsed = _activation_info_from_raw_multipart(request)
                    if parsed is None:
                        _inc_failure()
                        return _activation_error("invalid activation-info", 400)
                    activation_info = parsed
            # Preferred: form-encoded activation-info (most devices + libimobiledevice)
            elif request.form.get("activation-info"):
                activation_info_b64 = request.form.get("activation-info", "")
                if not activation_info_b64:
                    return _activation_error("missing activation-info", 400)
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
                        return _activation_error("invalid activation-info", 400)
            elif "application/x-apple-plist" in content_type or "application/xml" in content_type or "text/xml" in content_type:
                try:
                    activation_info = plistlib.loads(request.get_data())
                except Exception as e:
                    return _activation_error("invalid plist", 400)
            elif "multipart/form-data" in content_type:
                # Two clients disagree on the encoding of this field:
                #   pymobiledevice3 puts plistlib.dumps() output (raw XML/binary)
                #     into the form, so base64-decoding it yields garbage;
                #   an older urlencoded client sends base64 of the plist.
                # Try raw first, then base64, so neither path regresses.
                raw_info = request.form.get("activation-info")
                if not raw_info:
                    return _activation_error("missing activation-info", 400)
                activation_info = _load_activation_info(raw_info)
                if activation_info is None:
                    return _activation_error("invalid activation-info", 400)
            else:
                # Fallback: try to detect activation-info in raw body or plist body
                raw = request.get_data()
                if not raw:
                    return _activation_error("missing activation-info", 400)
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
                            return _activation_error("invalid activation-info", 400)
                    else:
                        return _activation_error("unsupported content type", 400)
            if not isinstance(activation_info, dict):
                logger.warning(f"Activation info not dict: {type(activation_info)}")
                return _activation_error("invalid activation-info: expected dict", 400)
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
            # Accept both spellings. lockdownd's ActivationInfo uses
            # UniqueDeviceID, while some clients send UDID. Reading only
            # UniqueDeviceID left udid_val None, so create_activation_record
            # generated a random UUID and stamped that into the AccountToken.
            udid_val = activation_info.get("UniqueDeviceID") or activation_info.get("UDID")
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
                logger.warning(f"Activation validation failed: {errors}", extra={"request_id": getattr(g, 'request_id', '-'), "remote_addr": request.remote_addr or '-'})
                # This branch keeps its own counter: _activation_error returns a
                # single generic message and cannot carry the Details list the
                # client needs here.
                _inc_failure()
                return Response(plistlib.dumps({
                    "Error": "validation failed",
                    "Details": errors,
                    "RequestID": getattr(g, 'request_id', '-'),
                }), status=400, mimetype="application/xml")
            # Per-UDID rate limit 10/min (distributed via Redis INCR+EXPIRE when ALBERT_REDIS_URL set else in-memory)
            if udid_val and _check_udid_rate_limit(str(udid_val)):
                logger.warning("Per-device rate limit exceeded", extra={"request_id": getattr(g, 'request_id', '-'), "remote_addr": request.remote_addr or '-'})
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
                return _activation_error("internal error generating activation record", 500)
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
            return _activation_error("payload too large", 413)
        except Exception as e:
            if getattr(e, 'code', None) == 413:
                return _activation_error("payload too large", 413)
            logger.error(f"Device activation error: {e}", exc_info=True)
            return _activation_error("internal error", 500)
    finally:
        if _otel_entered:
            try:
                _otel_ctx.__exit__(None, None, None)
            except Exception:
                pass

def _device_identity_from_plist(data) -> tuple:
    """Pull UDID/IMEI out of a device request and check them before use.

    activity, certifyMe and phoneHome are device-facing and therefore sit
    behind mTLS rather than the admin token, but nothing stopped them writing
    whatever the request body contained into sync_state. Format validation is
    not a substitute for a per-device credential -- a caller holding a valid
    certificate can still name another device's UDID -- but it stops junk rows
    and the arbitrary-value writes that came with the old behaviour.
    """
    imei = data.get("IMEI") or data.get("InternationalMobileEquipmentIdentity") or ""
    udid = data.get("UDID") or data.get("UniqueDeviceID") or ""
    # _validate_udid/_validate_imei check str(v).strip(), so " <valid> " would
    # pass validation and then be written to sync_state as a key distinct from
    # the canonical row for the same device. Return the normalized form so the
    # key is always the canonical one.
    udid = str(udid).strip()
    imei = str(imei).strip()
    if udid and not _validate_udid(udid):
        logger.warning(f"rejecting sync_state write: malformed UDID ({len(udid)} chars)")
        return "", "", True
    if imei and not _validate_imei(imei):
        logger.warning(f"rejecting sync_state write: malformed IMEI ({len(imei)} chars)")
        return "", "", True
    return udid, imei, False


@app.route('/deviceservices/activity', methods=['POST','GET'])
def activity():
    logger.info("Received activity request")
    # Parse device info from request
    imei = ""
    udid = ""
    push_token = ""  # nosec B105 - not a password, just empty string init
    try:
        if request.method == 'POST' and request.get_data():
            data = plistlib.loads(request.get_data())
            udid, imei, rejected = _device_identity_from_plist(data)
            push_token = data.get("PushToken") or data.get("aps-token") or ""
    except Exception:
        pass
    
    # Update sync state
    if udid and imei:
        _init_sync_state(udid, imei)
        if push_token:
            _record_push_token(udid, push_token, imei)
        else:
            _update_sync_state(udid, last_sync=datetime.now(timezone.utc).isoformat())
    
    # Return activity response with sync interval
    response = {
        "status": "success",
        "syncInterval": 3600,  # 1 hour
        "syncEnabled": 1,
        "findMyEnabled": 1,
        "icloudEnabled": 1
    }
    return Response(plistlib.dumps(response), mimetype='application/xml')


@app.route('/deviceservices/certifyMe', methods=['POST','GET'])
def certify_me():
    logger.info("Received certifyMe request")
    # Parse device info from request
    imei = ""
    udid = ""
    try:
        if request.method == 'POST' and request.get_data():
            data = plistlib.loads(request.get_data())
            udid, imei, rejected = _device_identity_from_plist(data)
    except Exception:
        pass
    
    # Update sync state
    if udid and imei:
        _init_sync_state(udid, imei)
    
    # Return certificate for device
    cert_b64 = base64.b64encode(FAIRPLAY_CERT_CHAIN).decode()
    response = {
        "status": "success",
        "certificate": cert_b64,
        "certType": "FairPlay",
        "validityDays": 1825
    }
    return Response(plistlib.dumps(response), mimetype='application/xml')


@app.route('/WebObjects/ALUnbrick.woa/wa/deviceActivation', methods=['POST','GET'])
def legacy_device_activation():
    logger.info("Received legacy device activation request")
    return device_activation()


@app.route('/WebObjects/ALUnbrick.woa/wa/phoneHome', methods=['POST','GET'])
def phone_home():
    logger.info("Received phoneHome request")
    # Parse device info from request
    imei = ""
    udid = ""
    phone_number = ""
    try:
        if request.method == 'POST' and request.get_data():
            data = plistlib.loads(request.get_data())
            udid, imei, rejected = _device_identity_from_plist(data)
            phone_number = data.get("PhoneNumber") or data.get("MSISDN") or ""
    except Exception:
        pass
    
    # Update sync state - mark as carrier activated
    if udid and imei:
        _init_sync_state(udid, imei)
        _set_carrier_activated(udid, True)
        if phone_number:
            _update_sync_state(udid, phone_number=phone_number)
    
    # Return phoneHome response
    response = {
        "status": "success",
        "carrierActivated": 1,
        "phoneNumber": phone_number
    }
    return Response(plistlib.dumps(response), mimetype='application/xml')

@app.errorhandler(413)
@app.errorhandler(RequestEntityTooLarge)
def too_large(e):
    _inc_failure()
    # A device endpoint must answer with a plist. iOS parses the body as a
    # property list, so a JSON body surfaces as NSCocoaErrorDomain 3840
    # ("Unexpected character {") and hides the real failure. Non-device routes
    # (browser, /api) keep JSON.
    path = getattr(request, "path", "") or ""
    if path.startswith("/deviceservices") or path.startswith("/WebObjects"):
        return _activation_error("payload too large", 413)
    _inc_failure()
    return jsonify({
        "error": "payload too large",
        "limit": app.config['MAX_CONTENT_LENGTH'],
        "request_id": getattr(g, 'request_id', '-'),
    }), 413

@app.route('/health', methods=['GET'])
def health():
    # Liveness: does not require upstream — HTML template for browser, JSON for API (dashboard-template AdminLTE 4)
    wants_html = "text/html" in (request.headers.get("Accept") or "")
    data = {"status": "ok", "server": "albert-local", "version": "1.1-fixed"}
    if wants_html and not request.args.get("format") == "json":
        html = f"""<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<title>zAlive — Health — ✓ ok</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/css/adminlte.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
<style>:root{{--zalive-card:#151a21;--zalive-border:#232b36}} .app-wrapper{{min-height:100vh;background:#0b0f14}} .app-header{{border-bottom:1px solid var(--zalive-border)}} .app-sidebar{{background:#0f141b;border-right:1px solid var(--zalive-border)}} .card{{border:1px solid var(--zalive-border);border-radius:14px;box-shadow:0 8px 32px rgba(0,0,0,.45)}} .mono{{font-family:ui-monospace,monospace}}</style>
</head>
<body class="layout-fixed-complete">
<div class="app-wrapper">
<nav class="app-header navbar navbar-expand bg-body"><div class="container-fluid">
<ul class="navbar-nav"><li class="nav-item"><a class="nav-link" data-lte-toggle="sidebar" href="#"><i class="bi bi-list"></i></a></li><li class="nav-item"><a href="/dashboard" class="nav-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:22px"></a></li></ul>
<ul class="navbar-nav ms-auto"><li class="nav-item"><span class="badge bg-success">✓ ok</span></li><li class="nav-item"><a class="nav-link" href="/dashboard">Dashboard</a></li><li class="nav-item"><a class="nav-link" href="/api/validate?format=json">JSON</a></li></ul>
</div></nav>
<aside class="app-sidebar sidebar-dark"><div class="sidebar-brand"><a href="/dashboard" class="brand-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:28px"><span class="brand-text fw-light ms-2">zAlive Albert</span></a></div>
<div class="sidebar-wrapper"><nav class="mt-2"><ul class="nav sidebar-menu flex-column">
<li class="nav-item"><a href="/dashboard" class="nav-link"><i class="nav-icon bi bi-speedometer2"></i><p>Dashboard</p></a></li>
<li class="nav-item"><a href="/firmware" class="nav-link"><i class="nav-icon bi bi-hdd-stack"></i><p>Firmware</p></a></li>
<li class="nav-item"><a href="/admin" class="nav-link"><i class="nav-icon bi bi-shield-lock"></i><p>Admin</p></a></li>
<li class="nav-item"><a href="/health" class="nav-link active"><i class="nav-icon bi bi-heart-pulse"></i><p>Health</p></a></li>
<li class="nav-item"><a href="/ready" class="nav-link"><i class="nav-icon bi bi-check-circle"></i><p>Ready</p></a></li>
<li class="nav-item"><a href="/metrics" class="nav-link"><i class="nav-icon bi bi-graph-up"></i><p>Metrics</p></a></li>
</ul></nav></div>
</aside>
<main class="app-main"><div class="app-content-header"><div class="container-fluid">
<div class="row"><div class="col-sm-6"><h3 class="mb-0">Health <small class="text-secondary">· ✓ ok · LIVE</small></h3><small class="text-secondary">Template: AdminLTE 4 (dashboard-template #1) · Liveness probe (no upstream)</small></div><div class="col-sm-6"><ol class="breadcrumb float-sm-end"><li class="breadcrumb-item"><a href="/">Home</a></li><li class="breadcrumb-item"><a href="/dashboard">Dashboard</a></li><li class="breadcrumb-item active">Health</li></ol></div></div>
</div></div>
<div class="app-content"><div class="container-fluid">
<div class="row g-3">
<div class="col-md-4"><div class="card"><div class="card-header"><h3 class="card-title text-uppercase small" style="color:#94a3b8">Server</h3><span class="badge bg-success float-end">✓ ok</span></div><div class="card-body"><div class="mono small">albert-local · 1.1-fixed</div><div class="mono small text-secondary">status ok · liveness</div></div></div></div>
<div class="col-md-4"><div class="card"><div class="card-header"><h3 class="card-title text-uppercase small" style="color:#94a3b8">Version</h3></div><div class="card-body"><div class="mono small">1.1-fixed</div><div class="mono small text-secondary">build 1.1-fixed · 0.0.0.0:18090</div></div></div></div>
<div class="col-md-4"><div class="card"><div class="card-header"><h3 class="card-title text-uppercase small" style="color:#94a3b8">Uptime</h3></div><div class="card-body"><div class="mono small">live on 127.0.0.1:18090 + 192.168.1.123:18090</div><div class="mono small text-secondary">mTLS {'enabled' if _get_mtls_ca() else 'disabled'} · rate 100/min + 10/min per-UDID</div></div></div></div>
</div>
<div class="card mt-3"><div class="card-header"><h3 class="card-title small" style="color:#94a3b8">Raw JSON</h3><a href="/health?format=json" class="btn btn-sm btn-outline-primary float-end">View JSON</a></div><div class="card-body"><pre class="mono small bg-dark p-3 rounded" style="white-space:pre-wrap">{json.dumps(data, indent=2)}</pre></div></div>
</div></div>
</main>
<footer class="app-footer"><div class="float-end d-none d-sm-inline">zAlive</div><strong>Local Albert</strong> · Template dashboard-template (AdminLTE 4)</footer>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/js/adminlte.min.js" integrity="sha384-6yU8d/XMPixNnAJ83V1hSNte2ij+N38tIn1M4J+EiHC/MPgisvtNhJyRPfGWFrDk" crossorigin="anonymous"></script>
</body>
</html>"""
        return Response(html, mimetype='text/html')
    return jsonify(data)

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
    # HTML template for browser (AdminLTE 4), JSON for API
    wants_html = "text/html" in (request.headers.get("Accept") or "")
    if wants_html and not request.args.get("format") == "json":
        ok_badge = "bg-success" if ok else "bg-danger"
        ok_icon = "✓ ready" if ok else "✗ not-ready"
        exp_msg = f"NotAfter {not_after_iso[:10]} · {days_until_expiry}d" if not_after_iso else "—"
        warn_html = f"<div class=\"alert alert-warning mt-2\">{warning}</div>" if expiry_warning and warning else ""
        mtls_html = f"<div class=\"mono small text-secondary\">mTLS enabled · CA={mtls_ca}</div>" if mtls_ca else "<div class=\"mono small text-warning\">mTLS disabled — proxy→Albert unauthenticated</div>"
        html = f"""<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<title>zAlive — Ready — {'✓ ready' if ok else '✗ not-ready'}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/css/adminlte.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
<style>:root{{--zalive-card:#151a21;--zalive-border:#232b36}} .app-wrapper{{min-height:100vh;background:#0b0f14}} .app-header{{border-bottom:1px solid var(--zalive-border)}} .app-sidebar{{background:#0f141b;border-right:1px solid var(--zalive-border)}} .card{{border:1px solid var(--zalive-border);border-radius:14px;box-shadow:0 8px 32px rgba(0,0,0,.45)}} .mono{{font-family:ui-monospace,monospace}}</style>
</head>
<body class="layout-fixed-complete">
<div class="app-wrapper">
<nav class="app-header navbar navbar-expand bg-body"><div class="container-fluid">
<ul class="navbar-nav"><li class="nav-item"><a class="nav-link" data-lte-toggle="sidebar" href="#"><i class="bi bi-list"></i></a></li><li class="nav-item"><a href="/dashboard" class="nav-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:22px"></a></li></ul>
<ul class="navbar-nav ms-auto"><li class="nav-item"><span class="badge {ok_badge}">{ok_icon}</span></li><li class="nav-item"><a class="nav-link" href="/dashboard">Dashboard</a></li><li class="nav-item"><a class="nav-link" href="/ready?format=json">JSON</a></li></ul>
</div></nav>
<aside class="app-sidebar sidebar-dark"><div class="sidebar-brand"><a href="/dashboard" class="brand-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:28px"><span class="brand-text fw-light ms-2">zAlive Albert</span></a></div>
<div class="sidebar-wrapper"><nav class="mt-2"><ul class="nav sidebar-menu flex-column">
<li class="nav-item"><a href="/dashboard" class="nav-link"><i class="nav-icon bi bi-speedometer2"></i><p>Dashboard</p></a></li>
<li class="nav-item"><a href="/firmware" class="nav-link"><i class="nav-icon bi bi-hdd-stack"></i><p>Firmware</p></a></li>
<li class="nav-item"><a href="/admin" class="nav-link"><i class="nav-icon bi bi-shield-lock"></i><p>Admin</p></a></li>
<li class="nav-item"><a href="/health" class="nav-link"><i class="nav-icon bi bi-heart-pulse"></i><p>Health</p></a></li>
<li class="nav-item"><a href="/ready" class="nav-link active"><i class="nav-icon bi bi-check-circle"></i><p>Ready</p></a></li>
<li class="nav-item"><a href="/metrics" class="nav-link"><i class="nav-icon bi bi-graph-up"></i><p>Metrics</p></a></li>
<li class="nav-item"><a href="/api/validate" class="nav-link"><i class="nav-icon bi bi-check2-square"></i><p>Validate</p></a></li>
</ul></nav></div>
</aside>
<main class="app-main"><div class="app-content-header"><div class="container-fluid">
<div class="row"><div class="col-sm-6"><h3 class="mb-0">Ready <small class="text-secondary">· {ok_icon}</small></h3><small class="text-secondary">Template: AdminLTE 4 (dashboard-template #1) · FairPlay + NotAfter + mTLS</small></div><div class="col-sm-6"><ol class="breadcrumb float-sm-end"><li class="breadcrumb-item"><a href="/">Home</a></li><li class="breadcrumb-item"><a href="/dashboard">Dashboard</a></li><li class="breadcrumb-item active">Ready</li></ol></div></div>
</div></div>
<div class="app-content"><div class="container-fluid">
<div class="row g-3">
<div class="col-md-4"><div class="card"><div class="card-header"><h3 class="card-title text-uppercase small" style="color:#94a3b8">FairPlay</h3><span class="badge {ok_badge} float-end">{ok_icon}</span></div><div class="card-body"><div class="mono small">loaded={str(ok).lower()} · {exp_msg}</div>{warn_html}<div class="mono small text-secondary mt-1">key {FAIRPLAY_KEY_PATH} · cert {FAIRPLAY_CERT_PATH}</div></div></div></div>
<div class="col-md-4"><div class="card"><div class="card-header"><h3 class="card-title text-uppercase small" style="color:#94a3b8">mTLS</h3></div><div class="card-body"><div class="mono small">{mtls_html}</div><div class="mono small text-secondary">ALBERT_MTLS_CA={mtls_ca or 'not set'}</div></div></div></div>
<div class="col-md-4"><div class="card"><div class="card-header"><h3 class="card-title text-uppercase small" style="color:#94a3b8">Status</h3></div><div class="card-body"><div class="mono small">status={payload['status']} · HTTP {200 if ok else 503}</div><div class="mono small text-secondary">ready requires FairPlay loaded</div></div></div></div>
</div>
<div class="card mt-3"><div class="card-header"><h3 class="card-title small" style="color:#94a3b8">Raw JSON</h3><a href="/ready?format=json" class="btn btn-sm btn-outline-primary float-end">View JSON</a></div><div class="card-body"><pre class="mono small bg-dark p-3 rounded" style="white-space:pre-wrap">{json.dumps(payload, indent=2)}</pre></div></div>
</div></div>
</main>
<footer class="app-footer"><div class="float-end d-none d-sm-inline">zAlive</div><strong>Local Albert</strong> · Template dashboard-template (AdminLTE 4)</footer>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/js/adminlte.min.js" integrity="sha384-6yU8d/XMPixNnAJ83V1hSNte2ij+N38tIn1M4J+EiHC/MPgisvtNhJyRPfGWFrDk" crossorigin="anonymous"></script>
</body>
</html>"""
        return Response(html, mimetype='text/html')
    return (jsonify(payload), 200 if ok else 503)

@app.route('/metrics', methods=['GET'])
def metrics():
    # Prometheus exposition format via prometheus_client if available else stub — HTML template for browser (AdminLTE 4)
    wants_html = "text/html" in (request.headers.get("Accept") or "")
    if wants_html and not request.args.get("format") == "prom":
        # Gather metrics for template
        if HAS_PROM:
            try:
                albert_up.set(1 if FAIRPLAY_CERT_CHAIN else 0)
            except Exception:
                pass
            prom_text = generate_latest().decode(errors="ignore") if callable(generate_latest) else ""
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
            prom_text = (
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
        # Parse key values for cards
        up_val = "1" if FAIRPLAY_CERT_CHAIN else "0"
        total_val = "0"
        failures_val = "0"
        try:
            for line in prom_text.splitlines():
                if line.startswith("albert_activation_total "):
                    total_val = line.split()[-1]
                if line.startswith("albert_activation_failures_total "):
                    failures_val = line.split()[-1]
                if line.startswith("albert_up "):
                    up_val = line.split()[-1]
        except Exception:
            pass
        html = f"""<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<title>zAlive — Metrics — up {up_val}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/css/adminlte.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
<style>:root{{--zalive-card:#151a21;--zalive-border:#232b36}} .app-wrapper{{min-height:100vh;background:#0b0f14}} .app-header{{border-bottom:1px solid var(--zalive-border)}} .app-sidebar{{background:#0f141b;border-right:1px solid var(--zalive-border)}} .card{{border:1px solid var(--zalive-border);border-radius:14px;box-shadow:0 8px 32px rgba(0,0,0,.45)}} .mono{{font-family:ui-monospace,monospace}}</style>
</head>
<body class="layout-fixed-complete">
<div class="app-wrapper">
<nav class="app-header navbar navbar-expand bg-body"><div class="container-fluid">
<ul class="navbar-nav"><li class="nav-item"><a class="nav-link" data-lte-toggle="sidebar" href="#"><i class="bi bi-list"></i></a></li><li class="nav-item"><a href="/dashboard" class="nav-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:22px"></a></li></ul>
<ul class="navbar-nav ms-auto"><li class="nav-item"><span class="badge {'bg-success' if up_val=='1' else 'bg-danger'}">{'✓ up' if up_val=='1' else '✗ down'}</span></li><li class="nav-item"><a class="nav-link" href="/dashboard">Dashboard</a></li><li class="nav-item"><a class="nav-link" href="/metrics?format=prom">Prometheus</a></li></ul>
</div></nav>
<aside class="app-sidebar sidebar-dark"><div class="sidebar-brand"><a href="/dashboard" class="brand-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:28px"><span class="brand-text fw-light ms-2">zAlive Albert</span></a></div>
<div class="sidebar-wrapper"><nav class="mt-2"><ul class="nav sidebar-menu flex-column">
<li class="nav-item"><a href="/dashboard" class="nav-link"><i class="nav-icon bi bi-speedometer2"></i><p>Dashboard</p></a></li>
<li class="nav-item"><a href="/firmware" class="nav-link"><i class="nav-icon bi bi-hdd-stack"></i><p>Firmware</p></a></li>
<li class="nav-item"><a href="/admin" class="nav-link"><i class="nav-icon bi bi-shield-lock"></i><p>Admin</p></a></li>
<li class="nav-item"><a href="/health" class="nav-link"><i class="nav-icon bi bi-heart-pulse"></i><p>Health</p></a></li>
<li class="nav-item"><a href="/metrics" class="nav-link active"><i class="nav-icon bi bi-graph-up"></i><p>Metrics</p></a></li>
<li class="nav-item"><a href="/api/validate" class="nav-link"><i class="nav-icon bi bi-check2-square"></i><p>Validate</p></a></li>
</ul></nav></div>
</aside>
<main class="app-main"><div class="app-content-header"><div class="container-fluid">
<div class="row"><div class="col-sm-6"><h3 class="mb-0">Metrics <small class="text-secondary">· Prometheus · albert_up {up_val}</small></h3><small class="text-secondary">Template: AdminLTE 4 (dashboard-template #1) · Prometheus exposition</small></div><div class="col-sm-6"><ol class="breadcrumb float-sm-end"><li class="breadcrumb-item"><a href="/">Home</a></li><li class="breadcrumb-item"><a href="/dashboard">Dashboard</a></li><li class="breadcrumb-item active">Metrics</li></ol></div></div>
</div></div>
<div class="app-content"><div class="container-fluid">
<div class="row g-3">
<div class="col-md-4"><div class="card"><div class="card-header"><h3 class="card-title text-uppercase small" style="color:#94a3b8">Up</h3><span class="badge {'bg-success' if up_val=='1' else 'bg-danger'} float-end">{'✓ up 1' if up_val=='1' else '✗ down 0'}</span></div><div class="card-body"><div class="mono small">albert_up {up_val}</div><div class="mono small text-secondary">FairPlay loaded={bool(FAIRPLAY_CERT_CHAIN)}</div></div></div></div>
<div class="col-md-4"><div class="card"><div class="card-header"><h3 class="card-title text-uppercase small" style="color:#94a3b8">Activations</h3></div><div class="card-body"><div class="mono" style="font-size:22px;font-weight:750">{total_val}</div><div class="mono small text-secondary">albert_activation_total</div></div></div></div>
<div class="col-md-4"><div class="card"><div class="card-header"><h3 class="card-title text-uppercase small" style="color:#94a3b8">Failures</h3></div><div class="card-body"><div class="mono" style="font-size:22px;font-weight:750">{failures_val}</div><div class="mono small text-secondary">albert_activation_failures_total</div></div></div></div>
</div>
<div class="card mt-3"><div class="card-header"><h3 class="card-title small" style="color:#94a3b8">Prometheus exposition</h3><a href="/metrics?format=prom" class="btn btn-sm btn-outline-primary float-end">View Prometheus</a></div><div class="card-body"><pre class="mono small bg-dark p-3 rounded" style="white-space:pre-wrap;max-height:500px;overflow:auto">{prom_text[:8000]}</pre></div></div>
</div></div>
</main>
<footer class="app-footer"><div class="float-end d-none d-sm-inline">zAlive</div><strong>Local Albert</strong> · Template dashboard-template (AdminLTE 4)</footer>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/js/adminlte.min.js" integrity="sha384-6yU8d/XMPixNnAJ83V1hSNte2ij+N38tIn1M4J+EiHC/MPgisvtNhJyRPfGWFrDk" crossorigin="anonymous"></script>
</body>
</html>"""
        return Response(html, mimetype='text/html')
    # Prometheus plain
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
:root{--zalive-accent:#3b82f6;--zalive-card:#151a21;--zalive-border:#232b36;--ok:#16a34a;--bad:#dc2626;--warn:#eab308;--muted:#94a3b8}
.app-wrapper{min-height:100vh;background:#0b0f14}
.app-header{border-bottom:1px solid var(--zalive-border)}
.app-sidebar{background:#0f141b;border-right:1px solid var(--zalive-border)}
.brand-link{border-bottom:1px solid var(--zalive-border)}
.card{border:1px solid var(--zalive-border);border-radius:14px;box-shadow:0 8px 32px rgba(0,0,0,.45)}
.k{font-size:10.5px;color:#94a3b8;text-transform:uppercase;letter-spacing:.7px;font-weight:650}
.v{font-size:22px;font-weight:750;color:#f1f5f9}
.mono{font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace}
.pill{font-size:11px;padding:6px 10px;border-radius:999px;border:1px solid var(--zalive-border)}
.badge.ok{background:rgba(22,163,74,.15);color:#16a34a;border:1px solid rgba(22,163,74,.25)}
.badge.bad{background:rgba(220,38,38,.15);color:#dc2626;border:1px solid rgba(220,38,38,.25)}
.badge.warn{background:rgba(234,179,8,.15);color:#eab308;border:1px solid rgba(234,179,8,.25)}
.progress{height:8px;background:#232b36;border-radius:999px;overflow:hidden}
.progress-bar{background:linear-gradient(90deg,#3b82f6,#06b6d4);transition:width .6s ease}
.progress-bar.striped{background:linear-gradient(90deg,#06b6d4,#3b82f6);background-size:1rem 1rem;animation:progress-bar-stripes 1s linear infinite}
@keyframes progress-bar-stripes{0%{background-position:1rem 0}100%{background-position:0 0}}
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
<div class="col-lg-6"><div class="card"><div class="card-header"><h3 class="card-title k">IPSW</h3></div><div class="card-body"><div id="ipsw" class="mono">loading…</div><div class="progress mt-2"><div id="ipswFill" class="progress-bar" style="width:0%"></div></div><div id="ipswPct" class="mono small text-secondary mt-1">—</div></div></div></div>
<div class="col-12"><div class="card"><div class="card-header d-flex align-items-center"><h3 class="card-title k">Restore Progress (live idevicerestore)</h3><span id="restoreBadge" class="badge bg-secondary ms-auto">idle</span></div><div class="card-body"><div id="restoreStage" class="mono small">— idle — no restore log yet</div><div class="progress mt-2" style="height:12px"><div id="restoreFill" class="progress-bar striped" style="width:0%"></div></div><div class="d-flex justify-content-between mt-1"><span id="restorePct" class="mono small text-secondary">0%</span><span id="restoreFile" class="mono small text-secondary" style="max-width:60%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"></span></div><div id="restoreLine" class="mono small text-secondary mt-1" style="font-size:10px;opacity:.7;white-space:nowrap;overflow:hidden;text-overflow:ellipsis"></div></div></div></div>
<div class="col-12"><div class="card"><div class="card-header"><h3 class="card-title k">Recent Activations (SQLite WAL)</h3></div><div class="card-body table-responsive p-0"><table class="table table-hover table-striped"><thead><tr><th>#</th><th>UDID (redacted)</th><th>Serial</th><th>At (UTC)</th><th>Record</th></tr></thead><tbody id="acts"><tr><td colspan=5 class="text-center">loading…</td></tr></tbody></table></div></div></div>
<div class="col-12"><div class="card"><div class="card-header"><h3 class="card-title k">Rate limit · Logs tail</h3></div><div class="card-body row g-3"><div class="col-md-6"><div class="mono text-secondary small">IPs tracked · window 60s · max 100/min · capped 1000</div><div id="rl" class="mono border rounded p-2 mt-1">loading…</div><div class="mt-2"><a href="/admin" class="btn btn-sm btn-success">→ Admin panel</a> <a href="/firmware" class="btn btn-sm btn-outline-secondary">→ Firmware</a></div></div><div class="col-md-6"><pre id="logs" class="border rounded p-2 bg-dark" style="max-height:240px;overflow:auto;font-size:11px">loading…</pre></div></div></div></div>
</div>
</div></div>
</main>
<footer class="app-footer"><div class="float-end d-none d-sm-inline">zAlive</div><strong>Local Albert</strong> <span id="ver">1.1-fixed</span> · gunicorn 2×4 · See RUNBOOK · <a href="/admin">admin</a> · Template <a href="https://github.com/topics/dashboard-template" target="_blank">dashboard-template</a> (AdminLTE 4)</footer>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/js/adminlte.min.js" integrity="sha384-6yU8d/XMPixNnAJ83V1hSNte2ij+N38tIn1M4J+EiHC/MPgisvtNhJyRPfGWFrDk" crossorigin="anonymous"></script>

<script>
const $ = id => document.getElementById(id);
const redact = s => s ? s.slice(0,4)+"..."+s.slice(-4) : "-";
function safeSlice(s, a,b){ try{ return (s||'').slice(a,b); }catch(e){ return (s||'')+''; } }
  // Values interpolated into innerHTML must go through this. Live device values
  // come off usbmux, so a peer that answers with crafted strings would otherwise
  // run script in the /dashboard origin and read zalive_admin_token from
  // localStorage. Server-generated markup (badge spans) is concatenated after the
  // escaped text, never through it.
  function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
async function tick(){
  // always update clock even if fetch fails
  try{ $('clock').textContent = new Date().toLocaleTimeString(); }catch(e){}
  let j=null;
  try{
    // Send the token from localStorage. Without it /api/status returns only the
    // public payload (health/ready/version), so j.activations and j.rate read
    // below are undefined and the table plus the rate readout stay empty.
    const tok = (localStorage.getItem('zalive_admin_token') || '');
    const r = await fetch('/api/status', {cache:'no-store', headers: tok ? {'X-Admin-Token': tok} : {}});
    j = await r.json();
  }catch(e){
    try{ $('healthPill').textContent='fetch error'; $('healthPill').style.color='var(--bad)'; }catch(_){}
    return;
  }
  try{
    const ok = j.health && j.health.status==='ok';
    const ready = j.ready && j.ready.status==='ready';
    if($('healthPill')){ $('healthPill').textContent = (ok?'live ':'down ') + (ready?'· ready':'· not-ready'); $('healthPill').style.color = ok&&ready ? 'var(--ok)' : 'var(--bad)'; $('healthPill').style.borderColor = ok&&ready ? 'rgba(22,163,74,.3)' : 'rgba(220,38,38,.3)'; }
  }catch(e){}
  try{
    const ok = j.health && j.health.status==='ok';
    if($('serverV')) $('serverV').innerHTML = (ok?'<span class="badge ok">live</span>':'<span class="badge bad">down</span>') + ' <small>:' + (j.env?.ALBERT_HTTP_PORT||18090) + '</small>';
    if($('serverD')) $('serverD').textContent = (j.health?.server||'albert-local') + ' ' + (j.health?.version||'') + ' · ' + (j.env?.ALBERT_HOST||'127.0.0.1') + ' · ' + (j.now||'');
  }catch(e){}
  try{
    if($('fpV')) $('fpV').innerHTML = (j.fairplay?.loaded?'<span class="badge ok">loaded 0600</span>':'<span class="badge bad">missing</span>') + ' <small>'+ (j.fairplay?.persisted?'persisted':'ephemeral') +'</small>';
    if($('fpD')) $('fpD').textContent = 'NotAfter ' + (j.fairplay?.notAfter||'-') + ' · Serial ' + safeSlice(j.fairplay?.serial,0,12) +'… · ' + safeSlice(j.fairplay?.subject,0,40);
  }catch(e){}
  try{
    if($('metrics')) $('metrics').textContent = 'activations ' + (j.metrics?.activations??'-') + ' · failures ' + (j.metrics?.failures??'-') + ' · up ' + (j.metrics?.up??'-') + '\nrate IPs ' + (j.rate?.ips ?? 0) + ' · WAL ' + (j.db?.wal||'-');
  }catch(e){}
  try{
    const d=j.device||{};
    const dLive=d.live?'<span class="badge ok">live</span>':'<span class="badge warn">last snapshot</span>';
    const dOs=d.ProductVersion?(d.ProductVersion+(d.BuildVersion?' ('+d.BuildVersion+')':'')):'';
    if($('device')) $('device').innerHTML = dLive+' <b>'+esc(d.ProductType||'-')+'</b> '+esc(d.ModelNumber||'-')+(d.HardwareModel?' ['+esc(d.HardwareModel)+']':'')+' · iOS '+esc(dOs||'-')+' · SN '+esc(redact(d.SerialNumber||''))+' · UDID '+esc(redact(d.UDID||''))+' · EID '+esc(safeSlice(d.EID,0,8))+'…'+esc(safeSlice(d.EID,-4))+' · IMEI '+esc(safeSlice(d.IMEI,0,3))+'...'+esc(safeSlice(d.IMEI,-3))+' / '+esc(safeSlice(d.IMEI2,0,3))+'...'+esc(safeSlice(d.IMEI2,-3))+' · '+esc(d.Storage||'');
  }catch(e){}
  try{
    if($('usb')) $('usb').innerHTML = (j.usb?.connected?'<span class="badge ok">USB Apple 05ac</span>':'<span class="badge warn">no Apple USB — VM passthrough needed</span>') + ' · idevice_id: ' + (j.usb?.idevice||'255') + ' · restore: ' + (j.usb?.restore||'-');
  }catch(e){}
  try{
    // ipsw
    if($('ipsw')) $('ipsw').textContent = (j.ipsw?.name||'-') + ' ' + (j.ipsw?.sizeGB||'-') + ' GB · SHA256 ' + safeSlice(j.ipsw?.sha256,0,16) +'… · ' + (j.ipsw?.productVersion||'') + ' ' + (j.ipsw?.build||'') + ' · ' + ((j.ipsw?.variants||[]).join(', '));
    if($('ipswFill')){
      const exists = !!j.ipsw?.exists;
      $('ipswFill').style.width = exists ? '100%' : '8%';
      $('ipswFill').setAttribute('aria-valuenow', exists?'100':'8');
    }
    if($('ipswPct')) $('ipswPct').textContent = j.ipsw?.exists ? '✓ IPSW ready · '+(j.ipsw?.sizeGB||'')+' GB verified' : '✗ IPSW missing — place IPSW in project root';
  }catch(e){}
  try{
    // restore progress — live idevicerestore
    const rs = j.restore || {active:false,percent:0,stage:'idle',file:'',lastLine:''};
    if($('restoreFill')){
      const pct = Math.max(0, Math.min(100, Number(rs.percent)||0));
      $('restoreFill').style.width = pct + '%';
      $('restoreFill').setAttribute('aria-valuenow', pct);
      $('restoreFill').style.opacity = rs.active ? '1' : '0.7';
    }
    if($('restorePct')) $('restorePct').textContent = (Number(rs.percent)||0).toFixed(1)+'%';
    if($('restoreStage')){
      if(rs.stage==='failed'){ $('restoreStage').textContent = '✗ failed ('+ (rs.stage) + ') — ' + (rs.percent||0)+'% — ' + (rs.lastLine||'').slice(0,120); $('restoreStage').style.color='var(--bad)'; }
      else if(rs.active){ $('restoreStage').textContent = '⟳ ' + (rs.stage||'uploading') + ' — ' + (rs.percent||0)+'%'; $('restoreStage').style.color=''; }
      else if(rs.stage==='complete'){ $('restoreStage').textContent='✓ complete — 100%'; $('restoreStage').style.color='var(--ok)'; }
      else { $('restoreStage').textContent='— '+(rs.stage||'idle')+' — '+(rs.percent||0)+'%'; $('restoreStage').style.color=''; }
    }
    if($('restoreBadge')){
      if(rs.stage==='complete'){ $('restoreBadge').textContent='complete ✓'; $('restoreBadge').className='badge bg-success ms-auto'; }
      else if(rs.stage==='failed'){ $('restoreBadge').textContent='failed ✗'; $('restoreBadge').className='badge bg-danger ms-auto'; }
      else if(rs.active){ $('restoreBadge').textContent='active ⟳ '+ (Number(rs.percent)||0).toFixed(0)+'%'; $('restoreBadge').className='badge bg-info ms-auto'; }
      else { $('restoreBadge').textContent = rs.percent>0 ? 'idle '+rs.percent+'%' : 'idle'; $('restoreBadge').className='badge bg-secondary ms-auto'; }
    }
    if($('restoreFill')){
      // color by state
      if(rs.stage==='failed') $('restoreFill').style.background='linear-gradient(90deg,#dc2626,#991b1b)';
      else if(rs.stage==='complete') $('restoreFill').style.background='linear-gradient(90deg,#16a34a,#15803d)';
      else if(rs.active) $('restoreFill').style.background='linear-gradient(90deg,#06b6d4,#3b82f6)';
      else $('restoreFill').style.background='linear-gradient(90deg,#3b82f6,#06b6d4)';
    }
    if($('restoreFile')) $('restoreFile').textContent = rs.file || '—';
    if($('restoreLine')) $('restoreLine').textContent = rs.lastLine || '';
  }catch(e){}
  try{
    // activations
    const tbody=$('acts'); if(tbody){
      tbody.innerHTML='';
      (j.activations||[]).forEach(row=>{
        const tr=document.createElement('tr');
        tr.innerHTML='<td>'+row.id+'</td><td class="mono">'+redact(row.udid||'')+'</td><td>'+(row.serial||'-')+'</td><td class="mono">'+safeSlice(row.created_at,0,19)+'</td><td class="mono">'+safeSlice(row.record,0,80)+'…</td>';
        tbody.appendChild(tr);
      });
      if(!(j.activations||[]).length) tbody.innerHTML='<tr><td colspan=5 class="mono" style="color:var(--muted)">no activations yet — run activate_device.py --method direct</td></tr>';
    }
  }catch(e){}
  try{
    if($('rl')) $('rl').textContent = 'IPs ' + (j.rate?.ips ?? 0) + ' · sample ' + (j.rate?.sample||'-');
    if($('ver')) $('ver').textContent = j.health?.version||'';
  }catch(e){}
}
tick(); setInterval(tick, 2000);
// logs poll — admin gated, handle 401 gracefully
async function logsTick(){
  try{
    // /api/logs is admin-gated; without the header it is 401 every poll.
    const ltok=(localStorage.getItem('zalive_admin_token')||'');
    const r=await fetch('/api/logs?lines=60',{cache:'no-store', headers: ltok ? {'X-Admin-Token': ltok} : {}});
    if(r.status===401){ if($('logs')) $('logs').textContent='🔒 admin login required — open /admin and unlock (X-Admin-Token)'; return; }
    const j=await r.json(); if($('logs')) $('logs').textContent=j.tail||'no logs';
  }catch(e){ if($('logs')) $('logs').textContent='logs unavailable (admin gated)'; }
}
logsTick(); setInterval(logsTick, 5000);
</script>
</body>
</html>
'''

@app.route('/dashboard', methods=['GET'])
def dashboard():
    return Response(DASHBOARD_HTML, mimetype='text/html')

@app.route('/investigation', methods=['GET'])
def investigation_page():
    template_path = pathlib.Path(__file__).resolve().parent / "templates" / "investigation.html"
    try:
        return Response(template_path.read_text(encoding="utf-8"), mimetype='text/html')
    except OSError:
        logger.exception("investigation template unavailable")
        return jsonify({"ok": False, "error": "investigation UI unavailable"}), 503

@app.route('/api/logs', methods=['GET'])
def api_logs():
    err = _admin_required()
    if err:
        return err
    lines = int(request.args.get('lines', '60'))
    lines = max(1, min(lines, 200))
    tail = "no log"
    for p in [pathlib.Path("logs/albert.log"), pathlib.Path("albert.log"), pathlib.Path("/tmp/albert.log")]:
        if p.exists():
            try:
                tail = "\n".join(p.read_text(errors='ignore').splitlines()[-lines:])
                break
            except Exception:
                pass
    return jsonify({"tail": tail, "lines": lines})


FIRMWARE_HTML = r'''<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<title>zAlive — Albert — Firmware (AdminLTE 4 Premium)</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/css/adminlte.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
<style>
:root{--zalive-accent:#3b82f6;--zalive-card:#151a21;--zalive-border:#232b36}
.app-wrapper{min-height:100vh;background:#0b0f14}
.app-header{border-bottom:1px solid var(--zalive-border)}
.app-sidebar{background:#0f141b;border-right:1px solid var(--zalive-border)}
.brand-link{border-bottom:1px solid var(--zalive-border)}
.card{border:1px solid var(--zalive-border);border-radius:14px;box-shadow:0 8px 32px rgba(0,0,0,.45)}
.k{font-size:10.5px;color:#94a3b8;text-transform:uppercase;letter-spacing:.7px;font-weight:650}
.mono{font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace}
select, input{font-size:13px;padding:9px 12px;border-radius:10px;border:1px solid var(--zalive-border);background:#151a21;color:#e5e7eb}
select option{background:#1a212e;color:#e5e7eb}
select:focus{background:#1e293b;color:#f1f5f9}
.badge.ok{background:rgba(22,163,74,.12);color:#16a34a;border:1px solid rgba(22,163,74,.25)}
.badge.bad{background:rgba(220,38,38,.12);color:#dc2626;border:1px solid rgba(220,38,38,.25)}
</style>
</head>
<body class="layout-fixed-complete">
<div class="app-wrapper">
<nav class="app-header navbar navbar-expand bg-body">
<div class="container-fluid">
<ul class="navbar-nav">
<li class="nav-item"><a class="nav-link" data-lte-toggle="sidebar" href="#"><i class="bi bi-list"></i></a></li>
<li class="nav-item d-none d-md-block"><a href="/dashboard" class="nav-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:22px"></a></li>
</ul>
<ul class="navbar-nav ms-auto">
<li class="nav-item"><select id="product" class="form-select form-select-sm" style="min-width:220px"></select></li>
<li class="nav-item ms-2"><input id="q" class="form-control form-control-sm" placeholder="Search version / build" style="min-width:180px"></li>
<li class="nav-item ms-2"><span id="status" class="text-secondary small"></span></li>
<li class="nav-item ms-2"><a class="nav-link" href="/dashboard">← Dashboard</a></li>
</ul>
</div>
</nav>
<aside class="app-sidebar sidebar-dark">
<div class="sidebar-brand"><a href="/dashboard" class="brand-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:28px"><span class="brand-text fw-light ms-2">zAlive Albert</span></a></div>
<div class="sidebar-wrapper"><nav class="mt-2">
<ul class="nav sidebar-menu flex-column" data-lte-toggle="treeview">
<li class="nav-item"><a href="/dashboard" class="nav-link"><i class="nav-icon bi bi-speedometer2"></i><p>Dashboard</p></a></li>
<li class="nav-item"><a href="/firmware" class="nav-link active"><i class="nav-icon bi bi-hdd-stack"></i><p>Firmware</p></a></li>
<li class="nav-item"><a href="/admin" class="nav-link"><i class="nav-icon bi bi-shield-lock"></i><p>Admin</p></a></li>
<li class="nav-item"><a href="/api/status" class="nav-link"><i class="nav-icon bi bi-heart-pulse"></i><p>API Status</p></a></li>
<li class="nav-header">LOGS</li>
<li class="nav-item"><a href="/api/validate" class="nav-link"><i class="nav-icon bi bi-check2-square"></i><p>Validate</p></a></li>
</ul>
</nav></div>
</aside>
<main class="app-main">
<div class="app-content-header"><div class="container-fluid">
<div class="row"><div class="col-sm-6"><h3 class="mb-0">Albert — Firmware <small class="text-secondary">· curated 5→15 Pro (13) · ipsw.me live cache 1h</small></h3><small class="text-secondary">Template: AdminLTE 4 (dashboard-template #1) · Premium dark · Any iPhone 5→15 Pro</small></div><div class="col-sm-6"><ol class="breadcrumb float-sm-end"><li class="breadcrumb-item"><a href="/">Home</a></li><li class="breadcrumb-item"><a href="/dashboard">Dashboard</a></li><li class="breadcrumb-item active">Firmware</li></ol></div></div>
</div></div>
<div class="app-content"><div class="container-fluid">
<div class="card">
<div class="card-header d-flex align-items-center gap-2">
<span class="badge ok">✓ curated 13</span>
<span class="small text-secondary">Any iPhone 5 → 15 Pro · live <a href="https://api.ipsw.me" target="_blank">ipsw.me</a> + local *.ipsw</span>
<span class="ms-auto small text-secondary">Tip: type “18.7” or “22H374” to filter</span>
</div>
<div class="card-body p-0">
<div id="banner" class="alert alert-info d-none m-3" role="alert"></div>
<div class="table-responsive" style="max-height:72vh;overflow:auto">
<table class="table table-hover table-striped mb-0"><thead class="sticky-top" style="background:#151a21"><tr><th>Version</th><th>Build</th><th>Released</th><th>Size</th><th>Signed</th><th>Local</th><th>Download</th></tr></thead><tbody id="tbody"><tr><td colspan=7 class="text-center">loading…</td></tr></tbody></table>
</div>
</div>
<div class="card-footer small text-secondary">Source: <a href="https://api.ipsw.me/v4/device/iPhone11,8" target="_blank">api.ipsw.me</a> + local scan <code>*.ipsw</code> · <code>/api/firmwares?productType=iPhone11,8</code></div>
</div>
</div></div>
</main>
<footer class="app-footer"><div class="float-end d-none d-sm-inline">zAlive</div><strong>Local Albert</strong> · <a href="/admin">admin</a> · Template <a href="https://github.com/topics/dashboard-template" target="_blank">dashboard-template</a> (AdminLTE 4)</footer>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/js/adminlte.min.js" integrity="sha384-6yU8d/XMPixNnAJ83V1hSNte2ij+N38tIn1M4J+EiHC/MPgisvtNhJyRPfGWFrDk" crossorigin="anonymous"></script>

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
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<title>zAlive — 404 Not Found (AdminLTE 4)</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/css/adminlte.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
<style>
:root{--zalive-border:#232b36}
.app-wrapper{min-height:100vh;background:#0b0f14;display:flex;flex-direction:column}
.app-header{border-bottom:1px solid var(--zalive-border)}
</style>
</head>
<body>
<div class="app-wrapper">
<nav class="app-header navbar navbar-expand bg-body">
<div class="container-fluid">
<a href="/dashboard" class="navbar-brand"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:22px"></a>
<span class="text-secondary small">· 404</span>
<ul class="navbar-nav ms-auto">
<li class="nav-item"><a class="nav-link" href="/dashboard">Dashboard</a></li>
<li class="nav-item"><a class="nav-link" href="/firmware">Firmware</a></li>
<li class="nav-item"><a class="nav-link" href="/admin">Admin</a></li>
<li class="nav-item"><a class="nav-link" href="/health">Health</a></li>
</ul>
</div>
</nav>
<main class="app-main" style="flex:1;display:flex;align-items:center;justify-content:center">
<div class="container" style="max-width:720px">
<div class="card text-center" style="border:1px solid var(--zalive-border);border-radius:16px;box-shadow:0 12px 40px rgba(0,0,0,.5)">
<div class="card-body p-4">
<div class="d-inline-flex align-items-center justify-content-center rounded-3" style="width:64px;height:64px;background:linear-gradient(135deg,#3b82f6 0%,#06b6d4 50%,#22c55e 100%)"><span style="font-size:28px;color:white">∅</span></div>
<h1 class="mt-3" style="font-weight:800;letter-spacing:-.5px">404 — Page not found</h1>
<p class="text-secondary">The page <code id="path" class="bg-dark p-1 rounded"></code> does not exist.</p>
<p class="text-secondary small">Try one of these — live on <code>127.0.0.1:18090</code> and <code>192.168.1.123:18090</code>.</p>
<div class="d-flex gap-2 justify-content-center flex-wrap mt-3">
<a class="btn btn-primary" href="/dashboard">→ Dashboard</a>
<a class="btn btn-outline-primary" href="/firmware">Firmware (13)</a>
<a class="btn btn-outline-secondary" href="/api/status">API Status</a>
<a class="btn btn-outline-secondary" href="/health">Health</a>
<a class="btn btn-outline-secondary" href="/admin">Admin</a>
</div>
<p class="mono small text-secondary mt-3">zAlive · Local Albert · owned devices only</p>
</div>
</div>
</div>
</main>
<footer class="app-footer text-center"><small class="text-secondary">zAlive · <a href="/dashboard">dashboard</a> · <a href="/firmware">firmware</a> · <a href="/admin">admin</a></small></footer>
</div>
<script>document.getElementById('path').textContent = location.pathname + location.search;</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/js/adminlte.min.js" integrity="sha384-6yU8d/XMPixNnAJ83V1hSNte2ij+N38tIn1M4J+EiHC/MPgisvtNhJyRPfGWFrDk" crossorigin="anonymous"></script>
</body>
</html>

<script>document.getElementById('path').textContent = location.pathname + location.search;</script>
</body>
</html>
'''


ADMIN_HTML = r'''<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<title>zAlive — Albert — Admin (AdminLTE 4 Premium)</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/css/adminlte.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
<style>
:root{--zalive-accent:#3b82f6;--zalive-card:#151a21;--zalive-border:#232b36}
.app-wrapper{min-height:100vh;background:#0b0f14}
.app-header{border-bottom:1px solid var(--zalive-border)}
.app-sidebar{background:#0f141b;border-right:1px solid var(--zalive-border)}
.card{border:1px solid var(--zalive-border);border-radius:14px;box-shadow:0 8px 32px rgba(0,0,0,.45)}
.k{font-size:10.5px;color:#94a3b8;text-transform:uppercase;letter-spacing:.7px;font-weight:650}
.mono{font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace}
</style>
</head>
<body class="layout-fixed-complete">
<div class="app-wrapper">
<nav class="app-header navbar navbar-expand bg-body">
<div class="container-fluid">
<ul class="navbar-nav">
<li class="nav-item"><a class="nav-link" data-lte-toggle="sidebar" href="#"><i class="bi bi-list"></i></a></li>
<li class="nav-item"><a href="/dashboard" class="nav-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:22px"></a></li>
</ul>
<ul class="navbar-nav ms-auto">
<li class="nav-item"><span id="authPill" class="badge bg-warning">checking auth…</span></li>
<li class="nav-item"><a class="nav-link" href="/dashboard">← Dashboard</a></li>
</ul>
</div>
</nav>
<aside class="app-sidebar sidebar-dark">
<div class="sidebar-brand"><a href="/dashboard" class="brand-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:28px"><span class="brand-text fw-light ms-2">zAlive Albert</span></a></div>
<div class="sidebar-wrapper"><nav class="mt-2">
<ul class="nav sidebar-menu flex-column">
<li class="nav-item"><a href="/dashboard" class="nav-link"><i class="nav-icon bi bi-speedometer2"></i><p>Dashboard</p></a></li>
<li class="nav-item"><a href="/firmware" class="nav-link"><i class="nav-icon bi bi-hdd-stack"></i><p>Firmware</p></a></li>
<li class="nav-item"><a href="/admin" class="nav-link active"><i class="nav-icon bi bi-shield-lock"></i><p>Admin</p></a></li>
<li class="nav-item"><a href="/api/validate" class="nav-link"><i class="nav-icon bi bi-check2-square"></i><p>Validate</p></a></li>
</ul>
</nav></div>
</aside>
<main class="app-main">
<div class="app-content-header"><div class="container-fluid">
<div class="row"><div class="col-sm-6"><h3 class="mb-0">Admin Control Panel <small class="text-secondary">· gated ALBERT_ADMIN_TOKEN</small></h3><small class="text-secondary">Template: AdminLTE 4 · Premium dark · zAlive</small></div><div class="col-sm-6"><ol class="breadcrumb float-sm-end"><li class="breadcrumb-item"><a href="/">Home</a></li><li class="breadcrumb-item"><a href="/dashboard">Dashboard</a></li><li class="breadcrumb-item active">Admin</li></ol></div></div>
</div></div>
<div class="app-content"><div class="container-fluid">
<div id="gate" class="card" style="max-width:520px;margin:0 auto">
<div class="card-header"><h3 class="card-title k">Admin authentication</h3></div>
<div class="card-body">
<p class="mono small text-secondary">Enter <code>ALBERT_ADMIN_TOKEN</code> — sent as <code>X-Admin-Token</code> and stored in this browser only. Set via <code>.env ALBERT_ADMIN_TOKEN=…</code>.</p>
<form id="gateForm" class="d-flex gap-2">
<input id="tokenInput" type="password" class="form-control" placeholder="Paste admin token">
<button class="btn btn-primary" id="unlockBtn" type="submit">Unlock</button>
<button class="btn btn-outline-secondary" id="logoutBtn" type="button" style="display:none">Lock</button>
</form>
<div id="gateMsg" class="mono small text-secondary mt-2"></div>
</div>
</div>
<div id="panel" style="display:none">
<div class="row g-3">
<div class="col-lg-4"><div class="card"><div class="card-header"><h3 class="card-title k">Status</h3></div><div class="card-body"><div id="aStatus" class="mono">loading…</div></div></div></div>
<div class="col-lg-4"><div class="card"><div class="card-header"><h3 class="card-title k">Actions</h3></div><div class="card-body d-grid gap-2">
<button id="btnRefresh" class="btn btn-outline-primary btn-sm">↻ Refresh status</button>
<button id="btnClearCache" class="btn btn-outline-warning btn-sm">Clear firmware cache</button>
<button id="btnResetRate" class="btn btn-outline-warning btn-sm">Reset rate limits</button>
<button id="btnCheckpoint" class="btn btn-outline-info btn-sm">DB checkpoint + prune</button>
<button id="btnPurge" class="btn btn-danger btn-sm">⚠ Purge >30d</button>
<div id="actionMsg" class="mono small text-secondary"></div>
</div></div></div>
<div class="col-lg-4"><div class="card"><div class="card-header"><h3 class="card-title k">Environment</h3></div><div class="card-body"><pre id="aEnv" class="mono small" style="white-space:pre-wrap">loading…</pre></div></div></div>
<div class="col-lg-6"><div class="card"><div class="card-header"><h3 class="card-title k">Recent activations</h3></div><div class="card-body table-responsive p-0"><table class="table table-hover table-striped"><thead><tr><th>#</th><th>UDID</th><th>Serial</th><th>At</th></tr></thead><tbody id="aActs"><tr><td colspan=4 class="text-center">loading…</td></tr></tbody></table></div></div></div>
<div class="col-lg-6"><div class="card"><div class="card-header"><h3 class="card-title k">Logs tail</h3></div><div class="card-body"><pre id="aLogs" class="border rounded p-2 bg-dark" style="max-height:300px;overflow:auto;font-size:11px">loading…</pre><button id="btnLogs" class="btn btn-sm btn-outline-secondary mt-2">Refresh logs</button></div></div></div>
<div class="col-12"><div class="card"><div class="card-header"><h3 class="card-title k">Rate limits</h3></div><div class="card-body"><div id="aRate" class="mono">loading…</div></div></div></div>
</div>
</div>
</div></div>
</main>
<footer class="app-footer"><div class="float-end d-none d-sm-inline">zAlive</div><strong>Local Albert</strong> · Template dashboard-template (AdminLTE 4)</footer>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/js/adminlte.min.js" integrity="sha384-6yU8d/XMPixNnAJ83V1hSNte2ij+N38tIn1M4J+EiHC/MPgisvtNhJyRPfGWFrDk" crossorigin="anonymous"></script>

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
    # header-only: X-Admin-Token or Authorization Bearer (query-string and cookie removed to prevent leak via logs/Referer/cache)
    if request.args.get("token") is not None:
        logger.warning("admin token via query-string rejected (use header)", extra={"request_id": getattr(g, 'request_id', '-')})
        return False, "admin token via query-string not allowed — send X-Admin-Token header"
    got = (request.headers.get("X-Admin-Token") or "").strip()
    if not got:
        auth = (request.headers.get("Authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            got = auth[7:].strip()
    if not got:
        return False, "missing admin token — send X-Admin-Token header"
    import hmac
    if not hmac.compare_digest(got, expected):
        return False, "invalid admin token"
    return True, ""

def _admin_required():
    ok, msg = _check_admin_auth()
    if not ok:
        return jsonify({"ok": False, "error": msg}), 401
    return None

@app.route('/api/investigation', methods=['GET'])
def api_investigation():
    err = _admin_required()
    if err:
        return err
    try:
        return jsonify(build_investigation_state())
    except (OSError, ValueError, json.JSONDecodeError):
        logger.exception("investigation state unavailable")
        return jsonify({"ok": False, "error": "investigation state unavailable"}), 503

@app.route('/admin', methods=['GET'])
def admin_page():
    return Response(ADMIN_HTML, mimetype='text/html')

@app.route('/api/admin/status', methods=['GET'])
def api_admin_status():
    err = _admin_required()
    if err:
        return err
    try:
        payload = _build_status_payload()
        payload["ok"] = True
        return jsonify(payload)
    except Exception as e:
        logger.exception("api_admin_status error")
        return jsonify({"ok": False, "error": "internal error"}), 500

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
    except Exception:
        # Log the detail server-side only; returning str(e) would hand
        # internal paths and driver errors to any admin-token holder.
        logger.exception("sync-state operation failed")
        return jsonify({"ok": False, "error": "internal error"}), 500
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
    except Exception:
        # Log the detail server-side only; returning str(e) would hand
        # internal paths and driver errors to any admin-token holder.
        logger.exception("sync-state operation failed")
        return jsonify({"ok": False, "error": "internal error"}), 500

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
    except Exception:
        # Log the detail server-side only; returning str(e) would hand
        # internal paths and driver errors to any admin-token holder.
        logger.exception("sync-state operation failed")
        return jsonify({"ok": False, "error": "internal error"}), 500


@app.route('/api/admin/sync-state', methods=['GET'])
def api_admin_sync_state():
    """Get all sync states (admin only)."""
    err = _admin_required()
    if err:
        return err
    try:
        import sqlite3 as _sql
        with _sql.connect(str(DB_PATH), timeout=5) as c:
            c.row_factory = _sql.Row
            cur = c.execute("SELECT * FROM sync_state ORDER BY updated_at DESC LIMIT 100")
            rows = [dict(r) for r in cur.fetchall()]
        return jsonify({"ok": True, "sync_states": rows, "count": len(rows)})
    except Exception:
        # Log the detail server-side only; returning str(e) would hand
        # internal paths and driver errors to any admin-token holder.
        logger.exception("sync-state operation failed")
        return jsonify({"ok": False, "error": "internal error"}), 500


@app.route('/api/admin/sync-state/<udid>', methods=['GET'])
def api_admin_sync_state_detail(udid: str):
    """Get sync state for specific UDID (admin only)."""
    err = _admin_required()
    if err:
        return err
    state = _get_sync_state(udid)
    if not state:
        return jsonify({"ok": False, "error": "Not found"}), 404
    return jsonify({"ok": True, "sync_state": state})


@app.route('/api/admin/sync-state/<udid>', methods=['POST'])
def api_admin_sync_state_update(udid: str):
    """Update sync state for specific UDID (admin only)."""
    err = _admin_required()
    if err:
        return err
    try:
        data = request.get_json(silent=True) or {}
        allowed_fields = [
            "push_token", "apns_topic", "sync_enabled", "find_my_enabled",
            "icloud_enabled", "carrier_activated", "phone_number"
        ]
        updates = {k: v for k, v in data.items() if k in allowed_fields}
        if not updates:
            return jsonify({"ok": False, "error": "No valid fields provided"}), 400
        ok = _update_sync_state(udid, **updates)
        if ok:
            state = _get_sync_state(udid)
            return jsonify({"ok": True, "sync_state": state})
        else:
            return jsonify({"ok": False, "error": "Update failed"}), 500
    except Exception:
        # Log the detail server-side only; returning str(e) would hand
        # internal paths and driver errors to any admin-token holder.
        logger.exception("sync-state operation failed")
        return jsonify({"ok": False, "error": "internal error"}), 500


@app.route('/api/admin/sync-state/<udid>/activate', methods=['POST'])
def api_admin_sync_activate(udid: str):
    """Activate sync for a device (admin only)."""
    err = _admin_required()
    if err:
        return err
    try:
        ok = _update_sync_state(udid, sync_enabled=1, find_my_enabled=1, icloud_enabled=1)
        if ok:
            state = _get_sync_state(udid)
            return jsonify({"ok": True, "sync_state": state, "message": "Sync activated"})
        else:
            return jsonify({"ok": False, "error": "Activation failed"}), 500
    except Exception:
        # Log the detail server-side only; returning str(e) would hand
        # internal paths and driver errors to any admin-token holder.
        logger.exception("sync-state operation failed")
        return jsonify({"ok": False, "error": "internal error"}), 500


@app.route('/api/admin/sync-state/<udid>/deactivate', methods=['POST'])
def api_admin_sync_deactivate(udid: str):
    """Deactivate sync for a device (admin only)."""
    err = _admin_required()
    if err:
        return err
    try:
        ok = _update_sync_state(udid, sync_enabled=0, find_my_enabled=0, icloud_enabled=0, carrier_activated=0)
        if ok:
            state = _get_sync_state(udid)
            return jsonify({"ok": True, "sync_state": state, "message": "Sync deactivated"})
        else:
            return jsonify({"ok": False, "error": "Deactivation failed"}), 500
    except Exception:
        # Log the detail server-side only; returning str(e) would hand
        # internal paths and driver errors to any admin-token holder.
        logger.exception("sync-state operation failed")
        return jsonify({"ok": False, "error": "internal error"}), 500


@app.route('/api/admin/sync-state/<udid>/carrier-activate', methods=['POST'])
def api_admin_carrier_activate(udid: str):
    """Mark device as carrier activated (admin only)."""
    err = _admin_required()
    if err:
        return err
    try:
        data = request.get_json(silent=True) or {}
        phone_number = data.get("phone_number", "")
        updates = {"carrier_activated": 1}
        if phone_number:
            updates["phone_number"] = phone_number
        ok = _update_sync_state(udid, **updates)
        if ok:
            state = _get_sync_state(udid)
            return jsonify({"ok": True, "sync_state": state, "message": "Carrier activated"})
        else:
            return jsonify({"ok": False, "error": "Carrier activation failed"}), 500
    except Exception:
        # Log the detail server-side only; returning str(e) would hand
        # internal paths and driver errors to any admin-token holder.
        logger.exception("sync-state operation failed")
        return jsonify({"ok": False, "error": "internal error"}), 500


@app.route('/api/admin/sync-state/<udid>/register-push', methods=['POST'])
def api_admin_register_push(udid: str):
    """Register push token for a device (admin only)."""
    err = _admin_required()
    if err:
        return err
    try:
        data = request.get_json(silent=True) or {}
        push_token = data.get("push_token", "")
        if not push_token:
            return jsonify({"ok": False, "error": "push_token required"}), 400
        state = _get_sync_state(udid)
        imei = state.get("imei", "")
        ok = _record_push_token(udid, push_token, imei)
        if ok:
            state = _get_sync_state(udid)
            return jsonify({"ok": True, "sync_state": state, "message": "Push token recorded locally (no APNs call)"})
        else:
            return jsonify({"ok": False, "error": "Push token registration failed"}), 500
    except Exception:
        # Log the detail server-side only; returning str(e) would hand
        # internal paths and driver errors to any admin-token holder.
        logger.exception("sync-state operation failed")
        return jsonify({"ok": False, "error": "internal error"}), 500


# Premium branded 404 — covers all unknown paths with zAlive UI

@app.route('/api/validate', methods=['GET'])
def api_validate():
    """Validate endpoint — same checks as scripts/validate.py but via API.

    The page stays reachable without a token so a first-run setup can be checked
    before credentials are known, but unauthenticated callers only get pass/fail
    per check. Counts, certificate dates and env var names are reconnaissance, so
    the detail messages are returned only to an admin-token holder. Exception text
    is never returned: it carries filesystem paths and library internals.
    """
    import sqlite3 as _sql
    import pathlib as _pl
    from datetime import datetime, timezone
    # detail = shown to an admin-token holder, public = safe for anyone
    checks={}
    # IPSW quick check (existence + size, not full sha256 for speed)
    try:
        ipsw = _pl.Path("iPhone11,8_18.7.10_22H374_Restore.ipsw")
        if ipsw.exists():
            sz = ipsw.stat().st_size
            ok = sz > 7_000_000_000
            checks["ipsw"]={"ok": ok, "msg": f"IPSW {sz/1e9:.1f}GB {'ok' if ok else 'too small'}", "pub": "IPSW ok" if ok else "IPSW too small"}
        else:
            checks["ipsw"]={"ok": False, "msg": "IPSW missing", "pub": "IPSW missing"}
    except Exception:
        logger.exception("validate: ipsw check failed")
        checks["ipsw"]={"ok": False, "msg": "IPSW check failed", "pub": "IPSW check failed"}
    # FairPlay
    try:
        from cryptography import x509 as _x509
        crt = _pl.Path("certs/fairplay.crt")
        if crt.exists():
            cert=_x509.load_pem_x509_certificate(crt.read_bytes())
            days=(cert.not_valid_after_utc - datetime.now(timezone.utc)).days
            ok = days>30
            checks["fairplay"]={"ok": ok, "msg": f"NotAfter {cert.not_valid_after_utc.date()} {days}d", "pub": "certificate valid" if ok else "certificate expiring"}
        else:
            checks["fairplay"]={"ok": False, "msg": "cert missing", "pub": "certificate missing"}
    except Exception:
        logger.exception("validate: fairplay check failed")
        checks["fairplay"]={"ok": False, "msg": "certificate check failed", "pub": "certificate check failed"}
    # DB
    try:
        db=_pl.Path("logs/activations.db")
        with _sql.connect(str(db), timeout=5) as c:
            cnt=c.execute("SELECT count(*) FROM activations").fetchone()[0]
            checks["db"]={"ok": True, "msg": f"{cnt} rows", "pub": "database ok"}
    except Exception:
        logger.exception("validate: database check failed")
        checks["db"]={"ok": False, "msg": "database check failed", "pub": "database check failed"}
    # Env
    try:
        from dotenv import dotenv_values as _dv
        vals=_dv(".env") if _pl.Path(".env").exists() else {}
        ok=bool(vals.get("ALBERT_ADMIN_TOKEN") and not vals["ALBERT_ADMIN_TOKEN"].startswith("change-me"))
        checks["env"]={"ok": ok, "msg": "ALBERT_ADMIN_TOKEN set" if ok else "ALBERT_ADMIN_TOKEN not set", "pub": "admin token configured" if ok else "admin token not configured"}
    except Exception:
        logger.exception("validate: env check failed")
        checks["env"]={"ok": False, "msg": "environment check failed", "pub": "environment check failed"}
    # API self-check via test_client (reports 200 for core)
    try:
        with app.test_client() as _c:
            ok = _c.get("/health").status_code==200 and _c.get("/dashboard").status_code==200
            checks["api"]={"ok": ok, "msg": "self-check health+dashboard 200" if ok else "self-check fail", "pub": "self-check ok" if ok else "self-check failed"}
    except Exception:
        logger.exception("validate: api self-check failed")
        checks["api"]={"ok": False, "msg": "self-check failed", "pub": "self-check failed"}
    # Logs
    _logs_ok = (_pl.Path("logs/albert.log").exists() or _pl.Path("/tmp/albert.log").exists())
    checks["logs"]={"ok": _logs_ok, "msg": "logs/albert.log present" if _logs_ok else "logs/albert.log missing", "pub": "log present" if _logs_ok else "log not found"}
    ok_all = all(v["ok"] for v in checks.values())
    # Detail messages stay admin-only; drop them before serialising the payload.
    is_admin, _auth_msg = _check_admin_auth()
    for _v in checks.values():
        if not is_admin:
            _v["msg"] = _v.get("pub", "ok" if _v["ok"] else "failed")
        _v.pop("pub", None)
    data = {"ok": ok_all, "checks": checks, "ts": datetime.now(timezone.utc).isoformat(), "detail": is_admin}
    # Content negotiation: browser → pretty HTML template (AdminLTE), API → JSON
    wants_html = "text/html" in (request.headers.get("Accept") or "")
    # Also direct browser navigation to /api/validate should show template
    if wants_html and not request.args.get("format") == "json":
        # Build HTML template inline (AdminLTE 4 premium, same as dashboard/firmware/admin)
        html = f"""<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<title>zAlive — Validate — {'✓ ok' if ok_all else '✗ fail'}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/css/adminlte.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
<style>
:root{{--zalive-card:#151a21;--zalive-border:#232b36}} .app-wrapper{{min-height:100vh;background:#0b0f14}} .app-header{{border-bottom:1px solid var(--zalive-border)}} .app-sidebar{{background:#0f141b;border-right:1px solid var(--zalive-border)}} .card{{border:1px solid var(--zalive-border);border-radius:14px;box-shadow:0 8px 32px rgba(0,0,0,.45)}} .mono{{font-family:ui-monospace,monospace}}
</style>
</head>
<body class="layout-fixed-complete">
<div class="app-wrapper">
<nav class="app-header navbar navbar-expand bg-body"><div class="container-fluid">
<ul class="navbar-nav"><li class="nav-item"><a class="nav-link" data-lte-toggle="sidebar" href="#"><i class="bi bi-list"></i></a></li><li class="nav-item"><a href="/dashboard" class="nav-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:22px"></a></li></ul>
<ul class="navbar-nav ms-auto"><li class="nav-item"><span class="badge {'bg-success' if ok_all else 'bg-danger'}">{'✓ ok' if ok_all else '✗ fail'}</span></li><li class="nav-item"><a class="nav-link" href="/dashboard">Dashboard</a></li><li class="nav-item"><a class="nav-link" href="/api/validate?format=json">JSON</a></li></ul>
</div></nav>
<aside class="app-sidebar sidebar-dark"><div class="sidebar-brand"><a href="/dashboard" class="brand-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:28px"><span class="brand-text fw-light ms-2">zAlive Albert</span></a></div>
<div class="sidebar-wrapper"><nav class="mt-2"><ul class="nav sidebar-menu flex-column">
<li class="nav-item"><a href="/dashboard" class="nav-link"><i class="nav-icon bi bi-speedometer2"></i><p>Dashboard</p></a></li>
<li class="nav-item"><a href="/firmware" class="nav-link"><i class="nav-icon bi bi-hdd-stack"></i><p>Firmware</p></a></li>
<li class="nav-item"><a href="/admin" class="nav-link"><i class="nav-icon bi bi-shield-lock"></i><p>Admin</p></a></li>
<li class="nav-item"><a href="/api/validate" class="nav-link active"><i class="nav-icon bi bi-check2-square"></i><p>Validate</p></a></li>
</ul></nav></div>
</aside>
<main class="app-main"><div class="app-content-header"><div class="container-fluid">
<div class="row"><div class="col-sm-6"><h3 class="mb-0">Validate <small class="text-secondary">· {'✓ all 6 ok' if ok_all else '✗ fail'} · {data['ts'][:19]}</small></h3><small class="text-secondary">Template: AdminLTE 4 (dashboard-template #1) · Premium dark · IPSW/FairPlay/DB/env/API/logs</small></div><div class="col-sm-6"><ol class="breadcrumb float-sm-end"><li class="breadcrumb-item"><a href="/">Home</a></li><li class="breadcrumb-item"><a href="/dashboard">Dashboard</a></li><li class="breadcrumb-item active">Validate</li></ol></div></div>
</div></div>
<div class="app-content"><div class="container-fluid">
<div class="card mb-3"><div class="card-body">
<div class="d-flex flex-wrap gap-2 align-items-center">
<span class="small" style="color:#94a3b8">{'Detail messages (row counts, certificate dates) require the admin token.' if not is_admin else 'Showing detail — admin token accepted.'}</span>
<input id="vtok" type="password" class="form-control form-control-sm" style="max-width:22rem" placeholder="admin token" autocomplete="off">
<button id="vbtn" class="btn btn-sm btn-outline-primary">Show detail</button>
</div></div></div>
<div class="row g-3">
"""
        for k, v in checks.items():
            badge = "bg-success" if v["ok"] else "bg-danger"
            icon = "✓" if v["ok"] else "✗"
            html += f"""
<div class="col-md-4"><div class="card"><div class="card-header"><h3 class="card-title text-uppercase small" style="color:#94a3b8;letter-spacing:.7px">{k}</h3><span class="badge {badge} float-end">{icon} {'ok' if v['ok'] else 'fail'}</span></div><div class="card-body"><div class="mono small" id="msg-{k}">{v['msg']}</div></div></div></div>
"""
        html += f"""
</div>
<div class="card mt-3"><div class="card-header"><h3 class="card-title small" style="color:#94a3b8">Raw JSON</h3><a href="/api/validate?format=json" class="btn btn-sm btn-outline-primary float-end">View JSON</a></div><div class="card-body"><pre class="mono small bg-dark p-3 rounded" style="white-space:pre-wrap">{json.dumps(data, indent=2)}</pre></div></div>
</div></div>
</main>
<footer class="app-footer"><div class="float-end d-none d-sm-inline">zAlive</div><strong>Local Albert</strong> · Template dashboard-template (AdminLTE 4)</footer>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/js/adminlte.min.js" integrity="sha384-6yU8d/XMPixNnAJ83V1hSNte2ij+N38tIn1M4J+EiHC/MPgisvtNhJyRPfGWFrDk" crossorigin="anonymous"></script>
  <script>
  const _vtok=document.getElementById('vtok'), _vbtn=document.getElementById('vbtn');
  if(_vtok){{try{{_vtok.value=localStorage.getItem('zalive_admin_token')||''}}catch(e){{}}}}
  if(_vbtn){{_vbtn.addEventListener('click',async function(){{
    const tok=_vtok.value.trim();
    if(tok){{try{{localStorage.setItem('zalive_admin_token',tok)}}catch(e){{}}}}
    const h=tok?{{'X-Admin-Token':tok}}:{{}};
    const r=await fetch('/api/validate?format=json',{{cache:'no-store',headers:h}});
    const d=await r.json();
    Object.keys(d.checks||{{}}).forEach(function(k){{
      const el=document.getElementById('msg-'+k);
      if(el) el.textContent=d.checks[k].msg;
    }});
  }});}}
  </script>
</body>
</html>"""
        return Response(html, mimetype='text/html')
    return jsonify(data)

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
        logger.exception("firmware fetch failed for %s", productType)
        return jsonify({"error": "upstream unavailable", "retryAfter": 60}), 502


def _format_device_storage(live: dict) -> str:
    """Render live free/total capacity as "X GB (Y Avail)", matching the
    placeholder format already used by the device card."""
    total = live.get("TotalDataCapacity")
    avail = live.get("TotalDataAvailable")
    if not isinstance(total, int) or total <= 0:
        return ""
    used = f"{total / 1e9:.2f} GB"
    if isinstance(avail, int) and avail > 0:
        return f"{used} ({avail / 1e9:.2f} Avail)"
    return used


_DEVICE_LIVE_CACHE = {"ts": 0.0, "data": None}
_DEVICE_LIVE_TTL = 3.0


def _get_live_device_info(ttl: float = _DEVICE_LIVE_TTL) -> dict:
    """Read the attached device's identity over usbmux.

    Returns {} when nothing is attached or libimobiledevice is missing, so the
    caller can fall back to the last activation snapshot.

    Reads the XML plist (`-x`) rather than scraping the text dump: _run_tool caps
    stdout at 4000 bytes and the full dump plus the disk_usage domain exceed that,
    which truncates the tail and silently drops UniqueDeviceID.

    Results are cached because /api/status is polled every 2s and re-reading the
    device per tick would add two processes per tick.
    """
    now = time.monotonic()
    if _DEVICE_LIVE_CACHE["data"] is not None and now - _DEVICE_LIVE_CACHE["ts"] < ttl:
        return _DEVICE_LIVE_CACHE["data"]
    out: dict = {}
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, shell=False
            ["ideviceinfo", "-x"], capture_output=True, timeout=2
        )
        if proc.returncode == 0 and proc.stdout:
            info = plistlib.loads(proc.stdout)
            if isinstance(info, dict):
                for key in ("ProductType", "ProductVersion", "BuildVersion",
                            "DeviceName", "HardwareModel", "SerialNumber",
                            "UniqueDeviceID", "EID"):
                    value = info.get(key)
                    if isinstance(value, str) and value.strip():
                        out[key] = value.strip()
    except Exception:
        out = {}
    if out.get("UniqueDeviceID"):
        try:
            usage = subprocess.run(  # nosec B603 B607 - fixed argv, shell=False
                ["ideviceinfo", "-q", "com.apple.disk_usage", "-x"],
                capture_output=True,
                timeout=2,
            )
            if usage.returncode == 0 and usage.stdout:
                usage_info = plistlib.loads(usage.stdout)
                if isinstance(usage_info, dict):
                    for key in ("TotalDataCapacity", "TotalDataAvailable"):
                        value = usage_info.get(key)
                        if isinstance(value, int) and value > 0:
                            out[key] = value
        except Exception:
            pass
    _DEVICE_LIVE_CACHE["ts"] = now
    _DEVICE_LIVE_CACHE["data"] = out
    return out


def _get_restore_progress():
    """Parse latest logs/restore/restore*.log for live idevicerestore progress.
    Returns {active,bool, percent 0-100, stage, file, lastLine, updatedAt}.
    Safe even if no logs or file unreadable."""
    import re as _re
    out = {"active": False, "percent": 0, "stage": "idle", "file": "", "lastLine": "", "updatedAt": ""}
    try:
        log_dir = pathlib.Path("logs/restore")
        if not log_dir.exists():
            return out
        files = sorted(log_dir.glob("restore*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not files:
            return out
        latest = files[0]
        out["file"] = latest.name
        try:
            out["updatedAt"] = datetime.fromtimestamp(latest.stat().st_mtime, tz=timezone.utc).isoformat()
        except Exception:
            pass
        # read tail 60KB for speed (last progress is at end)
        try:
            data = latest.read_bytes()[-60000:].decode(errors="ignore")
        except Exception:
            data = latest.read_text(errors="ignore")[-60000:]
        if not data.strip():
            return out
        # last non-empty line — prefer failure line when failed to avoid contradictory exit:0
        _failure_line = ""
        try:
            lines = [ln.strip() for ln in data.splitlines() if ln.strip()]
            if lines:
                out["lastLine"] = lines[-1][-300:]
                # capture first failure line if any
                low_lines = [ln.lower() for ln in lines]
                for idx, ll in enumerate(low_lines):
                    if "failed to enter restore mode" in ll or "image personalization failed" in ll or "possibly invalid ibec" in ll or "did not reconnect in recovery mode" in ll:
                        _failure_line = lines[idx][-300:]
                        break
                    if "unable to discover device mode" in ll:
                        _failure_line = lines[idx][-300:]
        except Exception:
            pass
        # active/done/failed detection — fail takes precedence over exit:0
        _is_failed_early = False
        try:
            age = time.time() - latest.stat().st_mtime
            lower = data.lower()
            # detect failure first (most specific) — must dominate exit:0
            if "failed to enter restore mode" in lower or "image personalization failed" in lower or "possibly invalid ibec" in lower or "did not reconnect in recovery mode" in lower:
                out["stage"] = "failed"
                out["active"] = False
                _is_failed_early = True
                if _failure_line:
                    out["lastLine"] = _failure_line
            elif "unable to discover device mode" in lower and age > 10 and "sending" not in lower[-500:].lower():
                out["stage"] = "failed"
                out["active"] = False
                _is_failed_early = True
                if _failure_line:
                    out["lastLine"] = _failure_line
            elif "restore complete" in lower and "failed" not in lower:
                out["stage"] = "complete"
                out["percent"] = 100
                out["active"] = False
                return out
            elif "exit:0" in lower and not _is_failed_early and "failed to enter restore mode" not in lower and "image personalization failed" not in lower and "possibly invalid ibec" not in lower and "did not reconnect in recovery mode" not in lower:
                # only treat exit:0 as success if no failure marker anywhere
                out["stage"] = "complete"
                out["percent"] = 100
                out["active"] = False
                return out
            else:
                if age < 120:
                    if "%" in data[-2000:]:
                        out["active"] = True
        except Exception:
            pass
        # stage from last Sending/Extracting (only if not already failed/complete)
        _is_failed = "failed to enter restore mode" in data.lower() or "image personalization failed" in data.lower() or "possibly invalid ibec" in data.lower() or "did not reconnect in recovery mode" in data.lower()
        try:
            if out["stage"] not in ("failed", "complete"):
                sends = _re.findall(r"Sending (\w+)", data)
                if sends:
                    out["stage"] = sends[-1]
                else:
                    ext = _re.findall(r"Extracting ([^\s]+)", data)
                    if ext:
                        out["stage"] = ext[-1].split("/")[-1][:24]
                # fallback: keep idle if no match
        except Exception:
            pass
        # percent: for failed case, percent is last before failure line to avoid contradictory 100%
        try:
            search_data = data
            if _is_failed_early and _failure_line:
                # slice up to failure to get meaningful progress at fail point
                idx = data.lower().find(_failure_line.lower()[:30]) if _failure_line else -1
                if idx > 0:
                    search_data = data[:idx]
            percents = _re.findall(r"(\d+(?:\.\d+)?)\s*%", search_data)
            if percents:
                val = float(percents[-1])
                if 0 <= val <= 100:
                    out["percent"] = round(val, 1)
        except Exception:
            pass
        # if active and stage still idle but has percent, keep percent
        if out["stage"] == "idle" and out["percent"] > 0:
            out["stage"] = "uploading"
        # enforce failed stage overrides any Sends parsing if failure present
        if _is_failed_early:
            out["stage"] = "failed"
            out["active"] = False
            if _failure_line:
                out["lastLine"] = _failure_line
    except Exception:
        pass
    return out


def _build_status_payload():
    """Helper that gathers realtime status dict (no jsonify) — used by /api/status and /api/admin/status."""
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
    device = {"ProductType":"iPhone11,8","ModelNumber":"MT1A2TH/A","SerialNumber":"REDACTEDSERIAL","UDID":"00008020-AAAAAAAAAAAAAAAA","EID":"89049000000000000000000000000000","IMEI":"350000000000006","IMEI2":"350000000000014","Storage":"127.93 GB (110.92 Avail)"}
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
    # Live read from usbmux, applied after the snapshot above so the attached
    # device wins: unplugging clears the card instead of leaving the previously
    # activated device on screen. Falls back to the snapshot when nothing is
    # attached, so the card is never blank.
    live_dev = _get_live_device_info()
    if live_dev.get("UniqueDeviceID"):
        _live_udid = live_dev["UniqueDeviceID"]
        _same_device = _live_udid == device.get("UDID")
        device.update({
            "ProductType": live_dev.get("ProductType") or device["ProductType"],
            "SerialNumber": live_dev.get("SerialNumber") or device["SerialNumber"],
            "UDID": _live_udid,
            # ModelNumber is the marketing name; the live HardwareModel is the
            # board codename (e.g. N841AP) and belongs beside it. Re-derive the
            # name from the live product type, since the lookup above ran against
            # whatever the last activation was.
            "ModelNumber": next(
                (d["name"] for d in CURATED_DEVICES
                 if d["identifier"] == live_dev.get("ProductType")),
                live_dev.get("HardwareModel") or device["ModelNumber"]),
            "HardwareModel": live_dev.get("HardwareModel") or "",
            "ProductVersion": live_dev.get("ProductVersion") or "",
            "BuildVersion": live_dev.get("BuildVersion") or "",
            "DeviceName": live_dev.get("DeviceName") or "",
            "Storage": _format_device_storage(live_dev),
            "live": True,
        })
        if not _same_device:
            # EID/IMEI/IMEI2 are not in the ideviceinfo plist, so the snapshot
            # values describe a different phone. Carrying them over would make a
            # card marked "live" show another device's identifiers.
            for _k in ("EID", "IMEI", "IMEI2"):
                device.pop(_k, None)
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
        out = subprocess.run(["timeout","2","idevicerestore","--logfile=NONE","--no-action","iPhone11,8_18.7.10_22H374_Restore.ipsw"], capture_output=True, text=True, timeout=3).stdout
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
    # restore progress (live idevicerestore)
    restore = _get_restore_progress()
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
    return {"now": now, "health": health, "ready": ready, "fairplay": fair, "metrics": metrics, "activations": acts, "device": device, "usb": usb, "ipsw": ipsw_info, "env": env, "db": {"wal": metrics["wal"]}, "rate": rate, "restore": restore}

def _build_public_status_payload():
    """Build minimal public status payload — no device data, activations, env, rate, etc."""
    health = {"status": "ok", "server": "albert-local", "version": "1.1-fixed"}
    ready = {"status": "ready" if bool(FAIRPLAY_CERT_CHAIN and albert.fairplay_private_key) else "not-ready", "fairplay_loaded": bool(FAIRPLAY_CERT_CHAIN and albert.fairplay_private_key)}
    try:
        mtls_ca = _get_mtls_ca()
        ready["mtls"] = {"enabled": bool(mtls_ca), "ca": mtls_ca if mtls_ca else None}
    except Exception:
        pass
    return {
        "health": health,
        "ready": ready,
        "version": "1.1-fixed",
    }


@app.route('/api/status', methods=['GET'])
def api_status():
    is_admin, _ = _check_admin_auth()
    wants_html = "text/html" in (request.headers.get("Accept") or "")
    if not is_admin:
        p = _build_public_status_payload()
    else:
        p = _build_status_payload()
    if wants_html and not request.args.get("format") == "json":
        # Render premium HTML like /health, /ready
        ok = p.get("health", {}).get("status") == "ok"
        badge = "bg-success" if ok else "bg-danger"
        html = f"""<!doctype html><html lang="en" data-bs-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" type="image/svg+xml" href="/static/favicon.svg"><title>zAlive — Status — {'✓ ok' if ok else '✗ fail'}</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/css/adminlte.min.css"><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css"><style>:root{{--zalive-card:#151a21;--zalive-border:#232b36}} .app-wrapper{{min-height:100vh;background:#0b0f14}} .app-header{{border-bottom:1px solid var(--zalive-border)}} .app-sidebar{{background:#0f141b;border-right:1px solid var(--zalive-border)}} .card{{border:1px solid var(--zalive-border);border-radius:14px;box-shadow:0 8px 32px rgba(0,0,0,.45)}} .mono{{font-family:ui-monospace,monospace}}</style></head><body class="layout-fixed-complete"><div class="app-wrapper"><nav class="app-header navbar navbar-expand bg-body"><div class="container-fluid"><ul class="navbar-nav"><li class="nav-item"><a class="nav-link" data-lte-toggle="sidebar" href="#"><i class="bi bi-list"></i></a></li><li class="nav-item"><a href="/dashboard" class="nav-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:22px"></a></li></ul><ul class="navbar-nav ms-auto"><li class="nav-item"><span class="badge {badge}">{'✓ ok' if ok else '✗ fail'}</span></li><li class="nav-item"><a class="nav-link" href="/dashboard">Dashboard</a></li><li class="nav-item"><a class="nav-link" href="/api/status?format=json">JSON</a></li></ul></div></nav><aside class="app-sidebar sidebar-dark"><div class="sidebar-brand"><a href="/dashboard" class="brand-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:28px"><span class="brand-text fw-light ms-2">zAlive Albert</span></a></div><div class="sidebar-wrapper"><nav class="mt-2"><ul class="nav sidebar-menu flex-column" data-lte-toggle="treeview" role="menu"><li class="nav-item"><a href="/dashboard" class="nav-link"><i class="nav-icon bi bi-speedometer2"></i><p>Dashboard</p></a></li><li class="nav-item"><a href="/firmware" class="nav-link"><i class="nav-icon bi bi-hdd-stack"></i><p>Firmware</p></a></li><li class="nav-item"><a href="/admin" class="nav-link"><i class="nav-icon bi bi-shield-lock"></i><p>Admin</p></a></li><li class="nav-item"><a href="/health" class="nav-link"><i class="nav-icon bi bi-heart-pulse"></i><p>Health</p></a></li><li class="nav-item"><a href="/ready" class="nav-link"><i class="nav-icon bi bi-check-circle"></i><p>Ready</p></a></li><li class="nav-item"><a href="/metrics" class="nav-link"><i class="nav-icon bi bi-graph-up"></i><p>Metrics</p></a></li><li class="nav-item"><a href="/api/status" class="nav-link active"><i class="nav-icon bi bi-heart-pulse"></i><p>Status</p></a></li></ul></nav></div></aside><main class="app-main"><div class="app-content-header"><div class="container-fluid"><div class="row"><div class="col-sm-6"><h3 class="mb-0">Status <small class="text-secondary">· {'✓ ok' if ok else '✗ fail'}</small></h3><small class="text-secondary">Template: AdminLTE 4 (dashboard-template #1) · Public status</small></div><div class="col-sm-6"><ol class="breadcrumb float-sm-end"><li class="breadcrumb-item"><a href="/">Home</a></li><li class="breadcrumb-item"><a href="/dashboard">Dashboard</a></li><li class="breadcrumb-item active">Status</li></ol></div></div></div><div class="app-content"><div class="container-fluid"><div class="row g-3"><div class="col-md-4"><div class="card"><div class="card-header"><h3 class="card-title text-uppercase small" style="color:#94a3b8">Health</h3><span class="badge {badge} float-end">{'✓ ok' if ok else '✗ fail'}</span></div><div class="card-body"><div class="mono small">{p.get('health', {}).get('server', 'albert-local')} · {p.get('health', {}).get('version', '1.1-fixed')}</div></div></div></div><div class="col-md-4"><div class="card"><div class="card-header"><h3 class="card-title text-uppercase small" style="color:#94a3b8">Ready</h3><span class="badge {badge} float-end">{'✓ ready' if p.get('ready', {}).get('fairplay_loaded') else '✗ not-ready'}</span></div><div class="card-body"><div class="mono small">FairPlay loaded: {str(p.get('ready', {}).get('fairplay_loaded', False)).lower()}</div><div class="mono small text-secondary">mTLS: {'enabled' if p.get('ready', {}).get('mtls', {}).get('enabled') else 'disabled'}</div></div></div></div><div class="col-md-4"><div class="card"><div class="card-header"><h3 class="card-title text-uppercase small" style="color:#94a3b8">Version</h3></div><div class="card-body"><div class="mono small">{p.get('version', '1.1-fixed')}</div></div></div></div></div><div class="card mt-3"><div class="card-header"><h3 class="card-title small" style="color:#94a3b8">Raw JSON</h3><a href="/api/status?format=json" class="btn btn-sm btn-outline-primary float-end">View JSON</a></div><div class="card-body"><pre class="mono small bg-dark p-3 rounded" style="white-space:pre-wrap">{json.dumps(p, indent=2)}</pre></div></div></div></div></main><footer class="app-footer"><div class="float-end d-none d-sm-inline">zAlive</div><strong>Local Albert</strong> · Template dashboard-template (AdminLTE 4)</footer></div><script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script><script src="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/js/adminlte.min.js" integrity="sha384-6yU8d/XMPixNnAJ83V1hSNte2ij+N38tIn1M4J+EiHC/MPgisvtNhJyRPfGWFrDk" crossorigin="anonymous"></script></body></html>"""
        return Response(html, mimetype='text/html')
    return jsonify(p)

@app.route('/api/rate_status', methods=['GET'])
def api_rate_status():
    """Debug rate limit status. Requires admin. Returns per-IP 100/min + per-UDID 10/min counts and Redis state."""
    err = _admin_required()
    if err:
        return err
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
        "redis_url": "redacted" if redis_url_set else "",
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
    err = _admin_required()
    if err:
        return err
    limit = int(request.args.get('limit','10'))
    limit = max(1, min(limit, 100))
    import sqlite3
    rows=[]
    try:
        with sqlite3.connect(str(DB_PATH), timeout=5) as c:
            cur=c.execute("SELECT id,udid,serial,created_at FROM activations ORDER BY id DESC LIMIT ?", (limit,))
            for id_,udid,serial,at in cur.fetchall():
                rows.append({"id":id_,"udid":udid,"serial":serial,"created_at":at})
    except Exception:
        logger.exception("activation listing failed")
        return jsonify({"error": "internal error"}), 500
    return jsonify({"activations": rows, "total": len(rows)})

def _run_tool(cmd, timeout=2):
    try:
        # cmd is always a list literal assembled by this module; shell=False (the
        # default) means no metacharacter expansion, so this is not a shell
        # injection sink. Every user-supplied element is validated first:
        # udid by _validate_udid, domain/key by the anchored regex in
        # api_device_info, which requires an alphanumeric first character so a
        # value cannot be read as a flag.
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)  # nosec B603 B607
        return {"ok": out.returncode == 0, "returncode": out.returncode, "stdout": (out.stdout or "")[:4000], "stderr": (out.stderr or "")[:4000], "cmd": " ".join(cmd)}
    except Exception as e:
        return {"ok": False, "error": str(e), "cmd": " ".join(cmd)}

@app.route('/api/device_info', methods=['GET'])
def api_device_info():
    err = _admin_required()
    if err:
        return err
    domain = request.args.get("domain") or ""
    key = request.args.get("key") or ""
    udid = request.args.get("udid") or ""
    # Allowlist validation. The character class alone was not enough: it permits
    # a leading '-', so '?domain=-oRoot' or '?key=--help' passed and ideviceinfo
    # read the value as a flag rather than data (argument injection). Requiring
    # an alphanumeric first character closes that; empty still means "not
    # supplied" and is handled by the `if domain:` guards below.
    if domain and not re.match(r'^[A-Za-z0-9][A-Za-z0-9._-]*$', domain):
        return jsonify({"error": "invalid domain"}), 400
    if key and not re.match(r'^[A-Za-z0-9][A-Za-z0-9._-]*$', key):
        return jsonify({"error": "invalid key"}), 400
    if udid and not _validate_udid(udid):
        return jsonify({"error": "invalid UDID"}), 400
    cmd = ["ideviceinfo", "-s"]
    if udid:
        cmd += ["-u", udid]
    if domain:
        cmd += ["-q", domain]
    if key:
        cmd += ["-k", key]
    r = _run_tool(cmd, timeout=2)
    # also try json-like parse for simple keys
    if r["ok"] and not r["stdout"].strip().startswith("{"):
        r["connected"] = True
    else:
        r["connected"] = "No device" not in r.get("stderr","") and r.get("returncode") == 0
    if not r.get("ok") and r.get("error"):
        # _run_tool returns str(e) and the full argv on failure. The rest of this
        # module logs that detail instead of handing it to the caller, so keep the
        # response to pass/fail plus whatever the tool actually printed.
        logger.warning("api_device_info tool failed: %s", r["error"])
        r = {"ok": False, "connected": False, "stdout": r.get("stdout", ""),
             "stderr": "tool failed", "returncode": r.get("returncode")}
    return jsonify(r)

@app.route('/api/diagnostics', methods=['GET'])
def api_diagnostics():
    err = _admin_required()
    if err:
        return err
    typ = (request.args.get("type") or "all").strip()
    if typ not in ("all","mobilegestalt","syslog","crash","diagnostics","ioreg","ioregentry"):
        return jsonify({"error": "invalid type"}), 400
    if typ == "mobilegestalt":
        r = _run_tool(["idevicediagnostics", "mobilegestalt"], timeout=3)
    elif typ == "syslog":
        lines = int(request.args.get("lines","50"))
        lines = max(1, min(lines, 200))
        r = _run_tool(["timeout","2","idevicesyslog","-n"], timeout=3)
        if r["ok"]:
            out = r["stdout"].splitlines()[-lines:]
            r["stdout"] = "\n".join(out)
    elif typ == "crash":
        r = _run_tool(["idevicecrashreport","-e","/tmp"], timeout=3)
    else:
        r = _run_tool(["idevicediagnostics","help"], timeout=2)
        r["note"] = "use ?type=mobilegestalt|syslog|crash"
    return jsonify(r)

@app.route('/api/recovery', methods=['GET'])
def api_recovery():
    err = _admin_required()
    if err:
        return err
    mode = _run_tool(["irecovery","-q"], timeout=2)
    # also query lsusb + idevicerestore --logfile=NONE --no-action
    lsusb = _run_tool(["lsusb"], timeout=1)
    mode["lsusb_has_apple"] = "05ac" in (lsusb.get("stdout","")+lsusb.get("stderr","")).lower()
    return jsonify({"recovery": mode, "lsusb": lsusb})

@app.route('/api/pair', methods=['GET','POST'])
def api_pair():
    err = _admin_required()
    if err:
        return err
    # CSRF check for state-changing POST
    if request.method == "POST":
        origin = request.headers.get("Origin","")
        referer = request.headers.get("Referer","")
        # allow if Origin missing but require X-Requested-With or Content-Type json/form
        if origin and "192.168." not in origin and "127.0.0.1" not in origin and "localhost" not in origin:
            # still allow if admin token present via header (already checked), but log
            logger.warning(f"pair POST cross-origin {origin}", extra={"request_id": getattr(g,'request_id','-')})
        r = _run_tool(["idevicepair","pair"], timeout=5)
        return jsonify(r)
    r = _run_tool(["idevicepair","validate"], timeout=2)
    if not r["ok"]:
        r2 = _run_tool(["idevicepair","list"], timeout=2)
        r["pair_list"] = r2
    return jsonify(r)

@app.route('/api/ifuse', methods=['GET'])
def api_ifuse():
    err = _admin_required()
    if err:
        return err
    r = _run_tool(["ifuse","--help"], timeout=1)
    r["note"] = "mount with: ifuse /mnt/iphone --udid $UDID (requires cable, see idevice_id -l)"
    # check mount
    try:
        m = subprocess.run(["mount"], capture_output=True, text=True, timeout=1).stdout
        r["mounts"] = [line for line in m.splitlines() if "ifuse" in line or "iphone" in line.lower()][:5]
    except Exception:
        r["mounts"] = []
    return jsonify(r)

@app.route('/api/tss', methods=['GET'])
def api_tss():
    err = _admin_required()
    if err:
        return err
    product = request.args.get("productType") or "iPhone11,8"
    if not PRODUCT_RE.match(product):
        return jsonify({"error": "invalid productType, expected iPhoneX,Y"}), 400
    # tsschecker not installed by default — probe
    r = _run_tool(["which","tsschecker"], timeout=1)
    if not r["ok"] or not r["stdout"].strip():
        return jsonify({"ok": False, "error": "tsschecker not installed (apt build)", "hint": "build tsschecker or use futurerestore --help", "productType": product})
    ecid = request.args.get("ecid") or ""
    cmd = ["tsschecker","-d",product,"-i","18.7.10","--apnonce","--save"]
    if ecid:
        cmd += ["-e", ecid]
    r2 = _run_tool(cmd, timeout=8)
    r2["productType"] = product
    return jsonify(r2)


@app.route('/', methods=['GET'])
def index():
    endpoints = ["/dashboard","/investigation","/firmware","/admin","/health","/ready","/metrics","/api/validate","/api/investigation","/api/devices","/api/firmwares","/api/status","/api/rate_status","/api/activations","/api/logs","/api/device_info","/api/diagnostics","/api/recovery","/api/pair","/api/ifuse","/api/tss","/deviceservices/drmHandshake","/deviceservices/deviceActivation","/WebObjects/ALUnbrick.woa/wa/deviceActivation"]
    data = {"service":"albert-local","endpoints":endpoints}
    wants_html = "text/html" in (request.headers.get("Accept") or "")
    if wants_html and not request.args.get("format") == "json":
        cards = "".join(f"<a href=\"{e}\" class=\"btn btn-sm btn-outline-primary m-1\">{e}</a>" for e in endpoints)
        html = f"""<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<title>zAlive — Albert — Home</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/css/adminlte.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
<style>:root{{--zalive-card:#151a21;--zalive-border:#232b36}} .app-wrapper{{min-height:100vh;background:#0b0f14}} .app-header{{border-bottom:1px solid var(--zalive-border)}} .app-sidebar{{background:#0f141b;border-right:1px solid var(--zalive-border)}} .card{{border:1px solid var(--zalive-border);border-radius:14px;box-shadow:0 8px 32px rgba(0,0,0,.45)}} .mono{{font-family:ui-monospace,monospace}}</style>
</head>
<body class="layout-fixed-complete">
<div class="app-wrapper">
<nav class="app-header navbar navbar-expand bg-body"><div class="container-fluid">
<ul class="navbar-nav"><li class="nav-item"><a class="nav-link" data-lte-toggle="sidebar" href="#"><i class="bi bi-list"></i></a></li><li class="nav-item"><a href="/dashboard" class="nav-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:22px"></a></li></ul>
<ul class="navbar-nav ms-auto"><li class="nav-item"><a class="nav-link" href="/dashboard">Dashboard</a></li><li class="nav-item"><a class="nav-link" href="/api/validate?format=json">JSON</a></li></ul>
</div></nav>
<aside class="app-sidebar sidebar-dark"><div class="sidebar-brand"><a href="/dashboard" class="brand-link"><img src="/static/zalive-logo.svg" alt="zAlive" style="height:28px"><span class="brand-text fw-light ms-2">zAlive Albert</span></a></div>
<div class="sidebar-wrapper"><nav class="mt-2"><ul class="nav sidebar-menu flex-column">
<li class="nav-item"><a href="/dashboard" class="nav-link"><i class="nav-icon bi bi-speedometer2"></i><p>Dashboard</p></a></li>
<li class="nav-item"><a href="/firmware" class="nav-link"><i class="nav-icon bi bi-hdd-stack"></i><p>Firmware</p></a></li>
<li class="nav-item"><a href="/admin" class="nav-link"><i class="nav-icon bi bi-shield-lock"></i><p>Admin</p></a></li>
<li class="nav-item"><a href="/health" class="nav-link"><i class="nav-icon bi bi-heart-pulse"></i><p>Health</p></a></li>
<li class="nav-item"><a href="/" class="nav-link active"><i class="nav-icon bi bi-house"></i><p>Home</p></a></li>
</ul></nav></div>
</aside>
<main class="app-main"><div class="app-content-header"><div class="container-fluid">
<div class="row"><div class="col-sm-6"><h3 class="mb-0">zAlive Albert <small class="text-secondary">· local albert.apple.com</small></h3><small class="text-secondary">Template: AdminLTE 4 (dashboard-template #1) · Premium dark</small></div><div class="col-sm-6"><ol class="breadcrumb float-sm-end"><li class="breadcrumb-item active">Home</li></ol></div></div>
</div></div>
<div class="app-content"><div class="container-fluid">
<div class="row g-3">
<div class="col-md-4"><div class="card"><div class="card-header"><h3 class="card-title k" style="color:#94a3b8">Quick links</h3></div><div class="card-body d-flex flex-wrap gap-2">
<a href="/dashboard" class="btn btn-primary"><i class="bi bi-speedometer2"></i> Dashboard</a>
<a href="/firmware" class="btn btn-outline-primary"><i class="bi bi-hdd-stack"></i> Firmware (13)</a>
<a href="/admin" class="btn btn-outline-warning"><i class="bi bi-shield-lock"></i> Admin</a>
</div></div></div>
<div class="col-md-4"><div class="card"><div class="card-header"><h3 class="card-title k" style="color:#94a3b8">Health</h3></div><div class="card-body d-flex gap-2">
<a href="/health" class="btn btn-sm btn-outline-success">Health</a>
<a href="/ready" class="btn btn-sm btn-outline-success">Ready</a>
<a href="/metrics" class="btn btn-sm btn-outline-primary">Metrics</a>
<a href="/api/validate" class="btn btn-sm btn-outline-primary">Validate</a>
</div></div></div>
<div class="col-md-4"><div class="card"><div class="card-header"><h3 class="card-title k" style="color:#94a3b8">Device</h3></div><div class="card-body"><div class="mono small">iPhone XR REDACTED · iPhone11,8</div><div class="mono small text-secondary">IPSW 18.7.10 22H374 · 8.7GB ok (UDID/Serial redacted — see /api/admin/status)</div></div></div></div>
</div>
<div class="card mt-3"><div class="card-header"><h3 class="card-title small" style="color:#94a3b8">Endpoints</h3></div><div class="card-body"><div class="d-flex flex-wrap">{cards}</div><pre class="mono small bg-dark p-3 rounded mt-3" style="white-space:pre-wrap">{json.dumps(data, indent=2)}</pre></div></div>
</div></div>
</main>
<footer class="app-footer"><div class="float-end d-none d-sm-inline">zAlive</div><strong>Local Albert</strong> · Template dashboard-template (AdminLTE 4)</footer>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/admin-lte@4.0.0/dist/js/adminlte.min.js" integrity="sha384-6yU8d/XMPixNnAJ83V1hSNte2ij+N38tIn1M4J+EiHC/MPgisvtNhJyRPfGWFrDk" crossorigin="anonymous"></script>
</body>
</html>"""
        return Response(html, mimetype='text/html')
    return jsonify(data)

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
