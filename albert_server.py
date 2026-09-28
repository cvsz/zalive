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
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from flask import Flask, request, Response, jsonify, g
from werkzeug.exceptions import RequestEntityTooLarge

app = Flask(__name__)
# Production hardening: request size limit (P0-3), env-driven port
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('ALBERT_MAX_CONTENT_LENGTH', str(512*1024)))
FAIRPLAY_KEY_PATH = os.environ.get('FAIRPLAY_KEY_PATH', 'certs/fairplay.key')
FAIRPLAY_CERT_PATH = os.environ.get('FAIRPLAY_CERT_PATH', 'certs/fairplay.crt')

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
                record TEXT
            )""")
            conn.commit()
            try:
                conn.execute("PRAGMA journal_mode=WAL;")
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"Failed to init activation DB {DB_PATH}: {e}")

_init_db()

_log_counter = 0
def log_activation(udid: str, serial: str, record):
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
                "INSERT INTO activations (udid, serial, created_at, record) VALUES (?, ?, ?, ?)",
                (udid or "", serial or "", created_at, record_text),
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

def _inc_failure():
    try:
        albert_activation_failures_total.inc()
    except Exception:
        pass

# --- Per-IP rate limit stub (P2) — simple in-memory dict, 100/min, no extra dep ---
_RATE_LIMIT_MAX = 100
_RATE_LIMIT_WINDOW = 60  # seconds
_rate_limit_store: dict = {}
_rate_limit_lock = threading.Lock()

def _check_rate_limit(ip: str) -> bool:
    """Return True if rate limit exceeded for ip. In-memory per-IP 100/min, prunes empty, caps 1000 IPs."""
    now = time.time()
    with _rate_limit_lock:
        # Prune empty entries periodically to avoid unbounded growth (P2 polish)
        if len(_rate_limit_store) > 1000:
            # evict oldest 100 IPs with smallest newest timestamp
            oldest = sorted(_rate_limit_store.items(), key=lambda kv: kv[1][-1] if kv[1] else 0)[:100]
            for k,_ in oldest:
                _rate_limit_store.pop(k, None)
        lst = _rate_limit_store.get(ip, [])
        lst = [t for t in lst if now - t < _RATE_LIMIT_WINDOW]
        if not lst and ip in _rate_limit_store and len(lst)==0:
            # keep empty list removal for memory
            _rate_limit_store.pop(ip, None)
        if len(lst) >= _RATE_LIMIT_MAX:
            _rate_limit_store[ip] = lst
            return True
        lst.append(now)
        _rate_limit_store[ip] = lst
        return False

def _reset_rate_limit():
    """For tests: clear rate limit store."""
    with _rate_limit_lock:
        _rate_limit_store.clear()

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
    # Per-IP rate limit stub (simple in-memory dict, 100/min) without extra dep
    # Apply only to activation-related endpoints to avoid breaking health checks
    if request.path.startswith("/deviceservices") or request.path.startswith("/WebObjects"):
        ip = request.remote_addr or "unknown"
        if _check_rate_limit(ip):
            logger.warning(f"Rate limit exceeded for {ip}", extra={"request_id": g.request_id, "remote_addr": ip})
            return jsonify({"error": "rate limit exceeded", "request_id": g.request_id}), 429

@app.after_request
def after_request_add_id(response):
    rid = getattr(g, "request_id", None)
    if rid:
        response.headers["X-Request-ID"] = rid
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
        # SHA1 usage for ARS is Apple-spec — Apple activation requires SHA1 for FairPlay signature
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
            log_activation(str(udid), str(serial), activation_record)
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
        session_mode = "FairPlaySignature" in str(activation_info) or "HandshakeRequestMessage" in str(activation_info)
        activation_record = albert.create_activation_record(activation_info, session_mode)
        if not isinstance(activation_record, dict):
            logger.error(f"create_activation_record returned non-dict: {type(activation_record)}")
            _inc_failure()
            return Response("Internal error generating activation record", status=500)
        response_plist = plistlib.dumps(activation_record)
        # SHA1 usage for ARS is Apple-spec — Apple requires SHA1 for ARS header (Alert: not for general hashing)
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
    # Readiness: FairPlay key and cert chain loaded
    ok = bool(FAIRPLAY_CERT_CHAIN and albert.fairplay_private_key)
    return (jsonify({"status": "ready" if ok else "not-ready", "fairplay_loaded": ok}), 200 if ok else 503)

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
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Albert — iPhone XR Restore Dashboard</title>
<style>
:root { --bg:#0b0f14; --card:#151a21; --border:#232b36; --accent:#3b82f6; --ok:#16a34a; --warn:#eab308; --bad:#dc2626; --text:#e5e7eb; --muted:#94a3b8; }
*{box-sizing:border-box} body{margin:0;font-family: -apple-system,Inter,system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text)}
header{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;background:var(--bg);z-index:10}
header h1{font-size:15px;margin:0;font-weight:600;letter-spacing:.3px}
header .pill{font-size:11px;padding:6px 10px;border-radius:999px;border:1px solid var(--border);background:var(--card);color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px;padding:14px}
.card{grid-column:span 4;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px}
.card.wide{grid-column:span 8} .card.full{grid-column:span 12}
@media(max-width:900px){.card,.card.wide{grid-column:span 12}}
.k{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px}
.v{font-size:22px;font-weight:700;margin-top:6px}
.v small{font-size:11px;font-weight:500;color:var(--muted)}
.badge{display:inline-block;font-size:11px;padding:4px 8px;border-radius:999px;border:1px solid var(--border)}
.badge.ok{background:rgba(22,163,74,.15);color:var(--ok);border-color:rgba(22,163,74,.3)}
.badge.bad{background:rgba(220,38,38,.15);color:var(--bad);border-color:rgba(220,38,38,.3)}
.badge.warn{background:rgba(234,179,8,.15);color:var(--warn);border-color:rgba(234,179,8,.3)}
table{width:100%;border-collapse:collapse;margin-top:8px}
th{font-size:11px;color:var(--muted);text-align:left;padding:8px 6px;border-bottom:1px solid var(--border)}
td{font-size:13px;padding:8px 6px;border-bottom:1px solid rgba(255,255,255,.06)}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
.bar{height:8px;background:#0f172a;border-radius:999px;overflow:hidden;margin-top:8px}
.bar>div{height:100%;background:var(--accent)}
.log{max-height:220px;overflow:auto;background:#0f141b;border:1px solid var(--border);border-radius:8px;padding:10px;font-family:ui-monospace,monospace;font-size:11px;white-space:pre-wrap}
a{color:var(--accent);text-decoration:none}
.footer{padding:12px 14px;color:var(--muted);font-size:11px;text-align:center;border-top:1px solid var(--border);margin-top:10px}
</style>
</head>
<body>
<header>
  <h1>Albert — iPhone XR <span style="color:var(--muted);font-weight:400">· iPhone11,8 · 18090</span></h1>
  <div style="display:flex;gap:8px;align-items:center">
    <span id="healthPill" class="pill">checking…</span>
    <span id="clock" class="pill">--:--:--</span>
  </div>
</header>
<div class="grid">
  <div class="card">
    <div class="k">Server</div>
    <div class="v" id="serverV">-</div>
    <div class="mono" id="serverD" style="color:var(--muted);margin-top:6px">-</div>
    <div style="margin-top:10px"><a href="/health" target="_blank">/health</a> · <a href="/ready" target="_blank">/ready</a> · <a href="/metrics" target="_blank">/metrics</a> · <a href="/api/status" target="_blank">/api/status</a></div>
  </div>
  <div class="card">
    <div class="k">FairPlay</div>
    <div class="v" id="fpV">-</div>
    <div class="mono" id="fpD">-</div>
  </div>
  <div class="card">
    <div class="k">Metrics</div>
    <div id="metrics" class="mono" style="font-size:12px">-</div>
  </div>
  <div class="card">
    <div class="k">iPhone XR — This Device</div>
    <div id="device" class="mono">-</div>
    <div class="k" style="margin-top:10px">USB / Restore</div>
    <div id="usb" class="mono">-</div>
  </div>
  <div class="card wide">
    <div class="k">IPSW</div>
    <div id="ipsw" class="mono">-</div>
    <div id="ipswBar" class="bar"><div id="ipswFill" style="width:0%"></div></div>
  </div>
  <div class="card full">
    <div class="k">Recent Activations (SQLite WAL)</div>
    <table><thead><tr><th>#</th><th>UDID (redacted)</th><th>Serial</th><th>At (UTC)</th><th>Record</th></tr></thead><tbody id="acts"></tbody></table>
  </div>
  <div class="card full">
    <div class="k">Rate limit · Logs tail</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
      <div><div class="mono" style="color:var(--muted)">IPs tracked · window 60s · max 100/min · capped 1000</div><div id="rl" class="mono" style="margin-top:6px">-</div></div>
      <div><div id="logs" class="log">loading…</div></div>
    </div>
  </div>
</div>
<div class="footer">Local Albert — owned devices only · <span id="ver">1.1-fixed</span> · <a href="/dashboard">dashboard</a> auto-refresh 2s · gunicorn 2×4 · 127.0.0.1:18090 · See <a href="/docs/RUNBOOK.md" target="_blank">RUNBOOK</a> · <a href="http://127.0.0.1:8081" target="_blank">mitmproxy 8081</a></div>
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
    $('metrics').textContent = 'activations ' + j.metrics.activations + ' · failures ' + j.metrics.failures + ' · up ' + j.metrics.up + '\nrate IPs ' + j.rate.ips + ' · WAL ' + j.db.wal;
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
    $('rl').textContent = 'IPs ' + j.rate.ips + ' · sample ' + (j.rate.sample||'-');
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

@app.route('/api/status', methods=['GET'])
def api_status():
    # Gather realtime status without blocking
    import subprocess, sqlite3
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
    # device (your XR)
    device = {"ProductType":"iPhone11,8","ModelNumber":"MT1A2TH/A","SerialNumber":"REDACTEDSERIAL","UDID":"00008020-AAAAAAAAAAAAAAAA","EID":"89049000000000000000000000000000","IMEI":"350000000000006","IMEI2":"350000000000014","Storage":"127.93 GB (110.92 Avail)"}
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
    # ipsw
    ipsw_info = {"name":"iPhone11,8_18.7.10_22H374_Restore.ipsw","exists": False, "sizeGB":"8.1","sha256":"b30474b679d9ec04","productVersion":"18.7.10","build":"22H374","variants":["Customer Erase Install (IPSW)","Customer Upgrade Install (IPSW)"]}
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
    return jsonify({"now": now, "health": health, "ready": ready, "fairplay": fair, "metrics": metrics, "activations": acts, "device": device, "usb": usb, "ipsw": ipsw_info, "env": env, "db": {"wal": metrics["wal"]}})

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
    return jsonify({"service":"albert-local","endpoints":["/health","/deviceservices/drmHandshake","/deviceservices/deviceActivation","/WebObjects/ALUnbrick.woa/wa/deviceActivation"]})

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
        try:
            for p in [pathlib.Path(FAIRPLAY_KEY_PATH), pathlib.Path(FAIRPLAY_CERT_PATH)]:
                if p.exists():
                    p.unlink()
                    print(f"Removed {p}")
            print("FairPlay key rotation requested — restart to regenerate (chmod 600).")
        except Exception as e:
            import sys
            print(f"Rotation failed: {e}", file=sys.stderr)
            sys.exit(1)
        import sys
        sys.exit(0)
    ssl_context = None
    if args.ssl_cert and args.ssl_key:
        ssl_context = (args.ssl_cert, args.ssl_key)
        logger.info(f"Starting HTTPS server on {args.host}:{args.port}")
    else:
        logger.info(f"Starting HTTP server on {args.host}:{args.port}")
    # also log risk acknowledgement
    if os.environ.get('ALBERT_ACCEPT_RISK') == '1':
        logger.info("ALBERT_ACCEPT_RISK=1 acknowledged — activation bypass enabled (owned devices only, see NOTICE)")
    else:
        logger.warning("Running with --allow-no-risk — bypass not acknowledged; for lab/sandbox only")
    app.run(host=args.host, port=args.port, ssl_context=ssl_context, debug=not args.no_debug, use_reloader=False)
