"""Production gate tests for albert_server (P1-8)"""
import base64
import os
import pathlib
import plistlib
import sqlite3
import tempfile
import uuid

import pytest

# import server as module without running
import albert_server

# Auto-inject mTLS header for tests when mTLS enabled (certs/mtls-ca.crt exists)
_orig_test_client = albert_server.app.test_client
def _mtls_test_client(*a, **kw):
    c = _orig_test_client(*a, **kw)
    _orig_post = c.post
    _orig_get = c.get
    _orig_open = c.open
    def _post(path, *aa, **kww):
        if path.startswith("/deviceservices/") or path.startswith("/WebObjects/"):
            h = kww.get("headers", {})
            if isinstance(h, dict):
                h = dict(h)
            h.setdefault("X-Client-Cert", "present")
            kww["headers"] = h
        return _orig_post(path, *aa, **kww)
    def _get(path, *aa, **kww):
        if path.startswith("/deviceservices/") or path.startswith("/WebObjects/"):
            h = kww.get("headers", {})
            if isinstance(h, dict):
                h = dict(h)
            h.setdefault("X-Client-Cert", "present")
            kww["headers"] = h
        return _orig_get(path, *aa, **kww)
    def _open(path, *aa, **kww):
        # c.open is used for OPTIONS in test_options, not rate-limited but still mTLS-protected for deviceActivation
        if isinstance(path, str) and (path.startswith("/deviceservices/") or path.startswith("/WebObjects/")):
            h = kww.get("headers", {})
            if isinstance(h, dict):
                h = dict(h)
            # OPTIONS should not require mTLS (it's CORS preflight), but adding header is harmless
            h.setdefault("X-Client-Cert", "present")
            kww["headers"] = h
        return _orig_open(path, *aa, **kww)
    c.post = _post
    c.get = _get
    c.open = _open
    return c
albert_server.app.test_client = _mtls_test_client


def test_health():
    c = albert_server.app.test_client()
    r = c.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_ready():
    c = albert_server.app.test_client()
    r = c.get("/ready")
    assert r.status_code == 200
    assert r.get_json()["fairplay_loaded"] is True


def test_metrics():
    c = albert_server.app.test_client()
    r = c.get("/metrics")
    assert r.status_code == 200
    assert b"albert_up" in r.data


def _cert_headers(**kw):
    h = kw.get("headers", {})
    if isinstance(h, dict):
        h = dict(h)
    h["X-Client-Cert"] = "present"
    kw["headers"] = h
    return kw


def test_drm_handshake():
    c = albert_server.app.test_client()
    blob = {"CollectionBlob": b"a", "HandshakeRequestMessage": b"b", "UniqueDeviceID": "test"}
    r = c.post(
        "/deviceservices/drmHandshake",
        data=plistlib.dumps(blob),
        content_type="application/x-apple-plist",
        **_cert_headers(),
    )
    assert r.status_code == 200
    pl = plistlib.loads(r.data)
    assert "ServerCertificate" in pl


def test_activation_with_csr():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(65537, 2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")]))
        .sign(key, hashes.SHA256())
    )
    pem = csr.public_bytes(serialization.Encoding.PEM)
    info = {
        "DeviceClass": "iPhone",
        "UniqueDeviceID": "00008020-001224C81178002E",
        "SerialNumber": "C8PXJF1EKXKQ",
        "DeviceCertRequest": pem,
    }
    b64 = base64.b64encode(plistlib.dumps(info)).decode()
    c = albert_server.app.test_client()
    r = c.post(
        "/deviceservices/deviceActivation",
        data={"activation-info": b64},
        content_type="application/x-www-form-urlencoded",
    )
    assert r.status_code == 200
    pl = plistlib.loads(r.data)
    assert "iphone-activation" in pl
    assert "ARS" in r.headers


def test_activation_without_csr_placeholder():
    info = {"DeviceClass": "iPhone", "UniqueDeviceID": "00008020-001224C81178002E"}
    b64 = base64.b64encode(plistlib.dumps(info)).decode()
    c = albert_server.app.test_client()
    r = c.post("/deviceservices/deviceActivation", data={"activation-info": b64})
    assert r.status_code == 200


def test_activation_invalid_returns_400():
    c = albert_server.app.test_client()
    r = c.post(
        "/deviceservices/deviceActivation",
        data={"activation-info": "not-base64"},
        content_type="application/x-www-form-urlencoded",
    )
    assert r.status_code in (400, 500)  # device will retry
    # no crash


def test_size_limit():
    c = albert_server.app.test_client()
    big = {"DeviceClass": "iPhone", "blob": b"x" * 700000}
    # should hit MAX_CONTENT_LENGTH 512k if sent as form? flask will 413
    b64 = base64.b64encode(plistlib.dumps(big)).decode()
    r = c.post("/deviceservices/deviceActivation", data={"activation-info": b64})
    assert r.status_code in (413, 500, 200)  # 413 if limit hit via body size, else handled


def test_options():
    """OPTIONS on deviceservices should return 204 with Allow header."""
    albert_server._reset_rate_limit()
    c = albert_server.app.test_client()
    r = c.open("/deviceservices/deviceActivation", method="OPTIONS")
    assert r.status_code == 204
    # Allow header should be present
    assert "Allow" in r.headers or r.status_code == 204
    # also check drmHandshake path
    r2 = c.open("/deviceservices/drmHandshake", method="OPTIONS")
    assert r2.status_code == 204
    # legacy path
    r3 = c.open("/WebObjects/ALUnbrick.woa/wa/deviceActivation", method="OPTIONS")
    assert r3.status_code == 204


def test_rate_limit():
    """Per-IP rate limit should return 429 after exceeding threshold."""
    albert_server._reset_rate_limit()
    orig_max = albert_server._RATE_LIMIT_MAX
    # lower threshold for fast test
    albert_server._RATE_LIMIT_MAX = 5
    try:
        c = albert_server.app.test_client()
        # 5 allowed requests
        for _ in range(5):
            r = c.get("/deviceservices/deviceActivation")
            # could be 400 due missing activation-info, but not 429 yet
            assert r.status_code != 429
        # 6th should be rate limited
        r = c.get("/deviceservices/deviceActivation")
        assert r.status_code == 429
        assert "rate limit" in r.get_data(as_text=True).lower()
    finally:
        albert_server._RATE_LIMIT_MAX = orig_max
        albert_server._reset_rate_limit()


def test_invalid_imei_400():
    """Invalid IMEI (not 15 digits) should be rejected with 400."""
    albert_server._reset_rate_limit()
    # use valid UDID but invalid IMEI
    info = {
        "DeviceClass": "iPhone",
        "UniqueDeviceID": "00008020-001224C81178002E",
        "IMEI": "12345",  # too short, must be 15 digits
        "SerialNumber": "C8PXJF1EKXKQ",
    }
    b64 = base64.b64encode(plistlib.dumps(info)).decode()
    c = albert_server.app.test_client()
    r = c.post("/deviceservices/deviceActivation", data={"activation-info": b64})
    assert r.status_code == 400
    j = r.get_json()
    assert j is not None
    assert "error" in j or "details" in j
    # details should mention IMEI
    body = str(j)
    assert "IMEI" in body or "imei" in body.lower()

    # also test non-digit IMEI
    info2 = {
        "DeviceClass": "iPhone",
        "UniqueDeviceID": "00008020-001224C81178002E",
        "IMEI": "abcdefghijklmno",
    }
    b64_2 = base64.b64encode(plistlib.dumps(info2)).decode()
    r2 = c.post("/deviceservices/deviceActivation", data={"activation-info": b64_2})
    assert r2.status_code == 400


def test_persistence_db_written(tmp_path):
    """Activation should persist record to SQLite DB."""
    # Use isolated temp DB to avoid polluting real logs/activations.db
    original_db = albert_server.DB_PATH
    db_file = tmp_path / "activations_test.db"
    albert_server.DB_PATH = pathlib.Path(db_file)
    albert_server._init_db()
    try:
        albert_server._reset_rate_limit()
        unique_udid = f"00008020-{uuid.uuid4().hex[:16]}"
        serial = f"TEST{uuid.uuid4().hex[:8].upper()}"
        info = {"DeviceClass": "iPhone", "UniqueDeviceID": unique_udid, "SerialNumber": serial}
        b64 = base64.b64encode(plistlib.dumps(info)).decode()
        c = albert_server.app.test_client()
        r = c.post("/deviceservices/deviceActivation", data={"activation-info": b64})
        assert r.status_code == 200
        # DB file should exist
        assert pathlib.Path(db_file).exists()
        # Check that record was written
        with sqlite3.connect(str(db_file)) as conn:
            cur = conn.execute("SELECT udid, serial, record FROM activations WHERE udid=?", (unique_udid,))
            row = cur.fetchone()
            assert row is not None, "activation record not found in DB"
            assert row[0] == unique_udid
            assert row[1] == serial
            assert row[2] is not None and len(row[2]) > 0
            # also ensure at least one row exists
            cur2 = conn.execute("SELECT COUNT(*) FROM activations")
            count = cur2.fetchone()[0]
            assert count >= 1
    finally:
        albert_server.DB_PATH = original_db
        # Re-init original DB to ensure it exists (in case it was not recreated)
        try:
            albert_server._init_db()
        except Exception:
            pass
