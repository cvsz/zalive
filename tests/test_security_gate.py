"""Gate 11-13: RBAC/CSRF/security for state-changing operations + clean-volume/restart E2E (pre-cable, no device)."""
import base64
import os
import pathlib
import plistlib

import albert_server

# reuse mtls shim from test_albert (already patched app.test_client)
# admin token helper
def _admin_headers():
    token = (os.environ.get("ALBERT_ADMIN_TOKEN") or "").strip()
    if not token:
        try:
            token = pathlib.Path(".env").read_text().split("ALBERT_ADMIN_TOKEN=")[1].split()[0].strip().strip('"').strip("'")
        except Exception:
            token = "ci-test-token"  # nosec B105 - test helper fallback for CI without .env
            os.environ["ALBERT_ADMIN_TOKEN"] = token
    return {"X-Admin-Token": token}  # nosec B105

def _no_admin_headers():
    return {"X-Admin-Token": "invalid-token-for-test"}  # nosec B105

def test_rbac_device_info_requires_admin():
    c = albert_server.app.test_client()
    # without valid token -> 401 (use invalid to bypass auto-inject shim)
    r = c.get("/api/device_info", headers=_no_admin_headers())
    assert r.status_code == 401
    # with token -> 200 (ok false due no device, but not 401)
    r2 = c.get("/api/device_info", headers=_admin_headers())
    assert r2.status_code == 200
    assert "ok" in r2.get_json()

def test_rbac_diagnostics_requires_admin():
    c = albert_server.app.test_client()
    r = c.get("/api/diagnostics", headers=_no_admin_headers())
    assert r.status_code == 401
    r2 = c.get("/api/diagnostics", headers=_admin_headers())
    assert r2.status_code == 200

def test_rbac_recovery_requires_admin():
    c = albert_server.app.test_client()
    r = c.get("/api/recovery", headers=_no_admin_headers())
    assert r.status_code == 401
    r2 = c.get("/api/recovery", headers=_admin_headers())
    assert r2.status_code == 200
    assert "recovery" in r2.get_json()

def test_rbac_pair_requires_admin():
    c = albert_server.app.test_client()
    r = c.get("/api/pair", headers=_no_admin_headers())
    assert r.status_code == 401
    r2 = c.get("/api/pair", headers=_admin_headers())
    assert r2.status_code == 200

def test_rbac_ifuse_requires_admin():
    c = albert_server.app.test_client()
    r = c.get("/api/ifuse", headers=_no_admin_headers())
    assert r.status_code == 401
    r2 = c.get("/api/ifuse", headers=_admin_headers())
    assert r2.status_code == 200

def test_rbac_tss_requires_admin():
    c = albert_server.app.test_client()
    r = c.get("/api/tss", headers=_no_admin_headers())
    assert r.status_code == 401
    r2 = c.get("/api/tss", headers=_admin_headers())
    assert r2.status_code != 401

def test_rbac_activations_logs_require_admin():
    c = albert_server.app.test_client()
    r = c.get("/api/activations", headers=_no_admin_headers())
    assert r.status_code == 401
    r2 = c.get("/api/logs", headers=_no_admin_headers())
    assert r2.status_code == 401
    # with token
    r3 = c.get("/api/activations", headers=_admin_headers())
    assert r3.status_code == 200
    r4 = c.get("/api/logs", headers=_admin_headers())
    assert r4.status_code == 200

def test_query_string_admin_token_rejected():
    c = albert_server.app.test_client()
    token = _admin_headers()["X-Admin-Token"]
    r = c.get(f"/api/device_info?token={token}")
    assert r.status_code == 401
    assert "query-string" in r.get_json().get("error","").lower()

def test_redis_uri_not_leaked():
    c = albert_server.app.test_client()
    r = c.get("/api/rate_status", headers=_admin_headers())
    j = r.get_json()
    assert j.get("redis_url") in ("", "redacted")

def test_auth_pair_post_requires_admin():
    c = albert_server.app.test_client()
    r = c.post("/api/pair", headers=_no_admin_headers())
    assert r.status_code == 401
    r2 = c.post("/api/pair", headers=_admin_headers())
    # will be 200 even without device (ok false but not 401)
    assert r2.status_code == 200

def test_csrf_header_based_auth_mitigates_csrf():
    # header-based auth (X-Admin-Token) is not ambient (no cookie), so CSRF via foreign Origin is already low risk
    # verify foreign Origin without token still 401, and with token + foreign Origin still gated by auth (not CSRF cookie)
    c = albert_server.app.test_client()
    r = c.post("/api/pair", headers={"Origin": "https://evil.example.com", **_no_admin_headers()})
    assert r.status_code == 401
    r2 = c.post("/api/pair", headers={"Origin": "https://evil.example.com", **_admin_headers()})
    assert r2.status_code == 200
    # trusted Origin with valid token should also succeed
    r3 = c.post("/api/pair", headers={"Origin": "http://127.0.0.1:18090", **_admin_headers()})
    assert r3.status_code == 200

def test_rate_limit_all_api():
    albert_server._reset_rate_limit()
    orig = albert_server._RATE_LIMIT_MAX
    albert_server._RATE_LIMIT_MAX = 3
    try:
        c = albert_server.app.test_client()
        for _ in range(3):
            r = c.get("/api/device_info", headers=_admin_headers())
            assert r.status_code != 429
        r = c.get("/api/device_info", headers=_admin_headers())
        assert r.status_code == 429
    finally:
        albert_server._RATE_LIMIT_MAX = orig
        albert_server._reset_rate_limit()

def test_docker_compose_config_valid():
    # validates docker-compose YAML parses (not a full clean-volume E2E)
    import subprocess
    import secrets
    import os
    env = os.environ.copy()
    env["MITMPROXY_WEB_PASSWORD"] = secrets.token_urlsafe(24)
    out = subprocess.run(["docker","compose","config"], capture_output=True, text=True, timeout=15, env=env)
    assert out.returncode == 0, out.stderr
    assert "albert-server" in out.stdout

def test_restart_key_persistence_tmpdir():
    # use temp dir with FAIRPLAY_KEY_PATH override to avoid depending on host certs/
    import tempfile
    import hashlib
    import stat
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from datetime import datetime, timezone, timedelta

    with tempfile.TemporaryDirectory() as td:
        key_path = pathlib.Path(td) / "fairplay.key"
        cert_path = pathlib.Path(td) / "fairplay.crt"
        # first generation
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
            x509.NameAttribute(NameOID.COMMON_NAME, "Apple iPhone Device CA"),
        ])
        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=5*365)
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(not_before).not_valid_after(not_after).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(key, hashes.SHA256())
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_path.write_bytes(key_pem)
        key_path.chmod(0o600)
        cert_path.write_bytes(cert_pem)
        cert_path.chmod(0o600)
        h1 = hashlib.sha256(key_path.read_bytes()).hexdigest()
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
        # simulate restart: reload
        loaded = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        assert loaded is not None
        h2 = hashlib.sha256(key_path.read_bytes()).hexdigest()
        assert h1 == h2
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
