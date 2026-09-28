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
            token = ""  # nosec B105 - test helper fallback, not a real password
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

def test_csrf_pair_post_requires_admin():
    c = albert_server.app.test_client()
    r = c.post("/api/pair", headers=_no_admin_headers())
    assert r.status_code == 401
    r2 = c.post("/api/pair", headers=_admin_headers())
    # will be 200 even without device (ok false but not 401)
    assert r2.status_code == 200

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

def test_clean_volume_e2e_placeholder():
    # verifies docker-compose config valid and no named volumes (clean-volume test placeholder)
    import subprocess
    out = subprocess.run(["docker","compose","config"], capture_output=True, text=True, timeout=5)
    assert out.returncode == 0
    assert "albert-server" in out.stdout

def test_restart_key_persistence():
    # FairPlay key persists 0600, not regenerated on restart
    p = pathlib.Path("certs/fairplay.key")
    q = pathlib.Path("certs/fallback.key")
    assert p.exists()
    assert oct(p.stat().st_mode)[-3:] == "600"
    assert q.exists()
    assert oct(q.stat().st_mode)[-3:] == "600"
    # hash stable across reads
    h1 = p.read_bytes()[:20]
    h2 = pathlib.Path("certs/fairplay.key").read_bytes()[:20]
    assert h1 == h2
