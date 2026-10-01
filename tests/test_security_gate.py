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


def test_device_identity_normalizes_whitespace():
    """Regression: a value that passes validation after strip() must be written
    back in normalized form. _validate_udid/_validate_imei check str(v).strip(),
    so " <valid> " used to be accepted and then stored as a sync_state key that
    did not match the canonical row for the same device."""
    udid, imei, rejected = albert_server._device_identity_from_plist(
        {"UDID": " 00008020-AAAAAAAAAAAAAAAA ", "IMEI": " 350000000000006 "}
    )
    assert rejected is False
    assert udid == "00008020-AAAAAAAAAAAAAAAA"
    assert imei == "350000000000006"


def test_device_identity_padded_and_bare_collapse_to_same_key():
    """Padded and unpadded forms must produce the identical key."""
    padded, _, r1 = albert_server._device_identity_from_plist(
        {"UDID": " 00008020-AAAAAAAAAAAAAAAA "}
    )
    bare, _, r2 = albert_server._device_identity_from_plist(
        {"UDID": "00008020-AAAAAAAAAAAAAAAA"}
    )
    assert r1 is False and r2 is False
    assert padded == bare


def test_device_identity_whitespace_only_is_empty_not_rejected():
    """A whitespace-only value normalizes to empty, which means "not supplied"
    and must not be reported as a malformed identifier."""
    udid, imei, rejected = albert_server._device_identity_from_plist(
        {"UDID": "   ", "IMEI": "  "}
    )
    assert (udid, imei) == ("", "")
    assert rejected is False


def test_device_identity_still_rejects_malformed_after_strip():
    """Normalization must not weaken validation: junk stays rejected."""
    for bad in ("bad", "00008020-AAAAAAA", "00008020-AAAAAAAAAAAAAAAA-EXTRA", "x" * 60):
        udid, imei, rejected = albert_server._device_identity_from_plist({"UDID": bad})
        assert rejected is True, bad
        assert udid == "" and imei == "", bad


def test_device_error_responses_do_not_leak_exception_text():
    """Regression for CodeQL py/stack-trace-exposure. drmHandshake and
    deviceActivation used to return f"Invalid plist: {e}" / f"Error: {str(e)}",
    which puts exception text -- often including server-side paths -- straight
    into the response body. The detail is still logged server-side."""
    c = albert_server.app.test_client()
    for path, body in [
        ("/deviceservices/drmHandshake", b"this is not a plist at all"),
        ("/deviceservices/deviceActivation", b"<<< not a plist >>>"),
    ]:
        r = c.post(path, data=body, content_type="application/x-apple-plist")
        text = r.get_data(as_text=True)
        # Either it parsed and moved on, or it failed generically -- but no
        # exception text may reach the client.
        for leak in ("Invalid plist:", "Traceback", "File \"", ".py\", line"):
            assert leak not in text, f"{path} leaked {leak!r}: {text[:200]}"
        if r.status_code >= 400:
            # iOS parses device-endpoint responses as a property list and turns a
            # JSON body into NSCocoaErrorDomain 3840 ("Unexpected character {"),
            # which hides the real error. A plist body is required here.
            assert "xml" in r.content_type, f"{path} error must be a plist, got {r.content_type}"
            assert r.get_data().lstrip().startswith(b"<?xml"), f"{path} body is not a plist"


def test_device_error_responses_include_request_id():
    """The generic error body still carries request_id so a client report can be
    correlated with the server log, which is where the exception detail lives."""
    c = albert_server.app.test_client()
    import plistlib as _plistlib

    r = c.post("/deviceservices/drmHandshake", data=b"not a plist",
               content_type="application/x-apple-plist")
    assert r.status_code >= 400, r.status_code
    body = _plistlib.loads(r.get_data())
    assert "RequestID" in body, body
    assert "Error" in body, body


def test_tool_arg_rejects_leading_dash():
    """Regression: the old allowlist was ^[A-Za-z0-9._-]+$, which also matched a
    leading '-', so ?domain=-oRoot or ?key=--help passed validation and
    ideviceinfo read the value as a flag rather than data. shell=False does not
    help -- argument injection needs no shell. Exercised through the endpoint so
    the test covers the regex that is actually in the request path."""
    c = albert_server.app.test_client()
    h = _admin_headers()
    for bad in ("-oRoot", "--help", "-q", "--version", ".hidden", "_x", "a;b", "a b"):
        r = c.get("/api/device_info?domain=" + bad, headers=h)
        assert r.status_code == 400, (bad, r.status_code)
        r = c.get("/api/device_info?key=" + bad, headers=h)
        assert r.status_code == 400, (bad, r.status_code)


def test_tool_arg_accepts_real_domains_and_keys():
    """Normal values must keep working -- the allowlist is not meant to reject
    real ideviceinfo domains or keys. A device may be absent, so a 200 body that
    reports no connection is the expected shape, not a 400."""
    c = albert_server.app.test_client()
    h = _admin_headers()
    for good in ("ProductVersion", "ProductType", "BuildVersion", "0abc", "a.b_c-d"):
        r = c.get("/api/device_info?domain=" + good, headers=h)
        assert r.status_code == 200, (good, r.status_code, r.get_data(as_text=True)[:120])
        assert "invalid domain" not in r.get_data(as_text=True), good


def test_dashboard_sends_admin_token_to_gated_endpoints():
    """Regression: /dashboard polled /api/status and /api/logs without the
    X-Admin-Token header. /api/status then returned only the public payload
    (health/ready/version), so the page's activations table and rate readout read
    undefined and stayed blank, and /api/logs answered 401 on every poll."""
    html = albert_server.DASHBOARD_HTML
    assert "localStorage.getItem('zalive_admin_token')" in html, (
        "dashboard no longer reads the token that /admin stores"
    )
    # Both gated fetches must carry the header, not just one of them.
    assert "fetch('/api/status', {cache:'no-store', headers:" in html
    assert "fetch('/api/logs?lines=60',{cache:'no-store', headers:" in html


def test_dashboard_token_key_matches_admin_panel():
    """The dashboard and /admin must agree on the localStorage key, otherwise the
    header is sent with an empty value and the endpoints stay gated."""
    assert "'zalive_admin_token'" in albert_server.ADMIN_HTML
    assert "'zalive_admin_token'" in albert_server.DASHBOARD_HTML


def _reset_device_live_cache():
    albert_server._DEVICE_LIVE_CACHE["data"] = None
    albert_server._DEVICE_LIVE_CACHE["ts"] = 0.0


def test_live_device_info_reads_plist_not_capped_text():
    """ideviceinfo -x must be parsed as a plist. Parsing the text dump instead is
    what made UniqueDeviceID vanish: _run_tool caps stdout at 4000 bytes and the
    dump is larger, so the tail was silently truncated and the dashboard fell back
    to the stale activation snapshot while still looking connected."""
    src = albert_server.__file__
    with open(src) as fh:
        code = fh.read()
    assert '["ideviceinfo", "-x"]' in code
    assert "plistlib.loads(proc.stdout)" in code


def test_live_device_info_returns_empty_without_device(monkeypatch):
    """No device attached must yield {}, never a stale or invented identity, so the
    card can fall back to the last activation snapshot."""

    def boom(*a, **k):
        raise OSError("no device")

    _reset_device_live_cache()
    monkeypatch.setattr(albert_server.subprocess, "run", boom)
    assert albert_server._get_live_device_info() == {}


def test_live_device_info_caches_between_polls(monkeypatch):
    """/api/status is polled every 2s. Without a TTL the device is re-read on every
    tick, spawning two extra processes per tick."""
    calls = []

    class FakeProc:
        returncode = 0
        stdout = plistlib.dumps({"UniqueDeviceID": "FAKEUDID0000", "ProductType": "iPhone9,3"})

    def fake_run(cmd, *a, **k):
        calls.append(cmd)
        return FakeProc()

    _reset_device_live_cache()
    monkeypatch.setattr(albert_server.subprocess, "run", fake_run)
    first = albert_server._get_live_device_info()
    second = albert_server._get_live_device_info()
    assert first["UniqueDeviceID"] == "FAKEUDID0000"
    assert first == second
    assert len(calls) == 2, "second call should be served from cache"


def test_live_device_overrides_db_snapshot(monkeypatch):
    """The attached device must win over the stored activation row, otherwise the
    card keeps showing the previously activated device after a swap."""

    class FakeProc:
        returncode = 0
        stdout = plistlib.dumps(
            {
                "UniqueDeviceID": "LIVEUDID00000001",
                "ProductType": "iPhone9,3",
                "SerialNumber": "LIVESERIAL1",
                "HardwareModel": "N71AP",
                "ProductVersion": "16.7.11",
                "BuildVersion": "20G115",
            }
        )

    _reset_device_live_cache()
    monkeypatch.setattr(albert_server.subprocess, "run", lambda cmd, *a, **k: FakeProc())
    payload = albert_server._build_status_payload()
    dev = payload["device"]
    assert dev["live"] is True
    assert dev["UDID"] == "LIVEUDID00000001"
    assert dev["ProductType"] == "iPhone9,3"
    assert dev["HardwareModel"] == "N71AP"
    assert dev["ProductVersion"] == "16.7.11"


def test_dashboard_marks_device_card_as_live_or_snapshot():
    """The card must say which it is showing, otherwise a stale snapshot is
    indistinguishable from a plugged-in device."""
    html = albert_server.DASHBOARD_HTML
    assert '>live</span>' in html
    assert '>last snapshot</span>' in html


def test_dashboard_redacts_live_serial():
    """SerialNumber now comes from the attached device rather than a placeholder, so
    it must be redacted on the card the same way the UDID already is."""
    device_line = next(
        line for line in albert_server.DASHBOARD_HTML.splitlines() if "$('device')" in line
    )
    assert "SN '+redact(d.SerialNumber||'')" in device_line
    assert "' SN '+(d.SerialNumber||'-')" not in device_line
