"""Tests for the phoneHome endpoint and the mTLS gate in front of it.

phoneHome is the one activation endpoint that writes to sync_state, and it had
no coverage at all. The mTLS gate matters more than usual here because the
running instance is bound to ALBERT_HOST=0.0.0.0, so these tests pin who is
allowed to reach a DB-writing endpoint.
"""
import os

from werkzeug.test import Client
import pathlib
import plistlib
import sqlite3

import pytest

import albert_server

UDID = "00008020-AAAAAAAAAAAAAAAA"
IMEI = "490154203237518"  # passes Luhn

# An HTTP header cannot carry newlines, so a proxy forwarding the real client
# certificate sends it as a single line. Werkzeug rejects multi-line values.
REAL_PEM = "-----BEGIN CERTIFICATE-----" + ("A" * 120) + "-----END CERTIFICATE-----"


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    db = tmp_path / "phonehome.db"
    monkeypatch.setattr(albert_server, "DB_PATH", db)
    monkeypatch.setenv("ALBERT_ADMIN_TOKEN", "test-admin-token")
    albert_server._init_db()
    yield db


@pytest.fixture(autouse=True)
def _gate_enabled(monkeypatch):
    """Force the mTLS gate on regardless of what certs/ happens to hold.

    The gate only engages when certs/mtls-ca.crt exists, and certs/ is
    gitignored, so CI runs with the gate silently disabled. Letting that leak
    into the assertions made these four tests fail off this machine (and would
    have made them pass vacuously in CI). Patch the lookup instead.
    """
    monkeypatch.setattr(albert_server, "_get_mtls_ca", lambda: "certs/mtls-ca.crt")


def _client():
    """A real client, bypassing the shared wrapper another test module installs.

    tests/test_albert.py rebinds albert_server.app.test_client at import time to
    inject X-Client-Cert on /WebObjects paths. Going through that wrapper would
    hand these assertions a certificate they are supposed to be proving is
    required, so build the Werkzeug client directly. Flask leaves
    test_client_class as None here, so Client is the route that works.
    """
    return Client(albert_server.app)


def _state(db, udid=UDID):
    with sqlite3.connect(str(db)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM sync_state WHERE udid=?", (udid,)).fetchone()
        return dict(row) if row else {}


def _plist_body(**fields):
    return plistlib.dumps(fields)


# --- the mTLS gate -------------------------------------------------------

def test_phonehome_without_any_client_evidence_is_rejected():
    """No certificate, no token, no PEM: must not reach the handler."""
    r = _client().post("/WebObjects/ALUnbrick.woa/wa/phoneHome")
    assert r.status_code == 401


def test_phonehome_rejects_bare_header_when_fallback_disabled(monkeypatch):
    """A bare "present" header is spoofable, so it needs an explicit opt-in."""
    monkeypatch.setenv("ALBERT_MTLS_ALLOW_HEADER_FALLBACK", "0")
    r = _client().post(
        "/WebObjects/ALUnbrick.woa/wa/phoneHome",
        headers={"X-Client-Cert": "present"},
    )
    assert r.status_code == 401, "spoofable bare header was accepted without opt-in"


def test_phonehome_accepts_real_pem(_isolated_db):
    r = _client().post(
        "/WebObjects/ALUnbrick.woa/wa/phoneHome",
        headers={"X-Client-Cert": REAL_PEM},
        data=_plist_body(UDID=UDID, IMEI=IMEI),
        content_type="application/xml",
    )
    assert r.status_code == 200
    assert _state(_isolated_db)["udid"] == UDID


def test_phonehome_accepts_shared_token(monkeypatch, _isolated_db):
    monkeypatch.setenv("ALBERT_MTLS_TOKEN", "shared-secret-value")
    r = _client().post(
        "/WebObjects/ALUnbrick.woa/wa/phoneHome",
        headers={"X-MTLS-Token": "shared-secret-value"},
        data=_plist_body(UDID=UDID, IMEI=IMEI),
        content_type="application/xml",
    )
    assert r.status_code == 200


def test_phonehome_rejects_wrong_shared_token(monkeypatch):
    monkeypatch.setenv("ALBERT_MTLS_TOKEN", "shared-secret-value")
    r = _client().post(
        "/WebObjects/ALUnbrick.woa/wa/phoneHome",
        headers={"X-MTLS-Token": "not-the-secret"},
        data=_plist_body(UDID=UDID, IMEI=IMEI),
        content_type="application/xml",
    )
    assert r.status_code == 401


# --- the handler ---------------------------------------------------------

def test_phonehome_creates_sync_state_row(_isolated_db):
    r = _client().post(
        "/WebObjects/ALUnbrick.woa/wa/phoneHome",
        headers={"X-Client-Cert": REAL_PEM},
        data=_plist_body(UDID=UDID, IMEI=IMEI),
        content_type="application/xml",
    )
    assert r.status_code == 200
    row = _state(_isolated_db)
    assert row["udid"] == UDID
    assert row["imei"] == IMEI
    assert row["carrier_activated"] == 1


def test_phonehome_returns_a_plist(_isolated_db):
    r = _client().post(
        "/WebObjects/ALUnbrick.woa/wa/phoneHome",
        headers={"X-Client-Cert": REAL_PEM},
        data=_plist_body(UDID=UDID, IMEI=IMEI),
        content_type="application/xml",
    )
    assert r.mimetype == "application/xml"
    body = plistlib.loads(r.data)
    assert body["status"] == "success"
    assert body["carrierActivated"] == 1


def test_phonehome_stores_phone_number_when_present(_isolated_db):
    _client().post(
        "/WebObjects/ALUnbrick.woa/wa/phoneHome",
        headers={"X-Client-Cert": REAL_PEM},
        data=_plist_body(UDID=UDID, IMEI=IMEI, PhoneNumber="+66912345678"),
        content_type="application/xml",
    )
    assert _state(_isolated_db)["phone_number"] == "+66912345678"


def test_phonehome_survives_a_malformed_plist(_isolated_db):
    """Bad input must be swallowed by the handler, not surface as a 500."""
    r = _client().post(
        "/WebObjects/ALUnbrick.woa/wa/phoneHome",
        headers={"X-Client-Cert": REAL_PEM},
        data=b"this is not a plist",
        content_type="application/xml",
    )
    assert r.status_code == 200
    assert _state(_isolated_db) == {}, "a malformed body must not create a row"


def test_phonehome_ignores_a_body_missing_identifiers(_isolated_db):
    """Only IMEI without a UDID must not produce a half-written row."""
    _client().post(
        "/WebObjects/ALUnbrick.woa/wa/phoneHome",
        headers={"X-Client-Cert": REAL_PEM},
        data=_plist_body(IMEI=IMEI),
        content_type="application/xml",
    )
    assert _state(_isolated_db) == {}


def test_phonehome_accepts_the_apple_key_spellings(_isolated_db):
    """Devices use UniqueDeviceID / InternationalMobileEquipmentIdentity."""
    _client().post(
        "/WebObjects/ALUnbrick.woa/wa/phoneHome",
        headers={"X-Client-Cert": REAL_PEM},
        data=_plist_body(UniqueDeviceID=UDID, InternationalMobileEquipmentIdentity=IMEI),
        content_type="application/xml",
    )
    assert _state(_isolated_db)["udid"] == UDID


def test_phonehome_is_idempotent(_isolated_db):
    """A device re-sending phoneHome must not create duplicate rows."""
    c = _client()
    for _ in range(3):
        c.post(
            "/WebObjects/ALUnbrick.woa/wa/phoneHome",
            headers={"X-Client-Cert": REAL_PEM},
            data=_plist_body(UDID=UDID, IMEI=IMEI),
            content_type="application/xml",
        )
    with sqlite3.connect(str(_isolated_db)) as conn:
        count = conn.execute("SELECT COUNT(*) FROM sync_state WHERE udid=?", (UDID,)).fetchone()[0]
    assert count == 1


# --- deployment posture --------------------------------------------------

def test_deployment_binds_lan_and_relies_on_the_gate():
    """Documents the live posture of this machine, not a behaviour contract.

    Skipped wherever certs/ is absent (it is gitignored, so CI skips it). The
    point is to fail loudly if someone reconfigures the host so that neither an
    mTLS token nor the header fallback is available, leaving the LAN-facing
    bind unprotected.
    """
    if not pathlib.Path("certs/mtls-ca.crt").exists():
        pytest.skip("certs/mtls-ca.crt not present; this host has no CA to assert about")
    assert "ALBERT_HOST" in pathlib.Path("gunicorn_conf.py").read_text()
    assert os.environ.get("ALBERT_MTLS_TOKEN", "").strip() or os.environ.get(
        "ALBERT_MTLS_ALLOW_HEADER_FALLBACK", ""
    ), "no mTLS credential configured on a host that binds 0.0.0.0"