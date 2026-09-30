"""Production gate tests for the /api/admin/sync-state endpoints.

These endpoints arrived as uncommitted work, so nothing covered them. Each one
mutates the sync_state table and is reachable over HTTP, which makes them the
highest-risk untested surface in the server.
"""
import pathlib
import sqlite3

import pytest

import albert_server

# Synthetic UDID: shape matches the real 25-char form (00008020 + '-' + 16 hex)
# but is obviously not a device.
UDID = "00008020-AAAAAAAAAAAAAAAA"
TOKEN = "test-admin-token-not-a-secret"  # nosec B105 - test fixture, not a credential
# Synthetic APNs token used only as a fixture value. It is never sent to Apple
# and carries no privilege, but bandit reads the "push_token" key as a secret,
# so the waiver below is deliberate rather than a way to hide a real finding.
PUSH_TOKEN = "abcdef0123456789"  # nosec B105 - synthetic fixture, not a credential


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    """Point sync_state at a throwaway DB so tests never touch the real one."""
    db = tmp_path / "test-activations.db"
    monkeypatch.setattr(albert_server, "DB_PATH", db)
    monkeypatch.setenv("ALBERT_ADMIN_TOKEN", TOKEN)
    albert_server._init_db()
    yield db


def _client():
    return albert_server.app.test_client()


def _auth():
    return {"X-Admin-Token": TOKEN}


def _seed(db, udid=UDID, imei="490154203237518", **cols):
    row = {
        "udid": udid,
        "imei": imei,
        "serial": "F2LX00TEST",
        "push_token": None,  # nosec B105 - default state, not a credential
        "apns_topic": None,
        "sync_enabled": 1,
        "find_my_enabled": 1,
        "icloud_enabled": 1,
        "carrier_activated": 0,
        "last_sync": None,
        "phone_number": "",
    }
    row.update(cols)
    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO sync_state (udid, imei, serial, push_token,"
            " apns_topic, sync_enabled, find_my_enabled, icloud_enabled,"
            " carrier_activated, last_sync, phone_number)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            tuple(row[k] for k in (
                "udid", "imei", "serial", "push_token", "apns_topic",
                "sync_enabled", "find_my_enabled", "icloud_enabled",
                "carrier_activated", "last_sync", "phone_number",
            )),
        )
        conn.commit()


def _state(db, udid=UDID):
    with sqlite3.connect(str(db)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM sync_state WHERE udid=?", (udid,)).fetchone()
        return dict(row) if row else {}


SYNC_ROUTES = [
    ("/api/admin/sync-state", "get"),
    (f"/api/admin/sync-state/{UDID}", "get"),
    (f"/api/admin/sync-state/{UDID}", "post"),
    (f"/api/admin/sync-state/{UDID}/activate", "post"),
    (f"/api/admin/sync-state/{UDID}/deactivate", "post"),
    (f"/api/admin/sync-state/{UDID}/carrier-activate", "post"),
    (f"/api/admin/sync-state/{UDID}/register-push", "post"),
]


# --- auth gate -----------------------------------------------------------

@pytest.mark.parametrize("path,method", SYNC_ROUTES)
def test_sync_routes_require_admin_token(path, method):
    """No endpoint may be reachable without a token."""
    c = _client()
    r = getattr(c, method)(path)
    assert r.status_code == 401, f"{method.upper()} {path} reachable without auth"


@pytest.mark.parametrize("path,method", SYNC_ROUTES)
def test_sync_routes_reject_wrong_token(path, method):
    c = _client()
    r = getattr(c, method)(path, headers={"X-Admin-Token": "wrong"})
    assert r.status_code == 401, f"{method.upper()} {path} accepted a wrong token"


@pytest.mark.parametrize("path,method", SYNC_ROUTES)
def test_sync_routes_reject_token_in_query_string(path, method):
    """Token via query string leaks into logs/Referer; must stay rejected."""
    c = _client()
    r = getattr(c, method)(f"{path}?token={TOKEN}")
    assert r.status_code == 401, f"{method.upper()} {path} accepted a query-string token"


# --- read paths ----------------------------------------------------------

def test_sync_state_list_requires_token():
    r = _client().get("/api/admin/sync-state")
    assert r.status_code == 401


def test_sync_state_detail_returns_seeded_row(_isolated_db):
    _seed(_isolated_db)
    r = _client().get(f"/api/admin/sync-state/{UDID}", headers=_auth())
    assert r.status_code == 200
    assert r.get_json()["sync_state"]["udid"] == UDID


def test_sync_state_detail_unknown_udid_is_404(_isolated_db):
    """A miss must 404 rather than fabricate a row or 500."""
    r = _client().get("/api/admin/sync-state/00008020-BBBBBBBBBBBBBBBB", headers=_auth())
    assert r.status_code == 404
    assert r.get_json()["ok"] is False


def test_sync_state_list_returns_every_seeded_device(_isolated_db):
    _seed(_isolated_db, udid=UDID, imei="490154203237518")
    _seed(_isolated_db, udid="00008020-CCCCCCCCCCCCCCCC", imei="490154203237500")
    r = _client().get("/api/admin/sync-state", headers=_auth())
    assert r.status_code == 200
    body = r.get_json()
    assert body["count"] == 2, body
    seen = {row["udid"] for row in body["sync_states"]}
    assert seen == {UDID, "00008020-CCCCCCCCCCCCCCCC"}


# --- writes --------------------------------------------------------------

def test_sync_state_update_refuses_to_overwrite_imei(_isolated_db):
    """IMEI/serial are not in the endpoint whitelist, so identity cannot be rewritten.

    Written deliberately after finding that a Luhn-valid IMEI also returned 400:
    the rejection was the whitelist, not validation, and the weaker test would
    have passed for the wrong reason.
    """
    _seed(_isolated_db, imei="490154203237518", serial="F2LX00TEST")
    assert albert_server._luhn_check("490154203237500"), "fixture must pass Luhn"
    r = _client().post(
        f"/api/admin/sync-state/{UDID}",
        json={"imei": "490154203237500"},
        headers=_auth(),
    )
    assert r.status_code == 400
    row = _state(_isolated_db)
    assert row["imei"] == "490154203237518", "IMEI was rewritten despite the whitelist"
    assert row["serial"] == "F2LX00TEST"


def test_sync_state_update_refuses_to_overwrite_serial(_isolated_db):
    _seed(_isolated_db, serial="F2LX00TEST")
    r = _client().post(
        f"/api/admin/sync-state/{UDID}",
        json={"serial": "TAMPERED"},
        headers=_auth(),
    )
    assert r.status_code == 400
    assert _state(_isolated_db)["serial"] == "F2LX00TEST"


def test_imei_validation_is_format_only_by_default(monkeypatch):
    """_validate_imei enforces shape, not the Luhn check digit, unless opted in.

    This is a deliberate opt-in toggle (ALBERT_IMEI_LUHN) and the module comment
    says some test IMEIs do not satisfy Luhn. Pinned here so a future change to
    the default has to update this test on purpose.
    """
    monkeypatch.delenv("ALBERT_IMEI_LUHN", raising=False)
    assert albert_server._validate_imei("490154203237518")
    assert albert_server._validate_imei("490154203237510"), "Luhn is off by default"
    assert not albert_server._validate_imei("12345"), "shape is still enforced"
    assert not albert_server._validate_imei("49015420323751a")


def test_imei_luhn_check_can_be_enforced(monkeypatch):
    monkeypatch.setenv("ALBERT_IMEI_LUHN", "1")
    assert albert_server._validate_imei("490154203237518")
    assert not albert_server._validate_imei("490154203237510")


def test_luhn_check_discriminates_check_digits():
    """The gate exists and works; _validate_imei simply does not call it by default."""
    assert albert_server._luhn_check("490154203237518")
    assert albert_server._luhn_check("490154203237500")
    assert not albert_server._luhn_check("490154203237510")
    assert not albert_server._luhn_check("not-an-imei")


def test_update_accepts_a_whitelisted_field(_isolated_db):
    _seed(_isolated_db)
    r = _client().post(
        f"/api/admin/sync-state/{UDID}",
        json={"phone_number": "+66912345678"},
        headers=_auth(),
    )
    assert r.status_code == 200
    assert _state(_isolated_db)["phone_number"] == "+66912345678"


def test_sync_state_update_ignores_unknown_column(_isolated_db):
    """Column whitelist must stop a caller writing arbitrary columns."""
    _seed(_isolated_db)
    r = _client().post(
        f"/api/admin/sync-state/{UDID}",
        json={"created_at": "1999-01-01T00:00:00+00:00"},
        headers=_auth(),
    )
    assert r.status_code == 400
    assert _state(_isolated_db)["created_at"] != "1999-01-01T00:00:00+00:00"


def test_sync_state_activate_sets_all_three_flags(_isolated_db):
    _seed(_isolated_db, sync_enabled=0, find_my_enabled=0, icloud_enabled=0)
    r = _client().post(f"/api/admin/sync-state/{UDID}/activate", headers=_auth())
    assert r.status_code == 200
    row = _state(_isolated_db)
    assert row["sync_enabled"] == 1
    assert row["find_my_enabled"] == 1
    assert row["icloud_enabled"] == 1


def test_sync_state_deactivate_clears_carrier_flag(_isolated_db):
    _seed(_isolated_db, carrier_activated=1)
    r = _client().post(f"/api/admin/sync-state/{UDID}/deactivate", headers=_auth())
    assert r.status_code == 200
    assert _state(_isolated_db)["carrier_activated"] == 0


def test_carrier_activate_sets_flag(_isolated_db):
    _seed(_isolated_db, carrier_activated=0)
    r = _client().post(f"/api/admin/sync-state/{UDID}/carrier-activate", headers=_auth())
    assert r.status_code == 200
    assert _state(_isolated_db)["carrier_activated"] == 1


def test_register_push_requires_a_token_in_the_body(_isolated_db):
    _seed(_isolated_db)
    r = _client().post(f"/api/admin/sync-state/{UDID}/register-push", json={}, headers=_auth())
    assert r.status_code == 400
    assert _state(_isolated_db)["push_token"] is None


def test_register_push_derives_topic_from_imei(_isolated_db):
    _seed(_isolated_db, imei="490154203237518")
    r = _client().post(
        f"/api/admin/sync-state/{UDID}/register-push",
        json={"push_token": PUSH_TOKEN},
        headers=_auth(),
    )
    assert r.status_code == 200
    row = _state(_isolated_db)
    assert row["push_token"] == PUSH_TOKEN
    assert row["apns_topic"] == "com.apple.activation.490154203237518"


def test_register_push_response_does_not_overclaim_apns(_isolated_db):
    """The message must not imply a real APNs registration happened."""
    _seed(_isolated_db)
    r = _client().post(
        f"/api/admin/sync-state/{UDID}/register-push",
        json={"push_token": PUSH_TOKEN},
        headers=_auth(),
    )
    msg = r.get_json().get("message", "").lower()
    assert "recorded" in msg, f"response message overclaims: {msg!r}"
    assert "apns" in msg, "response should state that no APNs call happened"


def test_record_push_token_only_writes_locally(_isolated_db):
    """_record_push_token must not perform network I/O."""
    import socket

    _seed(_isolated_db, imei="490154203237518")
    before = _state(_isolated_db)["push_token"]
    assert before is None

    def _blocked(*a, **kw):
        raise AssertionError("_record_push_token attempted a network call")

    original = socket.socket.connect
    socket.socket.connect = _blocked
    try:
        assert albert_server._record_push_token(UDID, "token123", "490154203237518")
    finally:
        socket.socket.connect = original
    assert _state(_isolated_db)["push_token"] == "token123"


# --- regression: empty body must not 500 --------------------------------

def test_carrier_activate_without_body_is_accepted(_isolated_db):
    """Regression: get_json() raised on an absent content-type and the broad
    except turned it into 500, making a bodyless POST unusable."""
    _seed(_isolated_db, carrier_activated=0)
    r = _client().post(f"/api/admin/sync-state/{UDID}/carrier-activate", headers=_auth())
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _state(_isolated_db)["carrier_activated"] == 1


def test_register_push_without_body_is_400_not_500(_isolated_db):
    """Same regression: missing push_token is a client error, not a server error."""
    _seed(_isolated_db)
    r = _client().post(f"/api/admin/sync-state/{UDID}/register-push", headers=_auth())
    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json()["error"] == "push_token required"


def test_update_without_body_is_400_not_500(_isolated_db):
    """Same regression: no fields supplied is a client error."""
    _seed(_isolated_db)
    r = _client().post(f"/api/admin/sync-state/{UDID}", headers=_auth())
    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json()["error"] == "No valid fields provided"


def test_post_with_malformed_json_is_400_not_500(_isolated_db):
    """A truncated body must not become a 500 either."""
    _seed(_isolated_db)
    r = _client().post(
        f"/api/admin/sync-state/{UDID}",
        data="{not json",
        content_type="application/json",
        headers=_auth(),
    )
    assert r.status_code == 400, r.get_data(as_text=True)


def test_sync_state_helpers_do_not_touch_real_db_path():
    """Guard the fixture itself: DB_PATH must be redirected during tests."""
    assert albert_server.DB_PATH.name == "test-activations.db", (
        f"tests must not write to {albert_server.DB_PATH}"
    )
    assert "test-activations" in str(albert_server.DB_PATH)
    assert pathlib.Path(albert_server.DB_PATH).exists()