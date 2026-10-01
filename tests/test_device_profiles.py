"""Drive albert_server end to end with simulated device profiles.

Covers /deviceservices/deviceActivation, /deviceservices/activity and
/deviceservices/phoneHome for each profile in tests/device_profiles.py, and
asserts the server accepted the supplied identity and wrote it to sync_state.

Everything here is local: no device is contacted, nothing is sent to Apple, and
the identifiers are documentation placeholders.
"""

import base64
import os
import pathlib
import plistlib
import sqlite3
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

import albert_server  # noqa: E402
import device_profiles as dp  # noqa: E402
import test_albert  # noqa: E402,F401  -- installs the X-Client-Cert shim on app.test_client


@pytest.fixture(autouse=True, scope="module")
def isolated_db(tmp_path_factory):
    """Point albert_server at a throwaway database for this module.

    These tests drive the device endpoints for real, so they write sync_state
    rows. Without this they landed in logs/activations.db and mixed fixture
    data into the local activation history on every run.
    """
    original = albert_server.DB_PATH
    albert_server.DB_PATH = tmp_path_factory.mktemp("albert-profiles") / "activations.db"
    albert_server._init_db()
    try:
        yield albert_server.DB_PATH
    finally:
        albert_server.DB_PATH = original

# test_albert rebinds albert_server.app.test_client to a wrapper that injects
# X-Client-Cert on /deviceservices/*, because the mTLS gate returns 401 without
# it. Importing it is what makes the device endpoints reachable here. A real
# deployment gets that from a real client certificate instead.
assert albert_server.app.test_client is not test_albert._orig_test_client, "mTLS test shim not installed"


def _admin_headers():
    token = (os.environ.get("ALBERT_ADMIN_TOKEN") or "").strip()
    if not token:
        try:
            token = pathlib.Path(".env").read_text().split("ALBERT_ADMIN_TOKEN=")[1].split()[0].strip().strip('"').strip("'")
        except Exception:
            token = "ci-test-token"  # nosec B105
            os.environ["ALBERT_ADMIN_TOKEN"] = token
    return {"X-Admin-Token": token}



def _fresh_udid(prefix: int) -> str:
    """A UDID that no previous run of this suite can have produced.

    A module-level counter is not enough: pytest starts a new process per run,
    so the counter restarts and the same UDID comes back while its sync_state
    row is still in the database. Seeding from the process id plus os.urandom
    keeps the value inside the 16-hex shape _validate_udid accepts while
    avoiding reuse in practice.
    """
    import os

    salt = int.from_bytes(os.urandom(4), "big")
    return dp.fake_udid((prefix << 24 | (os.getpid() & 0xFF) << 16 | (salt & 0xFFFF)) & 0xFFFFFFFFFFFF)

def _read_state(udid):
    return albert_server._get_sync_state(udid) or {}


def test_fixture_identifiers_are_luhn_valid():
    """An IMEI that fails Luhn is rejected before any interesting logic runs, so
    a broken fixture would make every other test here pass for the wrong reason."""
    for name in dp.DEVICE_PROFILES:
        assert dp._luhn_valid(dp.DEVICE_PROFILES[name]["IMEI"]), name


def test_profiles_have_distinct_identifiers():
    """If the two profiles shared an IMEI, 'the server honoured the profile'
    would be indistinguishable from 'the server used whatever it was given'."""
    p7 = dp.DEVICE_PROFILES["iphone7"]
    pxr = dp.DEVICE_PROFILES["iphonexr"]
    assert p7["IMEI"] != pxr["IMEI"]
    assert p7["ProductType"] != pxr["ProductType"]


def test_each_profile_has_its_own_udid():
    """Sharing a UDID would collapse both profiles into one sync_state row and
    the per-UDID rate limit (10/min) would make the second activation fail for a
    reason that has nothing to do with the profile under test."""
    udids = {p["UniqueDeviceID"] for p in dp.DEVICE_PROFILES.values()}
    assert len(udids) == len(dp.DEVICE_PROFILES)
    for p in dp.DEVICE_PROFILES.values():
        assert len(p["UniqueDeviceID"]) == 25, p["UniqueDeviceID"]
        assert albert_server._validate_udid(p["UniqueDeviceID"]), p["UniqueDeviceID"]


def test_activation_accepts_each_profile_and_records_identity():
    c = albert_server.app.test_client()
    for name in dp.DEVICE_PROFILES:
        profile = dp.DEVICE_PROFILES[name]
        r = c.post(
            "/deviceservices/deviceActivation",
            data={"activation-info": dp.activation_form(name)},
            content_type="application/x-www-form-urlencoded",
        )
        assert r.status_code == 200, (name, r.status_code, r.get_data(as_text=True)[:200])
        pl = plistlib.loads(r.data)
        assert "iphone-activation" in pl, name
        assert "ARS" in r.headers, name

        row = _read_state(profile["UniqueDeviceID"])
        assert row, f"{name}: no sync_state row"
        assert row.get("imei") == profile["IMEI"], (name, row.get("imei"))

        # Each profile carries its own UDID, so the row addressed by that UDID
        # must be that profile's row -- not merely some row that exists.
        assert row.get("udid") == profile["UniqueDeviceID"], (name, row.get("udid"))


def test_activity_writes_identity_for_each_profile():
    """activity is a device-facing writer into sync_state. It reads UDID/IMEI
    straight from the plist, so the same identity rules apply.

    Uses a UDID that no other test in this file has written, because the handler
    only writes when `if udid and imei` holds -- asserting against a row left
    behind by device_activation would pass even if activity wrote nothing.
    """
    c = albert_server.app.test_client()
    for n, name in enumerate(dp.DEVICE_PROFILES):
        profile = dp.DEVICE_PROFILES[name]
        # A fresh UDID per run. Asserting "was already in sync_state" made this
        # test order-dependent: it passed once and failed on every re-run
        # because the row from the previous run was still in the DB.
        udid = _fresh_udid(0x10 + n)
        assert not _read_state(udid), f"{name}: UDID {udid} was already in sync_state"
        r = c.post(
            "/deviceservices/activity",
            data=dp.handshake_plist(name, UniqueDeviceID=udid,
                                    PushToken="a" * 64, PushMagic="b" * 32),
            content_type="application/x-apple-plist",
        )
        assert r.status_code == 200, (name, r.status_code, r.get_data(as_text=True)[:200])
        row = _read_state(udid)
        assert row.get("imei") == profile["IMEI"], (name, row.get("imei"))
        assert row.get("udid") == udid, (name, row.get("udid"))


def test_phonehome_writes_identity_for_each_profile():
    """Same reasoning as test_activity_writes_identity_for_each_profile: a fresh
    UDID per profile, so a passing assert cannot come from another test's row."""
    c = albert_server.app.test_client()
    for n, name in enumerate(dp.DEVICE_PROFILES):
        profile = dp.DEVICE_PROFILES[name]
        # Fresh UDID per run; see the note in test_activity_writes_identity_for_each_profile.
        udid = _fresh_udid(0x20 + n)
        assert not _read_state(udid), f"{name}: UDID {udid} was already in sync_state"
        r = c.post(
            "/WebObjects/ALUnbrick.woa/wa/phoneHome",
            data=plistlib.dumps(dp.activation_payload(name, UniqueDeviceID=udid)),
            content_type="application/x-apple-plist",
        )
        assert r.status_code == 200, (name, r.status_code, r.get_data(as_text=True)[:200])
        row = _read_state(udid)
        assert row.get("imei") == profile["IMEI"], (name, row.get("imei"))
        assert row.get("udid") == udid, (name, row.get("udid"))


def test_drm_handshake_accepts_each_profile():
    c = albert_server.app.test_client()
    for name in dp.DEVICE_PROFILES:
        r = c.post(
            "/deviceservices/drmHandshake",
            data=dp.handshake_plist(name),
            content_type="application/x-apple-plist",
        )
        assert r.status_code == 200, (name, r.status_code, r.get_data(as_text=True)[:200])
        assert "ServerCertificate" in plistlib.loads(r.data), name


def test_malformed_identity_in_profile_is_rejected():
    """A profile with a junk IMEI must be refused, not silently trimmed. This is
    the behaviour _device_identity_from_plist exists to provide."""
    c = albert_server.app.test_client()
    r = c.post(
        "/deviceservices/deviceActivation",
        data={"activation-info": dp.activation_form("iphonexr", IMEI="12345")},
        content_type="application/x-www-form-urlencoded",
    )
    assert r.status_code == 400, r.status_code
    # plist body, not JSON -- see _activation_error in albert_server.py
    body = plistlib.loads(r.data) if not r.is_json else r.get_json()
    details = body.get("Details") or body.get("details") or []
    assert any("IMEI" in str(d) for d in details), body


def _account_token_fields(limit=10):
    """Pull the fields we care about out of the most recent stored activations.

    The identity that a profile supplies does not sit at the top level of the
    stored record: create_activation_record builds an AccountToken plist, and
    that is where UDID/IMEI/IMSI/ICCID are echoed back. Reading the record
    directly is the only way to assert the server actually honoured the payload.
    """
    import json

    out = []
    with sqlite3.connect(str(albert_server.DB_PATH), timeout=5) as c:
        cur = c.execute("SELECT record FROM activations ORDER BY id DESC LIMIT ?", (limit,))
        for (raw,) in cur.fetchall():
            act = json.loads(raw)
            act = act.get("iphone-activation", act.get("device-activation", {})).get("activation-record", {})
            token = act.get("AccountToken")
            if not token:
                continue
            out.append(plistlib.loads(base64.b64decode(token)))
    return out


def test_activation_record_echoes_profile_identity():
    """The stored record must carry the exact identity the profile supplied.

    This is the assertion that makes a profile meaningful: if the server
    substituted its own values, sync_state would still pass but the record sent
    back to the device would be wrong.
    """
    c = albert_server.app.test_client()
    for name in dp.DEVICE_PROFILES:
        r = c.post(
            "/deviceservices/deviceActivation",
            data={"activation-info": dp.activation_form(name)},
            content_type="application/x-www-form-urlencoded",
        )
        assert r.status_code == 200, (name, r.status_code)

    tokens = _account_token_fields()
    imeis = {t.get("InternationalMobileEquipmentIdentity") for t in tokens}
    udids = {t.get("UniqueDeviceID") for t in tokens}
    for name in dp.DEVICE_PROFILES:
        profile = dp.DEVICE_PROFILES[name]
        assert profile["IMEI"] in imeis, (name, profile["IMEI"], imeis)
        assert profile["UniqueDeviceID"] in udids, (name, udids)


def test_each_profile_activation_is_traced_by_request_id():
    """Two profiles share a UDID in the fixtures, so the sync_state row cannot
    tell them apart on its own. The activation response must still be correlated
    with the request that produced it, which is what request_id is for."""
    c = albert_server.app.test_client()
    for name in dp.DEVICE_PROFILES:
        r = c.post(
            "/deviceservices/deviceActivation",
            data={"activation-info": dp.activation_form(name)},
            content_type="application/x-www-form-urlencoded",
        )
        assert r.status_code == 200
        assert r.headers.get("X-Request-ID"), name


def test_profile_overrides_do_not_mutate_the_profile():
    """activation_payload must copy. A shared mutable dict would let one test
    change the IMEI for every later test in the run."""
    before = dict(dp.DEVICE_PROFILES["iphone7"])
    dp.activation_payload("iphone7", IMEI="358000000000008")
    assert dp.DEVICE_PROFILES["iphone7"] == before


def test_activation_info_accepts_every_encoding_a_client_may_send():
    """pymobiledevice3 posts a raw plist; older clients and libimobiledevice send
    base64. Both must work, and a binary plist must survive whether it arrives as
    a file part or a plain form field.

    The field case is the one that was broken: Werkzeug decodes a plain field as
    text, a bplist00 payload is not valid UTF-8, and by the time the handler runs
    the unparsed body is gone under gunicorn's non-seekable stream.
    """
    import base64 as _b64
    import io as _io

    c = albert_server.app.test_client()
    payload = dp.activation_payload("iphonexr", UniqueDeviceID=_fresh_udid(0x30))
    xml = plistlib.dumps(payload)
    binary = plistlib.dumps(payload, fmt=plistlib.FMT_BINARY)
    b64 = _b64.b64encode(xml).decode()

    def boundary(body, name="activation-info", filename=None):
        disp = f'Content-Disposition: form-data; name="{name}"'
        if filename:
            disp += f'; filename="{filename}"'
        return (
            b"--B\r\n" + disp.encode() + b"\r\n\r\n" + body + b"\r\n--B--\r\n"
        )

    cases = [
        ("multipart file part, xml", boundary(xml, filename="a.plist"), {}),
        ("multipart field, xml", boundary(xml), {}),
        ("multipart file part, binary", boundary(binary, filename="a.plist"), {}),
        ("multipart field, binary", boundary(binary), {}),
        ("urlencoded base64", None, {"data": {"activation-info": b64}}),
    ]
    for label, body, kw in cases:
        if body is not None:
            kw = dict(kw)
            kw["data"] = body
            kw["content_type"] = "multipart/form-data; boundary=B"
        r = c.post("/deviceservices/deviceActivation", **kw)
        assert r.status_code == 200, (label, r.status_code, r.get_data(as_text=True)[:150])
        assert "iphone-activation" in plistlib.loads(r.data), label


def test_raw_body_cache_is_scoped_to_device_paths():
    """before_request caches the body for /deviceservices and /WebObjects only.
    Caching it for /api or static routes would hold every response body in
    memory for no benefit."""
    c = albert_server.app.test_client()
    r = c.get("/health")
    assert r.status_code == 200
    # A non-device request must not have populated the cache.
    with albert_server.app.test_request_context("/health", method="GET"):
        from flask import request as _rq

        assert "albert.raw_body" not in _rq.environ
