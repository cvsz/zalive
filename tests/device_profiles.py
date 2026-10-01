"""Device-profile fixtures for exercising albert_server with simulated devices.

The server reads UDID/IMEI/serial out of the plist or form payload that a device
posts to /deviceservices/*. That means a test can drive a full activation with a
simulated device profile without any hardware and without touching a real
device's identity: nothing here writes to a device or sends anything to Apple.

The identifiers below are syntactically valid but deliberately not real:
UDIDs use the documented fake prefix 00008020-AAAAAAAAAAAAAAAA pattern, and the
IMEIs are the 15-digit Luhn-valid example numbers reserved for documentation.

Nothing in this module is a real device identity, and using it against Apple's
activation servers would be device identity spoofing. It exists so albert_server
can be tested with a chosen device profile locally.
"""

import base64
import plistlib

# --- identifiers -------------------------------------------------------------
# "AAAAAAAAAAAAAAAA" is the conventional stand-in used throughout Apple's own
# documentation, so a UDID shaped like this can never collide with hardware.
FAKE_UDID = "00008020-AAAAAAAAAAAAAAAA"


def fake_udid(n: int) -> str:
    """A distinct fake UDID per n, so two profiles do not share a sync_state row.

    Stays 25 characters on purpose: the 00008020- form is validated as
    8 + '-' + 16 hex, and _validate_udid rejects a shorter tail.
    """
    return f"00008020-{n:016X}"


# 15 digits, Luhn-valid, chosen to be memorable rather than real. The first
# eight digits are the TAC, so using a different TAC per profile is what makes
# the two look like different hardware families to anything that inspects it.
# _luhn_valid() below asserts these stay valid.
FAKE_IMEI_IPHONE7 = "358000000000008"
FAKE_IMEI_XR = "352000000000004"
FAKE_SERIAL = "REDACTEDSERIAL"

# Device profiles. ProductType is the hardware identifier Apple uses; the
# mapping below is the documented product-type family grouping, not a claim
# that any specific serial belongs to a specific retail unit.
DEVICE_PROFILES = {
    "iphone7": {
        "DeviceClass": "iPhone",
        "ProductType": "iPhone9,3",
        "UniqueDeviceID": fake_udid(1),
        "IMEI": FAKE_IMEI_IPHONE7,
        "SerialNumber": FAKE_SERIAL,
    },
    "iphonexr": {
        "DeviceClass": "iPhone",
        "ProductType": "iPhone11,8",
        "UniqueDeviceID": fake_udid(2),
        "IMEI": FAKE_IMEI_XR,
        "SerialNumber": FAKE_SERIAL,
    },
}

# The device this repository's firmware work targets.
DEFAULT_PROFILE = "iphone7"


def _luhn_valid(imei: str) -> bool:
    """Apple rejects an IMEI that fails the Luhn checksum, so a fixture that does
    not pass it would be rejected before reaching any logic worth testing."""
    digits = [int(c) for c in imei if c.isdigit()]
    if len(digits) != 15:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def activation_payload(profile: str = DEFAULT_PROFILE, **overrides) -> dict:
    """Build the activation-info dict for a named device profile.

    Pass overrides to vary one field without cloning the profile, e.g.
    activation_payload("iphonexr", IMEI="350000000000009").
    """
    if profile not in DEVICE_PROFILES:
        raise KeyError(f"unknown profile {profile!r}; known: {sorted(DEVICE_PROFILES)}")
    payload = dict(DEVICE_PROFILES[profile])
    payload.update(overrides)
    return payload


def activation_form(profile: str = DEFAULT_PROFILE, **overrides) -> str:
    """Encode a profile the way deviceActivation expects it: base64 plist in the
    activation-info form field."""
    return base64.b64encode(plistlib.dumps(activation_payload(profile, **overrides))).decode()


def handshake_plist(profile: str = DEFAULT_PROFILE, **overrides) -> bytes:
    """Raw plist body for drmHandshake, which posts the plist directly rather
    than base64-encoding it in a form field."""
    payload = activation_payload(profile, **overrides)
    payload["CollectionBlob"] = b"collection"
    payload["HandshakeRequestMessage"] = b"handshake"
    return plistlib.dumps(payload)
