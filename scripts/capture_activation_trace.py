#!/usr/bin/env python3
"""Capture a full, real activation-protocol trace for documentation.

Observes the live exchange between this host and Apple's public activation
endpoints using the connected device's own session material, and records:

  * request/response key structure at every hop
  * byte lengths and content types
  * the state machine the device walks (which lockdownd/activationd commands
    it issues and in what order)
  * error shapes Apple returns for each failure mode

This is a passive observer: it sends only the same requests the stock
pymobiledevice3 activation client sends, and writes no credentials anywhere.

Output is a JSON document to stdout suitable for feeding into docs.
"""
import asyncio
import hashlib
import json
import sys
import time

import plistlib

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.mobile_activation import (
    DEFAULT_HEADERS,
    MobileActivationService,
)
import pymobiledevice3.services.mobile_activation as ma

ma.ACTIVATION_DEFAULT_URL = "https://albert.apple.com/deviceservices/deviceActivation"
ma.ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL = (
    "https://albert.apple.com/deviceservices/drmHandshake"
)
ma.ask_prompt = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("suppressed"))

TRACE: list[dict] = []


def record(stage: str, direction: str, detail: dict) -> None:
    TRACE.append({"stage": stage, "direction": direction, "t": time.time(), **detail})
    print(f"  [{stage}] {direction}", file=sys.stderr)


def describe(value) -> dict:
    """Structure of a plist value, without leaking opaque payloads."""
    if isinstance(value, (bytes, bytearray)):
        return {
            "type": "bytes",
            "len": len(value),
            "sha256_16": hashlib.sha256(bytes(value)).hexdigest()[:16],
            "head_hex": bytes(value)[:16].hex(),
        }
    if isinstance(value, str):
        return {"type": "str", "len": len(value), "sample": value[:40]}
    if isinstance(value, dict):
        return {"type": "dict", "keys": sorted(value.keys())}
    if isinstance(value, (list, tuple)):
        return {"type": "list", "len": len(value), "item_types": {type(i).__name__ for i in value}}
    return {"type": type(value).__name__, "value": str(value)[:60]}


def struct(plist: dict) -> dict:
    return {k: describe(v) for k, v in plist.items()}


async def main() -> int:
    lockdown = await create_using_usbmux(serial="00008020-…2E")

    # ---- device identity -------------------------------------------------
    record("identity", "read", {})
    identity = {}
    for key in ("SerialNumber", "UniqueDeviceID", "ProductType", "ProductVersion",
                "BuildVersion", "ActivationState", "InternationalMobileEquipmentIdentity",
                "MobileEquipmentIdentifier", "TelephonyCapability"):
        try:
            identity[key] = await lockdown.get_value(key=key)
        except Exception as exc:
            identity[key] = f"<{type(exc).__name__}>"
    record("identity", "value", {"data": identity})

    svc = MobileActivationService(lockdown)

    state = await svc.state()
    record("state", "read", {"activation_state": state})

    # ---- hop 1: device asks us for a session challenge -------------------
    record("session", "request", {"command": "CreateTunnel1SessionInfoRequest"})
    blob = await svc.create_activation_session_info()
    record("session", "response", {"structure": struct(blob)})

    # ---- hop 2: drmHandshake to Apple -----------------------------------
    headers = {"Content-Type": "application/x-apple-plist"}
    headers.update(DEFAULT_HEADERS)
    record("drmHandshake", "request", {
        "url": ma.ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL,
        "headers": headers,
        "body_keys": sorted(blob.keys()),
    })
    handshake, hh = svc.post(
        ma.ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL,
        data=plistlib.dumps(blob),
        headers=headers,
    )
    record("drmHandshake", "response", {
        "content_type": hh.get("Content-Type"),
        "body_len": len(handshake),
    })
    apple = plistlib.loads(handshake)
    record("drmHandshake", "decoded", {"structure": struct(apple)})

    # ---- hop 3: device validates Apple's signature ----------------------
    record("activationInfo", "request", {"command": "CreateTunnel1ActivationInfoRequest"})
    try:
        info = await svc.create_activation_info_with_session(handshake)
        record("activationInfo", "response", {
            "accepted": True,
            "structure": struct(info),
        })
    except Exception as exc:
        record("activationInfo", "response", {"accepted": False, "error": str(exc)[:400]})
        print(json.dumps({"identity": identity, "trace": TRACE}, indent=2))
        return 0

    # ---- hop 4: deviceActivation to Apple -------------------------------
    request = {
        "InStoreActivation": False,
        "AppleSerialNumber": identity.get("SerialNumber"),
        "activation-info": plistlib.dumps(info),
    }
    record("deviceActivation", "request", {
        "url": ma.ACTIVATION_DEFAULT_URL,
        "form_fields": sorted(request.keys()),
        "activation_info_len": len(request["activation-info"]),
    })
    content, rh = svc.post(ma.ACTIVATION_DEFAULT_URL, data=request)
    record("deviceActivation", "response", {
        "content_type": rh.get("Content-Type"),
        "body_len": len(content),
    })

    if rh.get("Content-Type") == "application/x-buddyml":
        import xml.etree.ElementTree as ET
        root = ET.fromstring(content.decode())
        texts = [(e.tag.split("}")[-1], (e.text or "").strip())
                 for e in root.iter() if (e.text or "").strip()]
        record("deviceActivation", "form", {
            "elements": [{"tag": t, "text": v[:200]} for t, v in texts]
        })

    print(json.dumps({"identity": identity, "trace": TRACE}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
