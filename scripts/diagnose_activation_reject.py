#!/usr/bin/env python3
"""Diagnose why Apple rejected the activation credential submission.

Sends the owner's Apple ID once and prints the decoded response body so the
failure reason (bad password / 2FA / rate limit / account lockout) is visible.

Credentials come from the environment, are never printed, and are never
written to disk.
"""
import asyncio
import os
import sys

# The XML here is Apple's activation response, i.e. untrusted input, so use
# defusedxml instead of the stdlib parser that is open to entity expansion.
from defusedxml import ElementTree as ET

import plistlib

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.mobile_activation import (
    DEFAULT_HEADERS,
    MobileActivationService,
)
import pymobiledevice3.services.mobile_activation as ma

UDID = os.environ["TARGET_UDID"]
LOGIN = os.environ["APPLE_LOGIN"]
PASSWORD = os.environ["APPLE_PASSWORD"]

ma.ACTIVATION_DEFAULT_URL = "https://albert.apple.com/deviceservices/deviceActivation"
ma.ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL = "https://albert.apple.com/deviceservices/drmHandshake"
ma.ask_prompt = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("suppressed"))


def describe(xml_bytes: str) -> None:
    """Print every human-readable string Apple put in the response."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        print("  (not parseable as XML:", exc, ")")
        return
    seen = set()
    for elem in root.iter():
        tag = elem.tag.split("}")[-1]
        text = (elem.text or "").strip()
        if text and text not in seen:
            seen.add(text)
            print(f"  <{tag}> {text[:300]}")
        for attr, val in elem.attrib.items():
            if val and val not in seen:
                seen.add(val)
                print(f"  <{tag} {attr}={val!r}>")


async def main() -> int:
    lockdown = await create_using_usbmux(serial=UDID)
    svc = MobileActivationService(lockdown)

    blob = await svc.create_activation_session_info()
    headers = {"Content-Type": "application/x-apple-plist"}
    headers.update(DEFAULT_HEADERS)
    handshake, _ = svc.post(
        ma.ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL,
        data=plistlib.dumps(blob),
        headers=headers,
    )
    info = await svc.create_activation_info_with_session(handshake)

    request = {
        "InStoreActivation": False,
        "AppleSerialNumber": await lockdown.get_value(key="SerialNumber"),
        "activation-info": plistlib.dumps(info),
    }
    content, hdrs = svc.post(ma.ACTIVATION_DEFAULT_URL, data=request)
    form = svc._get_activation_form_from_response(content.decode())

    data = {f.id: (PASSWORD if f.secure else LOGIN) for f in form.fields if f.id}
    data.update(form.server_info)
    content2, hdrs2 = svc.post(ma.ACTIVATION_DEFAULT_URL, data=data)

    print("=== APPLE RESPONSE TO CREDENTIAL SUBMISSION ===")
    print("content-type:", hdrs2.get("Content-Type"))
    print("status-ish headers:", {k: v for k, v in hdrs2.items() if k.lower() in ("x-apple-error", "x-apple-error-detail", "retry-after")})
    body = content2.decode(errors="replace")
    print("body length:", len(body))
    print("--- decoded content ---")
    describe(body)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except Exception as exc:
        print(f"FAILED: {type(exc).__name__}: {exc}")
        sys.exit(1)
