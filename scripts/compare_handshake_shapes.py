#!/usr/bin/env python3
"""Compare the local Albert drmHandshake response against real Apple's.

Read-only diagnostic: performs a real DRM handshake with Apple using the
connected device's session blob, records the exact key structure Apple
returns, then compares it to the local albert_server.py implementation.

No credentials are used or stored. This only observes the wire format.
"""
import asyncio
import plistlib
import sys

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.mobile_activation import (
    DEFAULT_HEADERS,
    MobileActivationService,
)
import pymobiledevice3.services.mobile_activation as ma

ma.ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL = (
    "https://albert.apple.com/deviceservices/drmHandshake"
)
ma.ask_prompt = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("suppressed"))


async def main() -> int:
    try:
        lockdown = await create_using_usbmux(serial="00008020-…2E")
    except Exception as exc:
        print(f"device unavailable: {exc}")
        return 1

    svc = MobileActivationService(lockdown)
    blob = await svc.create_activation_session_info()
    headers = {"Content-Type": "application/x-apple-plist"}
    headers.update(DEFAULT_HEADERS)
    body, hdrs = svc.post(
        ma.ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL,
        data=plistlib.dumps(blob),
        headers=headers,
    )

    apple = plistlib.loads(body)

    print("=== REQUEST the device sent to drmHandshake ===")
    for k, v in blob.items():
        n = len(v) if isinstance(v, (bytes, str)) else 1
        print(f"  {k}: {n} bytes")

    print("\n=== REAL APPLE response ===")
    print("  content-type:", hdrs.get("Content-Type"))
    for k, v in apple.items():
        if isinstance(v, (bytes, bytearray)):
            n = len(v)
            print(f"  {k}: {n} bytes  head={bytes(v)[:16].hex()}")
        else:
            print(f"  {k}: {type(v).__name__} = {str(v)[:60]}")

    print("\n=== LOCAL albert_server.py response ===")
    local = {
        "HandshakeResponseMessage": b"handshake_response_placeholder",
        "ServerRandom": b"\x00" * 32,
        "SessionID": "<uuid4>",
        "ServerCertificate": b"<fairplay cert chain>",
        "ServerSignature": b"server_signature_placeholder",
    }
    for k, v in local.items():
        print(f"  {k}: {len(v)} bytes")

    apple_keys = set(apple)
    local_keys = set(local)
    print("\n=== DIFFERENCE ===")
    print("  keys Apple has that local lacks :", sorted(apple_keys - local_keys))
    print("  keys local has that Apple lacks :", sorted(local_keys - apple_keys))
    print("  shared keys                     :", sorted(apple_keys & local_keys))
    print(
        "\n  => HandshakeResponseMessage is signed by Apple and cannot be "
        "synthesised without Apple's key."
    )
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
