#!/usr/bin/env python3
"""One-shot: complete iOS activation against real Apple using owner-supplied
Apple ID credentials for the account the device is Activation-Locked to.

Credentials are read from the environment (never argv) and are never printed.
"""
import asyncio
import os
import sys

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

# Talk to real Apple, not the local Albert redirect.
ma.ACTIVATION_DEFAULT_URL = "https://albert.apple.com/deviceservices/deviceActivation"
ma.ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL = "https://albert.apple.com/deviceservices/drmHandshake"

# Never let pymobiledevice3 open an interactive prompt (no TTY in automation).
ma.ask_prompt = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("interactive prompt suppressed"))


async def main() -> int:
    lockdown = await create_using_usbmux(serial=UDID)
    svc = MobileActivationService(lockdown)

    state = await svc.state()
    print(f"state before: {state}")
    if state == "Activated":
        print("already activated")
        return 0

    # 1. session blob from the device
    blob = await svc.create_activation_session_info()

    # 2. DRM handshake with real Apple (User-Agent is mandatory)
    headers = {"Content-Type": "application/x-apple-plist"}
    headers.update(DEFAULT_HEADERS)
    handshake, _ = svc.post(
        ma.ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL,
        data=plistlib.dumps(blob),
        headers=headers,
    )
    print("handshake response bytes:", len(handshake))

    # 3. device validates Apple's signature and produces activation info
    activation_info = await svc.create_activation_info_with_session(handshake)
    print("device accepted Apple handshake; activation info keys:", list(activation_info.keys()))

    # 4. first deviceActivation call -> expect Activation Lock form
    request = {
        "InStoreActivation": False,
        "AppleSerialNumber": await lockdown.get_value(key="SerialNumber"),
        "activation-info": plistlib.dumps(activation_info),
    }
    content, resp_headers = svc.post(ma.ACTIVATION_DEFAULT_URL, data=request)
    ctype = resp_headers.get("Content-Type")
    print("deviceActivation #1 ->", ctype)

    if ctype == "application/x-buddyml":
        form = svc._get_activation_form_from_response(content.decode())
        print("form title:", form.title)
        print("form description:", form.description)
        data: dict = {}
        for field in form.fields:
            if field.id is None:
                continue
            data[field.id] = PASSWORD if field.secure else LOGIN
            print(f"  filling field id={field.id!r} secure={field.secure}")
        data.update(form.server_info)
        content, resp_headers = svc.post(ma.ACTIVATION_DEFAULT_URL, data=data)
        ctype = resp_headers.get("Content-Type")
        print("deviceActivation #2 ->", ctype)

    if ctype == "application/x-buddyml":
        # Apple wants more (typically a 2FA code). Show it and stop.
        form2 = svc._get_activation_form_from_response(content.decode())
        print("STILL A FORM:", form2.title)
        print("description:", form2.description)
        for f in form2.fields:
            print(f"   id={f.id!r} label={f.label!r} secure={f.secure}")
        return 2

    if ctype != "text/xml":
        print("unexpected content type:", ctype)
        print(content[:400])
        return 3

    # 5. apply the activation record to the device
    print("applying activation record to device...")
    try:
        await svc.activate_with_session(content, resp_headers)
    except Exception:
        await svc.activate_with_lockdown(content)

    await lockdown.set_value(True, key="ActivationStateAcknowledged")
    print("*** ACTIVATION APPLIED ***")
    print("state after:", await svc.state())
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except Exception as exc:
        print(f"FAILED: {type(exc).__name__}: {exc}")
        sys.exit(1)
