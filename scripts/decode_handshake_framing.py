#!/usr/bin/env python3
"""Second-pass decode: custom framing on the cert blobs + ActivationInfoXML.

The first pass showed FairPlayCertChain and RKCertification are DER-shaped
(30 82 ...) but do not parse as X.509 directly, which means they carry an
outer container/header before the DER certificate. This locates the DER
offset, extracts the certificates, and prints them.

Also summarises the 8 logical sections of ActivationInfoXML so the local
server can be made to request the same fields.
"""
import asyncio
import json
import sys

import plistlib

from cryptography import x509

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.mobile_activation import (
    DEFAULT_HEADERS,
    MobileActivationService,
)
import pymobiledevice3.services.mobile_activation as ma

ma.ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL = (
    "https://albert.apple.com/deviceservices/drmHandshake"
)
ma.ask_prompt = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x"))


def find_der_offsets(buf: bytes) -> list[int]:
    """Locate every plausible DER SEQUENCE header (30 82 hi lo) in a buffer."""
    offs = []
    i = 0
    while i < len(buf) - 4:
        if buf[i] == 0x30 and buf[i + 1] == 0x82:
            declared = int.from_bytes(buf[i + 2:i + 4], "big")
            if 8 < declared + 4 < len(buf) - i:
                offs.append(i)
        i += 1
    return offs


def cert_summary(der: bytes) -> dict:
    try:
        c = x509.load_der_x509_certificate(der)
    except Exception as exc:
        return {"error": str(exc)[:90]}
    out = {
        "subject": c.subject.rfc4514_string(),
        "issuer": c.issuer.rfc4514_string(),
        "serial": format(c.serial_number, "x"),
        "not_after": c.not_valid_after_utc.isoformat(),
        "sig_alg": c.signature_algorithm_oid._name,
    }
    try:
        out["key_size"] = c.public_key().key_size
    except Exception:
        pass
    return out


async def main() -> int:
    lockdown = await create_using_usbmux(serial="00008020-…2E")
    svc = MobileActivationService(lockdown)
    blob = await svc.create_activation_session_info()
    headers = {"Content-Type": "application/x-apple-plist"}
    headers.update(DEFAULT_HEADERS)
    handshake, _ = svc.post(
        ma.ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL,
        data=plistlib.dumps(blob), headers=headers,
    )
    info = await svc.create_activation_info_with_session(handshake)

    out = {}

    for label in ("FairPlayCertChain", "RKCertification"):
        raw = bytes(info[label])
        offs = find_der_offsets(raw)
        prefix = raw[:offs[0]] if offs else raw[:16]
        entry = {
            "total_len": len(raw),
            "der_offsets": offs[:6],
            "framing_prefix_len": offs[0] if offs else None,
            "framing_prefix_hex": prefix.hex() if offs else None,
        }
        if offs:
            o = offs[0]
            declared = int.from_bytes(raw[o + 2:o + 4], "big")
            entry["first_cert"] = cert_summary(raw[o:o + declared + 4])
        out[label] = entry

    xml = bytes(info["ActivationInfoXML"])
    inner = plistlib.loads(xml)
    sections = {}
    for k, v in inner.items():
        if isinstance(v, dict):
            sections[k] = {
                "keys": sorted(v.keys())[:18],
                "n_keys": len(v),
            }
        elif isinstance(v, (bytes, bytearray)):
            sections[k] = {"type": "bytes", "len": len(v)}
        else:
            sections[k] = {"type": type(v).__name__, "value": str(v)[:60]}
    out["ActivationInfoXML_sections"] = sections

    # UIKCertification / DeviceCertRequest detail
    for k in ("DeviceCertRequest", "UIKCertification"):
        v = inner.get(k)
        if isinstance(v, dict):
            out[f"{k}_detail"] = {kk: (f"<{type(vv).__name__} len={len(vv)}>"
                                        if isinstance(vv, (bytes, str)) and len(str(vv)) > 40
                                        else str(vv)[:60])
                                  for kk, vv in list(v.items())[:14]}

    json.dump(out, sys.stdout, indent=2, default=str)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
