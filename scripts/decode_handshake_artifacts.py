#!/usr/bin/env python3
"""Deep structural decode of the activation handshake artifacts.

Captures live handshake/activation artifacts from the connected device and
tears them down: parses the XML payloads, the DER certificates, and
classifies the signature blobs. Writes nothing to disk except the JSON
report, and uses no credentials.

This documents Apple's *format* so the local test server can be made
structurally faithful. It does not and cannot reproduce Apple's signatures.
"""
import asyncio
import json
import sys

import plistlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.mobile_activation import (
    DEFAULT_HEADERS,
    MobileActivationService,
)
import pymobiledevice3.services.mobile_activation as ma

ma.ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL = (
    "https://albert.apple.com/deviceservices/drmHandshake"
)
ma.ask_prompt = lambda *a, **k: (_ for _ in ()).throw(RuntimeException := RuntimeError("x"))


def parse_cert(der: bytes) -> dict:
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:
        return {"parse_error": str(exc)}
    out = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sig_alg": cert.signature_algorithm_oid._name,
        "pubkey_type": type(cert.public_key()).__name__,
    }
    try:
        out["san"] = [str(gc.value) for gc in cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value]
    except Exception:
        pass
    return out


def parse_cert_bundle(der: bytes) -> list:
    """Split a concatenated DER certificate bundle."""
    certs, rest = [], der
    while rest:
        try:
            cert = x509.load_der_x509_certificate(rest)
        except Exception:
            break
        certs.append(parse_cert(cert.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER)))
        # advance past this cert
        import re
        m = re.search(rb"\x30\x82", rest[2:])
        break
    return certs or [parse_cert(der)]


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
    apple = plistlib.loads(handshake)
    info = await svc.create_activation_info_with_session(handshake)

    report = {
        "serverKP": {
            "len": len(apple["serverKP"]),
            "head_hex": apple["serverKP"][:8].hex(),
            "note": "opaque key blob; 0x03 prefix is an ASN.1 context tag",
        },
        "FDRBlob": {"len": len(apple["FDRBlob"]), "note": "32-byte nonce"},
        "SUInfo": {
            "len": len(apple["SUInfo"]),
            "head_hex": apple["SUInfo"][:8].hex(),
            "note": "starts 9502 0100 -> likely versioned TLV (v2, len 0x0100=256) + 95 01 011a (26-byte field)",
        },
        "HandshakeResponseMessage": {
            "len": len(apple["HandshakeResponseMessage"]),
            "head_hex": apple["HandshakeResponseMessage"][:8].hex(),
            "note": "0x02 = ASN.1 OCTET STRING wrapper; remainder is signed payload",
        },
        "FairPlayCertChain": parse_cert_bundle(bytes(info["FairPlayCertChain"])),
        "RKCertification": parse_cert(bytes(info["RKCertification"])),
        "FairPlaySignature": {
            "len": len(info["FairPlaySignature"]),
            "alg": "RSA-1024 (128-byte raw signature)" if len(info["FairPlaySignature"]) == 128 else "unknown",
        },
        "RKSignature": {
            "len": len(info["RKSignature"]),
            "note": "72 bytes -> likely ECDSA P-256 r||s plus 8-byte trailer",
        },
        "signActRequest": {
            "len": len(info["signActRequest"]),
            "hex": info["signActRequest"].hex(),
        },
    }

    # ActivationInfoXML is a plist wrapped in XML -- show its top-level keys
    xml = bytes(info["ActivationInfoXML"])
    try:
        inner = plistlib.loads(xml)
        report["ActivationInfoXML"] = {
            "len": len(xml),
            "format": "XML plist (embedded in <?xml ...?>)",
            "top_level_keys": sorted(inner.keys()) if isinstance(inner, dict) else type(inner).__name__,
        }
    except Exception as exc:
        report["ActivationInfoXML"] = {"len": len(xml), "parse_error": str(exc)[:120]}

    json.dump(report, sys.stdout, indent=2, default=str)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
