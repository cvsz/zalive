#!/usr/bin/env python3
"""Inspect the structure of CollectionBlob that an unactivated device sends.

Read-only. Reads what the device exports through
MobileActivationService.create_activation_session_info() and breaks down the
layers. It does not contact Apple, does not touch FairPlay, and does not attempt
to decrypt anything — the parts that Apple signed stay opaque.

Output deliberately redacts IMEI, MEID, serial and UDID, because the raw JSON
inside IngestBody carries them in plaintext from hop 1 onward.

    venv/bin/python scripts/inspect_collection_blob.py
    venv/bin/python scripts/inspect_collection_blob.py --compare-sessions
"""
import argparse
import asyncio
import base64
import json
import math
import plistlib
import sys
from collections import Counter

# Fields that identify the device. Printed truncated, never in full.
SENSITIVE = {"serial-number", "udid", "imei", "ime2", "meid", "unique-device-id"}

TAGS = {
    0x02: "INTEGER", 0x03: "BIT STRING", 0x04: "OCTET STRING", 0x05: "NULL",
    0x06: "OID", 0x0C: "UTF8String", 0x13: "PRINTABLE", 0x16: "IA5String",
    0x17: "UTCTime", 0x30: "SEQUENCE", 0x31: "SET",
    0xA0: "[0] constructed", 0xA1: "[1] constructed", 0xA3: "[3] constructed",
}


def redact(key, value):
    """Show enough to correlate two captures, never enough to identify a phone."""
    if key in SENSITIVE:
        s = str(value)
        if len(s) <= 8:
            return "<redacted>"
        return f"{s[:4]}…{s[-4:]} ({len(s)} chars)"
    return value


def entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte. 8.0 looks random or encrypted, ~6 plaintext."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def read_tlv(buf: bytes, off: int):
    """Parse one ASN.1 TLV header. Returns (tag, content_start, content_end) or None.

    Returns None rather than guessing when the length is indefinite or runs past
    the buffer, so a non-DER container cannot send the walk off the end.
    """
    if off + 2 > len(buf):
        return None
    tag = buf[off]
    i = off + 1
    length = buf[i]
    i += 1
    if length == 0x80:  # indefinite length — not valid DER
        return None
    if length & 0x80:
        num = length & 0x7F
        if num == 0 or num > 3 or i + num > len(buf):
            return None
        length = int.from_bytes(buf[i:i + num], "big")
        i += num
    end = i + length
    if end > len(buf):
        return None
    return tag, i, end


def walk(buf: bytes, off: int, end: int, depth: int = 0, max_depth: int = 5,
         prefix: str = ""):
    """Yield (depth, path, tag_name, length) for each TLV inside the range."""
    index = 0
    while off < end and index < 32:
        parsed = read_tlv(buf, off)
        if parsed is None:
            return
        tag, cstart, cend = parsed
        path = f"{prefix}/{index}"
        name = TAGS.get(tag, f"0x{tag:02x}")
        yield depth, path, name, cend - cstart
        if (tag & 0x20) or tag in (0x30, 0x31):
            if depth < max_depth:
                yield from walk(buf, cstart, cend, depth + 1, max_depth, path)
        off = cend
        index += 1


def largest_octets(blob: bytes):
    """Descend the outer SEQUENCE and return the biggest OCTET STRING inside.

    Apple's scrt containers wrap their payload this way; the ASN.1 wrapper
    itself carries nothing useful.
    """
    parsed = read_tlv(blob, 0)
    if not parsed or parsed[0] != 0x30:
        return None
    _, _, outer_end = parsed
    off = parsed[1]
    step = read_tlv(blob, off)
    if step and step[0] == 0x02:  # version INTEGER
        off = step[2]
    step = read_tlv(blob, off)
    if step and step[0] == 0x30:  # inner SEQUENCE
        off = step[1]
    best = None
    while off < outer_end:
        step = read_tlv(blob, off)
        if not step:
            break
        tag, cstart, cend = step
        if tag == 0x04 and (best is None or cend - cstart > best[1] - best[0]):
            best = (cstart, cend)
        off = cend
    return None if best is None else blob[best[0]:best[1]]


async def grab(udid: str | None) -> dict:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.mobile_activation import MobileActivationService

    lockdown = await create_using_usbmux(serial=udid)
    service = MobileActivationService(lockdown)
    return await service.create_activation_session_info()


def report(raw: dict, label: str = "") -> dict:
    print(f"\n{'=' * 72}")
    print(f"  {label or 'session'}".ljust(72))
    print("=" * 72)

    blob = raw["CollectionBlob"]
    handshake = raw.get("HandshakeRequestMessage", b"")
    outer = plistlib.loads(blob)

    print("\n  Layer 1 — CollectionBlob is an XML plist")
    print(f"    size              : {len(blob)} B")
    print(f"    keys              : {', '.join(sorted(outer))}")
    sig = outer.get("X-Apple-Signature", "")
    key = outer.get("X-Apple-Sig-Key", "")
    algo = "ECDSA-P256" if sig.startswith("MEUC") else "unknown"
    if key:
        try:
            algo = f"{algo}, {len(base64.b64decode(key)) * 8} bit key"
        except Exception:
            pass
    print(f"    signature         : {algo}, {len(sig)} B base64")

    body = outer["IngestBody"]
    print("\n  Layer 2 — IngestBody")
    print(f"    size              : {len(body)} B")
    print(f"    entropy           : {entropy(body):.2f} bits/byte "
          f"({'encrypted' if entropy(body) > 7.5 else 'plaintext'})")
    try:
        parsed = json.loads(body.decode("utf-8"))
    except Exception as exc:
        print(f"    not JSON: {exc}")
        parsed = {}
    if parsed:
        print(f"    encoding          : JSON, {len(parsed)} fields")
        for field in sorted(parsed):
            value = parsed[field]
            if isinstance(value, str) and len(value) > 60:
                try:
                    kind = f"base64 → {len(base64.b64decode(value))} B"
                except Exception:
                    kind = f"str, {len(value)} chars"
                shown = f"<{len(value)} chars>"
            elif isinstance(value, str):
                kind = "str"
                shown = str(redact(field, value))
            else:
                kind = type(value).__name__
                shown = str(redact(field, value))
            print(f"      {field:16} {kind:20} {shown}")

    print("\n  Layer 3 — opaque Apple containers")
    for field in ("pcrt", "scrt-part1", "scrt-part2"):
        if field not in parsed:
            continue
        raw_field = base64.b64decode(parsed[field])
        print(f"\n    {field}: {len(raw_field)} B, entropy {entropy(raw_field):.2f}")
        payload = largest_octets(raw_field)
        if payload:
            print(f"      largest OCTET STRING: {len(payload)} B, "
                  f"entropy {entropy(payload):.2f}")
        rows = list(walk(raw_field, 0, len(raw_field), max_depth=4))
        if not rows:
            print("      not DER-walkable — proprietary binary container")
            continue
        for depth, path, name, length in rows[:12]:
            print(f"      {'  ' * depth}{path:9} {name:12} {length}")

    return {
        "blob_len": len(blob),
        "body_len": len(body),
        "handshake_len": len(handshake),
        "signature": outer.get("X-Apple-Signature", ""),
        "sig_key": outer.get("X-Apple-Sig-Key", ""),
        "pcrt": base64.b64decode(parsed["pcrt"]) if parsed.get("pcrt") else None,
        "scrt1": base64.b64decode(parsed["scrt-part1"]) if parsed.get("scrt-part1") else None,
        "scrt2": base64.b64decode(parsed["scrt-part2"]) if parsed.get("scrt-part2") else None,
    }


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--udid", help="device UDID; omit to use the only device on usbmux")
    ap.add_argument("--compare-sessions", action="store_true",
                    help="grab twice and show what changes per session")
    args = ap.parse_args()

    first = report(await grab(args.udid), "session 1")

    if args.compare_sessions:
        second = report(await grab(args.udid), "session 2")
        print(f"\n{'=' * 72}\n  what changes between sessions\n{'=' * 72}")
        for field in ("pcrt", "scrt1", "scrt2"):
            a, b = first[field], second[field]
            if a is None or b is None:
                continue
            same = a == b
            note = "identical" if same else (
                "same length, different bytes" if len(a) == len(b) else "different length")
            print(f"    {field:8} {note:26} {len(a)} vs {len(b)} B")
        for field in ("signature", "sig_key"):
            verdict = "identical" if first[field] == second[field] else "regenerated"
            print(f"    {field:8} {verdict}")
        for field in ("blob_len", "body_len", "handshake_len"):
            verdict = "fixed" if first[field] == second[field] else "varies"
            print(f"    {field:8} {verdict:26} {first[field]} vs {second[field]}")

    print()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))