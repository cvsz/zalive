#!/usr/bin/env python3
"""Describe Apple Image4 firmware images as a nested DER tree.

Firmware components in a modern IPSW are a DER SEQUENCE whose members are
ASN.1 primitives. Their bodies are 4-byte ASCII magics/tags ("IM4P", "IM4M",
"krnl", "rtsc", "kcrz", ...) and the actual bytes are carried in the
primitive that follows a length-prefixed field.

Layout observed on kernelcache.release.iphone11b (iOS 18.7.10):

    30 84 <len:4>                       SEQUENCE
      16 04 "IM4P"                     OCTET STRING, magic
      16 04 "krnl"                     OCTET STRING, tag
      16 1f "KernelManagement_host-463.10.100.7"   OCTET STRING, component name
      04 82 <len:4> <payload bytes>    OCTET STRING, the component data
      30 ...  a0 ...                   signature / certificate wrapper
        16 04 "kcrz" ...               kernelcache root (compressed root fs)

Usage: parse_im4.py FILE [FILE...]

Descriptive only: reads, never writes, never modifies firmware.
"""
import struct
import sys
from pathlib import Path

TAGS = {
    0x30: "SEQUENCE", 0x31: "SET", 0x02: "INTEGER", 0x03: "BITSTRING",
    0x04: "OCTETSTRING", 0x05: "NULL", 0x06: "OID", 0x0C: "UTF8",
    0x13: "PRINTABLE", 0x16: "SEQUENCE(APPLESE)", 0x17: "SET(APPLESE)",
    0x30 | 0x20: "CONSTRUCTED",
}


def read_len(buf: bytes, off: int):
    """Return (length, header_size) for a DER length at off."""
    b0 = buf[off]
    if b0 < 0x80:
        return b0, 1
    n = b0 & 0x7F
    if n == 0 or off + 1 + n > len(buf):
        return None, 1
    return int.from_bytes(buf[off + 1:off + 1 + n], "big"), 1 + n


def printable_ascii(chunk: bytes) -> str | None:
    if not chunk or len(chunk) > 80:
        return None
    try:
        s = chunk.decode("ascii")
    except UnicodeDecodeError:
        return None
    if all(32 <= ord(c) < 127 for c in s):
        return s
    return None


def walk(buf: bytes, off: int, end: int, depth: int, out: list) -> None:
    pad = "  " * depth
    while off < end - 1:
        tag = buf[off]
        ln, hdr = read_len(buf, off + 1)
        if ln is None:
            return
        body = off + 1 + hdr
        if body + ln > end:
            return
        constructed = bool(tag & 0x20)
        if constructed:
            out.append(f"{pad}[{off:>9}] {TAGS.get(tag, hex(tag)):<14} len={ln}")
            walk(buf, body, body + ln, depth + 1, out)
        else:
            text = printable_ascii(buf[body:body + min(ln, 80)])
            shown = repr(text) if text is not None else buf[body:body + 12].hex()
            out.append(f"{pad}[{off:>9}] {TAGS.get(tag, hex(tag)):<14} len={ln:<10} {shown}")
        off = body + ln


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: parse_im4.py FILE [FILE...]", file=sys.stderr)
        return 2
    for p in argv:
        buf = Path(p).read_bytes()
        print(f"=== {Path(p).name}  ({len(buf)} bytes) ===")
        lines: list[str] = []
        # top-level: expect a SEQUENCE
        if buf[0] == 0x30:
            ln, hdr = read_len(buf, 1)
            if ln is not None:
                lines.append(f"[{0:>9}] SEQUENCE             len={ln}")
                walk(buf, 1 + hdr, 1 + hdr + ln, 1, lines)
        for line in lines[:60]:
            print(line)
        if len(lines) > 60:
            print(f"  ... +{len(lines) - 60} more nodes")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
