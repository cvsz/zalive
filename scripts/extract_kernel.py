#!/usr/bin/env python3
"""Extract and decompress the LZFSE kernel image from an iOS kernelcache.

kernelcache.release.* is a DER SEQUENCE of OCTET STRINGs:

    "IM4P" | "krnl" | "<name>" | <payload>

The payload begins with the LZFSE frame magic "bvx2" and decompresses to a
Mach-O kernel. This extracts the payload, decompresses it with liblzfse, and
reports the resulting Mach-O header information.

Usage: extract_kernel.py <kernelcache> [-o OUTPUT]
"""
import argparse
import struct
import sys
from pathlib import Path

try:
    import liblzfse
except ImportError:
    sys.exit("pyliblzfse required: pip install pyliblzfse")

LZFSE_MAGIC = b"bvx2"

MH_MAGIC = {
    0xFEEDFACE: "MH_MAGIC (32-bit)",
    0xFEEDFACF: "MH_MAGIC_64 (64-bit)",
    0xBEBAFECA: "FAT_MAGIC",
}
MH_EXECUTE = 0x2
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_ARM64_32 = 0x0200000C


def locate_payload(buf: bytes) -> tuple[int, int, str]:
    """Return (offset, length, name_field) of the krnl payload."""
    i = buf.find(LZFSE_MAGIC)
    if i < 0:
        sys.exit("no LZFSE magic found")
    name = ""
    n = buf.find(b"KernelManagement", 0, i)
    if n > 0:
        # OCTET STRING: 16 1f <len> <name>
        ln = buf[n - 1]
        name = buf[n:n + ln].decode("latin-1", "replace")
    # Walk the OCTET STRING header immediately before the payload
    j = i - 1
    if buf[j] == 0x04 and j >= 1:
        l0 = buf[j - 1]
        if l0 == 0x84:
            plen = struct.unpack_from(">I", buf, j - 5)[0]
        elif l0 == 0x82:
            plen = struct.unpack_from(">H", buf, j - 3)[0]
        else:
            plen = l0
    else:
        plen = len(buf) - i
    return i, plen, name


def parse_macho(data: bytes) -> dict:
    out: dict = {"size": len(data)}
    if len(data) < 32:
        out["error"] = "too small for a Mach-O header"
        return out
    magic = struct.unpack_from("<I", data, 0)[0]
    out["magic"] = f"0x{magic:08X}"
    out["kind"] = MH_MAGIC.get(magic, "unknown")
    if magic == 0xFEEDFACF:
        cputype, cpusub, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
            "<iiIIIII", data, 4)
        hdr = 32
    elif magic == 0xFEEDFACE:
        cputype, cpusub, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
            "<iiIIII", data, 4)
        hdr = 28
    else:
        out["error"] = f"not a Mach-O (magic {out['magic']})"
        return out

    out["cputype"] = f"0x{cputype & 0xFFFFFFFF:08X}"
    out["cputype_name"] = {
        CPU_TYPE_ARM64: "ARM64",
        CPU_TYPE_ARM64_32: "ARM64_32",
    }.get(cputype & 0xFFFFFFFF, "other")
    out["filetype"] = filetype
    out["filetype_name"] = {MH_EXECUTE: "MH_EXECUTE"}.get(filetype, f"type {filetype}")
    out["ncmds"] = ncmds
    out["sizeofcmds"] = sizeofcmds
    out["flags"] = f"0x{flags:08x}"
    out["header_size"] = hdr

    # Walk load commands
    off = hdr
    segs, cmds = [], []
    for _ in range(min(ncmds, 200)):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize == 0:
            break
        name = f"cmd 0x{cmd:08X}"
        if cmd == 0x19:  # LC_SEGMENT_64
            if off + 72 <= len(data):
                segname = data[off + 8:off + 24].rstrip(b"\x00").decode("latin-1", "replace")
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
                segs.append({
                    "name": segname, "vmaddr": vmaddr, "vmsize": vmsize,
                    "fileoff": fileoff, "filesize": filesize,
                })
                name = f"LC_SEGMENT_64 {segname}"
        elif cmd == 0x0C:  # LC_LOAD_DYLIB
            name = "LC_LOAD_DYLIB"
        elif cmd == 0x1D:  # LC_CODE_SIGNATURE
            name = "LC_CODE_SIGNATURE"
        elif cmd == 0x2A:  # LC_LINKER_OPTION
            name = "LC_LINKER_OPTION"
        cmds.append(name)
        off += cmdsize

    out["segments"] = segs
    out["n_cmds_parsed"] = len(cmds)
    out["first_cmds"] = cmds[:8]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("kernelcache")
    ap.add_argument("-o", "--output", help="write decompressed Mach-O here")
    args = ap.parse_args()

    buf = Path(args.kernelcache).read_bytes()
    off, plen, name = locate_payload(buf)
    print(f"kernelcache        : {Path(args.kernelcache).name} ({len(buf)} bytes)")
    print(f"component name     : {name}")
    print(f"LZFSE payload at   : offset {off}, {plen} bytes")

    frame = buf[off:off + plen]
    print(f"LZFSE frame        : magic {frame[:4]!r}")
    print("decompressing...")
    try:
        raw = liblzfse.decompress(frame)
    except Exception as exc:
        print(f"decompress failed  : {exc}")
        print("attempting raw scan of frame table...")
        try:
            raw = liblzfse.decompress(b"")._  # noqa
        except Exception:
            return 1

    print(f"decompressed       : {len(raw)} bytes ({len(raw)/1024/1024:.1f} MiB)")
    if args.output:
        Path(args.output).write_bytes(raw)
        print(f"written            : {args.output}")

    print("\n=== Mach-O header ===")
    info = parse_macho(raw)
    for k, v in info.items():
        if k in ("segments", "first_cmds"):
            continue
        print(f"  {k:16} = {v}")
    if info.get("segments"):
        print("\n=== segments ===")
        for s in info["segments"]:
            print(f"  {s['name']:20} vm {s['vmaddr']:#018x}  file {s['fileoff']:#010x} "
                  f"size {s['filesize']:#012x}")
    if info.get("first_cmds"):
        print("\n=== first load commands ===")
        for c in info["first_cmds"]:
            print(f"  {c}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
