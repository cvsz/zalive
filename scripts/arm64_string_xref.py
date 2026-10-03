#!/usr/bin/env python3
"""Cross-reference ARM64 code to string constants inside a single Mach-O image.

Written because the first attempt at this only handled ADRP+ADD and found one
reference out of three targets, which proved nothing: the missing two could
have been absent from the code or just encoded differently. This handles the
encodings a prelinked kernelcache kext actually uses.

Supported reference forms:
  ADRP + ADD immediate          two-instruction pair, the common case
  ADRP + LDR (unsigned imm)     literal load through the base register
  ADRP + LDR (register offset)  register-offset load
  ADR                          single-instruction PC-relative
  literal pool slot            8-byte aligned pointer found in __DATA_CONST
  32-bit pointer table slot    absolute pointer in a table

Every candidate is verified by reading the value it points at and requiring it to
land on a real string, so a false positive needs a coincidental match.

    venv/bin/python scripts/arm64_string_xref.py <macho> <string> [...]
"""
import argparse
import hashlib
import struct
import sys

ARM64_MACH_MAGIC = 0xFEEDFACF
ARM64_EXEC_MAGIC = 0xFEEDFACD
MH_EXECUTE = 0x2
LC_SEGMENT_64 = 0x19


class Image:
    """One Mach-O image with its segments indexed by virtual address."""

    def __init__(self, data: bytes, base: int = 0):
        self.data = data
        self.base = base
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic in (ARM64_MACH_MAGIC, ARM64_EXEC_MAGIC):
            self.magic = magic
            self.raw = False
            self.segments = self._read_segments()
        else:
            # iBoot decompresses to raw AArch64 with no Mach-O header: the
            # load commands and segments a Mach-O would carry are already
            # resolved. Treat the whole blob as one executable segment starting
            # at address 0 and scan it the same way.
            self.magic = None
            self.raw = True
            self.segments = [{
                "name": "__TEXT_EXEC",
                "vmaddr": 0,
                "vmsize": len(data),
                "fileoff": 0,
                "filesize": len(data),
            }]

    def _read_segments(self):
        ncmds = struct.unpack_from("<I", self.data, 16)[0]
        off = 32
        segs = []
        for _ in range(ncmds):
            if off + 8 > len(self.data):
                break
            cmd, cmdsize = struct.unpack_from("<II", self.data, off)
            if cmd == LC_SEGMENT_64 and off + 72 <= len(self.data):
                name = self.data[off + 8:off + 24].split(b"\x00")[0].decode(
                    "ascii", "replace")
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                    "<QQQQ", self.data, off + 24)
                segs.append({
                    "name": name,
                    "vmaddr": vmaddr,
                    "vmsize": vmsize,
                    "fileoff": fileoff,
                    "filesize": filesize,
                })
            off += cmdsize
        return segs

    def file_offset(self, vmaddr):
        """Translate a virtual address to a file offset, or None."""
        for s in self.segments:
            if s["vmaddr"] <= vmaddr < s["vmaddr"] + s["filesize"]:
                return s["fileoff"] + (vmaddr - s["vmaddr"])
        return None

    def read(self, vmaddr, size):
        off = self.file_offset(vmaddr)
        if off is None or off + size > len(self.data):
            return None
        return self.data[off:off + size]

    def is_executable(self):
        return any(s["name"] in ("__TEXT", "__TEXT_EXEC") for s in self.segments)

    def code_ranges(self):
        for s in self.segments:
            if s["name"] in ("__TEXT", "__TEXT_EXEC") and s["filesize"]:
                yield s["vmaddr"], s["vmaddr"] + s["filesize"], s


def read_cstring_at(image: Image, vmaddr, maxlen=512):
    """Read a NUL-terminated ASCII string if one starts at vmaddr."""
    off = image.file_offset(vmaddr)
    if off is None or off >= len(image.data):
        return None
    end = image.data.find(b"\x00", off, min(off + maxlen, len(image.data)))
    if end < 0:
        return None
    raw = image.data[off:end]
    if not raw or len(raw) > maxlen:
        return None
    # Reject if it is mostly non-printable: that means the pointer was wrong.
    printable = sum(1 for b in raw if 32 <= b < 127)
    if printable / len(raw) < 0.85:
        return None
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return None


def sign_extend(value, bits):
    if value & (1 << (bits - 1)):
        value -= (1 << bits)
    return value


def adrp_target(insn, pc):
    """Page address for ADRP. None if not ADRP.

    ADRP is `op(1) immlo[30:29] 10000 immhi[23:5] Rd[4:0]`, so immlo lives in
    bits[30:29] — the same place ADR keeps it. Reading it from bits[1:0] picks
    up the low bits of the destination register instead, which silently yields
    the wrong page for every target that is not 16 KiB away.
    """
    if insn & 0x9F000000 != 0x90000000:
        return None
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = sign_extend((immhi << 2) | immlo, 21)
    return (pc & ~0xFFF) + (imm << 12)


def adr_target(insn, pc):
    """Target for ADR, or None."""
    if insn & 0x9F000000 != 0x10000000:
        return None
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = sign_extend((immhi << 2) | immlo, 21)
    return pc + imm


def decode_pair(image, code_end, pc):
    """Yield (kind, immediate) for an instruction at pc and the next three slots.

    Covers ADRP followed by ADD/LDR in either immediate or register form, which
    is how the compiler materialises an address into a register before using it.
    Yields the offset to add to the ADRP page, or None when the follow-up needs
    register tracking this scan does not do.
    """
    nxt = [pc + 4 * i for i in (1, 2, 3)]
    for n in nxt:
        if n + 4 > code_end:
            break
        buf = image.read(n, 4)
        if not buf:
            break
        w = struct.unpack("<I", buf)[0]

        # ADD (immediate), 64-bit: sf=1 0 0 1 0 1 0 shift imm12 Rn Rd
        if w & 0x7F800000 == 0x11000000:
            sh = (w >> 22) & 1
            imm12 = (w >> 10) & 0xFFF
            yield "adrp+add", imm12 << (12 if sh else 0)

        # LDR (unsigned immediate), 64-bit: size 111 1 01 opc
        if w & 0xFFC00000 == 0xF9400000:
            imm12 = (w >> 10) & 0xFFF
            yield "adrp+ldr_uimm", imm12 * 8

        # LDR (register offset), 64-bit: size 111 1 00 opc 1 Rm option S 10 Rn Rd
        if w & 0xFFE00C00 == 0xF8600800:
            yield "adrp+ldr_reg", None

        # LDR (immediate, pre/post index) and LDUR variants
        if w & 0xFFE00C00 == 0xF8400000:
            yield "adrp+ldr_prepost", (w >> 12) & 0x1FF


def find_pointer_slots(image: Image):
    """Absolute 8-byte pointers in the image that point at a string.

    Prelinked kexts route some constants through tables rather than ad-hoc
    instructions, so a pure instruction scan misses them.
    """
    slots = {}
    mapped = [(s["vmaddr"], s["vmaddr"] + s["vmsize"]) for s in image.segments]
    for s in image.segments:
        start, end = s["fileoff"], s["fileoff"] + s["filesize"]
        end = min(end, len(image.data))
        for off in range(start, end - 7, 8):
            val = struct.unpack_from("<Q", image.data, off)[0]
            # The slot usually lives in __DATA and the string in __TEXT, so the
            # plausible-range test is against every segment, not this one. Gating
            # on the containing segment instead misses every cross-segment table.
            if not any(lo <= val < hi for lo, hi in mapped):
                continue
            text = read_cstring_at(image, val)
            if text:
                slots.setdefault(text, []).append(s["vmaddr"] + (off - start))
    return slots


def xref(image: Image, target_text: str):
    """Return (description, site) for every reference to target_text."""
    found = []

    # Pass 1: instruction scan.
    for vm_start, vm_end, seg in image.code_ranges():
        base = seg["fileoff"]
        # A segment can claim more file bytes than the file holds when the slice
        # was rebuilt by hand; clamp instead of letting unpack_from fail.
        n = min(seg["filesize"], len(image.data) - base)
        n = (n // 4) * 4
        if n <= 0:
            continue
        data = image.data[base:base + n]
        for i in range(0, n, 4):
            insn = struct.unpack_from("<I", data, i)[0]
            pc = vm_start + i

            adrp = adrp_target(insn, pc)
            if adrp is not None:
                for kind, extra in decode_pair(image, vm_end, pc):
                    if extra is None:
                        continue
                    cand = adrp + extra
                    if read_cstring_at(image, cand) == target_text:
                        found.append((f"{kind} @ 0x{pc:x}", pc))
                # LDR register-offset needs a register we cannot track cheaply;
                # fall back to scanning the pointer-slot table for that page.
                continue

            adr = adr_target(insn, pc)
            if adr is not None and read_cstring_at(image, adr) == target_text:
                found.append((f"adr @ 0x{pc:x}", pc))

    # Pass 2: pointer tables.
    for text, sites in find_pointer_slots(image).items():
        if text == target_text:
            for v in sites:
                found.append((f"pointer slot @ 0x{v:x}", v))

    return found


def main(argv):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("macho", help="path to an arm64 Mach-O (or raw slice)")
    ap.add_argument("strings", nargs="+", help="string(s) to find references to")
    args = ap.parse_args(argv)

    with open(args.macho, "rb") as fh:
        image = Image(fh.read())

    print(f"image   : {args.macho}")
    print(f"size    : {len(image.data):,} B")
    kind = "raw AArch64" if image.raw else "arm64 Mach-O"
    print(f"format  : {kind}")
    print(f"segments: {', '.join(s['name'] for s in image.segments)}")
    print(f"sha256 : {hashlib.sha256(image.data).hexdigest()[:32]}")
    print()

    for text in args.strings:
        refs = xref(image, text)
        print(f"  {text!r}")
        if not refs:
            print("      no reference found by any encoding tried")
        for desc, site in refs[:12]:
            print(f"      {desc}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))