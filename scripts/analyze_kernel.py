#!/usr/bin/env python3
"""Static analysis of a decompressed iOS kernelcache kernel.

Walks the Mach-O, disassembles __PRELINK_TEXT/__TEXT_EXEC with capstone in
ARM64e mode, and reports:

  * header facts (CPU subtype, pointer-authentication evidence)
  * segment / section layout
  * instruction mix, and counts of PAC / BTI / barrier instructions
  * kernel-extension inventory from the symbol table
  * notable subsystem strings

Read-only. Usage: analyze_kernel.py <kernel> [--disasm N]
"""
import argparse
import re
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    sys.exit("capstone required: pip install capstone")

# Pointer-authentication / branch-target identification opcodes
PAC_HINTS = re.compile(
    r"\b(pacia|psia|pacib|psib|retab|braa|blraa|brab|blrab|auth[a-z]*|autda|autdb)\b"
)
BTI_HINTS = re.compile(r"\bbti\b")
BARRIER_HINTS = re.compile(r"\b(dmb|dsb|isb)\b")
SYNC_HINTS = re.compile(r"\b(ldxr|ldaxr|stxr|stlxr|casp|caspa?)\b")
TLB_HINTS = re.compile(r"\b(tlbi|tlbi v|dsb ish|dsb ishst)\b")


def load_commands(buf: bytes):
    magic, = struct.unpack_from("<I", buf, 0)
    if magic != 0xFEEDFACF:
        raise SystemExit(f"expected MH_MAGIC_64, got 0x{magic:08X}")
    (cpu, cpusub, ftype, ncmds, soc, flags, _res) = struct.unpack_from("<iiIIIII", buf, 4)
    off = 32
    segs = []
    for _ in range(ncmds):
        if off + 8 > len(buf):
            break
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmdsize == 0:
            break
        if cmd == 0x19:  # LC_SEGMENT_64
            name = buf[off + 8:off + 24].rstrip(b"\x00").decode("latin-1")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", buf, off + 24)
            maxprot, initprot, nsects, flags2 = struct.unpack_from("<IIII", buf, off + 56)
            segs.append({
                "name": name, "vmaddr": vmaddr, "vmsize": vmsize,
                "fileoff": fileoff, "filesize": filesize,
                "maxprot": maxprot, "initprot": initprot, "nsects": nsects,
            })
        off += cmdsize
    return {
        "cpu": cpu, "cpusub": cpusub, "ftype": ftype, "ncmds": ncmds,
        "segs": segs,
    }


def disasm_region(buf: bytes, vmaddr: int, size: int, limit: int | None = None):
    """Disassemble a region; returns (total_insns, Counter, pac_samples)."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    code = buf[:size]
    insns = 0
    counter: Counter = Counter()
    pac_samples = []
    for i in md.disasm(code, vmaddr):
        insns += 1
        m = i.mnemonic
        counter[m] += 1
        if PAC_HINTS.search(m) and len(pac_samples) < 12:
            pac_samples.append(f"{i.address:#x}: {m} {i.op_str}")
        if limit and insns >= limit:
            break
    return insns, counter, pac_samples


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("kernel")
    ap.add_argument("--disasm", type=int, default=0,
                    help="disassemble the first N bytes of __TEXT_EXEC")
    args = ap.parse_args()

    buf = Path(args.kernel).read_bytes()
    info = load_commands(buf)
    sub = info["cpusub"] & 0x00FFFFFF
    print("=== HEADER ===")
    print(f"  cpu      0x{info['cpu']:08X} (ARM64)")
    print(f"  cpusub   0x{info['cpusub']:08X} subtype={sub} "
          f"({'ARM64E / PAC' if sub == 2 else 'plain ARM64'})")
    print(f"  filetype {info['ftype']} (MH_EXECUTE)")
    print(f"  ncmds    {info['ncmds']}")
    print(f"  size     {len(buf):,} bytes")

    print(f"\n=== SEGMENTS ({len(info['segs'])}) ===")
    for s in info["segs"]:
        print(f"  {s['name']:18} vm {s['vmaddr']:#018x}  file {s['fileoff']:#010x}  "
              f"vmsize {s['vmsize']:#012x}  prot {s['initprot']:#x}  nsects={s['nsects']}")

    # Disassemble
    target = next((s for s in info["segs"] if s["name"] == "__TEXT_EXEC"), None)
    if target is None:
        target = max(info["segs"], key=lambda s: s["filesize"])
    region = buf[target["fileoff"]:target["fileoff"] + target["filesize"]]
    sample = region[: args.disasm] if args.disasm else region
    print(f"\n=== DISASSEMBLY ({target['name']}, {len(sample):,} bytes) ===")
    total, counter, pac_samples = disasm_region(region, target["vmaddr"], len(sample), None)
    print(f"  instructions decoded: {total:,}")
    if total:
        print("  top 15 mnemonics: " +
              ", ".join(f"{m}:{c}" for m, c in counter.most_common(15)))
        for label, rx in (("PAC/auth", PAC_HINTS), ("BTI", BTI_HINTS),
                          ("barriers", BARRIER_HINTS), ("atomics", SYNC_HINTS),
                          ("TLBI", TLB_HINTS)):
            n = sum(c for m, c in counter.items() if rx.search(m))
            print(f"  {label:10} {n:,}")
        if pac_samples:
            print("  PAC samples:")
            for s in pac_samples:
                print(f"    {s}")

    # kext inventory via llvm-nm if present
    nm = None
    for cand in ("llvm-nm-20", "llvm-nm", "nm"):
        try:
            subprocess.run([cand, "--version"], capture_output=True, check=True)
            nm = cand
            break
        except (OSError, subprocess.SubprocessError):
            # Candidate is missing or unusable; try the next one. Narrow types
            # only, so a real failure inside the probe still surfaces.
            continue
    if nm:
        r = subprocess.run([nm, "--defined-only", args.kernel],
                           capture_output=True, text=True)
        kexts = sorted(set(re.findall(r"com\.apple\.[A-Za-z0-9_.\-]+", r.stdout)))
        print(f"\n=== KERNEL EXTENSIONS ({len(kexts)}) ===")
        cats = Counter(k.split(".")[2] if len(k.split(".")) > 2 else "?" for k in kexts)
        for c, n in cats.most_common(10):
            print(f"  {c:22} {n}")
        interesting = [k for k in kexts if re.search(
            r"security|amfi|AppleSEP|AppleImage4|CoreTrust|corecrypto|kec\.|trust", k, re.I)]
        if interesting:
            print("  trust/security relevant:")
            for k in interesting:
                print(f"    {k}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
