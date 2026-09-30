#!/usr/bin/env python3
"""Full-segment AArch64 instruction sweep of the iOS kernel.

Disassembles every executable segment with capstone and produces a census of
architecturally significant instructions -- TLB maintenance, barriers,
atomics, pointer authentication, exception/sync -- so claims about what the
kernel does are based on the whole image rather than a sample.

Read-only. Usage: sweep_kernel.py <kernel> [--jobs N]
"""
import argparse
import os
import re
import struct
import sys
from collections import Counter
from multiprocessing import Pool
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    sys.exit("capstone required: pip install capstone")

GROUPS = {
    "TLBI":            re.compile(r"^tlbi"),
    "TLB_insn":        re.compile(r"^(tt|tc|tl|bi)?"),  # replaced below
    "barrier_dmb":     re.compile(r"^dmb"),
    "barrier_dsb":     re.compile(r"^dsb"),
    "barrier_isb":     re.compile(r"^isb"),
    "excl_monitors":   re.compile(r"^(ldxr|stxr|ldaxr|stlxr|ldxp|stxp|ldaxp|stlxp|casp|caspa|caspl|caspal|ldaddal|ldsetal|swpal)$"),
    "PAC":             re.compile(r"^(pacia|psia|pacib|psib|retab|braa|blraa|brab|blrab|auth[a-z]*|autda|autdb|xpaci|xpacl|xpacd)$"),
    "BTI":             re.compile(r"^bti"),
    "SVC_trap":        re.compile(r"^(svc|brk|hlt|hvc|smc|dcps1|dcps2|dcps3)$"),
    "ERET":            re.compile(r"^eret$"),
    "cache_maint":     re.compile(r"^(ic ivau|dc cvau|dc civac|ic iallu|dc zva|at s1e1r|at s1e1w|at s1e0r|at s1e0w)$"),
    "sysreg_msr":      re.compile(r"^msr"),
    "sysreg_mrs":      re.compile(r"^mrs"),
    "AES_crypto":      re.compile(r"^(aese|aesd|aesmc|aesimc|pmull|poly|rbit|rev32|rev64|ror)$"),
}
# drop the placeholder group
del GROUPS["TLB_insn"]

# Opcodes worth flagging: exception-return and system-register access appear
# in tight syscall/exit paths and are useful anchors for locating the
# kernel's trap handler.
INTERESTING = re.compile(
    r"^(svc|brk|eret|drps|tlbi|dsb|dmb|isb|retab|blraa|braa|pacia|psia|autda|casp[a-z]*|ldxr|stxr|bti|hvc|smc)$"
)


def segments(buf: bytes):
    magic, = struct.unpack_from("<I", buf, 0)
    if magic != 0xFEEDFACF:
        raise SystemExit("not MH_MAGIC_64")
    (_, _, _, ncmds, _, _, _) = struct.unpack_from("<iiIIIII", buf, 4)
    off, segs = 32, []
    for _ in range(ncmds):
        if off + 8 > len(buf):
            break
        cmd, size = struct.unpack_from("<II", buf, off)
        if size == 0:
            break
        if cmd == 0x19:
            name = buf[off + 8:off + 24].rstrip(b"\x00").decode("latin-1")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", buf, off + 24)
            maxprot, initprot, nsects, _ = struct.unpack_from("<IIII", buf, off + 56)
            segs.append({"name": name, "vmaddr": vmaddr, "fileoff": fileoff,
                         "filesize": filesize, "prot": initprot})
        off += size
    return segs


def work(job):
    path, seg = job
    buf = Path(path).read_bytes()
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    # skipdata is essential: the kernel segments embed data/table regions and
    # literal pools, so without it capstone halts at the first invalid word and
    # the sweep silently under-reports the whole image.
    md.skipdata = True
    data = buf[seg["fileoff"]:seg["fileoff"] + seg["filesize"]]
    counts: Counter = Counter()
    samples: list[str] = []
    total = 0
    for i in md.disasm(data, seg["vmaddr"]):
        if i.mnemonic == ".byte":
            continue
        total += 1
        m = i.mnemonic
        counts[m] += 1
        for label, rx in GROUPS.items():
            if rx.match(m):
                counts["@" + label] += 1
                if label in ("TLBI", "ERET", "SVC_trap", "excl_monitors", "cache_maint") \
                   and len(samples) < 25:
                    samples.append(f"{i.address:#x}: {m} {i.op_str}")
                break
    return seg["name"], total, counts, samples


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("kernel")
    ap.add_argument("--jobs", type=int, default=max(1, os.cpu_count() or 1))
    args = ap.parse_args()

    buf = Path(args.kernel).read_bytes()
    segs = [s for s in segments(buf) if s["prot"] & 0x4 or s["name"] in
            ("__PRELINK_TEXT", "__TEXT_EXEC")]
    print("=== sweeping executable segments ===")
    for s in segs:
        print(f"  {s['name']:16} {s['filesize']:>12,} bytes  prot={s['prot']:#x}")

    jobs = [(args.kernel, s) for s in segs]
    total_all: Counter = Counter()
    grand = 0
    all_samples: list[str] = []
    with Pool(min(args.jobs, len(jobs) or 1)) as pool:
        for name, total, counts, samples in pool.imap_unordered(work, jobs):
            grand += total
            total_all.update(counts)
            all_samples.extend((name, s) for s in samples)
            print(f"  {name:16} {total:>12,} instructions decoded")

    plain = [(k, v) for k, v in total_all.most_common() if not k.startswith("@")]
    print("\n=== TOTAL ===")
    print(f"  instructions decoded : {grand:,}")
    print(f"  distinct mnemonics   : {len(plain)}")
    print("  top 20 mnemonics     : " +
          ", ".join(f"{m}:{n}" for m, n in plain[:20]))

    print("\n=== architecturally significant ===")
    for label in GROUPS:
        key = "@" + label
        n = total_all.get(key, 0)
        if n:
            print(f"  {label:16} {n:>10,}")

    if all_samples:
        print("\n=== samples ===")
        for name, s in all_samples[:25]:
            print(f"  {name:16} {s}")

    import json
    Path(args.kernel + ".sweep.json").write_text(json.dumps(
        {"total": grand,
         "mnemonics": {k: v for k, v in total_all.items() if not k.startswith("@")},
         "groups": {k: total_all.get("@" + k, 0) for k in GROUPS}},
        indent=2))
    print(f"\nwrote {args.kernel}.sweep.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
