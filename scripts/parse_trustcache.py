#!/usr/bin/env python3
"""Parse the IMG4-wrapped trustcache files shipped in an iOS IPSW.

The trustcache files inside an IPSW are not raw structs. Each one is a full
IMG4 container, and two different record layouts appear depending on the
component the cache belongs to. Both were derived from the 18.7.10 / 22H374
firmware in this repository rather than from documentation, so the magic
numbers below are recorded alongside the evidence that produced them.

Usage:
    scripts/parse_trustcache.py firmware/Firmware/094-32147-038.dmg.trustcache
    scripts/parse_trustcache.py --json firmware/Firmware/*.trustcache
"""
import argparse
import collections
import glob
import json
import struct
import sys
from pathlib import Path



def img4_payload(blob: bytes) -> bytes:
    """Return the OCTET STRING body of an IMG4/IM4P container.

    Layout confirmed by walking every TLV of 094-32147-038.dmg.trustcache:
        30 82 xx xx                SEQUENCE
          16 04 "IM4P"             APPLICATION, tag
          16 04 "rtsc"             APPLICATION, tag
          16 01                    APPLICATION, single byte
          04 82 xx xx <payload>    OCTET STRING, the trustcache itself

    The header length is not fixed across files: 094-32147 encodes it as
    30 82 <len2> while 094-31934 uses 30 83 <len3>, which shifts the IM4P tag
    by one byte. Rather than hardcoding offsets, locate the tag and then take
    the OCTET STRING that accounts for exactly the rest of the file.
    """
    tag = blob.find(b"IM4P")
    if tag < 0:
        raise ValueError("not an IMG4/IM4P container (missing IM4P tag)")
    for j in range(tag + 4, len(blob) - 4):
        if blob[j] != 0x04:
            continue
        first = blob[j + 1]
        if first < 0x80:
            length, header = first, 2
        elif first == 0x82:
            length, header = struct.unpack(">H", blob[j + 2:j + 4])[0], 4
        elif first == 0x83:
            length, header = int.from_bytes(blob[j + 2:j + 5], "big"), 5
        else:
            continue
        if j + header + length == len(blob):
            return blob[j + header:]
    raise ValueError("no OCTET STRING accounts for the remainder of the file")


def detect_layout(payload: bytes):
    """Choose a record layout from the structure of the payload itself.

    A trustcache stores its hashes in ascending order, so the layout that
    yields fully sorted 20-byte records is the correct one. Only candidates
    whose records tile the payload exactly are considered: a partial tail is
    proof the stride was guessed wrong, and several wrong strides still score
    1.0 on sortedness because they sample a subsequence.
    """
    best = None
    for stride in range(20, 49):
        for start in range(stride):
            if start > len(payload) or (len(payload) - start) % stride:
                continue
            count = (len(payload) - start) // stride
            if count < 4:
                continue
            records = [payload[start + stride * i: start + stride * i + 20] for i in range(count)]
            ascending = sum(1 for a, b in zip(records, records[1:]) if a <= b)
            ratio = ascending / (count - 1)
            # Prefer the highest sortedness, then the smallest stride so that a
            # genuine layout wins over a larger stride that happens to agree.
            if best is None or (ratio, -stride) > (best[0], -best[1]):
                best = (ratio, stride, start)
    if best is None:
        return None
    ratio, stride, start = best
    return {"stride": stride, "start": start, "sorted_ratio": round(ratio, 4)}


def parse(payload: bytes):
    layout = detect_layout(payload)
    if layout is None:
        raise ValueError("no record layout divides the payload evenly")
    stride, start = layout["stride"], layout["start"]
    prefix = payload[:start]
    count = (len(payload) - start) // stride
    entries = []
    for i in range(count):
        rec = payload[start + stride * i: start + stride * (i + 1)]
        hash1 = rec[:20]
        trailer = rec[20:]
        entry = {"hash": hash1.hex(), "trailer": trailer.hex()}
        # 44-byte records carry a second 20-byte hash between two identical
        # 02 00 markers; 24-byte records carry only the flags.
        if stride >= 44 and len(trailer) >= 22:
            entry["hash2"] = trailer[2:22].hex()
        entries.append(entry)
    return {
        "prefix": prefix.hex(),
        "prefix_len": start,
        "stride": stride,
        "count": count,
        "sorted_ratio": layout["sorted_ratio"],
        "trailer_variants": dict(collections.Counter(e["trailer"] for e in entries)),
        "entries": entries,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="trustcache file(s)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--limit", type=int, default=0, help="print only the first N entries")
    args = ap.parse_args()

    paths = []
    for pattern in args.files:
        paths.extend(sorted(glob.glob(pattern)) or [pattern])

    results = []
    for path in paths:
        try:
            blob = Path(path).read_bytes()
            payload = img4_payload(blob)
            parsed = parse(payload)
            parsed["file"] = path
            parsed["payload_len"] = len(payload)
            results.append(parsed)
        except Exception as exc:
            results.append({"file": path, "error": f"{type(exc).__name__}: {exc}"})

    if args.json:
        print(json.dumps(results, indent=2))
        return 0

    for r in results:
        if "error" in r:
            print(f"{r['file']}: ERROR {r['error']}")
            continue
        print(f"{r['file']}")
        print(f"  payload={r['payload_len']}  prefix={r['prefix'] or '-'} ({r['prefix_len']}B)"
              f"  stride={r['stride']}  entries={r['count']}  sorted={r['sorted_ratio']}")
        print(f"  trailer variants: {r['trailer_variants']}")
        for e in (r["entries"][:args.limit] if args.limit else r["entries"][:3]):
            extra = f"  hash2={e['hash2']}" if "hash2" in e else ""
            print(f"    {e['hash']}{extra}  [{e['trailer']}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())