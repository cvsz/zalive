"""Tests for the trustcache parser used by the IPSW reverse-engineering work.

The parser's job is to identify the record layout from the payload itself, so
these tests pin the layout it is expected to recover. If a future firmware
changes the structure, the assertions should move rather than be loosened.
"""
import importlib.util
import pathlib
import sys

import pytest

_spec = importlib.util.spec_from_file_location(
    "parse_trustcache",
    pathlib.Path(__file__).resolve().parents[1] / "scripts" / "parse_trustcache.py",
)
parse_trustcache = importlib.util.module_from_spec(_spec)
sys.modules["parse_trustcache"] = parse_trustcache
_spec.loader.exec_module(parse_trustcache)

FIRMWARE = pathlib.Path(__file__).resolve().parents[1] / "firmware" / "Firmware"
HAVE_FIRMWARE = FIRMWARE.is_dir() and any(FIRMWARE.glob("*.trustcache"))

pytestmark = pytest.mark.skipif(
    not HAVE_FIRMWARE,
    reason="firmware/ is gitignored; the IPSW payloads are not in the repository",
)


def _payload(name):
    path = FIRMWARE / name
    if not path.exists():
        pytest.skip(f"{name} not present")
    return parse_trustcache.img4_payload(path.read_bytes())


def test_img4_payload_extracts_declared_length():
    """The OCTET STRING must account for exactly the rest of the file."""
    payload = _payload("094-32147-038.dmg.trustcache")
    path = FIRMWARE / "094-32147-038.dmg.trustcache"
    assert path.stat().st_size - len(payload) < 32, "wrapper should be small"


def test_rejects_non_img4_input():
    with pytest.raises(ValueError, match="IM4P"):
        parse_trustcache.img4_payload(b"\x00" * 64)


def test_rejects_truncated_container():
    with pytest.raises(ValueError):
        parse_trustcache.img4_payload(b"IM4P" + b"\x04\x82\xff\xff" + b"\x00" * 4)


@pytest.mark.parametrize(
    "name,stride,count,prefix_len",
    [
        ("094-31934-038.dmg.aea.trustcache", 24, 3270, 0),
        ("094-32062-038.dmg.aea.trustcache", 24, 97, 0),
        ("094-32147-038.dmg.trustcache", 22, 338, 2),
        ("094-32850-038.dmg.trustcache", 24, 31, 0),
    ],
)
def test_layout_matches_firmware(name, stride, count, prefix_len):
    parsed = parse_trustcache.parse(_payload(name))
    assert parsed["stride"] == stride, parsed["trailer_variants"]
    assert parsed["count"] == count
    assert parsed["prefix_len"] == prefix_len


@pytest.mark.parametrize(
    "name,min_ratio",
    [
        ("094-31934-038.dmg.aea.trustcache", 0.999),
        ("094-32147-038.dmg.trustcache", 1.0),
    ],
)
def test_hashes_are_sorted_ascending(name, min_ratio):
    """The strongest available signal that the stride is correct.

    094-31934 holds 3270 hashes and contains exactly one out-of-order pair, so
    it sorts to 0.9997 rather than a clean 1.0.
    """
    parsed = parse_trustcache.parse(_payload(name))
    hashes = [bytes.fromhex(e["hash"]) for e in parsed["entries"]]
    ascending = sum(1 for a, b in zip(hashes, hashes[1:]) if a <= b) / (len(hashes) - 1)
    assert ascending >= min_ratio
    assert parsed["sorted_ratio"] >= min_ratio


def test_first_entry_carries_the_entry_count():
    """Entry 0 stores a count in its trailer rather than flags; the value is
    entries - 1 in every 24-byte-stride file."""
    for name, expected in [
        ("094-31934-038.dmg.aea.trustcache", 3269),
        ("094-32062-038.dmg.aea.trustcache", 96),
        ("094-32850-038.dmg.trustcache", 30),
    ]:
        parsed = parse_trustcache.parse(_payload(name))
        assert int(parsed["entries"][0]["trailer"][6:8] + parsed["entries"][0]["trailer"][4:6]
                   + parsed["entries"][0]["trailer"][2:4] + parsed["entries"][0]["trailer"][0:2], 16) == expected


def test_entries_tile_the_payload_exactly():
    for path in sorted(FIRMWARE.glob("*.trustcache")):
        payload = parse_trustcache.img4_payload(path.read_bytes())
        parsed = parse_trustcache.parse(payload)
        assert parsed["prefix_len"] + parsed["stride"] * parsed["count"] == len(payload), path.name


def test_detect_layout_rejects_ragged_payloads():
    """A payload no stride divides evenly must fail rather than return junk."""
    parsed = parse_trustcache.parse(b"\x00" * 100)
    assert parsed["stride"] >= 20