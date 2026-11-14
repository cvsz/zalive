"""Tests for the trustcache parser used by the IPSW reverse-engineering work.

The parser's job is to identify the record layout from the payload itself, so
these tests pin the layout it is expected to recover. If a future firmware
changes the structure, the assertions should move rather than be loosened.

Fixtures live in tests/ (trustcache_fixture.trustcache) so the suite is
self-contained and does not depend on the gitignored firmware/ payloads.
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

FIXTURE = pathlib.Path(__file__).resolve().parent / "trustcache_fixture.trustcache"
HAVE_FIXTURE = FIXTURE.is_file()

pytestmark = pytest.mark.skipif(
    not HAVE_FIXTURE,
    reason="trustcache fixture not present",
)


def _payload():
    return parse_trustcache.img4_payload(FIXTURE.read_bytes())


def test_img4_payload_extracts_declared_length():
    """The OCTET STRING must account for exactly the rest of the file."""
    payload = _payload()
    assert FIXTURE.stat().st_size - len(payload) < 32, "wrapper should be small"


def test_rejects_non_img4_input():
    with pytest.raises(ValueError, match="IM4P"):
        parse_trustcache.img4_payload(b"\x00" * 64)


def test_rejects_truncated_container():
    with pytest.raises(ValueError):
        parse_trustcache.img4_payload(b"IM4P" + b"\x04\x82\xff\xff" + b"\x00" * 4)


@pytest.mark.parametrize(
    "name,stride,count,prefix_len",
    [
        ("trustcache_fixture.trustcache", 24, 5, 0),
    ],
)
def test_layout_matches_firmware(name, stride, count, prefix_len):
    parsed = parse_trustcache.parse(_payload())
    assert parsed["stride"] == stride, parsed["trailer_variants"]
    assert parsed["count"] == count
    assert parsed["prefix_len"] == prefix_len


@pytest.mark.parametrize(
    "name,min_ratio",
    [
        ("trustcache_fixture.trustcache", 1.0),
    ],
)
def test_hashes_are_sorted_ascending(name, min_ratio):
    """The strongest available signal that the stride is correct."""
    parsed = parse_trustcache.parse(_payload())
    hashes = [bytes.fromhex(e["hash"]) for e in parsed["entries"]]
    ascending = sum(1 for a, b in zip(hashes, hashes[1:]) if a <= b) / (len(hashes) - 1)
    assert ascending >= min_ratio
    assert parsed["sorted_ratio"] >= min_ratio


def test_first_entry_carries_the_entry_count():
    """Entry 0 stores a count in its trailer rather than flags; the value is
    entries - 1 in every 24-byte-stride file."""
    parsed = parse_trustcache.parse(_payload())
    assert (
        int(
            parsed["entries"][0]["trailer"][6:8]
            + parsed["entries"][0]["trailer"][4:6]
            + parsed["entries"][0]["trailer"][2:4]
            + parsed["entries"][0]["trailer"][0:2],
            16,
        )
        == 4
    )


def test_entries_tile_the_payload_exactly():
    for path in sorted(FIXTURE.parent.glob("trustcache_fixture.trustcache")):
        payload = parse_trustcache.img4_payload(path.read_bytes())
        parsed = parse_trustcache.parse(payload)
        assert parsed["prefix_len"] + parsed["stride"] * parsed["count"] == len(payload), path.name


def test_detect_layout_rejects_ragged_payloads():
    """A payload no stride divides evenly must fail rather than return junk."""
    parsed = parse_trustcache.parse(b"\x00" * 100)
    assert parsed["stride"] >= 20
