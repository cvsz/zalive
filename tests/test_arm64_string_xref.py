"""Tests for the ARM64 string cross-reference scanner.

The scanner's value depends entirely on resolving ADRP to the right page, so
these tests pin the encodings against known-good instruction words rather than
against the scanner's own output. Two bugs motivated them:

- ADRP keeps immlo in bits[30:29]. Reading it from bits[1:0] picks up the low
  bits of the destination register instead, which silently yields a wrong page
  for every target that is not 16 KiB away.
- A pointer slot in __DATA usually points at a string in __TEXT. Gating the
  plausible-range test on the containing segment misses every cross-segment
  table.

- A follow-up load or add is only paired with an ADRP when it reads the register
  that ADRP wrote, otherwise a string is attributed to the wrong code site.
- LDR pre/post-index carries a *signed* imm9. Read as unsigned, `[x0, #-16]!`
  becomes +496 and every backward reference is silently lost.

All of these bugs produced "no reference found" rather than an error, so only an
explicit positive control catches them.
"""
import importlib.util
import pathlib
import struct
import sys

import pytest

_spec = importlib.util.spec_from_file_location(
    "arm64_string_xref",
    pathlib.Path(__file__).resolve().parents[1] / "scripts" / "arm64_string_xref.py",
)
arm64_string_xref = importlib.util.module_from_spec(_spec)
sys.modules["arm64_string_xref"] = arm64_string_xref
_spec.loader.exec_module(arm64_string_xref)

BASE = 0x100000000
TEXT_LEN = 0x8000
DATA_LEN = 0x200
HDR = 32
SEGSZ = 72
BODY = SEGSZ * 2
TEXT_OFF = HDR + BODY
DATA_OFF = TEXT_OFF + TEXT_LEN


def _segment(name, vmaddr, vmsize, fileoff, filesize):
    return (struct.pack("<II", 0x19, SEGSZ)
            + name.encode().ljust(16, b"\x00")
            + struct.pack("<QQQQ", vmaddr, vmsize, fileoff, filesize)
            + struct.pack("<iiII", 7, 5, 0, 0))


def _encode_adrp(byte_offset, rd=0):
    """ADRP as `op immlo[30:29] 10000 immhi[23:5] Rd[4:0]`."""
    imm21 = byte_offset >> 12
    assert -(1 << 20) <= imm21 < (1 << 20)
    return (0x90000000 | ((imm21 & 3) << 29)
            | (((imm21 >> 2) & 0x7FFFF) << 5) | rd)


def _encode_adr(byte_offset, rd=0):
    """ADR as `op immlo[30:29] 10000 immhi[23:5] Rd[4:0]`, PC-relative."""
    assert -(1 << 20) <= byte_offset < (1 << 20)
    return (0x10000000 | ((byte_offset & 3) << 29)
            | (((byte_offset >> 2) & 0x7FFFF) << 5) | rd)


@pytest.mark.parametrize("page_offset", [0x1000, 0x2000, 0x3000, 0x4000, 0x5000,
                                        0x8000, 0x10000, 0x4000000])
def test_adrp_target_resolves_forward_page_offsets(page_offset):
    insn = _encode_adrp(page_offset)
    assert arm64_string_xref.adrp_target(insn, BASE) == BASE + page_offset


@pytest.mark.parametrize("page_offset", [-0x1000, -0x3000, -0x8000])
def test_adrp_target_resolves_backward_page_offsets(page_offset):
    insn = _encode_adrp(page_offset)
    assert arm64_string_xref.adrp_target(insn, BASE) == BASE + page_offset


def test_adrp_immlo_comes_from_bits_30_29_not_the_register_field():
    """immlo lives in bits[30:29]; bits[1:0] are part of Rd.

    Same page offset, different destination register: the target must not move.
    """
    page_offset = 0x3000
    targets = {
        arm64_string_xref.adrp_target(_encode_adrp(page_offset, rd), BASE)
        for rd in (0, 1, 2, 3, 28, 29, 30, 31)
    }
    assert targets == {BASE + page_offset}


def test_adrp_and_adr_agree_on_immlo_placement():
    page_offset = 0x5000
    adrp = arm64_string_xref.adrp_target(_encode_adrp(page_offset), BASE)
    adr = arm64_string_xref.adr_target(_encode_adr(page_offset), BASE)
    assert adrp == (BASE & ~0xFFF) + page_offset
    assert adr == BASE + page_offset


def test_non_adrp_and_non_adr_are_rejected():
    assert arm64_string_xref.adrp_target(0xD503201F, BASE) is None  # NOP
    assert arm64_string_xref.adr_target(0xD503201F, BASE) is None
    assert arm64_string_xref.adrp_target(0x91000000, BASE) is None  # ADD imm


def _encode_add_imm(imm12, rn=0, rd=1, shift=0, sf=1):
    """ADD (immediate): `sf op S 100010 shift imm12 Rn Rd`."""
    return ((0x91000000 if sf else 0x11000000)
            | (shift << 22) | ((imm12 & 0xFFF) << 10) | (rn << 5) | rd)


def _encode_ldr_uimm(byte_offset, rn=0, rt=1):
    """LDR (unsigned immediate), 64-bit: imm12 counts 8-byte units."""
    return 0xF9400000 | ((byte_offset // 8) << 10) | (rn << 5) | rt


def _encode_ldr_prepost(imm9, rn=0, rt=1):
    """LDR (immediate, pre-index), 64-bit: imm9 is signed, in bytes."""
    return 0xF8400000 | ((imm9 & 0x1FF) << 12) | (rn << 5) | rt


def _build_image():
    """One Mach-O holding one reference of each supported form.

    __TEXT carries ADR, ADRP+ADD, ADRP+LDR and a backward pre-index load; a
    __DATA slot points across into __TEXT, which is the layout a prelinked kext
    actually uses. Every add/load offset is non-zero on purpose: a target that
    sits on a page boundary cannot tell an implementation that reads the offset
    field from one that ignores it.
    """
    a_site, a_str = 0x80, 0x3000          # ADR, page-aligned
    b_site, b_str = 0x100, 0x5160         # ADRP + ADD, off-page
    c_site, c_str = 0x180, 0x3160         # ADRP + LDR uimm, off-page
    d_site, d_str, d_page = 0x200, 0x5FF0, 0x6000   # pre-index, negative imm9
    e_str = 0x7000
    slot_off = 0x40

    text = bytearray(TEXT_LEN)
    struct.pack_into("<II", text, a_site,
                     _encode_adr((BASE + a_str) - (BASE + a_site)), 0xD503201F)
    for site, page_target, follow in (
            (b_site, b_str & ~0xFFF, _encode_add_imm(b_str & 0xFFF, rn=0, rd=1)),
            (c_site, c_str & ~0xFFF, _encode_ldr_uimm(c_str & 0xFFF, rn=0, rt=1)),
            (d_site, d_page, _encode_ldr_prepost(d_str - d_page, rn=0, rt=1))):
        page = (BASE + page_target) - ((BASE + site) & ~0xFFF)
        struct.pack_into("<II", text, site, _encode_adrp(page, rd=0), follow)
    for offset, text_value in ((a_str, b"ZeazAdrString\x00"),
                               (b_str, b"ZeazAddString\x00"),
                               (c_str, b"ZeazLdrString\x00"),
                               (d_str, b"ZeazPrePostString\x00"),
                               (e_str, b"ZeazSlotString\x00")):
        text[offset:offset + len(text_value)] = text_value

    data = bytearray(DATA_LEN)
    struct.pack_into("<Q", data, slot_off, BASE + e_str)

    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 2, BODY, 0, 0)
    body = (_segment("__TEXT", BASE, TEXT_LEN, TEXT_OFF, TEXT_LEN)
            + _segment("__DATA", BASE + 0x10000, DATA_LEN, DATA_OFF, DATA_LEN))
    return arm64_string_xref.Image(header + body + bytes(text) + bytes(data))


def _image_with_text(text):
    """Same segment layout as _build_image but with caller-supplied __TEXT."""
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 2, BODY, 0, 0)
    body = (_segment("__TEXT", BASE, TEXT_LEN, TEXT_OFF, TEXT_LEN)
            + _segment("__DATA", BASE + 0x10000, DATA_LEN, DATA_OFF, DATA_LEN))
    return arm64_string_xref.Image(header + body + bytes(text)
                                   + bytes(DATA_LEN))


@pytest.fixture(scope="module")
def image():
    return _build_image()


def test_xref_finds_adr_reference(image):
    sites = arm64_string_xref.xref(image, "ZeazAdrString")
    assert [desc for desc, _ in sites] == [f"adr @ 0x{BASE + 0x80:x}"]


def test_xref_finds_adrp_add_reference(image):
    """The common form, with a non-zero low 12 bits of the target."""
    sites = arm64_string_xref.xref(image, "ZeazAddString")
    assert [desc for desc, _ in sites] == [f"adrp+add @ 0x{BASE + 0x100:x}"]


def test_xref_finds_adrp_ldr_reference(image):
    sites = arm64_string_xref.xref(image, "ZeazLdrString")
    assert [desc for desc, _ in sites] == [f"adrp+ldr_uimm @ 0x{BASE + 0x180:x}"]


def test_xref_finds_backward_prepost_reference(image):
    """`[x0, #-16]!`: the imm9 has to be sign-extended or this reads as +496."""
    sites = arm64_string_xref.xref(image, "ZeazPrePostString")
    assert [desc for desc, _ in sites] == [f"adrp+ldr_prepost @ 0x{BASE + 0x200:x}"]


def test_xref_ignores_a_follow_up_that_reads_a_different_register(image):
    """An ADD off another register is not part of this ADRP pair."""
    text = bytearray(TEXT_LEN)
    site, target = 0x400, 0x3160
    page = (BASE + (target & ~0xFFF)) - ((BASE + site) & ~0xFFF)
    struct.pack_into("<II", text, site, _encode_adrp(page, rd=0),
                     _encode_add_imm(target & 0xFFF, rn=5, rd=1))
    struct.pack_into("<16s", text, target, b"ZeazWrongReg\x00")
    sites = arm64_string_xref.xref(_image_with_text(text), "ZeazWrongReg")
    assert sites == []


def test_xref_ignores_a_32bit_add_whose_offset_is_not_an_address(image):
    """sf=0 means the destination is a 32-bit value, not a pointer."""
    text = bytearray(TEXT_LEN)
    site, target = 0x400, 0x3160
    page = (BASE + (target & ~0xFFF)) - ((BASE + site) & ~0xFFF)
    struct.pack_into("<II", text, site, _encode_adrp(page, rd=0),
                     _encode_add_imm(target & 0xFFF, rn=0, rd=1, sf=0))
    struct.pack_into("<16s", text, target, b"Zeaz32BitAdd\x00")
    sites = arm64_string_xref.xref(_image_with_text(text), "Zeaz32BitAdd")
    assert sites == []


def test_xref_finds_pointer_slot_in_another_segment(image):
    """The slot sits in __DATA and the string in __TEXT."""
    sites = arm64_string_xref.xref(image, "ZeazSlotString")
    assert [desc for desc, _ in sites] == [f"pointer slot @ 0x{BASE + 0x10000 + 0x40:x}"]


def test_xref_reports_nothing_for_a_string_that_is_absent(image):
    assert arm64_string_xref.xref(image, "NoSuchStringAnywhere") == []


def test_pointer_slot_scan_accepts_targets_in_any_segment(image):
    slots = arm64_string_xref.find_pointer_slots(image)
    assert "ZeazSlotString" in slots
    assert BASE + 0x10000 + 0x40 in slots["ZeazSlotString"]


def test_read_cstring_at_rejects_a_pointer_into_unmapped_space(image):
    assert arm64_string_xref.read_cstring_at(image, 0xDEADBEEF00) is None


@pytest.mark.parametrize("magic", [0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA])
def test_fat_container_is_rejected_instead_of_scanned_as_code(magic):
    """A universal binary is a header table, not an AArch64 slice."""
    blob = struct.pack("<II", magic, 2) + bytes(0x100)
    with pytest.raises(ValueError, match="fat/universal"):
        arm64_string_xref.Image(blob)


def test_truncated_input_is_rejected_instead_of_raising_struct_error():
    with pytest.raises(ValueError, match="too short"):
        arm64_string_xref.Image(b"\xcf\xfa")


def test_raw_slice_finds_a_pointer_slot_when_given_its_load_address():
    """A raw slice has no segments, so absolute pointers only land in range when
    the caller supplies the base the blob was loaded at."""
    blob = bytearray(0x2000)
    blob[0x40:0x48] = struct.pack("<Q", BASE + 0x800)
    blob[0x800:0x80F] = b"RawSlot\x00"

    without_base = arm64_string_xref.Image(bytes(blob))
    assert "RawSlot" not in arm64_string_xref.find_pointer_slots(without_base)

    with_base = arm64_string_xref.Image(bytes(blob), base=BASE)
    slots = arm64_string_xref.find_pointer_slots(with_base)
    assert slots["RawSlot"] == [BASE + 0x40]
