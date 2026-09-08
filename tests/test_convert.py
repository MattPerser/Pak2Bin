"""The safety net: every known-good pair must come back bit for bit.

If one of these fails, a primitive is wrong -- not the test.
"""

import hashlib
import os

import pytest

from conftest import (NON_ROM_MEMBERS, VECTORS, expected_bytes, pak_path,
                      requires_test_data)
from subaru_pak import ConversionError, convert_pak, inspect_pak, write_results
from subaru_pak import convert as convert_mod

pytestmark = requires_test_data

CASES = [(pak, member, name)
         for pak, roms in VECTORS.items()
         for member, name in roms.items()]


@pytest.fixture(scope="module")
def converted():
    """Convert each vector pak once; the RC2 pass is the slow part."""
    return {name: convert_pak(pak_path(name)) for name in VECTORS}


@pytest.mark.parametrize("pak,member,expected_name", CASES,
                         ids=[f"{p}:{m}" for p, m, _ in CASES])
def test_rom_is_bit_exact(converted, pak, member, expected_name):
    rom = next(r for r in converted[pak].roms if r.member == member)
    assert rom.ok, rom.message
    assert rom.data == expected_bytes(expected_name)


@pytest.mark.parametrize("pak,member,expected_name", CASES,
                         ids=[f"{p}:{m}" for p, m, _ in CASES])
def test_output_name_matches_the_known_good_name(converted, pak, member,
                                                 expected_name):
    rom = next(r for r in converted[pak].roms if r.member == member)
    assert rom.filename == expected_name


@pytest.mark.parametrize("pak,member,expected_name", CASES,
                         ids=[f"{p}:{m}" for p, m, _ in CASES])
def test_sha256_is_reported_correctly(converted, pak, member, expected_name):
    rom = next(r for r in converted[pak].roms if r.member == member)
    assert rom.sha256 == hashlib.sha256(expected_bytes(expected_name)).hexdigest()


def test_multi_rom_pak_yields_both_roms(converted):
    roms = converted["UD-S211B.pak"].roms
    assert sorted(r.member for r in roms) == ["A2WC412D_j.sob", "A2WC412I_j.sob"]
    assert {r.metadata.transmission for r in roms} == {"AT", "MT"}


@pytest.mark.parametrize("pak,members", NON_ROM_MEMBERS.items())
def test_writers_kernels_and_blobs_are_not_converted(pak, members):
    result = convert_pak(pak_path(pak))
    skipped = {entry["member"] for entry in result.skipped}
    assert set(members) <= skipped
    assert not (set(members) & {rom.member for rom in result.roms})


def test_detected_keys_and_offsets(converted):
    detected = {r.member: (r.key, r.key_method, r.download)
                for result in converted.values() for r in result.roms}
    assert detected["EB4I350A_r.sob"] == ("denso_can", "calid", 0x8000)
    assert detected["A2WC412D_j.sob"] == ("denso", "calid", 0x2000)
    assert detected["DF105742_SKE_REPchg2.mot"] == ("module_biu_82201", "structure", 0x8000)


def test_engine_rom_checksums_validate(converted):
    for member in ("EB4I350A_r.sob", "A2WC412D_j.sob", "A2WC412I_j.sob"):
        rom = next(r for result in converted.values() for r in result.roms
                   if r.member == member)
        assert rom.checksum == "ok", rom.checksum_detail


def test_module_has_no_dbw_checksum_to_claim(converted):
    rom = converted["82201AL30D.pak"].roms[0]
    assert rom.checksum == "n/a"


def test_inspect_reads_metadata_without_decrypting(converted):
    result = inspect_pak(pak_path("22765AJ13F.pak"))
    rom = result.roms[0]
    assert rom.data is None
    assert rom.metadata.cid == "EB4I350A"
    assert rom.metadata.year == "2016"
    assert rom.metadata.market == "CDM"
    assert rom.filename == "EB4I350A-2016-CDM-Subaru-Legacy-2.5i-MT.hex"


def test_forced_swap_key_is_honoured():
    result = convert_pak(pak_path("22765AJ13F.pak"), swap_key="denso_can")
    assert result.roms[0].key_method == "forced"
    assert result.roms[0].data == expected_bytes(
        "EB4I350A-2016-CDM-Subaru-Legacy-2.5i-MT.hex")


def test_wrong_forced_key_produces_a_different_image():
    result = convert_pak(pak_path("22765AJ13F.pak"), swap_key="hitachi1")
    assert result.roms[0].data != expected_bytes(
        "EB4I350A-2016-CDM-Subaru-Legacy-2.5i-MT.hex")


def test_unknown_swap_key_is_rejected():
    with pytest.raises(ConversionError, match="unknown swap-cipher key"):
        convert_pak(pak_path("22765AJ13F.pak"), swap_key="nope")


def test_missing_rc2_key_explains_itself():
    """The message has to name the fix, not just the failure."""
    from subaru_pak import PackDatabase
    with pytest.raises(ConversionError, match="Pack File Database"):
        convert_pak(pak_path("22765AJ13F.pak"), database=PackDatabase([]))


def test_explicit_rc2_key_bypasses_the_database():
    from subaru_pak import PackDatabase
    result = convert_pak(pak_path("22765AJ13F.pak"), database=PackDatabase([]),
                         rc2_key="88295D8A")
    assert result.roms[0].data == expected_bytes(
        "EB4I350A-2016-CDM-Subaru-Legacy-2.5i-MT.hex")
    # With no database there is no CALID metadata, so the name falls back.
    assert result.roms[0].filename == "EB4I350A_r__22765AJ13F.hex"


def test_write_results_writes_named_files(tmp_path, converted):
    written = write_results(converted["UD-S211B.pak"], str(tmp_path))
    assert sorted(os.path.basename(p) for p in written) == sorted(
        VECTORS["UD-S211B.pak"].values())
    for path in written:
        assert os.path.getsize(path) == 0x100000


def test_scan_sizes_match_full_conversion(converted):
    """The tail-only scan must agree with parsing the whole member."""
    for name, result in converted.items():
        scan = inspect_pak(pak_path(name))
        assert {r.member: (r.covered, r.download, r.size) for r in scan.roms} == \
               {r.member: (r.covered, r.download, r.size) for r in result.roms}, name


def test_scan_is_quick():
    """A scan must not RC2 megabytes -- the GUI shows cards on drop."""
    import time
    start = time.perf_counter()
    result = inspect_pak(pak_path("UD-S211B.pak"))     # 6.5 MB, two 1 MB ROMs
    elapsed = time.perf_counter() - start
    assert len(result.roms) == 2
    assert elapsed < 2.0, f"scan took {elapsed:.1f}s"


# -- the fast scan must never report a confident wrong size ------------------

def test_extent_check_accepts_a_real_tail():
    """Numbers taken from EB4I350A: 8 KB of 46-byte S2 lines, 16 bytes each."""
    sample_len, sample_span = 8_050, 2_800
    assert convert_mod._extent_is_consistent(sample_len, sample_span,
                                             member_len=3_665_200,
                                             span=0x137F00)


def test_extent_check_rejects_a_tail_that_is_not_the_end():
    """A tail holding low-addressed records implies far too small an image."""
    assert not convert_mod._extent_is_consistent(8_050, 2_800,
                                                 member_len=3_665_200,
                                                 span=0x100000)
    assert not convert_mod._extent_is_consistent(8_050, 2_800,
                                                 member_len=3_665_200, span=0x1000)


def test_extent_check_rejects_a_degenerate_sample():
    assert not convert_mod._extent_is_consistent(8_050, 0, 3_665_200, 0x137F00)
    assert not convert_mod._extent_is_consistent(8_050, 2_800, 3_665_200, 0)


def test_an_unsizeable_scan_says_so_instead_of_guessing(monkeypatch):
    monkeypatch.setattr(convert_mod, "_scan_extent", lambda *a, **k: None)
    rom = inspect_pak(pak_path("22765AJ13F.pak")).roms[0]
    assert rom.download_source == "unknown"
    assert (rom.covered, rom.size, rom.download) == (0, 0, 0)
    assert rom.metadata.cid == "EB4I350A"          # identity is still known
    assert rom.filename == "EB4I350A-2016-CDM-Subaru-Legacy-2.5i-MT.hex"
    assert "converting determines them" in rom.message


# -- --fix-checksum actually repairs, and only where a table exists ----------

def test_repair_makes_a_corrupted_rom_validate():
    """The branch behind --fix-checksum, on a genuinely broken image."""
    import struct
    from subaru_pak import checksum
    data = bytearray(expected_bytes("EB4I350A-2016-CDM-Subaru-Legacy-2.5i-MT.hex"))
    table = checksum.table_offset(len(data))
    block_start = struct.unpack_from(">I", data, table)[0]
    data[block_start] ^= 0xFF

    assert convert_mod._checksum_state(bytes(data))[0] == "bad"
    image, state, detail = convert_mod.repair_checksum(bytes(data))
    assert state == "ok"
    assert detail["fixed_blocks"] == 1
    assert len(image) == len(data)


def test_repair_of_a_healthy_rom_is_a_no_op():
    good = expected_bytes("A2WC412D-2005-USDM-Subaru-Forester-XT-AT.hex")
    image, state, detail = convert_mod.repair_checksum(good)
    assert image == good and state == "ok"
    assert "fixed_blocks" not in detail


def test_fix_checksum_leaves_good_roms_byte_identical():
    for pak, member, name in CASES:
        result = convert_pak(pak_path(pak), fix_checksum=True)
        rom = next(r for r in result.roms if r.member == member)
        assert rom.data == expected_bytes(name), name


# -- the CALID fallback beyond the sampled head -----------------------------

def test_calid_found_past_the_sample_window():
    """Forces the full-cal pass: the CALID sits beyond the sampled head."""
    from subaru_pak import pak as pakmod, rc2, srec
    member = pakmod.read(pak_path("22611AG83D.pak")).member("E6PF101A_j.sob")
    cal = bytes(srec.parse(rc2.decrypt_pak_blob(member.data, "0834B667")).data)

    # The swap cipher is ECB on 4-byte blocks, so a 4-aligned prefix just shifts
    # the CALID out of the sample without disturbing the rest.
    padded = b"\x00" * 0x10000 + cal
    name, key, method = convert_mod.detect_key(padded, "E6PF101A", sample=0x1000)
    assert (name, method) == ("denso", "calid")


def test_detection_gives_up_rather_than_guessing():
    """Random data matches no key by CALID and has no 0xFF structure."""
    import random
    noise = bytes(random.Random(11).randrange(256) for _ in range(0x2000))
    assert convert_mod.detect_key(noise, "NOSUCHID") == (None, None, "")
