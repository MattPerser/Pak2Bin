"""The subarudbw 32-bit checksum, against real converted ROMs."""

import struct

import pytest

from conftest import VECTORS, expected_bytes, requires_test_data
from subaru_pak import checksum

ENGINE_ROMS = ["EB4I350A-2016-CDM-Subaru-Legacy-2.5i-MT.hex",
               "A2WC412D-2005-USDM-Subaru-Forester-XT-AT.hex",
               "A2WC412I-2005-USDM-Subaru-Forester-XT-MT.hex"]


def test_table_offset_by_size():
    assert checksum.table_offset(0x80000) == 0x7FB80
    assert checksum.table_offset(0x100000) == 0xFFB80
    assert checksum.table_offset(0x140000) == 0x13F500
    assert checksum.table_offset(0x12345) is None


@requires_test_data
@pytest.mark.parametrize("name", ENGINE_ROMS)
def test_real_engine_roms_validate(name):
    ok, active, passed, bad = checksum.validate(expected_bytes(name))
    assert ok, bad
    assert active and passed == active


@requires_test_data
def test_a_corrupted_block_fails_and_can_be_fixed():
    data = bytearray(expected_bytes(ENGINE_ROMS[0]))
    table = checksum.table_offset(len(data))
    start = struct.unpack_from(">I", data, table)[0]
    data[start] ^= 0xFF                       # flip a byte inside block 0

    ok, _, _, bad = checksum.validate(bytes(data), table)
    assert not ok and any(entry[1] == "FAIL" for entry in bad)

    fixed, changed = checksum.fix(bytes(data), table)
    assert changed == 1
    assert checksum.validate(bytes(fixed), table)[0]


@requires_test_data
def test_fixing_a_valid_rom_changes_nothing():
    data = expected_bytes(ENGINE_ROMS[1])
    fixed, changed = checksum.fix(data)
    assert changed == 0
    assert bytes(fixed) == data


@requires_test_data
def test_module_image_has_no_table_to_validate():
    """Random data at the table offset must not read as a failed checksum."""
    from subaru_pak.convert import _plausible_table
    data = expected_bytes(VECTORS["82201AL30D.pak"]["DF105742_SKE_REPchg2.mot"])
    assert _plausible_table(data, checksum.table_offset(len(data))) == 0
