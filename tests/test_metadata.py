"""Naming, market mapping, flash sizing and the flash-offset inference."""

import pytest

from subaru_pak import metadata
from subaru_pak.keys import PackRow
from subaru_pak.metadata import (RomMetadata, flash_size, infer_download_address,
                                 output_name, parse_header_csv)


def test_flash_size_rounds_up_to_a_class():
    assert flash_size(0x100000) == 0x100000
    assert flash_size(0x100001) == 0x140000
    assert flash_size(0x13FF00) == 0x140000
    assert flash_size(0x1) == 0x28000


def test_flash_size_beyond_the_known_classes():
    assert flash_size(0x400001) == 0x410000


@pytest.mark.parametrize("covered,address,confidence", [
    (0xFE000, 0x2000, "exact"),      # SH7058 1 MB
    (0x7E000, 0x2000, "exact"),      # SH7055 512 KB
    (0xF8000, 0x8000, "exact"),      # BIU module, 1 MB
    (0x137F00, 0x8000, "tight"),     # SH72531 1.25 MB
])
def test_download_inference_reproduces_known_offsets(covered, address, confidence):
    assert infer_download_address(covered) == (address, confidence)


def test_download_inference_admits_when_it_cannot_tell():
    """An image too small to fill any flash part gets a convention, flagged."""
    assert infer_download_address(0x10) == (metadata.DEFAULT_DOWNLOAD, "default")


def test_download_inference_is_deterministic_on_a_tie():
    """Two offsets that both fit exactly: always the smaller one."""
    address, confidence = infer_download_address(0x80000, candidates=(0x0, 0x80000))
    assert (address, confidence) == (0x0, "exact")


def _row(**kwargs):
    return PackRow(**{"country": "N.AMERICA", **kwargs})


def test_names_an_engine_rom_the_way_the_community_does():
    meta = metadata.from_pack_row(
        _row(cid="A2WC412D", vehicle="Forester", year="2005", engine="2.5L",
             aspiration="Turbo", transmission="AT", spec="FED  CAL", unit="ECM"),
        cid="A2WC412D", member="A2WC412D_j.sob", pack_number="UD-S211B")
    assert output_name(meta) == "A2WC412D-2005-USDM-Subaru-Forester-XT-AT.hex"


def test_canada_spec_becomes_cdm():
    meta = metadata.from_pack_row(
        _row(cid="EB4I350A", vehicle="Legacy", year="2016", engine="2.5L",
             aspiration="non-Turbo", transmission="MT", spec="CANADA", unit="ECM"),
        cid="EB4I350A", member="EB4I350A_r.sob", pack_number="22765AJ13F")
    assert meta.market == "CDM"
    assert output_name(meta) == "EB4I350A-2016-CDM-Subaru-Legacy-2.5i-MT.hex"


def test_a_module_keeps_its_member_name_qualified_by_the_pack():
    """Its database row describes the pack, not the ROM -- so do not name from it."""
    meta = metadata.from_pack_row(
        _row(cid="---", vehicle="Legacy", year="2018", engine="2.5L",
             aspiration="non-Turbo", transmission="CVT", unit="BIU"),
        cid="DF105742_SKE_REPchg2", member="DF105742_SKE_REPchg2.mot",
        pack_number="82201AL30D", matched=False)
    assert meta.source == "database-pack"
    assert output_name(meta, ".bin") == "DF105742_SKE_REPchg2__82201AL30D.bin"


def test_no_database_row_at_all():
    meta = metadata.from_pack_row(None, cid="ABC12345", member="ABC12345_j.sob",
                                  pack_number="12345AB678")
    assert meta.source == "filename"
    assert output_name(meta) == "ABC12345_j__12345AB678.hex"


def test_vehicle_names_with_spaces_stay_readable():
    meta = metadata.from_pack_row(
        _row(cid="ZZ1A234B", vehicle="XV Crosstrek", year="2014", engine="2.0L",
             aspiration="non-Turbo", transmission="CVT", unit="ECM"),
        cid="ZZ1A234B", member="ZZ1A234B_j.sob", pack_number="P1")
    assert output_name(meta) == "ZZ1A234B-2014-USDM-Subaru-XV-Crosstrek-2.0i-CVT.hex"


@pytest.mark.parametrize("engine,aspiration,expected", [
    ("2.5L", "Turbo", "XT"),
    ("2.5L", "non-Turbo", "2.5i"),
    ("3.6L", "non-Turbo", "3.6R"),
    ("2.0L", "non-Turbo", "2.0i"),
    ("1.8L", "Turbo", "1.8T"),
])
def test_engine_naming(engine, aspiration, expected):
    meta = RomMetadata(engine=engine, aspiration=aspiration)
    assert metadata.engine_name(meta) == expected


def test_cid_from_member_strips_the_language_suffix():
    assert metadata.cid_from_member("A2WC412D_j.sob") == "A2WC412D"
    assert metadata.cid_from_member("EB4I350A_r.sob") == "EB4I350A"
    assert metadata.cid_from_member("DF105742_SKE_REPchg2.mot") == "DF105742_SKE_REPchg2"


def test_header_csv_parser_reads_ecudata_rows():
    """Ready for the day the fixed header key turns up."""
    text = ("DataType,FileName,NewCid,NewPartsNo,Model,Grade,DownloadAddress,"
            "EcuMaker,System\r\n"
            "EcuData,EB4I350A_r.sob,EB4I350A,22765AJ13A,Legacy,2.5i,8000,DENSO,ENGINE\r\n"
            "Kernel,EGISBLJ2.sob,,,,,0,,\r\n")
    entries = parse_header_csv(text)
    assert len(entries) == 1
    assert entries[0]["member"] == "EB4I350A_r.sob"
    assert entries[0]["cid"] == "EB4I350A"
    assert int(entries[0]["download"], 16) == 0x8000


def test_header_csv_parser_tolerates_junk():
    assert parse_header_csv("") == []
    assert parse_header_csv(b"\x00\x01\x02") == []
