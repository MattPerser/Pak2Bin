"""Pack database loading, including running without a bundled copy."""

import os

import pytest

from conftest import requires_test_data
from subaru_pak import keys
from subaru_pak.keys import CRYPT_KEYS, PackDatabase, default_database


def test_every_swap_key_is_four_16_bit_words():
    names = [name for name, _ in CRYPT_KEYS]
    assert len(names) == len(set(names)) == 12
    for name, words in CRYPT_KEYS:
        assert len(words) == 4, name
        assert all(0 <= word <= 0xFFFF for word in words), name


def test_installed_databases_returns_paths_that_exist():
    """Scanning for a FlashWrite install must never invent a path."""
    for path in keys.installed_databases():
        assert os.path.isfile(path)
        assert path.lower().endswith(".csv")


def test_default_database_works_with_nothing_bundled(monkeypatch, tmp_path):
    """The database is Subaru's file; the tool has to cope without a copy."""
    monkeypatch.setattr(keys, "_PACKAGED_DB", str(tmp_path / "absent.csv"))
    monkeypatch.setattr(keys, "installed_databases", lambda: [])
    default_database.cache_clear()
    try:
        db = default_database()
        assert len(db) == 0
        assert not db                      # falsey, so callers can test it
        assert db.key_for("22765AJ13F") is None
        assert db.row_for_cid("22765AJ13F", "EB4I350A") == (None, False)
    finally:
        default_database.cache_clear()


def test_an_explicit_database_is_used_and_wins(monkeypatch, tmp_path):
    csv_path = tmp_path / "Pack File Database_TEST.csv"
    csv_path.write_text(
        '"ID","Latestdata","Latestdata2","Affected_Unit","Part_Number",'
        '"Pack_Number","ProblemFixedHistory","AppricableCID","CID","CVN",'
        '"Keyword","Checksum","Country Spec"\n'
        '"1","-1","-1","ECM","22611XX000","TESTPACK","","","AB1C234D","",'
        '"DEADBEEF","---","N.AMERICA"\n', encoding="utf-16")
    monkeypatch.setattr(keys, "installed_databases", lambda: [])
    default_database.cache_clear()
    try:
        db = default_database(str(csv_path))
        assert db.key_for("TESTPACK") == "DEADBEEF"
        assert db.key_for("testpack") == "DEADBEEF"     # lookup is case-folded
    finally:
        default_database.cache_clear()


def test_a_bad_explicit_path_is_reported_not_swallowed(monkeypatch, tmp_path):
    monkeypatch.setattr(keys, "installed_databases", lambda: [])
    default_database.cache_clear()
    try:
        with pytest.raises(OSError):
            default_database(str(tmp_path / "nope.csv"))
    finally:
        default_database.cache_clear()


def test_databases_merge_rather_than_replace(tmp_path):
    a = PackDatabase.from_csv(keys._PACKAGED_DB) if os.path.exists(keys._PACKAGED_DB) \
        else PackDatabase([])
    merged = a.extend(PackDatabase([]))
    assert len(merged) == len(a)


@requires_test_data
def test_conversion_without_a_database_explains_the_fix(monkeypatch):
    """The error has to tell a technician what to do about it."""
    from subaru_pak import ConversionError, convert_pak
    from conftest import pak_path
    monkeypatch.setattr(keys, "_PACKAGED_DB", "does-not-exist.csv")
    monkeypatch.setattr(keys, "installed_databases", lambda: [])
    default_database.cache_clear()
    try:
        with pytest.raises(ConversionError, match="Pack File Database"):
            convert_pak(pak_path("22765AJ13F.pak"), database=PackDatabase([]))
    finally:
        default_database.cache_clear()


@requires_test_data
def test_explicit_key_still_converts_without_any_database():
    """--key is the escape hatch when no database is available at all."""
    from subaru_pak import convert_pak
    from conftest import pak_path, expected_bytes
    result = convert_pak(pak_path("22765AJ13F.pak"), database=PackDatabase([]),
                         rc2_key="88295D8A")
    assert result.roms[0].data == expected_bytes(
        "EB4I350A-2016-CDM-Subaru-Legacy-2.5i-MT.hex")
