"""The CArchive container reader."""

import struct

import pytest

from conftest import pak_path, requires_test_data
from subaru_pak import pak

pytestmark = requires_test_data

EXPECTED_MEMBERS = {
    "22765AJ13F.pak": ["EB4I350A_r.sob"],
    "82201AL30D.pak": ["DF105742_SKE_REPchg2.mot"],
    "22611AG83D.pak": ["FW084000.MOT", "EGISBLJ2.sob", "E6PF101A_j.sob",
                       "EcuDataMap", "PcVerData"],
    "UD-S211B.pak": ["FW084000.MOT", "EGISBLJ0_7058.sob", "A2WC412D_j.sob",
                     "A2WC412I_j.sob", "ETCCTLJ2.mot", "AD3A104D.mot",
                     "EcuDataMap", "PcVerData"],
}


@pytest.mark.parametrize("name,members", EXPECTED_MEMBERS.items())
def test_members_are_read_in_order(name, members):
    archive = pak.read(pak_path(name))
    assert [m.name for m in archive.members] == members


@pytest.mark.parametrize("name,members", EXPECTED_MEMBERS.items())
def test_declared_object_count_is_honoured(name, members):
    """A pak that declares more objects than we read means a silent drop."""
    archive = pak.read(pak_path(name))
    assert archive.object_count == len(members)


@pytest.mark.parametrize("name", EXPECTED_MEMBERS)
def test_members_cover_the_file_exactly(name):
    archive = pak.read(pak_path(name))
    with open(pak_path(name), "rb") as fh:
        size = len(fh.read())
    last = archive.members[-1]
    assert last.offset + last.length == size


def test_pack_number_comes_from_the_file_name():
    assert pak.read(pak_path("UD-S211B.pak")).pack_number == "UD-S211B"


def test_payload_and_metadata_members_are_distinguished():
    archive = pak.read(pak_path("UD-S211B.pak"))
    assert [m.name for m in archive.payloads][-1] == "AD3A104D.mot"
    assert not archive.member("EcuDataMap").is_payload


def test_member_stem_strips_the_extension():
    archive = pak.read(pak_path("22765AJ13F.pak"))
    assert archive.members[0].stem == "EB4I350A_r"


def test_header_blob_is_carried_but_still_encrypted():
    archive = pak.read(pak_path("22765AJ13F.pak"))
    assert len(archive.header_blob) == 816
    assert len(archive.header_blob) % 8 == 0          # RC2 block aligned
    printable = sum(32 <= c < 127 for c in archive.header_blob)
    assert printable < len(archive.header_blob) * 0.6


def test_rejects_a_file_that_is_not_a_pak():
    with pytest.raises(pak.PakError, match="not a PAK"):
        pak.read(b"not a pak file at all")


def test_reports_a_truncated_archive():
    with open(pak_path("22765AJ13F.pak"), "rb") as fh:
        data = fh.read(0x10000)
    with pytest.raises(pak.PakError, match="past end of file"):
        pak.read(data)


def test_reports_a_bad_object_tag():
    with open(pak_path("22765AJ13F.pak"), "rb") as fh:
        data = bytearray(fh.read())
    csv_len = struct.unpack_from("<H", data, 4)[0]
    struct.pack_into("<H", data, 6 + csv_len + 2, 0x1234)   # first class tag
    with pytest.raises(pak.PakError, match="unexpected object tag"):
        pak.read(bytes(data))


def test_accepts_raw_bytes_without_a_path():
    with open(pak_path("22765AJ13F.pak"), "rb") as fh:
        archive = pak.read(fh.read())
    assert archive.path is None
    assert archive.pack_number == ""
    assert len(archive.members) == 1
