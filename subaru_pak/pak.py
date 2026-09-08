"""Reader for the MFC ``CArchive`` container used by FlashWrite ``.pak`` files.

Layout::

    u32   0x00000101                  magic
    u16   len                         length of the (encrypted) header CSV
    bytes header CSV
    u16   n                           number of serialized objects
    ...   objects, each preceded by an MFC class tag:
            0xFFFF  new class: u16 schema, varlen name  -- then the object body
            0x8000|i  an object of a class already seen -- then the object body
    object body:
            u8    len, name bytes
            u32   0x00000001
            varlen data length (u16, or 0xFFFF followed by u32)
            bytes data

Every member is RC2 encrypted (see :mod:`subaru_pak.rc2`).  The payloads and the
``EcuDataMap``/``PcVerData`` metadata blobs use the pack's key from the pack
database; the leading header CSV uses a fixed key that is not published -- see
:mod:`subaru_pak.metadata`.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

__all__ = ["PakError", "PakMember", "PakArchive", "read"]

MAGIC = 0x00000101

#: Members that are container bookkeeping rather than flashable images.
NON_PAYLOAD = frozenset({"EcuDataMap", "PcVerData"})


class PakError(Exception):
    """Raised when a file is not a PAK, or its structure does not add up."""


@dataclass
class PakMember:
    """One serialized file inside the archive."""

    name: str
    offset: int
    length: int
    class_name: str
    data: bytes = field(repr=False)

    @property
    def stem(self) -> str:
        return os.path.splitext(self.name)[0]

    @property
    def is_payload(self) -> bool:
        return self.name not in NON_PAYLOAD


@dataclass
class PakArchive:
    path: str | None
    header_blob: bytes = field(repr=False)
    members: list[PakMember]
    object_count: int

    @property
    def pack_number(self) -> str:
        """Pack number as FlashWrite knows it -- the file name without ``.pak``."""
        return os.path.splitext(os.path.basename(self.path))[0] if self.path else ""

    @property
    def payloads(self) -> list[PakMember]:
        return [m for m in self.members if m.is_payload]

    def member(self, name: str) -> PakMember | None:
        return next((m for m in self.members if m.name == name), None)


def _varlen(buf: bytes, off: int) -> tuple[int, int]:
    (value,) = struct.unpack_from("<H", buf, off)
    off += 2
    if value == 0xFFFF:
        (value,) = struct.unpack_from("<I", buf, off)
        off += 4
    return value, off


def read(source, *, strict: bool = True) -> PakArchive:
    """Parse ``source`` (a path or raw bytes) into a :class:`PakArchive`."""
    if isinstance(source, (bytes, bytearray)):
        buf, path = bytes(source), None
    else:
        path = os.fspath(source)
        with open(path, "rb") as fh:
            buf = fh.read()

    if len(buf) < 8 or struct.unpack_from("<I", buf, 0)[0] != MAGIC:
        raise PakError(f"{path or '<bytes>'} is not a PAK/PK2 CArchive (bad magic)")

    off = 4
    csv_len, off = _varlen(buf, off)
    header_blob = buf[off:off + csv_len]
    if len(header_blob) != csv_len:
        raise PakError("truncated header CSV")
    off += csv_len
    (object_count,) = struct.unpack_from("<H", buf, off)
    off += 2

    members: list[PakMember] = []
    classes: list[str] = []
    try:
        while off + 2 <= len(buf):
            (tag,) = struct.unpack_from("<H", buf, off)
            off += 2
            if tag == 0xFFFF:                       # new class definition
                off += 2                            # schema word, always 0 here
                name_len, off = _varlen(buf, off)
                classes.append(buf[off:off + name_len].decode("latin1"))
                off += name_len
            elif tag & 0x8000:                      # object of a known class
                pass
            else:
                raise PakError(f"unexpected object tag 0x{tag:04X} at 0x{off - 2:X}")

            name_len = buf[off]
            off += 1
            name = buf[off:off + name_len].decode("latin1")
            off += name_len
            (marker,) = struct.unpack_from("<I", buf, off)
            off += 4
            if marker != 1:
                raise PakError(f"unexpected member marker 0x{marker:X} at 0x{off - 4:X}")
            length, off = _varlen(buf, off)
            if off + length > len(buf):
                raise PakError(f"member '{name}' runs past end of file")
            members.append(PakMember(name=name, offset=off, length=length,
                                     class_name=classes[-1] if classes else "",
                                     data=buf[off:off + length]))
            off += length
    except (struct.error, IndexError) as exc:
        raise PakError(f"malformed archive near 0x{off:X}: {exc}") from exc

    if strict and len(members) != object_count:
        raise PakError(f"archive declares {object_count} objects but {len(members)} were read")
    return PakArchive(path=path, header_blob=header_blob,
                      members=members, object_count=object_count)
