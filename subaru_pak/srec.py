"""Motorola S-record parsing -> flat bytes plus a coverage mask.

Subaru ROM payloads are S1 records for the first 64 KB and S2 records above it,
16 data bytes per line, CRLF terminated.  Anything the ECU does not program is
simply absent, which is why callers need the mask as well as the bytes.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["SRecord", "parse"]

_ADDR_LEN = {0x31: 4, 0x32: 6, 0x33: 8}   # b'1', b'2', b'3' -> address hex digits

# A sane ceiling: no Subaru flash image is anywhere near this, and it stops a
# corrupt record from asking for a multi-hundred-megabyte allocation.
MAX_IMAGE = 64 * 1024 * 1024


@dataclass
class SRecord:
    """Decoded S-record file, addressed absolutely from zero."""

    data: bytearray
    mask: bytearray
    end: int          # one past the highest address written
    start: int        # lowest address written
    count: int        # number of data records accepted

    def __bool__(self) -> bool:
        return self.end > 0


def _records(blob: bytes):
    """Yield ``(addr, data)`` for every well-formed S1/S2/S3 record."""
    for line in blob.splitlines():
        line = line.strip()
        if len(line) < 4 or line[0:1] != b"S":
            continue
        alen = _ADDR_LEN.get(line[1])
        if alen is None:
            continue
        try:
            count = int(line[2:4], 16)
            addr = int(line[4:4 + alen], 16)
            ndata = count - (alen // 2) - 1
            if ndata < 0:
                continue
            payload = bytes.fromhex(line[4 + alen:4 + alen + ndata * 2].decode("ascii"))
        except ValueError:
            continue
        if len(payload) != ndata:
            continue
        yield addr, payload


def parse(blob: bytes | str) -> SRecord:
    """Parse an S-record file into a flat image plus its coverage mask."""
    if isinstance(blob, str):
        blob = blob.encode("latin1")

    lo, hi, count = 1 << 62, 0, 0
    for addr, payload in _records(blob):
        lo = min(lo, addr)
        hi = max(hi, addr + len(payload))
        count += 1
    if count == 0:
        return SRecord(bytearray(), bytearray(), 0, 0, 0)
    if hi > MAX_IMAGE:
        raise ValueError(f"S-records span 0x{hi:X} bytes, past the {MAX_IMAGE:#x} ceiling")

    data = bytearray(hi)
    mask = bytearray(hi)
    one = b"\x01"
    for addr, payload in _records(blob):
        n = len(payload)
        data[addr:addr + n] = payload
        mask[addr:addr + n] = one * n
    return SRecord(data, mask, hi, lo, count)
