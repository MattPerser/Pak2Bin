"""Denso/Subaru 32-bit "swap" cipher.

The algorithm and its ``index_transformation`` constants originate in FastECU by
Miika Syvänen (https://github.com/miikasyvanen/fastecu). This is an independent
table-driven Python reimplementation of that algorithm; credit for the reverse
engineering is theirs.


A four-round Feistel-ish network over 32-bit big-endian blocks in ECB mode,
keyed by four 16-bit words.  Encryption and decryption are the *same* routine;
the decrypt key is the encrypt key reversed.  The key tuples in :mod:`keys` are
already stored in the order that decrypts, so pass them through unchanged.

Each round derives a 16-bit ``encryption_key`` from the low half of the block
alone, so the whole round function collapses into one 65536-entry lookup table
(:func:`_ektab`) -- roughly 20x faster than evaluating the nibble
transformation per block, which matters when autodetecting across 13 keys.
"""

from __future__ import annotations

import struct

__all__ = ["INDEX_TRANSFORMATION", "transform", "decrypt", "encrypt"]

# 32 nibbles indexed by 5 bits of the (doubled) round index -- from crypt_utils.cpp.
INDEX_TRANSFORMATION = (
    0x5, 0x6, 0x7, 0x1, 0x9, 0xC, 0xD, 0x8,
    0xA, 0xD, 0x2, 0xB, 0xF, 0x4, 0x0, 0x3,
    0xB, 0x4, 0x6, 0x0, 0xF, 0x2, 0xD, 0x9,
    0x5, 0xC, 0x1, 0xA, 0x3, 0xD, 0xE, 0x8,
)

_EKTAB: list[int] | None = None


def _ektab() -> list[int]:
    """``index -> encryption_key`` for all 65536 indices; built once, ~50 ms."""
    global _EKTAB
    if _EKTAB is None:
        it = INDEX_TRANSFORMATION
        tab = [0] * 65536
        for idx in range(65536):
            # The C code does `index += index << 16` so that the n=3 lookup can
            # borrow bit 16 -- which is bit 0 of the 16-bit index.
            i32 = idx | (idx << 16)
            ek = (it[i32 & 0x1F]
                  + (it[(i32 >> 4) & 0x1F] << 4)
                  + (it[(i32 >> 8) & 0x1F] << 8)
                  + (it[(i32 >> 12) & 0x1F] << 12)) & 0xFFFF
            tab[idx] = ((ek >> 3) | (ek << 13)) & 0xFFFF   # 16-bit rotate right 3
        _EKTAB = tab
    return _EKTAB


def transform(data: bytes, key) -> bytes:
    """Run the cipher over ``data`` with the four 16-bit words ``key``.

    ``crypt.exe`` streamed the file in 4-byte reads without clearing its buffer,
    so a length that is not a multiple of 4 leaves the previous block's bytes in
    the tail positions.  That quirk is reproduced here; only ``len(data)`` bytes
    come back either way.  (In practice S-record coverage is always a multiple
    of 16, so the partial-block path is exercised only by its unit test.)
    """
    k0, k1, k2, k3 = (int(k, 16) if isinstance(k, str) else int(k) for k in key)
    tab = _ektab()
    n = len(data)
    full = n & ~3
    rem = n - full

    words = struct.unpack(f">{full // 4}I", data[:full]) if full else ()
    out = []
    append = out.append
    for d in words:
        g = d & 0xFFFF
        d = (tab[g ^ k0] ^ (d >> 16)) | (g << 16)
        g = d & 0xFFFF
        d = (tab[g ^ k1] ^ (d >> 16)) | (g << 16)
        g = d & 0xFFFF
        d = (tab[g ^ k2] ^ (d >> 16)) | (g << 16)
        g = d & 0xFFFF
        d = (tab[g ^ k3] ^ (d >> 16)) | (g << 16)
        append((d >> 16) | ((d & 0xFFFF) << 16))
    result = struct.pack(f">{len(out)}I", *out) if out else b""

    if rem:
        stale = data[full - 4:full] if full >= 4 else b"\x00\x00\x00\x00"
        tail = transform(data[full:] + stale[rem:], (k0, k1, k2, k3))
        result += tail[:rem]
    return result


# The cipher is an involution only in the sense that running it with the
# reversed key undoes it; both directions call the same code.
decrypt = transform
encrypt = transform
