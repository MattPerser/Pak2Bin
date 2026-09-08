"""RC2 (Ron's Code 2, RFC 2268) in pure Python, Windows CryptoAPI compatible.

Subaru's FlashWrite ``.pak`` payloads are encrypted the way the original
``rc2decode.exe`` decrypted them: the key string is MD5-hashed and handed to
``CryptDeriveKey(CALG_RC2)`` on the *Microsoft Base Cryptographic Provider*,
which yields a 40-bit key.  That provider pads the 5 key bytes with 11 zero
salt bytes (``CRYPT_CREATE_SALT`` unset => zero salt), keys RC2 with all 16
bytes at an effective key length of 40 bits, and runs CBC with a zero IV and
PKCS#5 padding.  :func:`derive_key` reproduces that derivation so no Windows
crypto handles -- and no bundled ``.exe`` -- are needed.

The 40-bit effective length is not a guess: at 128 the same key produces noise,
at 40 it produces the S-records the ECU flash images are made of.  RFC 2268's
eight published test vectors are checked in ``tests/test_rc2.py``.
"""

from __future__ import annotations

import hashlib
import struct

__all__ = ["derive_key", "decrypt_cbc", "decrypt_pak_blob", "key_schedule"]

# RFC 2268 "PITABLE" -- a fixed permutation of 0..255 built from the digits of pi.
PITABLE = bytes.fromhex("""
    d9 78 f9 c4 19 dd b5 ed 28 e9 fd 79 4a a0 d8 9d
    c6 7e 37 83 2b 76 53 8e 62 4c 64 88 44 8b fb a2
    17 9a 59 f5 87 b3 4f 13 61 45 6d 8d 09 81 7d 32
    bd 8f 40 eb 86 b7 7b 0b f0 95 21 22 5c 6b 4e 82
    54 d6 65 93 ce 60 b2 1c 73 56 c0 14 a7 8c f1 dc
    12 75 ca 1f 3b be e4 d1 42 3d d4 30 a3 3c b6 26
    6f bf 0e da 46 69 07 57 27 f2 1d 9b bc 94 43 03
    f8 11 c7 f6 90 ef 3e e7 06 c3 d5 2f c8 66 1e d7
    08 e8 ea de 80 52 ee f7 84 aa 72 ac 35 4d 6a 2a
    96 1a d2 71 5a 15 49 74 4b 9f d0 5e 04 18 a4 ec
    c2 e0 41 6e 0f 51 cb cc 24 91 af 50 a1 f4 70 39
    99 7c 3a 85 23 b8 b4 7a fc 02 36 5b 25 55 97 31
    2d 5d fa 98 e3 8a 92 ae 05 df 29 10 67 6c ba c9
    d3 00 e6 cf e1 9e a8 2c 63 16 01 3f 58 e2 89 a9
    0d 38 34 1b ab 33 ff b0 bb 48 0c 5f b9 b1 cd 2e
    c5 f3 db 47 e5 a5 9c 77 0a a6 20 68 fe 7f c1 ad
""")
assert len(PITABLE) == 256 and len(set(PITABLE)) == 256, "PITABLE is not a permutation"

_ZERO_IV = b"\x00" * 8


def key_schedule(key: bytes, effective_bits: int = 40) -> list[int]:
    """Expand ``key`` into the 64 sixteen-bit round-key words of RFC 2268."""
    t = len(key)
    if not 1 <= t <= 128:
        raise ValueError("RC2 key must be 1..128 bytes")
    t8 = (effective_bits + 7) // 8
    tm = 255 % (1 << (8 + effective_bits - 8 * t8))

    buf = bytearray(128)
    buf[:t] = key
    for i in range(t, 128):
        buf[i] = PITABLE[(buf[i - 1] + buf[i - t]) & 0xFF]
    buf[128 - t8] = PITABLE[buf[128 - t8] & tm]
    for i in range(127 - t8, -1, -1):
        buf[i] = PITABLE[buf[i + 1] ^ buf[i + t8]]
    return [buf[2 * i] | (buf[2 * i + 1] << 8) for i in range(64)]


def derive_key(password: str | bytes) -> bytes:
    """CryptoAPI ``CryptDeriveKey(MD5(password), CALG_RC2)`` on the base provider.

    40 bits of key material from the head of the MD5 digest, zero-salted out to
    the 16 bytes RC2 is actually keyed with.
    """
    if isinstance(password, str):
        password = password.encode("ascii")
    return hashlib.md5(password).digest()[:5] + b"\x00" * 11


def _decrypt_block(k: list[int], r0: int, r1: int, r2: int, r3: int):
    """One 64-bit RC2 block: 5 r-mix, r-mash, 6 r-mix, r-mash, 5 r-mix."""
    j = 63
    for _ in range(5):
        r3 = ((r3 >> 5) | (r3 << 11)) & 0xFFFF
        r3 = (r3 - k[j] - (r2 & r1) - (~r2 & r0)) & 0xFFFF
        r2 = ((r2 >> 3) | (r2 << 13)) & 0xFFFF
        r2 = (r2 - k[j - 1] - (r1 & r0) - (~r1 & r3)) & 0xFFFF
        r1 = ((r1 >> 2) | (r1 << 14)) & 0xFFFF
        r1 = (r1 - k[j - 2] - (r0 & r3) - (~r0 & r2)) & 0xFFFF
        r0 = ((r0 >> 1) | (r0 << 15)) & 0xFFFF
        r0 = (r0 - k[j - 3] - (r3 & r2) - (~r3 & r1)) & 0xFFFF
        j -= 4
    r3 = (r3 - k[r2 & 63]) & 0xFFFF
    r2 = (r2 - k[r1 & 63]) & 0xFFFF
    r1 = (r1 - k[r0 & 63]) & 0xFFFF
    r0 = (r0 - k[r3 & 63]) & 0xFFFF
    for _ in range(6):
        r3 = ((r3 >> 5) | (r3 << 11)) & 0xFFFF
        r3 = (r3 - k[j] - (r2 & r1) - (~r2 & r0)) & 0xFFFF
        r2 = ((r2 >> 3) | (r2 << 13)) & 0xFFFF
        r2 = (r2 - k[j - 1] - (r1 & r0) - (~r1 & r3)) & 0xFFFF
        r1 = ((r1 >> 2) | (r1 << 14)) & 0xFFFF
        r1 = (r1 - k[j - 2] - (r0 & r3) - (~r0 & r2)) & 0xFFFF
        r0 = ((r0 >> 1) | (r0 << 15)) & 0xFFFF
        r0 = (r0 - k[j - 3] - (r3 & r2) - (~r3 & r1)) & 0xFFFF
        j -= 4
    r3 = (r3 - k[r2 & 63]) & 0xFFFF
    r2 = (r2 - k[r1 & 63]) & 0xFFFF
    r1 = (r1 - k[r0 & 63]) & 0xFFFF
    r0 = (r0 - k[r3 & 63]) & 0xFFFF
    for _ in range(5):
        r3 = ((r3 >> 5) | (r3 << 11)) & 0xFFFF
        r3 = (r3 - k[j] - (r2 & r1) - (~r2 & r0)) & 0xFFFF
        r2 = ((r2 >> 3) | (r2 << 13)) & 0xFFFF
        r2 = (r2 - k[j - 1] - (r1 & r0) - (~r1 & r3)) & 0xFFFF
        r1 = ((r1 >> 2) | (r1 << 14)) & 0xFFFF
        r1 = (r1 - k[j - 2] - (r0 & r3) - (~r0 & r2)) & 0xFFFF
        r0 = ((r0 >> 1) | (r0 << 15)) & 0xFFFF
        r0 = (r0 - k[j - 3] - (r3 & r2) - (~r3 & r1)) & 0xFFFF
        j -= 4
    return r0, r1, r2, r3


def _decrypt_cbc_python(data: bytes, key: bytes, iv: bytes,
                        effective_bits: int) -> bytes:
    """The reference implementation: portable, dependency-free, ~1 MB/s."""
    k = key_schedule(key, effective_bits)
    out = bytearray(len(data))
    p0, p1, p2, p3 = struct.unpack("<4H", iv)
    pack_into = struct.pack_into
    dec = _decrypt_block
    off = 0
    for c0, c1, c2, c3 in struct.iter_unpack("<4H", data):
        r0, r1, r2, r3 = dec(k, c0, c1, c2, c3)
        pack_into("<4H", out, off, r0 ^ p0, r1 ^ p1, r2 ^ p2, r3 ^ p3)
        p0, p1, p2, p3 = c0, c1, c2, c3
        off += 8
    return bytes(out)


def _find_accelerator():
    """Use pycryptodome's C implementation, but only once it has proved itself.

    A wrong ROM is worse than a slow one, so the candidate must reproduce the
    pure-Python result byte for byte -- in exactly the configuration this
    library uses, across enough blocks to exercise CBC chaining -- before it is
    trusted.  Absent or disagreeing, the pure path stands.
    """
    try:
        from Crypto.Cipher import ARC2
    except ImportError:
        return None

    def accelerated(data, key, iv, effective_bits):
        return ARC2.new(key, ARC2.MODE_CBC, iv=iv,
                        effective_keylen=effective_bits).decrypt(data)

    probe_key = derive_key("self-check")
    probe_data = bytes((i * 37 + 11) & 0xFF for i in range(64))
    try:
        for bits in (40, 128):
            if (accelerated(probe_data, probe_key, _ZERO_IV, bits)
                    != _decrypt_cbc_python(probe_data, probe_key, _ZERO_IV, bits)):
                return None
    except Exception:                               # pragma: no cover - defensive
        return None
    return accelerated


_ACCELERATOR = _find_accelerator()

#: True when the verified C backend is in use; the result is identical either way.
ACCELERATED = _ACCELERATOR is not None

#: RC2 allows keys from one byte up, but pycryptodome refuses anything under
#: 40 bits.  Whether the backend is installed must not change what this library
#: accepts, so short keys always take the pure path.  (Pak keys are 16 bytes.)
_MIN_ACCELERATED_KEY = 5


def decrypt_cbc(data: bytes, key: bytes, iv: bytes = _ZERO_IV,
                effective_bits: int = 40) -> bytes:
    """RC2-CBC decrypt ``data`` (a whole number of 8-byte blocks). No unpadding."""
    if len(data) % 8:
        raise ValueError(f"ciphertext length {len(data)} is not a multiple of 8")
    if _ACCELERATOR is not None and len(key) >= _MIN_ACCELERATED_KEY:
        return _ACCELERATOR(data, key, iv, effective_bits)
    return _decrypt_cbc_python(data, key, iv, effective_bits)


def strip_pkcs5(plain: bytes) -> bytes:
    """Remove PKCS#5 padding if it is well formed, else leave the data alone.

    CryptDecrypt would hard-fail on bad padding; a converter is more useful if a
    slightly odd tail still yields the S-records in front of it.
    """
    if not plain:
        return plain
    n = plain[-1]
    if 1 <= n <= 8 and len(plain) >= n and plain[-n:] == bytes([n]) * n:
        return plain[:-n]
    return plain


def decrypt_pak_blob(data: bytes, password: str | bytes) -> bytes:
    """Decrypt one PAK member (payload or in-pak header CSV) with a key string."""
    return strip_pkcs5(decrypt_cbc(data, derive_key(password)))
