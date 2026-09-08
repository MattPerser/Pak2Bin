"""The Denso swap cipher, checked against a direct transcription of the C."""

import random
import struct

from subaru_pak import swapcipher
from subaru_pak.keys import CRYPT_KEYS


def reference_transform(buf, key):
    """Line-by-line port of ``subaru_denso_calculate_32bit_payload``.

    Deliberately unoptimised: this is what the table-driven implementation is
    tested against, so it must not share any of its shortcuts.
    """
    it = swapcipher.INDEX_TRANSFORMATION
    out = bytearray()
    for i in range(0, len(buf) - 3, 4):
        d = struct.unpack_from(">I", buf, i)[0]
        for ki in range(4):
            word_to_generate_index = d & 0xFFFF
            word_to_be_encrypted = (d >> 16) & 0xFFFF
            index = (word_to_generate_index ^ key[ki]) & 0xFFFF
            index += index << 16
            encryption_key = 0
            for n in range(4):
                encryption_key += it[(index >> (n * 4)) & 0x1F] << (n * 4)
            encryption_key &= 0xFFFF
            encryption_key = ((encryption_key >> 3) + (encryption_key << 13)) & 0xFFFF
            d = ((encryption_key ^ word_to_be_encrypted)
                 + (word_to_generate_index << 16)) & 0xFFFFFFFF
        d = ((d >> 16) + (d << 16)) & 0xFFFFFFFF
        out += struct.pack(">I", d)
    return bytes(out)


def test_matches_reference_implementation_on_random_data():
    rng = random.Random(20240423)
    data = bytes(rng.randrange(256) for _ in range(4096))
    for name, key in CRYPT_KEYS:
        assert swapcipher.transform(data, key) == reference_transform(data, key), name


def test_reversed_key_undoes_the_transform():
    """[k0 k1 k2 k3] encrypts and [k3 k2 k1 k0] decrypts -- the C says so."""
    rng = random.Random(7)
    data = bytes(rng.randrange(256) for _ in range(512))
    for name, key in CRYPT_KEYS:
        once = swapcipher.transform(data, key)
        assert swapcipher.transform(once, tuple(reversed(key))) == data, name


def test_is_ecb_so_blocks_are_independent():
    key = CRYPT_KEYS[0][1]
    data = bytes(range(64))
    whole = swapcipher.transform(data, key)
    piecewise = b"".join(swapcipher.transform(data[i:i + 4], key)
                         for i in range(0, 64, 4))
    assert whole == piecewise


def test_accepts_hex_string_key_words():
    key = CRYPT_KEYS[0][1]
    as_hex = tuple(f"0x{word:04X}" for word in key)
    data = b"\x01\x02\x03\x04" * 4
    assert swapcipher.transform(data, as_hex) == swapcipher.transform(data, key)


def test_partial_trailing_block_reuses_the_previous_bytes():
    """crypt.exe never cleared its 4-byte read buffer; the tail inherits it.

    Real cal regions are always a multiple of 16 bytes, so this path exists for
    fidelity rather than because a test vector reaches it.
    """
    key = CRYPT_KEYS[0][1]
    data = bytes(range(10))                       # 2 full blocks + 2 bytes
    got = swapcipher.transform(data, key)
    stale = data[4:8]
    expected_tail = swapcipher.transform(data[8:] + stale[2:], key)[:2]
    assert len(got) == len(data)
    assert got[:8] == swapcipher.transform(data[:8], key)
    assert got[8:] == expected_tail


def test_short_input_without_a_previous_block():
    key = CRYPT_KEYS[0][1]
    got = swapcipher.transform(b"\xAB\xCD", key)
    assert len(got) == 2
    assert got == swapcipher.transform(b"\xAB\xCD\x00\x00", key)[:2]


def test_index_transformation_is_nibbles():
    assert len(swapcipher.INDEX_TRANSFORMATION) == 32
    assert all(0 <= value <= 0xF for value in swapcipher.INDEX_TRANSFORMATION)
