"""RC2 correctness: RFC 2268's own vectors, then the CryptoAPI derivation."""

import hashlib
import sys

import pytest

from conftest import pak_path, requires_test_data
from subaru_pak import rc2

# RFC 2268 section 5, as (key, effective bits, plaintext, ciphertext).
RFC_VECTORS = [
    ("0000000000000000", 63, "0000000000000000", "ebb773f993278eff"),
    ("ffffffffffffffff", 64, "ffffffffffffffff", "278b27e42e2f0d49"),
    ("3000000000000000", 64, "1000000000000001", "30649edf9be7d2c2"),
    ("88", 64, "0000000000000000", "61a8a244adacccf0"),
    ("88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f"),
    ("88bca90e90875a7f0f79c384627bafb2", 64, "0000000000000000", "1a807d272bbe5db1"),
    ("88bca90e90875a7f0f79c384627bafb2", 128, "0000000000000000", "2269552ab0f85ca6"),
    ("88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e",
     129, "0000000000000000", "5b78d3a43dfff1f1"),
]


# Both backends must satisfy the RFC, not just whichever one is active here.
BACKENDS = [("python", rc2._decrypt_cbc_python)]
if rc2.ACCELERATED:
    BACKENDS.append(("accelerated", rc2._ACCELERATOR))


@pytest.mark.parametrize("backend", [b for _, b in BACKENDS],
                         ids=[name for name, _ in BACKENDS])
@pytest.mark.parametrize("key,effective,plain,cipher", RFC_VECTORS)
def test_rfc2268_vectors(backend, key, effective, plain, cipher):
    """A single block with a zero IV is ECB, which is what the RFC tabulates."""
    if backend is not rc2._decrypt_cbc_python and len(key) // 2 < rc2._MIN_ACCELERATED_KEY:
        pytest.skip("pycryptodome refuses keys under 40 bits; the pure path takes them")
    got = backend(bytes.fromhex(cipher), bytes.fromhex(key), b"\x00" * 8, effective)
    assert got.hex() == plain


@pytest.mark.parametrize("key,effective,plain,cipher", RFC_VECTORS)
def test_public_api_takes_every_vector_on_any_backend(key, effective, plain, cipher):
    """Installing the C backend must not change what the library accepts.

    RFC 2268 includes a one-byte key; pycryptodome rejects it, so ``decrypt_cbc``
    has to route short keys to the pure implementation rather than raise.
    """
    got = rc2.decrypt_cbc(bytes.fromhex(cipher), bytes.fromhex(key),
                          effective_bits=effective)
    assert got.hex() == plain


@pytest.mark.skipif(not rc2.ACCELERATED, reason="pycryptodome not installed")
@requires_test_data
def test_accelerator_agrees_with_pure_python_on_real_data():
    from subaru_pak import pak
    archive = pak.read(pak_path("22765AJ13F.pak"))
    blob = archive.member("EB4I350A_r.sob").data[:0x8000]
    key = rc2.derive_key("88295D8A")
    assert (rc2._ACCELERATOR(blob, key, b"\x00" * 8, 40)
            == rc2._decrypt_cbc_python(blob, key, b"\x00" * 8, 40))


def test_a_disagreeing_accelerator_is_refused(monkeypatch):
    """The self-check is what makes the fast path safe -- prove it rejects."""
    class Wrong:
        MODE_CBC = 2

        @staticmethod
        def new(*args, **kwargs):
            return type("C", (), {"decrypt": staticmethod(lambda data: b"\x00" * len(data))})()

    module = type(sys)("Crypto.Cipher")
    module.ARC2 = Wrong
    monkeypatch.setitem(sys.modules, "Crypto.Cipher", module)
    monkeypatch.setitem(sys.modules, "Crypto", type(sys)("Crypto"))
    assert rc2._find_accelerator() is None


def test_pitable_is_a_permutation():
    assert len(rc2.PITABLE) == 256
    assert sorted(rc2.PITABLE) == list(range(256))


def test_derive_key_is_md5_prefix_zero_salted():
    key = rc2.derive_key("88295D8A")
    assert key == hashlib.md5(b"88295D8A").digest()[:5] + b"\x00" * 11
    assert len(key) == 16
    assert rc2.derive_key(b"88295D8A") == key


def test_decrypt_rejects_ragged_input():
    with pytest.raises(ValueError):
        rc2.decrypt_cbc(b"1234567", rc2.derive_key("x"))


def test_strip_pkcs5_only_strips_valid_padding():
    assert rc2.strip_pkcs5(b"abcdef\x02\x02") == b"abcdef"
    assert rc2.strip_pkcs5(b"abcdef\x01\x02") == b"abcdef\x01\x02"
    assert rc2.strip_pkcs5(b"") == b""


@requires_test_data
def test_decrypts_real_payload_to_srecords():
    """The oracle the whole port rests on: a real member becomes S-records."""
    from subaru_pak import pak
    archive = pak.read(pak_path("22765AJ13F.pak"))
    member = archive.member("EB4I350A_r.sob")
    plain = rc2.decrypt_pak_blob(member.data[:0x4000], "88295D8A")
    assert plain.startswith(b"S1130000")
    assert plain.count(b"\r\n") > 100
    assert all(32 <= c < 127 or c in (10, 13) for c in plain)


@requires_test_data
def test_effective_key_length_40_not_128():
    """At 128 bits the same key yields noise -- the 40 is load-bearing."""
    from subaru_pak import pak
    archive = pak.read(pak_path("22765AJ13F.pak"))
    head = archive.member("EB4I350A_r.sob").data[:0x800]
    key = rc2.derive_key("88295D8A")
    assert rc2.decrypt_cbc(head, key, effective_bits=40).startswith(b"S113")
    assert not rc2.decrypt_cbc(head, key, effective_bits=128).startswith(b"S113")
