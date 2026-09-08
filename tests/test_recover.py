"""Key recovery: the algebra is exact, the plumbing finds and cancels.

All run single-process (``pool=False``) over small spaces, so they are fast and
free of spawn flakiness. The full-space multi-core path is the same code with a
process pool; :func:`test_pool_path_finds_a_synthetic_key` smoke-tests that.
"""

import hashlib

import pytest

from conftest import pak_path, requires_test_data
from subaru_pak import pak, rc2, srec, swapcipher, recover
from subaru_pak.keys import CRYPT_KEYS, default_database

pytestmark = requires_test_data


@pytest.fixture(scope="module")
def engine_member():
    m = pak.read(pak_path("22765AJ13F.pak")).member("EB4I350A_r.sob")
    return bytes(m.data)


@pytest.fixture(scope="module")
def engine_cal(engine_member):
    """The swap-encrypted cal region (what recovery is handed)."""
    return bytes(srec.parse(rc2.decrypt_pak_blob(engine_member, "88295D8A")).data)


# -- RC2 keyword ------------------------------------------------------------

def test_rc2_known_keyword_is_instant(engine_member):
    kws = [r.key for r in default_database().rows if r.key]
    result = recover.recover_rc2_key(engine_member, keywords=kws, pool=False)
    assert result.found and result.key == "88295D8A"
    assert result.stage == "known"


def test_rc2_brute_worker_finds_the_true_key(engine_member):
    """The raw worker over a window straddling the real keyword index."""
    k = int("88295D8A", 16)
    assert recover._rc2_scan(engine_member, k - 2000, k + 2000) == k
    assert recover._rc2_scan(engine_member, k + 1, k + 2000) is None


def test_rc2_recognises_only_real_srec_headers():
    assert recover._looks_like_srec(b"S1130000AB")
    assert recover._looks_like_srec(b"S00600004")
    assert not recover._looks_like_srec(b"XX130000AB")
    assert not recover._looks_like_srec(b"S1ZZZZZZ")     # non-hex after the type
    assert not recover._looks_like_srec(b"S1")


def test_rc2_brute_confirms_a_synthetic_low_index_key(engine_member):
    """Full orchestrator (single-process) recovers a re-encrypted member."""
    from Crypto.Cipher import ARC2
    plain = rc2.decrypt_pak_blob(engine_member, "88295D8A")[:0x2000]
    target = "00000041"                                  # index 65
    key = hashlib.md5(target.encode()).digest()[:5] + b"\x00" * 11
    synthetic = ARC2.new(key, ARC2.MODE_CBC, iv=b"\x00" * 8,
                         effective_keylen=40).encrypt(plain)
    result = recover.recover_rc2_key(synthetic, keywords=[], space=4096,
                                     chunks=512, pool=False)
    assert result.found and result.key == target and result.stage == "brute"


def test_rc2_reports_exhaustion_when_no_key_exists():
    result = recover.recover_rc2_key(b"\x11" * 32, keywords=[], space=4096,
                                     chunks=512, pool=False)
    assert not result.found and result.exhausted


def test_rc2_stop_flag_cancels():
    stop_after = {"n": 0}

    def stop():
        stop_after["n"] += 1
        return stop_after["n"] > 1
    result = recover.recover_rc2_key(b"\x11" * 32, keywords=[], space=1 << 20,
                                     chunks=4096, pool=False, stop=stop)
    assert result.cancelled and not result.found


# -- swap cipher ------------------------------------------------------------

def test_swap_worker_recovers_engine_key_via_calid(engine_cal):
    gen, positions, values = recover._swap_anchors(engine_cal, "EB4I350A")
    k = dict(CRYPT_KEYS)["denso_can"]
    packed = k[0] | (k[3] << 16)
    assert recover._swap_scan(gen, positions, values,
                              packed - 1000, packed + 1000) == k


def test_swap_worker_recovers_module_key_via_padding():
    m = pak.read(pak_path("82201AL30D.pak")).member("DF105742_SKE_REPchg2.mot")
    cal = bytes(srec.parse(rc2.decrypt_pak_blob(m.data, "A9A12BB1")).data)
    gen, positions, values = recover._swap_anchors(cal, "")   # module: no CALID
    assert positions == ()                                     # uses 0xFF + enc(0)
    k = dict(CRYPT_KEYS)["module_biu_82201"]
    packed = k[0] | (k[3] << 16)
    assert recover._swap_scan(gen, positions, values,
                              packed - 1000, packed + 1000) == k


def test_swap_R_matches_the_cipher(engine_cal):
    """The search's block primitive must equal swapcipher on one block."""
    T = swapcipher._ektab()
    k = dict(CRYPT_KEYS)["denso_can"]
    import struct
    c_hi, c_lo = struct.unpack(">HH", engine_cal[:4])
    got = recover._swap_R(c_hi, c_lo, k, T)
    want = struct.unpack(">HH", swapcipher.transform(engine_cal[:4], k))
    assert got == want


def test_swap_recovers_a_synthetic_low_index_key(engine_cal):
    plain = swapcipher.transform(engine_cal, dict(CRYPT_KEYS)["denso_can"])
    assert plain[:8] == b"EB4I350A"
    fake = (0x0003, 0xABCD, 0x1234, 0x0001)              # packed = 65539
    enc = swapcipher.transform(plain, tuple(reversed(fake)))
    result = recover.recover_swap_key(enc, "EB4I350A", space=1 << 17,
                                      chunks=1 << 14, pool=False)
    assert result.found and result.key == fake


def test_swap_without_known_plaintext_gives_up():
    result = recover.recover_swap_key(b"\x00" * 4, "", pool=False)
    assert not result.found


# -- the real pool path (one smoke test) ------------------------------------

def test_pool_path_finds_a_synthetic_key(engine_member):
    """Exercise the actual ProcessPoolExecutor path once, on a tiny space."""
    from Crypto.Cipher import ARC2
    # Enough S-records that the full-member confirmation is satisfied.
    plain = rc2.decrypt_pak_blob(engine_member, "88295D8A")[:0x4000]
    target = "00000021"
    key = hashlib.md5(target.encode()).digest()[:5] + b"\x00" * 11
    synthetic = ARC2.new(key, ARC2.MODE_CBC, iv=b"\x00" * 8,
                         effective_keylen=40).encrypt(plain)
    result = recover.recover_rc2_key(synthetic, keywords=[], space=1 << 16,
                                     chunks=4096, workers=2, pool=True)
    assert result.found and result.key == target


# -- spurious keys must be rejected, not returned -----------------------------

def test_swap_plausible_rejects_a_real_spurious_collision(engine_cal):
    """The confirm must reject a key that fakes the CALID but garbles the rest.

    ``0xD180 0xAC61 0x5B21 0x0830`` is a real collision found in-space for the
    key below: it reproduces ``EB4I350A`` at offset 0 but nothing else.
    """
    plain = swapcipher.transform(engine_cal, dict(CRYPT_KEYS)["denso_can"])
    unknown = (0xD180, 0xACE1, 0x5B27, 0x08F0)
    spurious = (0xD180, 0xAC61, 0x5B21, 0x0830)
    enc = swapcipher.transform(plain, tuple(reversed(unknown)))

    spurious_plain = swapcipher.transform(enc, spurious)
    assert spurious_plain[:8] == b"EB4I350A"                 # it fools the CALID
    assert not recover._swap_plausible(spurious_plain, "EB4I350A")   # but not this
    assert recover._swap_plausible(swapcipher.transform(enc, unknown), "EB4I350A")


def test_swap_resume_finds_the_true_key_past_a_spurious_one(engine_cal):
    """End to end over a window holding both the spurious and the true key."""
    plain = swapcipher.transform(engine_cal, dict(CRYPT_KEYS)["denso_can"])
    unknown = (0xD180, 0xACE1, 0x5B27, 0x08F0)
    enc = swapcipher.transform(plain, tuple(reversed(unknown)))
    true_packed = unknown[0] | (unknown[3] << 16)            # 150,000,000
    # Search just past the true key; the pool covers the earlier spurious hit.
    result = recover.recover_swap_key(enc, "EB4I350A",
                                      space=true_packed + 50_000, pool=True)
    assert result.found and result.key == unknown
    assert swapcipher.transform(enc, result.key) == plain


def test_structure_fraction_separates_real_from_random(engine_cal):
    real = swapcipher.transform(engine_cal, dict(CRYPT_KEYS)["denso_can"])
    assert recover._structure_fraction(real) > 0.2       # ROM: lots of 00/FF
    import os
    assert recover._structure_fraction(os.urandom(4096)) < 0.02   # random: ~0.8%


def test_rc2_confirm_needs_many_records(engine_member):
    """One fluke record is not a decrypt; a real key yields thousands."""
    assert recover._confirm_rc2(engine_member, "88295D8A")
    assert not recover._confirm_rc2(engine_member, "00000000")   # wrong key


# -- module brute recovery (Finding 4): filename CID must not misroute ---------

def test_module_swap_brute_is_refused_not_guessed():
    """Module swap-brute is under-constrained (ECB erased flash), so the
    orchestrator must decline rather than return a plausible wrong key."""
    m = pak.read(pak_path("82201AL30D.pak")).member("DF105742_SKE_REPchg2.mot")
    cal = bytes(srec.parse(rc2.decrypt_pak_blob(m.data, "A9A12BB1")).data)
    result = recover.recover_swap_key(cal, "DF105742_SKE_REPchg2", pool=False)
    assert not result.found
    assert "module" in result.extra.get("reason", "")


def test_swap_anchors_module_beats_calidish_filename():
    """The old len(cid)>=8 test would have mis-picked the CALID branch here."""
    m = pak.read(pak_path("82201AL30D.pak")).member("DF105742_SKE_REPchg2.mot")
    cal = bytes(srec.parse(rc2.decrypt_pak_blob(m.data, "A9A12BB1")).data)
    gen, positions, values = recover._swap_anchors(cal, "DF105742_SKE_REPchg2")
    assert positions == ()                     # module branch, despite long CID
    assert (gen.p_hi, gen.p_lo) == (0xFFFF, 0xFFFF)
