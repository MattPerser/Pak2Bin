"""Key recovery for paks with no known key -- brute force, done honestly.

Two independent searches, each over a 2**32 space that is small only because of
a quirk in the target:

* :func:`recover_rc2_key` -- the archive's RC2 keyword. Subaru's keywords are
  uniformly eight uppercase hex characters (16**8 == 2**32), and the plaintext
  is always Motorola S-record text, so a decrypt that begins ``S`` + digit + hex
  is the key. This opens a pak that is in no pack database.

* :func:`recover_swap_key` -- the ROM's Denso swap key, when it is none of the
  twelve known ones. The cipher's round function lets two of the four key words
  be solved algebraically once the other two are fixed, turning a 2**64 search
  into 2**32. Erased flash (0xFFFFFFFF), betrayed by ECB as the most common
  block, is the known plaintext.

Both stream progress to a callback and honour a stop flag, so a UI can show the
search and cancel it. Both use a process pool for real multi-core speed and fall
back to a single process if one cannot start.
"""

from __future__ import annotations

import collections
import hashlib
import multiprocessing as mp
import os
import struct
import time
from concurrent.futures import (FIRST_COMPLETED, BrokenExecutor,
                                 ProcessPoolExecutor, wait)
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence

from . import rc2, srec, swapcipher
from .keys import CRYPT_KEYS

__all__ = ["Progress", "RecoveryResult", "recover_rc2_key", "recover_swap_key",
           "recover_pak_keys", "HEX_KEYSPACE", "SWAP_KEYSPACE"]

HEX_KEYSPACE = 16 ** 8           # eight uppercase hex characters
SWAP_KEYSPACE = 1 << 32          # the (k0, k3) pairs the swap search enumerates

# Keys per work chunk. Sized so a chunk is ~1-2 s -- fine progress and a cancel
# that lands within a couple of seconds, without drowning in scheduling overhead.
_RC2_CHUNK = 1 << 18             # RC2 trial ~7 us  -> ~1.8 s / chunk
_SWAP_CHUNK = 1 << 21           # swap step ~0.4 us -> ~0.8 s / chunk

_HEX = b"0123456789ABCDEF"


@dataclass
class Progress:
    """A snapshot handed to the progress callback during a search."""

    tried: int
    total: int
    rate: float                  # keys per second
    elapsed: float
    stage: str                   # "known" | "brute"

    @property
    def fraction(self) -> float:
        return min(1.0, self.tried / self.total) if self.total else 1.0

    @property
    def eta(self) -> float:
        remaining = max(0, self.total - self.tried)
        return remaining / self.rate if self.rate > 0 else float("inf")


@dataclass
class RecoveryResult:
    """What a search found (or didn't)."""

    kind: str                            # "rc2" | "swap"
    found: bool
    key: str | tuple | None = None       # hex keyword, or four swap words
    tried: int = 0
    elapsed: float = 0.0
    stage: str = ""                      # how it was found: "known" | "brute"
    exhausted: bool = False              # searched the whole space, found nothing
    cancelled: bool = False
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# RC2 keyword search
# ---------------------------------------------------------------------------

def _looks_like_srec(plain: bytes) -> bool:
    """A decrypt that opens like an S-record file: ``S`` + type digit + hex."""
    if len(plain) < 8 or plain[0:1] != b"S" or plain[1] not in b"0123":
        return False
    return all(c in b"0123456789ABCDEFabcdef" for c in plain[2:8])


def _rc2_trial(ct: bytes, keyword: bytes) -> bool:
    key = hashlib.md5(keyword).digest()[:5] + b"\x00" * 11
    return _looks_like_srec(rc2.decrypt_cbc(ct[:16], key))


def keyword_str(index: int) -> str:
    """The eight-hex-char keyword numbered ``index`` in 0 .. 16**8 - 1."""
    return f"{index:08X}"


def _rc2_scan(ct: bytes, lo: int, hi: int) -> int | None:
    """Scan keyword indices [lo, hi); return the first that decrypts, or None."""
    hexb = _HEX
    md5 = hashlib.md5
    decrypt = rc2.decrypt_cbc
    head = ct[:16]
    for index in range(lo, hi):
        kw = bytes((hexb[(index >> 28) & 0xF], hexb[(index >> 24) & 0xF],
                    hexb[(index >> 20) & 0xF], hexb[(index >> 16) & 0xF],
                    hexb[(index >> 12) & 0xF], hexb[(index >> 8) & 0xF],
                    hexb[(index >> 4) & 0xF], hexb[index & 0xF]))
        key = md5(kw).digest()[:5] + b"\x00" * 11
        if _looks_like_srec(decrypt(head, key)):
            return index
    return None


#: A ROM member decrypts to thousands of S-records; a 16-byte prefilter hit that
#: is really a fluke yields at most a handful. This cleanly tells them apart.
_MIN_CONFIRM_RECORDS = 64


def _confirm_rc2(full_member: bytes, keyword: str) -> bool:
    """A hit on 16 bytes is cheap; make sure the whole member really decrypts.

    The prefilter matches ``S`` + digit + hex on two blocks, which a wrong key
    can satisfy by chance roughly once per 2**38 keys. A genuine key turns the
    *entire* member into S-records, so requiring many records rejects the fluke.
    """
    plain = rc2.decrypt_pak_blob(full_member, keyword)
    return srec.parse(plain).count >= _MIN_CONFIRM_RECORDS


def recover_rc2_key(member: bytes, *, keywords: Sequence[str] = (),
                    workers: int | None = None, space: int = HEX_KEYSPACE,
                    chunks: int | None = None,
                    progress: Callable[[Progress], None] | None = None,
                    stop: Callable[[], bool] | None = None,
                    pool: bool = True) -> RecoveryResult:
    """Recover the RC2 keyword that decrypts ``member``.

    ``keywords`` are tried first (instant) -- pass the distinct keywords already
    in the pack database, since packs reuse them. Then the ``space`` of eight-hex
    keywords is brute-forced. ``space`` and ``chunks`` exist mainly for tests.
    """
    start = time.perf_counter()
    stop = stop or (lambda: False)
    tried = 0

    # Stage 1: keywords we already know. A miss here still counts as effort.
    seen = set()
    for kw in keywords:
        if stop():
            return RecoveryResult("rc2", False, tried=tried,
                                  elapsed=time.perf_counter() - start,
                                  cancelled=True)
        kw = kw.strip().upper()
        if kw in seen:
            continue
        seen.add(kw)
        tried += 1
        if _rc2_trial(member, kw.encode()):
            return RecoveryResult("rc2", True, key=kw, tried=tried,
                                  elapsed=time.perf_counter() - start,
                                  stage="known")
    if progress:
        progress(Progress(tried, space, 0.0, time.perf_counter() - start, "known"))

    # Stage 2: brute force the whole eight-hex space.
    workers = workers or os.cpu_count() or 1
    chunk_keys = chunks or _RC2_CHUNK

    # ``offset`` keeps progress absolute across resumes so the bar never jumps
    # backward; ``searched`` accumulates keys tried across resumes.
    offset = [0]
    searched = [0]

    def report(done_keys: int):
        if progress:
            elapsed = time.perf_counter() - start
            total_done = offset[0] + done_keys
            rate = total_done / elapsed if elapsed > 0 else 0.0
            progress(Progress(tried + total_done, space, rate, elapsed, "brute"))

    # Resume past any prefilter fluke that fails the full-member confirmation.
    search_from = 0
    while search_from < space:
        offset[0] = search_from
        hit = _run_pool(_rc2_scan, (member,), space, chunk_keys, workers, report,
                        stop, pool, start=search_from)
        searched[0] += _last_done[0]
        elapsed = time.perf_counter() - start
        if hit is _CANCELLED:
            return RecoveryResult("rc2", False, tried=tried + searched[0],
                                  elapsed=elapsed, cancelled=True)
        if hit is None:
            break
        keyword = keyword_str(hit)
        if _confirm_rc2(member, keyword):
            return RecoveryResult("rc2", True, key=keyword,
                                  tried=tried + searched[0], elapsed=elapsed,
                                  stage="brute")
        search_from = hit + 1                    # the hit was a fluke; keep going
    return RecoveryResult("rc2", False, tried=tried + searched[0],
                          elapsed=time.perf_counter() - start, exhausted=True)


# ---------------------------------------------------------------------------
# swap-cipher key search
# ---------------------------------------------------------------------------

# A known pair is (C, P): applying the cipher's round primitive R to the cal
# block C with the true key yields the plaintext block P.  R(C, key) is exactly
# what swapcipher.transform does to one block (it decrypts), so R == _swap_R.
_Pair = collections.namedtuple("_Pair", "c_hi c_lo p_hi p_lo")


def _swap_anchors(cal: bytes, cid: str) -> tuple | None:
    """Known (cal, plaintext) pairs for the swap search.

    Returns ``(generator, positions, zero_values)``:

    * ``generator`` -- one ``_Pair`` used to solve k1, k2 from a fixed k0, k3.
      An engine cal begins with its CALID in ASCII (exact, certain plaintext);
      a module cal is mostly erased flash, so its most common block decrypts to
      ``0xFFFFFFFF``.
    * ``positions`` -- more ``_Pair`` filters at fixed offsets (the rest of the
      CALID), which pin the key uniquely with no guessing.
    * ``zero_values`` -- the set of cal block values, used only when there is no
      positional filter (modules): a true key's ``enc(0x00000000)`` must be one
      of them.
    """
    if len(cal) < 8:
        return None

    # Engine vs module is decided by the data, not the name: a module cal is
    # dominated by one block (erased 0xFFFFFFFF flash, ~70%), an engine cal is
    # dense program (its most common block is well under half). Deciding on the
    # CID string would misroute a module whose filename merely looks CALID-ish.
    counts = collections.Counter(cal[i:i + 4] for i in range(0, len(cal) - 3, 4))
    (modal, modal_count), = counts.most_common(1)
    modal_fraction = modal_count * 4 / len(cal)

    label = cid.encode("ascii", "ignore") if cid else b""
    usable = (len(label) // 4) * 4                # whole CALID blocks available
    if modal_fraction <= 0.40 and usable >= 4:   # engine: anchor on the CALID
        pairs = []
        for off in range(0, min(usable, 8), 4):  # one or two CALID blocks
            c_hi, c_lo = struct.unpack(">HH", cal[off:off + 4])
            p_hi, p_lo = struct.unpack(">HH", label[off:off + 4])
            pairs.append(_Pair(c_hi, c_lo, p_hi, p_lo))
        return pairs[0], tuple(pairs[1:]), frozenset()

    # Module / erased-flash: the modal block is enc(0xFFFFFFFF).
    c_hi, c_lo = struct.unpack(">HH", modal)
    generator = _Pair(c_hi, c_lo, 0xFFFF, 0xFFFF)
    zero_values = frozenset(struct.unpack(">I", b)[0] for b in counts)
    return generator, (), zero_values


#: A genuine ROM is full of 0x00/0xFF (padding, empty tables); a wrong-key
#: decrypt is near-random (~0.8%). Real conversions sit far above this; the
#: spurious keys seen in testing sit well below it.
_STRUCTURE_MIN = 0.06


def _structure_fraction(plain: bytes) -> float:
    """Fraction of bytes that are 0x00 or 0xFF -- how ROM-like a decrypt is."""
    if not plain:
        return 0.0
    return (plain.count(0) + plain.count(0xFF)) / len(plain)


def _swap_plausible(plain: bytes, cid: str) -> bool:
    """Is this decrypt a real ROM, not a key that merely faked the known blocks?"""
    if cid and cid.encode("ascii", "ignore") not in plain:
        return False
    return _structure_fraction(plain) >= _STRUCTURE_MIN


def _swap_R(c_hi: int, c_lo: int, key, T) -> tuple[int, int]:
    """The round primitive: R((c_hi, c_lo), key) -- one block through the cipher."""
    l1 = T[c_lo ^ key[0]] ^ c_hi
    l2 = T[l1 ^ key[1]] ^ c_lo
    l3 = T[l2 ^ key[2]] ^ l1
    l4 = T[l3 ^ key[3]] ^ l2
    return l4, l3


def _swap_scan(gen: tuple, positions: tuple, zero_values: frozenset,
               lo: int, hi: int) -> tuple | None:
    """Search (k0, k3) in [lo, hi); return the first key consistent with the data.

    From the generator pair (C -> P), each (k0, k3) fixes k1 and k2 up to the
    round table's inverse; survivors must satisfy every positional pair, or --
    lacking those -- have ``enc(0x00000000)`` occur in the image.
    """
    T = swapcipher._ektab()
    inv = _swap_inverse()
    gc_hi, gc_lo, gp_hi, gp_lo = gen
    for packed in range(lo, hi):
        k0 = packed & 0xFFFF
        k3 = packed >> 16
        l1 = T[gc_lo ^ k0] ^ gc_hi
        l2 = gp_hi ^ T[gp_lo ^ k3]
        for s in inv.get(l2 ^ gc_lo, ()):
            k1 = l1 ^ s
            for t in inv.get(gp_lo ^ l1, ()):
                k2 = l2 ^ t
                key = (k0, k1, k2, k3)
                if positions:
                    if all(_swap_R(p.c_hi, p.c_lo, key, T) == (p.p_hi, p.p_lo)
                           for p in positions):
                        return key
                else:
                    # enc(0) = R(0, reversed key); is that cal block present?
                    z = _swap_R(0, 0, (k3, k2, k1, k0), T)
                    if (z[0] << 16 | z[1]) in zero_values:
                        return key
    return None


_SWAP_INVERSE: dict[int, list[int]] | None = None


def _swap_inverse() -> dict[int, list[int]]:
    global _SWAP_INVERSE
    if _SWAP_INVERSE is None:
        inv: dict[int, list[int]] = {}
        for x, y in enumerate(swapcipher._ektab()):
            inv.setdefault(y, []).append(x)
        _SWAP_INVERSE = inv
    return _SWAP_INVERSE


def recover_swap_key(cal: bytes, cid: str = "", *, workers: int | None = None,
                     space: int = SWAP_KEYSPACE, chunks: int | None = None,
                     progress: Callable[[Progress], None] | None = None,
                     stop: Callable[[], bool] | None = None,
                     pool: bool = True) -> RecoveryResult:
    """Recover the swap-cipher key for an engine cal none of the known keys fit.

    Only engine ROMs are brute-forced: the CALID at the start of the cal is
    strong known-plaintext (two blocks) that both drives the search and confirms
    the result. Module cals lack a CALID and are dominated by erased flash, which
    does not constrain the key enough to verify a brute-force hit, so those are
    declined (``found=False`` with a reason) rather than guessed at.
    """
    start = time.perf_counter()
    stop = stop or (lambda: False)
    anchors = _swap_anchors(cal, cid)
    if anchors is None:
        return RecoveryResult("swap", False, elapsed=time.perf_counter() - start,
                              extra={"reason": "no usable known plaintext"})
    generator, positions, zero_values = anchors
    engine = (generator.p_hi, generator.p_lo) != (0xFFFF, 0xFFFF)
    if not engine:
        # Module cal: dominated by erased flash. In ECB, *any* key that maps the
        # modal block to 0xFFFFFFFF makes ~70% of the image 0xFF, so nothing
        # here distinguishes the real key from an impostor -- brute force would
        # return a plausible-looking wrong key. Refuse rather than mislead.
        # (A known module key is still found by detection; only brute is scoped
        # out. Recovering a genuinely new module key needs known plaintext
        # beyond erased flash -- outside what this tool does.)
        return RecoveryResult(
            "swap", False, elapsed=time.perf_counter() - start,
            extra={"reason": "cannot brute-force a module swap key from erased "
                             "flash alone (no CALID to anchor on)"})

    workers = workers or os.cpu_count() or 1
    chunk_keys = chunks or _SWAP_CHUNK

    offset = [0]
    searched = [0]

    def report(done: int):
        if progress:
            elapsed = time.perf_counter() - start
            total_done = offset[0] + done
            rate = total_done / elapsed if elapsed > 0 else 0.0
            progress(Progress(total_done, space, rate, elapsed, "brute"))

    # Resume past spurious keys: matching the CALID blocks (or enc(0)) does not
    # prove the key -- a wrong one reproduces those by construction while leaving
    # the rest random. The real key makes the whole cal look like a ROM.
    search_from = 0
    while search_from < space:
        offset[0] = search_from
        hit = _run_pool(_swap_scan, (generator, positions, zero_values),
                        space, chunk_keys, workers, report, stop, pool,
                        start=search_from)
        searched[0] += _last_done[0]
        elapsed = time.perf_counter() - start
        if hit is _CANCELLED:
            return RecoveryResult("swap", False, tried=searched[0],
                                  elapsed=elapsed, cancelled=True)
        if hit is None:
            break
        plain = swapcipher.transform(cal, hit)
        if _swap_plausible(plain, cid):
            return RecoveryResult("swap", True, key=hit, tried=searched[0],
                                  elapsed=elapsed, stage="brute",
                                  extra={"structure": _structure_fraction(plain)})
        search_from = (hit[0] | (hit[3] << 16)) + 1     # spurious; keep going
    return RecoveryResult("swap", False, tried=searched[0],
                          elapsed=time.perf_counter() - start, exhausted=True)


# ---------------------------------------------------------------------------
# the shared pool runner
# ---------------------------------------------------------------------------

_CANCELLED = object()
_last_done = [0]        # keys searched when a run ended; read after _run_pool


def _chunks(space: int, chunk_keys: int, start: int = 0):
    for lo in range(start, space, chunk_keys):
        yield lo, min(lo + chunk_keys, space)


def _run_pool(worker, args: tuple, space: int, chunk_keys: int, workers: int,
              report: Callable[[int], None], stop: Callable[[], bool],
              pool: bool = True, start: int = 0):
    """Search ``[0, space)`` for ``worker(*args, lo, hi) is not None``.

    Chunks are small and submitted lazily -- only ~2x workers are ever in flight
    -- so progress is fine-grained, a stop request is honoured within a chunk,
    and finding the key returns at once instead of waiting for coarse in-flight
    work. Falls back to a single process if a pool will not start.
    """
    _last_done[0] = 0
    ranges = _chunks(space, chunk_keys, start)

    try:
        executor = ProcessPoolExecutor(max_workers=workers) if pool else None
    except (OSError, ValueError):
        executor = None

    if executor is None:
        return _run_inline(worker, args, ranges, report, stop)

    try:
        return _run_with_pool(executor, worker, args, ranges, workers, report, stop)
    except BrokenExecutor:
        # A worker process died -- common in frozen builds with awkward spawn.
        # Fall back to a single process rather than failing the whole search.
        return _run_inline(worker, args, _chunks(space, chunk_keys, start),
                           report, stop)


def _run_inline(worker, args, ranges, report, stop):
    """Run the search in this process, one chunk at a time."""
    done = 0
    for lo, hi in ranges:
        if stop():
            _last_done[0] = done
            return _CANCELLED
        result = worker(*args, lo, hi)
        done += hi - lo
        report(done)
        if result is not None:
            _last_done[0] = done
            return result
    _last_done[0] = done
    return None


def _run_with_pool(executor, worker, args, ranges, workers, report, stop):
    """Return the *lowest-index* hit, not merely the first chunk to finish.

    Chunks are dispatched in increasing index order, so once any chunk reports a
    hit no new chunks are submitted, but every chunk already in flight -- which
    includes all lower-index chunks -- is drained before choosing the lowest hit.
    Returning first-completed instead would let a higher-index fluke mask the
    real, lower-index key when its chunk happens to finish first.
    """
    done = 0
    spans: dict = {}                     # future -> (lo, span)
    hits: list = []                      # (lo, value)
    stop_submitting = False

    def submit_one() -> bool:
        if stop_submitting:
            return False
        try:
            lo, hi = next(ranges)
        except StopIteration:
            return False
        spans[executor.submit(worker, *args, lo, hi)] = (lo, hi - lo)
        return True

    cancelled = False
    try:
        for _ in range(workers * 2):
            if not submit_one():
                break
        while spans:
            finished, _ = wait(list(spans), return_when=FIRST_COMPLETED)
            for future in finished:
                lo, span = spans.pop(future)
                done += span
                value = future.result()
                if value is not None:
                    hits.append((lo, value))
                    stop_submitting = True   # no need to search higher indices
            report(done)
            if stop() and not hits:
                cancelled = True
                break
            for _ in range(len(finished)):
                submit_one()                 # a no-op once stop_submitting is set
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    _last_done[0] = done
    if cancelled:
        return _CANCELLED
    return min(hits, key=lambda h: h[0])[1] if hits else None


# ---------------------------------------------------------------------------
# whole-pak orchestration -- shared by the CLI and the GUI battle
# ---------------------------------------------------------------------------

def recover_pak_keys(path, *, database=None, workers: int | None = None,
                     progress: Callable[[Progress], None] | None = None,
                     stage: Callable[[str], None] | None = None,
                     stop: Callable[[], bool] | None = None,
                     pool: bool = True) -> dict:
    """Recover every key needed to convert ``path``.

    Finds the RC2 keyword (known list, then brute force), then -- for each
    member that is genuinely a ROM -- the swap key, brute-forcing it only when
    none of the known keys fit. Uses the same classification as conversion, so
    the flash writer and kernels are not mistaken for ROMs.

    Returns a summary dict: ``{"rc2", "rc2_stage", "roms": [...]}`` on success,
    or ``{"error": ...}`` / ``{"cancelled": True}``.
    """
    from . import pak as pakmod, rc2 as rc2mod, srec as srecmod
    from . import convert as convmod
    from .keys import default_database
    from .metadata import cid_from_member

    stage = stage or (lambda _s: None)
    stop = stop or (lambda: False)
    archive = pakmod.read(path)
    database = database if database is not None else default_database()
    payloads = sorted((m for m in archive.members if m.is_payload),
                      key=lambda m: m.length, reverse=True)
    if not payloads:
        return {"error": "no ROM-shaped members in this pak"}

    known = [r.key for r in database.rows if r.key] if database else []
    stage("breaking the archive (RC2)")
    rc2_result = recover_rc2_key(payloads[0].data, keywords=known, workers=workers,
                                 progress=progress, stop=stop, pool=pool)
    if stop():
        return {"cancelled": True}
    if not rc2_result.found:
        return {"error": "RC2 key not found", "rc2": None}

    key = rc2_result.key
    summary = {"rc2": key, "rc2_stage": rc2_result.stage, "roms": []}
    only = len(payloads) == 1
    for member in archive.members:
        ok, _reason = convmod._classify(
            member, key, min_rom_bytes=convmod.MIN_ROM_BYTES, only_member=only)
        if not ok:
            continue
        cid = cid_from_member(member.name)
        cal = bytes(srecmod.parse(rc2mod.decrypt_pak_blob(member.data, key)).data)
        name, words, method = convmod.detect_key(cal, cid)
        if words is None:
            stage(f"cracking {cid} (swap cipher)")
            sr = recover_swap_key(cal, cid, workers=workers, progress=progress,
                                  stop=stop, pool=pool)
            if stop():
                return {"cancelled": True, **summary}
            if sr.found:
                name, words, method = "recovered", sr.key, "bruteforce"
        summary["roms"].append({
            "cid": cid, "member": member.name,
            "swap_key": tuple(words) if words else None,
            "swap_key_name": name if words else None, "method": method})
    return summary
