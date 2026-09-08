"""PAK -> raw ROM image.  This is the whole pipeline in one place.

For each archive member: RC2-decrypt it with the pack key, parse the S-records,
decide whether it is a flashable ROM, detect its swap-cipher key, decrypt the
cal region, and lay it into an 0xFF-filled image at the flash offset.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field

from . import checksum as dbw
from . import keys as keymod
from . import metadata as meta_mod
from . import pak as pakmod
from . import rc2, srec, swapcipher
from .metadata import RomMetadata

__all__ = ["RomResult", "PakResult", "ConversionError", "convert_pak", "inspect_pak"]

#: A cal region smaller than this is a kernel or a writer, not a ROM.
MIN_ROM_BYTES = 0x20000

#: S-record text is ~2.8x the bytes it carries; 2.0 is a safe floor for deciding
#: a member is too small to be worth decrypting in full.
SREC_EXPANSION = 2.0

#: Cal regions based this high are not flash images laid out from zero.
NEWGEN_BASE = 0x100000

#: Bytes of a member decrypted when classifying it, and when detecting the key.
_CLASSIFY_BYTES = 0x1000
_DETECT_BYTES = 0x10000

#: Bytes of a member's tail decrypted to size an image during a metadata scan.
_SCAN_TAIL_BYTES = 0x2000


class ConversionError(Exception):
    """Raised when a pak cannot be processed at all (bad file, unknown key)."""


@dataclass
class RomResult:
    """One ROM out of a pak -- converted, or explained."""

    status: str                       # "ok" or a machine-readable failure tag
    member: str
    metadata: RomMetadata
    data: bytes | None = field(default=None, repr=False)
    filename: str = ""
    key: str = ""                     # swap-cipher key name
    key_method: str = ""              # calid | structure | forced
    download: int = 0
    download_source: str = ""         # header | inferred-exact | inferred-tight | forced
    layout: str = "classic"
    covered: int = 0
    size: int = 0
    sha256: str = ""
    checksum: str = "unknown"         # ok | bad | unknown | disabled
    checksum_detail: dict = field(default_factory=dict)
    recovered_swap: tuple | None = None   # the swap key, when brute-forced
    message: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict:
        """JSON-safe record -- the shape the CLI's ``--json`` emits."""
        record = {
            "status": self.status,
            "member": self.member,
            "filename": self.filename,
            "key": self.key,
            "key_method": self.key_method,
            "download": hex(self.download),
            "download_source": self.download_source,
            "layout": self.layout,
            "covered": hex(self.covered),
            "size": self.size,
            "sha256": self.sha256,
            "checksum": self.checksum,
        }
        record.update(self.metadata.to_dict())
        if self.message:
            record["message"] = self.message
        return record


@dataclass
class PakResult:
    """Everything that came out of one pak."""

    path: str
    pack_number: str
    rc2_key: str
    roms: list[RomResult] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)

    rc2_recovered: bool = False          # the RC2 key came from a brute-force

    @property
    def ok(self) -> bool:
        return bool(self.roms) and all(rom.ok for rom in self.roms)


# ---------------------------------------------------------------------------
# member classification


def _classify(member: pakmod.PakMember, rc2_key: str, *,
              min_rom_bytes: int, only_member: bool) -> tuple[bool, str]:
    """Cheaply decide whether a member is worth a full decrypt.

    Returns ``(is_candidate, reason)``.  Only the head of the member is
    decrypted here -- enough to see the first S-record's address.
    """
    if not member.is_payload:
        return False, "container metadata"
    floor = int(min_rom_bytes * SREC_EXPANSION)
    if not only_member and member.length < floor:
        return False, f"too small to hold a ROM ({member.length:#x} < {floor:#x})"

    # RC2 ciphertext is always a whole number of blocks; a member that is not
    # says the archive is damaged rather than that the ROM is unusual.
    usable = min(len(member.data), _CLASSIFY_BYTES) // 8 * 8
    if not usable:
        return False, "member is empty"
    head = rc2.decrypt_cbc(member.data[:usable], rc2.derive_key(rc2_key))
    parsed = srec.parse(head)
    if not parsed.count:
        return False, "not S-record data"
    if parsed.start >= NEWGEN_BASE:
        return False, f"loads at {parsed.start:#x}, not a flash image"
    return True, ""


# ---------------------------------------------------------------------------
# swap-cipher key detection


def _targets(cid: str) -> list[bytes]:
    """CALID needles to look for in a correctly decrypted cal region."""
    out = []
    if cid:
        out.append(cid.encode("ascii", "ignore"))
        if len(cid) > 8:
            out.append(cid[:8].encode("ascii", "ignore"))
    return [t for t in out if t]


def detect_key(cal: bytes, cid: str, *, candidates=None, sample=_DETECT_BYTES):
    """Find the swap-cipher key for a cal region.

    The CALID appearing in the plaintext is definitive.  Modules carry no CALID,
    so the fallback is structural: only the right key leaves flash padding as
    long runs of 0xFF, and a wrong key turns that padding into noise.

    Returns ``(name, key, method)`` or ``(None, None, "")``.
    """
    candidates = candidates or keymod.all_swap_keys()
    needles = _targets(cid)
    window = cal[:sample] if sample else cal
    scored = []
    for name, key in candidates:
        plain = swapcipher.transform(window, key)
        if any(needle in plain for needle in needles):
            return name, key, "calid"
        scored.append((plain.count(0xFF), name, key))

    if needles and sample and len(cal) > sample:
        # CALID was not in the sampled head; it is worth one full pass before
        # falling back to structure, which is what the proven pipeline did.
        for name, key in candidates:
            plain = swapcipher.transform(cal, key)
            if any(needle in plain for needle in needles):
                return name, key, "calid"

    scored.sort(reverse=True)
    if scored:
        best_ff, name, key = scored[0]
        runner_up = scored[1][0] if len(scored) > 1 else 0
        if best_ff > 0.02 * len(window) and best_ff > 3 * runner_up:
            return name, key, "structure"
    return None, None, ""


# ---------------------------------------------------------------------------
# image assembly


def _mask_runs(mask: bytearray):
    """Yield ``(start, end)`` for each covered run -- scanned at C speed."""
    index, length = 0, len(mask)
    while index < length:
        try:
            start = mask.index(1, index)
        except ValueError:
            return
        try:
            end = mask.index(0, start)
        except ValueError:
            end = length
        yield start, end
        index = end


def _assemble(parsed: srec.SRecord, cal: bytes, base: int) -> tuple[bytes, int]:
    """Lay the decrypted cal region into an 0xFF-filled flash image."""
    size = meta_mod.flash_size(base + parsed.end)
    image = bytearray(b"\xFF" * size)
    for start, end in _mask_runs(parsed.mask):
        image[base + start:base + end] = cal[start:end]
    return bytes(image), size


def _plausible_table(image: bytes, table: int) -> int:
    """How many of the 17 table entries look like real block descriptors."""
    plausible = 0
    for _, _, start, end, cval in dbw.blocks(image, table):
        if start == 0 and end == 0:
            plausible += cval == dbw.MAGIC          # deliberately disabled block
        elif (start % 4 == 0 and (end + 1) % 4 == 0
                and start < end < len(image)):
            plausible += 1
    return plausible


def _checksum_state(image: bytes) -> tuple[str, dict]:
    """Validate the subarudbw checksum, but only where one actually exists.

    Modules (a BIU, a camera) have no Denso DBW table, so the bytes at the table
    offset are ordinary data and would otherwise read as a failed checksum.
    """
    table = dbw.table_offset(len(image))
    if table is None:
        return "n/a", {"reason": f"no checksum table location known for {len(image):#x}"}
    if not _plausible_table(image, table):
        return "n/a", {"table": hex(table),
                       "reason": "no subarudbw checksum table at this offset"}
    ok, active, passed, bad = dbw.validate(image, table)
    detail = {"table": hex(table), "active": active, "passed": passed,
              "bad": [list(map(str, entry)) for entry in bad]}
    if ok:
        return ("ok" if active else "disabled"), detail
    return "bad", detail


def repair_checksum(image: bytes) -> tuple[bytes, str, dict]:
    """Recompute failing subarudbw block checksums, then re-validate.

    Only ever reached for an image whose state is already "bad", which
    :func:`_checksum_state` reports only when a plausible table exists -- so a
    module with no table can never be rewritten by this.
    """
    fixed, changed = dbw.fix(image, dbw.table_offset(len(image)))
    if not changed:
        state, detail = _checksum_state(image)
        return image, state, detail
    image = bytes(fixed)
    state, detail = _checksum_state(image)
    detail["fixed_blocks"] = changed
    return image, state, detail


# ---------------------------------------------------------------------------
# public API


def convert_pak(source, *, database=None, rc2_key=None, download=None,
                swap_key=None, extension=None, min_rom_bytes=MIN_ROM_BYTES,
                fix_checksum=False, metadata_only=False,
                recover=False, recover_kwargs=None) -> PakResult:
    """Convert every ROM in one pak.

    ``rc2_key`` overrides the pack-database lookup, ``download`` forces the
    flash offset, ``swap_key`` forces a named entry of :data:`keys.CRYPT_KEYS`.
    ``recover`` allows a missing RC2 key -- and, per ROM, a missing swap key --
    to be brute-forced (see :mod:`subaru_pak.recover`); ``recover_kwargs`` is
    passed to the recovery calls (e.g. ``progress``, ``stop``, ``workers``).
    """
    archive = pakmod.read(source)
    database = database if database is not None else keymod.default_database()
    pack_number = archive.pack_number
    recover_kwargs = dict(recover_kwargs or {})

    key = rc2_key or database.key_for(pack_number)
    recovered_rc2 = False
    if not key and recover:
        key = _recover_rc2(archive, database, recover_kwargs)
        recovered_rc2 = key is not None
    if not key:
        # Kept short and actionable; "no RC2 key" is also how the GUI card
        # recognises this case to offer the battle. (Recovery was already tried
        # above when recover=True, so only mention it when it wasn't.)
        hint = "" if recover else " --recover to brute-force it,"
        raise ConversionError(
            f"no RC2 key on file for '{pack_number}'.{hint} "
            f"--key HEX to supply it, or --db to point at another "
            f"Pack File Database.")

    result = PakResult(path=archive.path or "<bytes>", pack_number=pack_number,
                       rc2_key=key)
    result.rc2_recovered = recovered_rc2
    payloads = [m for m in archive.members if m.is_payload]
    for member in archive.members:
        candidate, reason = _classify(member, key, min_rom_bytes=min_rom_bytes,
                                      only_member=len(payloads) == 1)
        if not candidate:
            result.skipped.append({"member": member.name, "reason": reason,
                                   "length": member.length})
            continue
        result.roms.append(_convert_member(
            member, key, database, pack_number,
            download=download, swap_key=swap_key, extension=extension,
            min_rom_bytes=min_rom_bytes, fix_checksum=fix_checksum,
            metadata_only=metadata_only, recover=recover,
            recover_kwargs=recover_kwargs))
    return result


def _recover_rc2(archive, database, recover_kwargs) -> str | None:
    """Brute-force the RC2 keyword from the largest ROM-shaped member."""
    from . import recover as rec
    payloads = sorted((m for m in archive.members if m.is_payload),
                      key=lambda m: m.length, reverse=True)
    if not payloads:
        return None
    known = [r.key for r in database.rows if r.key] if database else []
    kwargs = {k: v for k, v in recover_kwargs.items()
              if k in ("workers", "progress", "stop", "pool")}
    result = rec.recover_rc2_key(payloads[0].data, keywords=known, **kwargs)
    return result.key if result.found else None


def _placement(covered: int, download) -> tuple[int, int, str, str]:
    """Resolve the flash offset into ``(address, base, source, layout)``."""
    if download is not None:
        address, source_tag = download, "forced"
    else:
        address, confidence = meta_mod.infer_download_address(covered)
        source_tag = f"inferred-{confidence}"
    if address >= NEWGEN_BASE:
        # A high physical base would pad the image out to hundreds of MB; emit
        # the cal region alone instead, as the proven pipeline did.
        return address, 0, source_tag, "newgen"
    return address, address, source_tag, "classic"


def _extent_is_consistent(sample_len: int, sample_span: int, member_len: int,
                          span: int, tolerance: float = 0.1) -> bool:
    """Does a tail-derived span match what the member's own size implies?

    S-record text expands the image it carries by a fixed ratio -- a function of
    the line length and bytes per record, which differ between members (16 bytes
    a line here, 32 there).  Measuring that ratio from the sample itself gives an
    expected total, and a tail that is *not* the end of an ascending image
    reports a span that does not match it.

    The tolerance only has to be tighter than the things this feeds: the flash
    size class and the offset inference are step functions, so a few percent of
    drift changes nothing and a wrong tail is out by far more.
    """
    if sample_span <= 0 or span <= 0:
        return False
    expansion = sample_len / sample_span
    implied = member_len / expansion
    return abs(span / implied - 1.0) <= tolerance


def _scan_extent(member, rc2_key) -> int | None:
    """Highest address a member covers, read from its last few KB alone.

    CBC lets any block be decrypted given the ciphertext block before it, and
    S-records run in ascending address order, so the tail is enough to size the
    image.  That keeps a metadata scan instant instead of RC2-ing megabytes --
    conversion still parses the whole thing and takes its own measurement.

    Returns ``None`` when the tail cannot be trusted to hold the highest
    address, which the caller reports as an unknown size rather than guessing:
    a confident wrong size is worse than no size at all.
    """
    data = member.data
    end = len(data) // 8 * 8
    start = max(0, end - _SCAN_TAIL_BYTES) // 8 * 8
    if end - start < 8:
        return None
    iv = data[start - 8:start] if start >= 8 else rc2._ZERO_IV
    plain = rc2.strip_pkcs5(rc2.decrypt_cbc(data[start:end], rc2.derive_key(rc2_key), iv))
    if not start:
        # Small enough that the whole member was decrypted: the parse is exact.
        return srec.parse(plain).end or None

    newline = plain.find(b"\n")                 # first line is a fragment
    if newline == -1:
        return None
    plain = plain[newline + 1:]
    tail = srec.parse(plain)
    if not tail.end:
        return None

    # The head says where the image starts, so the span can be compared against
    # what the member's length implies.  Decrypting it again costs a millisecond.
    head = rc2.decrypt_cbc(data[:min(end, _CLASSIFY_BYTES)], rc2.derive_key(rc2_key))
    head_start = srec.parse(head).start
    if not _extent_is_consistent(len(plain), tail.end - tail.start,
                                 len(data), tail.end - head_start):
        return None
    return tail.end


def _convert_member(member, rc2_key, database, pack_number, *, download,
                    swap_key, extension, min_rom_bytes, fix_checksum,
                    metadata_only, recover=False, recover_kwargs=None) -> RomResult:
    cid = meta_mod.cid_from_member(member.name)
    row, matched = database.row_for_cid(pack_number, cid)
    info = meta_mod.from_pack_row(row, cid=cid, member=member.name,
                                  pack_number=pack_number, matched=matched)
    result = RomResult(status="ok", member=member.name, metadata=info)

    if metadata_only:
        result.filename = meta_mod.output_name(info, extension or _extension_for(info))
        covered = _scan_extent(member, rc2_key)
        if not covered:
            # Identity still comes from the database; only the geometry is
            # unknown, and converting settles it. Not an error -- an unknown.
            result.download_source = "unknown"
            result.message = ("size and offset cannot be read from the archive "
                              "tail; converting determines them")
            return result
        result.covered = covered
        address, base, source_tag, layout = _placement(covered, download)
        result.download, result.download_source, result.layout = \
            address, source_tag, layout
        result.size = meta_mod.flash_size(base + covered)
        return result

    try:
        plain = rc2.decrypt_pak_blob(member.data, rc2_key)
    except ValueError as exc:
        result.status = "undecryptable"
        result.message = str(exc)
        return result
    parsed = srec.parse(plain)
    if not parsed.count:
        result.status = "empty-srec"
        result.message = "member decrypted but held no S-records"
        return result
    result.covered = parsed.end
    if parsed.end < min_rom_bytes:
        result.status = "too-small"
        result.message = f"cal region is only {parsed.end:#x} bytes"
        return result

    cal = bytes(parsed.data)
    if swap_key:
        chosen = dict(keymod.CRYPT_KEYS).get(swap_key)
        if chosen is None:
            raise ConversionError(f"unknown swap-cipher key '{swap_key}'")
        name, key_words, method = swap_key, chosen, "forced"
    else:
        name, key_words, method = detect_key(cal, cid)
    if key_words is None and recover:
        from . import recover as rec
        kwargs = {k: v for k, v in (recover_kwargs or {}).items()
                  if k in ("workers", "progress", "stop", "pool")}
        rr = rec.recover_swap_key(cal, cid, **kwargs)
        if rr.found:
            name, key_words, method = "recovered", rr.key, "bruteforce"
            result.recovered_swap = tuple(rr.key)
    if key_words is None:
        result.status = "no-key"
        result.message = ("no swap-cipher key decrypts this ROM -- an unknown "
                          "module key. Pass --recover to brute-force it.")
        return result
    result.key, result.key_method = name, method

    address, base, source_tag, layout = _placement(parsed.end, download)
    result.download, result.download_source, result.layout = \
        address, source_tag, layout

    cal_plain = swapcipher.transform(cal, key_words)
    image, size = _assemble(parsed, cal_plain, base)
    state, detail = _checksum_state(image)
    if fix_checksum and state == "bad":
        image, state, detail = repair_checksum(image)

    result.data = image
    result.size = size
    result.sha256 = hashlib.sha256(image).hexdigest()
    result.checksum, result.checksum_detail = state, detail
    result.filename = meta_mod.output_name(info, extension or _extension_for(info))
    return result


def _extension_for(info: RomMetadata) -> str:
    """Engine ROMs are named ``.hex`` by convention; other modules ``.bin``."""
    return ".hex" if info.unit.upper() in ("ECM", "TCM", "") and info.cid else ".bin"


def inspect_pak(source, *, database=None, rc2_key=None, extension=None) -> PakResult:
    """Metadata only -- no swap decryption, no image assembly, no writing.

    ``extension`` only affects the names reported, so a preview can show the
    same file names the conversion will actually write.
    """
    return convert_pak(source, database=database, rc2_key=rc2_key,
                       extension=extension, metadata_only=True)


def write_results(result: PakResult, out_dir: str, *, use_names=True,
                  overwrite=True) -> list[str]:
    """Write each converted ROM to ``out_dir``; returns the paths written."""
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for rom in result.roms:
        if not rom.ok or rom.data is None:
            continue
        name = rom.filename if use_names else \
            os.path.splitext(rom.member)[0] + os.path.splitext(rom.filename)[1]
        path = os.path.join(out_dir, name)
        if not overwrite and os.path.exists(path):
            base, ext = os.path.splitext(path)
            index = 2
            while os.path.exists(f"{base}-{index}{ext}"):
                index += 1
            path = f"{base}-{index}{ext}"
        with open(path, "wb") as fh:
            fh.write(rom.data)
        written.append(path)
    return written
