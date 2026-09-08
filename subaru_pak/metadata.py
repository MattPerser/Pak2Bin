"""Describing and naming a ROM: pack database rows, in-pak header CSV, filenames.

Two metadata sources, in precedence order:

1. the pak's own ``header.csv`` -- authoritative, and the only place the
   ``DownloadAddress`` is recorded, but it is RC2 encrypted under a fixed key
   that has not been recovered (see :func:`parse_header_csv` and the README);
2. the pack database shipped with FlashWrite, matched on pack number and CALID,
   which supplies everything the output file name needs.

When (1) is unavailable the flash offset is inferred instead -- see
:func:`infer_download_address`, which reproduces the recorded offsets of every
known-good conversion.
"""

from __future__ import annotations

import csv
import io
import os
import re
from dataclasses import dataclass, asdict

from .keys import FLASH_CLASSES, PackRow

__all__ = ["RomMetadata", "parse_header_csv", "infer_download_address",
           "flash_size", "output_name", "engine_name", "MARKETS"]

#: Country-spec -> the market tag used in ROM file names.
MARKETS = {
    "N.AMERICA": "USDM",
    "EUROPE": "EDM",
    "AUSTRALIA": "ADM",
    "GENERAL": "GDM",
    "JAPAN": "JDM",
}

#: Marketing names for engine/aspiration pairs, purely to make file names read
#: the way the tuning community writes them.  Anything not listed falls back to
#: "<displacement>i" / "<displacement>T".
ENGINE_NAMES = {
    ("2.5L", "Turbo"): "XT",
    ("2.0L", "Turbo"): "WRX",
    ("2.4L", "Turbo"): "XT",
    ("3.6L", "non-Turbo"): "3.6R",
    ("3.0L", "non-Turbo"): "3.0R",
}

#: Candidate flash offsets, in the order they are tried when inferring.
DOWNLOAD_CANDIDATES = (0x2000, 0x8000, 0x0, 0x1000, 0x4000, 0x10000, 0x20000)

_SUFFIX_RE = re.compile(r"^(?P<cid>.+?)_[A-Za-z0-9]{1,2}$")


@dataclass
class RomMetadata:
    """Everything known about one ROM inside a pak."""

    cid: str = ""                 # CALID
    member: str = ""              # archive member the ROM came from
    pack_number: str = ""
    part_number: str = ""
    unit: str = ""                # ECM / TCM / BIU / CAMERA ...
    model: str = ""               # vehicle line
    year: str = ""
    market: str = ""
    transmission: str = ""
    engine: str = ""
    aspiration: str = ""
    grade: str = ""
    spec: str = ""
    cvn: str = ""
    source: str = "database"      # "header" | "database" | "filename"

    def to_dict(self) -> dict:
        return asdict(self)


def cid_from_member(name: str) -> str:
    """CALID from an archive member name: ``A2WC412D_j.sob`` -> ``A2WC412D``."""
    stem = os.path.splitext(os.path.basename(name))[0]
    match = _SUFFIX_RE.match(stem)
    return match.group("cid") if match else stem


def from_pack_row(row: PackRow | None, *, cid: str, member: str,
                  pack_number: str, matched: bool = True) -> RomMetadata:
    """Build metadata from a database row (or almost nothing, if there is none).

    ``matched`` says whether the row describes *this ROM* (its CALID lines up)
    or merely the pack it came in, which is all a module's rows can offer.
    """
    if row is None:
        return RomMetadata(cid=cid, member=member, pack_number=pack_number,
                           source="filename")
    spec = row.spec.strip()
    market = MARKETS.get(row.country.strip().upper(), "")
    if row.country.strip().upper() == "N.AMERICA" and "CANADA" in spec.upper():
        market = "CDM"
    return RomMetadata(
        cid=cid or row.cid,
        member=member,
        pack_number=pack_number or row.pack_number,
        part_number=row.part_number,
        unit=row.unit,
        model=row.vehicle,
        year=row.year,
        market=market,
        transmission=row.transmission,
        engine=row.engine,
        aspiration=row.aspiration,
        grade=row.grade,
        spec=spec,
        cvn=row.cvn,
        source="database" if matched else "database-pack",
    )


def parse_header_csv(text: str | bytes) -> list[dict]:
    """Parse a *decrypted* in-pak ``header.csv`` into its ``EcuData`` rows.

    Kept faithful to the real schema so that the moment the fixed header key is
    recovered, this becomes the authoritative source with no other changes:
    ``DownloadAddress`` is the true flash offset, and ``DataType == EcuData``
    is what marks a member as a flashable ROM rather than a kernel or writer.
    """
    if isinstance(text, bytes):
        text = text.decode("latin1", errors="ignore")
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return []
    index = {name.strip(): i for i, name in enumerate(rows[0])}

    def get(record, name):
        i = index.get(name)
        return record[i].strip() if i is not None and i < len(record) else ""

    entries = []
    for record in rows[1:]:
        if len(record) < 3 or get(record, "DataType") != "EcuData" or not record[1].strip():
            continue
        entries.append({
            "member": record[1].strip(),
            "cid": get(record, "NewCid"),
            "romid": get(record, "NewRomid"),
            "part_number": get(record, "NewPartsNo"),
            "model": get(record, "Model"),
            "grade": get(record, "Grade"),
            "download": get(record, "DownloadAddress"),
            "ecu_maker": get(record, "EcuMaker"),
            "system": get(record, "System"),
        })
    return entries


def flash_size(total: int) -> int:
    """Round a byte count up to a physical flash size."""
    for size in FLASH_CLASSES:
        if total <= size:
            return size
    return ((total + 0xFFFF) // 0x10000) * 0x10000


#: Offset used when nothing about the image suggests one; the common SH705x case.
DEFAULT_DOWNLOAD = 0x2000

#: Slack, as a fraction of the flash part, still considered a full image.
_TIGHT_FRACTION = 1 / 16


def infer_download_address(covered: int,
                           candidates=DOWNLOAD_CANDIDATES) -> tuple[int, str]:
    """Infer the flash offset a cal region is programmed at.

    A Subaru cal image plus its offset fills its flash part: 0x2000 + 0xFE000 =
    1 MB for an SH7058, 0x8000 + 0xF8000 = 1 MB for a BIU module, 0x8000 +
    0x137F00 just under the 1.25 MB of an SH72531.  So the offset that leaves
    the image filling its part is the one the ECU actually uses; every
    known-good conversion agrees.

    "Least slack" alone would be perverse for an image far smaller than any
    flash part -- padding it with a *bigger* offset would score better -- so a
    candidate only counts if it leaves the part essentially full.

    Returns ``(address, confidence)``: ``"exact"`` when the fit lands precisely
    on a flash boundary, ``"tight"`` when it very nearly does, and ``"default"``
    when no offset makes a full image and the answer is a convention, not a
    deduction.
    """
    scored = []
    for address in candidates:
        total = address + covered
        size = flash_size(total)
        scored.append((size - total, address, size))

    exact = sorted((s for s in scored if s[0] == 0))
    if exact:
        return exact[0][1], "exact"
    tight = sorted((s for s in scored if s[0] < s[2] * _TIGHT_FRACTION))
    if tight:
        return tight[0][1], "tight"
    return DEFAULT_DOWNLOAD, "default"


def engine_name(meta: RomMetadata) -> str:
    engine, aspiration = meta.engine.strip(), meta.aspiration.strip()
    name = ENGINE_NAMES.get((engine, aspiration))
    if name:
        return name
    displacement = engine[:-1] if engine.upper().endswith("L") else engine
    if not displacement:
        return ""
    return f"{displacement}T" if aspiration.lower().startswith("turbo") else f"{displacement}i"


def _clean(part: str) -> str:
    """Filename-safe field: collapse whitespace to dashes, drop separators."""
    part = re.sub(r"[\\/:*?\"<>|]", "", part).strip()
    part = re.sub(r"\s+", "-", part)
    return part.strip("-")


def output_name(meta: RomMetadata, extension: str = ".hex") -> str:
    """``CALID-YEAR-MARKET-Subaru-Model-Engine-Trans.hex`` where possible.

    Modules with no CALID in the database (a BIU, a camera) have no such name to
    build, so they keep their archive member name qualified by the pack number
    -- ``DF105742_SKE_REPchg2__82201AL30D.bin``.
    """
    fields = [meta.cid, meta.year, meta.market, "Subaru", meta.model,
              engine_name(meta), meta.transmission]
    parts = [_clean(f) for f in fields]
    usable = [p for p in parts if p and p != "-"]
    # Only a row that matched this ROM's CALID describes the car it belongs to;
    # a module's row describes the pack, so its vehicle details must not end up
    # in the file name as though they were the ROM's own.
    descriptive = (meta.source == "database" and meta.cid and meta.model
                   and meta.year and len(usable) >= 5)
    if not descriptive:
        stem = os.path.splitext(meta.member)[0] if meta.member else (meta.cid or "rom")
        pack = meta.pack_number
        return f"{stem}__{pack}{extension}" if pack else f"{stem}{extension}"
    return "-".join(usable) + extension
