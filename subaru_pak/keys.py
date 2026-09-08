"""Key material: the Denso swap-cipher key set and the pack-database lookup.

Two different keys are in play for one ``.pak``:

* the **RC2 key**, a hex string in the pack database's ``Keyword`` column, which
  decrypts the archive members into S-record text;
* the **swap-cipher key**, one of :data:`CRYPT_KEYS`, which decrypts the ROM
  image itself.  Which one applies is not recorded anywhere in the pak, so
  :mod:`subaru_pak.convert` detects it (CALID in the plaintext, else 0xFF
  padding structure).
"""

from __future__ import annotations

import csv
import glob
import io
import os
from dataclasses import dataclass
from functools import lru_cache

__all__ = ["CRYPT_KEYS", "FLASH_CLASSES", "PackRow", "PackDatabase", "default_database"]

#: Swap-cipher keys, ordered by likelihood, stored in *decrypt* order -- pass
#: them to :func:`subaru_pak.swapcipher.transform` unchanged.  The engine keys
#: are the long-known FastECU set; the module keys were recovered by
#: known-plaintext bruteforce against 0xFF flash padding.
CRYPT_KEYS: tuple[tuple[str, tuple[int, int, int, int]], ...] = (
    ("denso_can",        (0x92A0, 0xE282, 0x32C0, 0xC85B)),
    ("denso",            (0x6E86, 0xF513, 0xCE22, 0x7856)),
    ("hitachi1",         (0x5FB1, 0xA7CA, 0x42DA, 0xB740)),
    ("hitachi2",         (0xF50E, 0x973C, 0x77F4, 0x14CA)),
    ("hitachi_my04",     (0x7C03, 0x9312, 0x2962, 0x78F1)),
    ("tcu_hitachi",      (0x6587, 0x4492, 0xA8B4, 0x7BF2)),
    ("tcu_hitachi_my03", (0x3E27, 0xB291, 0x6640, 0x1336)),
    ("module_biu_82201", (0x0307, 0x2B1A, 0xE859, 0xA30B)),   # BIU 82201AL* (1 MB)
    ("module_camera",    (0x909D, 0x13DD, 0xC7C1, 0x33E2)),   # EyeSight camera MOTs
    ("module_dmcm",      (0xA731, 0x9A48, 0x1486, 0x8942)),   # dual-mode clutch
    ("module_brz_tcm",   (0xC536, 0x41E2, 0x6418, 0x24AE)),   # BRZ 6AT (Aisin) TCM
    ("module_biu_du66",  (0x50AB, 0xA9B7, 0x10C3, 0x2C5A)),   # BIU DU66 88281VA* (512 KB)
)

#: Swap keys recovered at runtime (by the bruteforce), tried after the built-in
#: set. A recovered key stays useful for the rest of the session, and the GUI
#: persists it so it survives a restart.
EXTRA_SWAP_KEYS: list[tuple[str, tuple[int, int, int, int]]] = []


def register_swap_key(name: str, words) -> tuple[str, tuple[int, int, int, int]]:
    """Add a recovered swap key to the runtime set, if not already present."""
    words = tuple(int(w, 16) if isinstance(w, str) else int(w) for w in words)
    for _, existing in all_swap_keys():
        if existing == words:
            return name, words
    entry = (name, words)
    EXTRA_SWAP_KEYS.append(entry)
    return entry


def all_swap_keys() -> tuple[tuple[str, tuple[int, int, int, int]], ...]:
    """The built-in keys plus any recovered this session -- what detection tries."""
    return CRYPT_KEYS + tuple(EXTRA_SWAP_KEYS)


#: Physical flash sizes an image may be padded out to.
FLASH_CLASSES = (0x28000, 0x30000, 0x40000, 0x80000, 0xC0000, 0x100000,
                 0x140000, 0x180000, 0x200000, 0x300000, 0x400000)

_PACKAGED_DB = os.path.join(os.path.dirname(__file__), "data",
                            "Pack_File_Database_N_AMERICA.csv")

#: Where FlashWrite keeps its pack databases. Searched when none is bundled --
#: the database is Subaru's file, so a distribution may legitimately ship
#: without it and read the one the technician already has installed.
_FLASHWRITE_DIRS = (
    r"C:\Program Files (x86)\Subaru\FlashWrite",
    r"C:\Program Files\Subaru\FlashWrite",
    r"C:\Program Files (x86)\Subaru\Subaru Flash Write (Older)\FlashWrite",
    r"C:\Subaru\FlashWrite",
)

#: Both spellings occur in the wild, and every region is worth picking up.
_DB_PATTERNS = ("Pack File Database*.csv", "Pack_File_Database*.csv")


def installed_databases() -> list[str]:
    """Pack database CSVs from a local FlashWrite installation, if any."""
    found: list[str] = []
    for directory in _FLASHWRITE_DIRS:
        if not os.path.isdir(directory):
            continue
        for pattern in _DB_PATTERNS:
            found.extend(sorted(glob.glob(os.path.join(directory, pattern))))
    seen, unique = set(), []
    for path in found:
        key = os.path.normcase(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique

# Column names as they appear in the FlashWrite database, with the fixed
# positions used as a fallback for regional databases with odd headers.
_COLUMNS = {
    "unit": ("Affected_Unit", 3),
    "part_number": ("Part_Number", 4),
    "pack_number": ("Pack_Number", 5),
    "applicable_cid": ("AppricableCID", 7),
    "cid": ("CID", 8),
    "cvn": ("CVN", 9),
    "key": ("Keyword", 10),
    "country": ("Country Spec", 12),
    "vehicle": ("Vehicle", 13),
    "year": ("Year", 14),
    "engine": ("Engine", 15),
    "aspiration": ("Aspiration", 16),
    "model_line": ("Model-Line", 17),
    "transmission": ("Transmission", 18),
    "spec": ("Specification", 19),
    "grade": ("Grade", 23),
}


@dataclass(frozen=True)
class PackRow:
    """One row of the pack database."""

    unit: str = ""
    part_number: str = ""
    pack_number: str = ""
    applicable_cid: str = ""
    cid: str = ""
    cvn: str = ""
    key: str = ""
    country: str = ""
    vehicle: str = ""
    year: str = ""
    engine: str = ""
    aspiration: str = ""
    model_line: str = ""
    transmission: str = ""
    spec: str = ""
    grade: str = ""


class PackDatabase:
    """Index of ``Pack File Database_*.csv`` rows, keyed by pack number."""

    def __init__(self, rows: list[PackRow] | None = None):
        self.rows: list[PackRow] = rows or []
        self._by_pack: dict[str, list[PackRow]] = {}
        for row in self.rows:
            if row.pack_number:
                self._by_pack.setdefault(row.pack_number.upper(), []).append(row)

    # -- loading -----------------------------------------------------------
    @classmethod
    def from_csv(cls, path: str) -> "PackDatabase":
        """Read a FlashWrite database.  They ship as UTF-16, but be forgiving."""
        with open(path, "rb") as fh:
            raw = fh.read()
        for encoding in ("utf-16", "utf-8-sig", "latin1"):
            try:
                text = raw.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        else:  # pragma: no cover - latin1 never raises
            raise ValueError(f"cannot decode {path}")

        reader = csv.reader(io.StringIO(text))
        try:
            header = next(reader)
        except StopIteration:
            return cls([])
        index = {name.strip(): i for i, name in enumerate(header)}
        slots = {attr: index.get(name, fallback)
                 for attr, (name, fallback) in _COLUMNS.items()}

        rows = []
        for record in reader:
            if len(record) < 11:
                continue
            rows.append(PackRow(**{
                attr: (record[i].strip() if i is not None and i < len(record) else "")
                for attr, i in slots.items()
            }))
        return cls(rows)

    def extend(self, other: "PackDatabase") -> "PackDatabase":
        """Merge another database in; later rows lose to earlier ones on ties."""
        return PackDatabase(self.rows + other.rows)

    # -- lookup ------------------------------------------------------------
    def rows_for(self, pack_number: str) -> list[PackRow]:
        return self._by_pack.get((pack_number or "").upper(), [])

    def key_for(self, pack_number: str) -> str | None:
        """The RC2 keyword for a pack number, if the database knows it."""
        for row in self.rows_for(pack_number):
            if row.key:
                return row.key
        return None

    def row_for_cid(self, pack_number: str, cid: str) -> tuple[PackRow | None, bool]:
        """The row describing one ROM of a pack, matched on CALID.

        Multi-ROM paks carry one row per CALID (an AT and an MT build, say), so
        matching on the CALID is what tells the two apart.  Returns
        ``(row, matched)``; ``matched`` is False when the row merely describes
        the pack -- modules have no CALID, and their rows list ``---`` -- which
        means its vehicle details apply to the pack, not to this ROM.
        """
        rows = self.rows_for(pack_number)
        cid = (cid or "").upper()
        if cid:
            for row in rows:
                if row.cid.upper() == cid:
                    return row, True
            for row in rows:                   # tolerate spec-suffixed CALIDs
                if row.cid and row.cid not in ("---", "-") and (
                        cid.startswith(row.cid.upper())
                        or row.cid.upper().startswith(cid[:8])):
                    return row, True
            for row in rows:
                if cid in row.applicable_cid.upper():
                    return row, True
        return (rows[0] if rows else None), False

    def __len__(self) -> int:
        return len(self.rows)

    def __bool__(self) -> bool:
        return bool(self.rows)


@lru_cache(maxsize=4)
def default_database(extra: str | None = None) -> PackDatabase:
    """Every pack database available, most trusted first.

    An explicit path wins, then the bundled copy if this distribution has one,
    then whatever a local FlashWrite installation provides -- which is what
    makes the tool useful when the database cannot be redistributed with it.
    """
    sources: list[str] = []
    if extra:
        sources.append(extra)
    if os.path.exists(_PACKAGED_DB):
        sources.append(_PACKAGED_DB)
    sources.extend(installed_databases())

    db = PackDatabase([])
    for path in sources:
        try:
            db = db.extend(PackDatabase.from_csv(path))
        except (OSError, ValueError):
            if path == extra:                  # an explicit path must not fail quietly
                raise
    return db
