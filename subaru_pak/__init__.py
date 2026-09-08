"""subaru_pak -- convert Subaru FlashWrite ``.pak`` files to raw ROM images.

Pure Python, no bundled executables::

    from subaru_pak import convert_pak
    result = convert_pak("22765AJ13F.pak")
    for rom in result.roms:
        print(rom.filename, rom.metadata.cid, rom.checksum)
        open(rom.filename, "wb").write(rom.data)
"""

from .convert import (ConversionError, PakResult, RomResult, convert_pak,
                      inspect_pak, write_results)
from .keys import CRYPT_KEYS, PackDatabase, default_database
from .metadata import RomMetadata
from .pak import PakArchive, PakError, PakMember

__version__ = "0.1.0"

__all__ = [
    "convert_pak", "inspect_pak", "write_results",
    "PakResult", "RomResult", "RomMetadata", "ConversionError",
    "PakArchive", "PakMember", "PakError",
    "PackDatabase", "default_database", "CRYPT_KEYS",
    "__version__",
]
