# Subaru PAK→BIN — Desktop App (build spec)

Build a **polished, open-source Windows app** that converts Subaru SSM FlashWrite
`.pak` files to raw ROM `.bin`/`.hex`. Three audiences, one codebase:
**technicians** (GUI, drag-drop), **Claude/automation** (CLI + importable library),
**devs** (clean pip-installable package, contributable on GitHub).

The reverse-engineering is **done** — this is packaging + UX, not research. All the
hard facts (keys, offsets, cipher, checksum) already live in `reference/pak2bin.py`
and `reference/dbw_checksum.py`; port and wrap them.

## Architecture — one core, three faces
```
subaru-pak/                  (the GitHub repo)
  subaru_pak/                CORE LIBRARY (pure Python, no bundled .exe)
    pak.py         # unpak the CArchive (port of reference/unpak.py, drop bitstring dep)
    rc2.py         # RC2 decrypt (PORT from cipher_source/rc2decode.cpp)
    swapcipher.py  # Denso swap cipher (PORT from cipher_source/crypt_utils.cpp, ~40 lines)
    srec.py        # S-record parse -> bytes+mask (ALREADY pure Python: pak2bin.parse_srec)
    checksum.py    # subarudbw validate/fix (COPY reference/dbw_checksum.py, done)
    keys.py        # RC2 key lookup (from the pack DB csv) + the swap-cipher key set
    metadata.py    # header.csv parse -> CID/model/year/market/trans/DownloadAddress
    convert.py     # orchestrator: pak -> [(bin, metadata)]  (port of pak2bin.convert_sob)
    data/Pack_File_Database_N_AMERICA.csv   # embedded (RC2 keys + naming metadata)
  cli.py                     CLI (Click) — `subaru-pak convert *.pak --out ./bins --json`
  gui/                       PySide6 GUI (technicians)
  tests/                     bit-exact diff vs test_data/expected
  pyproject.toml             pip-installable; console-script entry point for the CLI
```
Core has **no GUI imports** and **no subprocess/exe calls** — pure Python so devs
import it, Claude imports it, and it runs on Mac/Linux too.

## The only real coding: port 2 primitives to pure Python
Everything else already exists in Python. Port these, then delete the exe calls:
1. **RC2** (`rc2decode.exe`) → `rc2.py`. Standard Ron's Code 2; exact key schedule +
   how the pak/CsvKey is used is in `cipher_source/rc2decode.cpp`. Validate against
   the S-record it should produce.
2. **Swap cipher** (`crypt.exe`) → `swapcipher.py`. 32-bit-block ECB, 4×16-bit key,
   `cipher_source/crypt_utils.cpp` (`subaru_denso_*_32bit_payload` + the
   `index_transformation` table). Encrypt key `[k0 k1 k2 k3]`; **decrypt = reverse**.
`srec` and `checksum` are already pure Python (copy them). `unpak.py` is Python but
uses the `bitstring` lib — reimplement its ~120 lines with `struct` to drop the dep.

### Key facts (already encoded in reference/pak2bin.py — don't re-derive)
- Flash offset per pak from `header.csv` `DownloadAddress` (`0x2000` SH7058,
  `0x8000` SH72531); FF-fill `0x0..offset` and uncovered bytes.
- Swap-cipher key auto-detect: try the key set, accept the one whose output contains
  the CALID ascii (engine ROMs) or maximizes `0xFF` padding (modules). Full key set —
  including the 5 module keys — is in `pak2bin.CRYPT_KEYS`.
- Checksum: `subarudbw`, table at `0x7FB80/0xFFB80/0x13F500` by size (`checksum.py`).

## CLI (Claude/automation)
`subaru-pak convert <paks...> --out DIR [--json] [--hex|--bin] [--no-name]`
- `--json` → one machine-readable record per ROM (cid, model, year, market, trans,
  key, size, checksum, sha256, output path). Predictable exit codes.
- Also `subaru-pak info <pak>` (metadata only, no write). Ship as a pip console-script
  **and** a standalone Nuitka binary for no-Python users.

## GUI (technicians) — PySide6
- Drag a `.pak` or a folder onto the window (or Browse).
- Per pak: a card showing detected **CID · model · year · market · transmission ·
  ECU/size · checksum ✓**. Multi-ROM paks show each ROM.
- One **Convert** button → auto-named output (`CALID-YEAR-MARKET-Subaru-Model-Engine-Trans.hex`),
  choosable output folder, batch queue, progress, results log.
- Graceful errors: "not a PAK", "unknown key (module?)", "no ROM in pak".
- Theme: clean light/dark, big drop zone. Keep it obvious for a first-time tech.

## Tests (do this FIRST, before the GUI)
`test_data/paks/*.pak` + `test_data/expected/*` are known-good pairs from the proven
pipeline. Port a primitive → assert the core reproduces the expected bytes **exactly**:
- `22765AJ13F.pak` → `EB4I350A…hex` (SH72531 engine, `0x8000`, denso_can)
- `UD-S211B.pak` → `A2WC412D…` + `A2WC412I…` (multi-ROM, SH7058, `0x2000`, denso)
- `82201AL30D.pak` → `DF105742_SKE…bin` (BIU module, module_biu_82201 key, FF-detect)
Bit-exact match = the port is correct. This is your safety net for the whole rewrite.

## Packaging / release
- **Nuitka** (compiles to C — smaller, far fewer AV false-positives than PyInstaller)
  → single GUI `.exe` + installer. **Code-sign it** (SmartScreen/AV will scrutinize an
  ECU tool). GitHub Releases for binaries; pip for the library/CLI.
- MIT or GPL license (dev's call). README with the 3 install paths.

## First steps for this session
1. `pyproject.toml` + `subaru_pak/` package skeleton.
2. Port `swapcipher.py` and `rc2.py`; copy `srec.py`/`checksum.py`; wire `convert.py`.
3. Green the `tests/` against `test_data/` (bit-exact).
4. Click CLI with `--json`.
5. PySide6 skeleton: drop zone → metadata card → convert. Polish after it works.

Reference `reference/pak2bin.py` is the working end-to-end logic — the app is that,
cleaned into a library with the exe calls replaced by the two ported modules, plus a
CLI and GUI on top.
