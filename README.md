# subaru-pak

Convert Subaru SSM **FlashWrite `.pak`** files into raw ROM images (`.bin` / `.hex`).

One pure-Python core with three faces: a **GUI** for technicians, a **CLI** for
automation, and an **importable library** for developers. No bundled `.exe`, no
Windows crypto handles, no `subprocess` — so it runs on Windows, macOS and Linux
alike.

```
22765AJ13F.pak  ->  EB4I350A-2016-CDM-Subaru-Legacy-2.5i-MT.hex   (1280 KB, checksum ok)
```

## Install

**Technicians — the app.** Download `pak2bin.exe` from
[Releases](../../releases) and run it. One file, nothing else to install: double
click it for the window, or drag `.pak` files straight onto it.

Windows may show **"Windows protected your PC"** the first time — click *More
info* → *Run anyway*. That appears because the download is new, not because
anything is wrong with it; every release ships a `SHA256SUMS.txt` you can check
against first:

```powershell
Get-FileHash pak2bin.exe -Algorithm SHA256    # compare with SHA256SUMS.txt
```

**Automation — the CLI.**

```bash
pip install subaru-pak
subaru-pak convert *.pak --out ./bins --json
```

**Developers — the library.**

```bash
pip install subaru-pak            # core + CLI
pip install "subaru-pak[gui]"     # adds the PySide6 window
pip install "subaru-pak[fast]"    # optional C backend for RC2, ~50x quicker
```

The core has no required dependency beyond Click, and the `fast` extra changes
nothing about the output: pure-Python RC2 stays the reference implementation,
and the C backend is only used after it has reproduced that reference byte for
byte at import time.

```python
from subaru_pak import convert_pak

for rom in convert_pak("22765AJ13F.pak").roms:
    print(rom.filename, rom.metadata.cid, rom.checksum, rom.sha256)
    open(rom.filename, "wb").write(rom.data)
```

## Using it

### GUI

`subaru-pak gui` (or the installed shortcut). Drop `.pak` files or a whole
folder on the window. Each pak gets a card showing every ROM it contains —
CALID, vehicle, year, market, transmission, ECU and size, and whether the
checksum validates — then **Convert** writes them to the output folder with
proper names.

**Settings** holds two choices, both remembered between runs alongside the
output folder:

| Setting | Options |
| --- | --- |
| Appearance | Match Windows (default), Light, Dark |
| Output file extension | Automatic (default) — `.hex` for ECUs, `.bin` for modules — or always one or the other |

Both extensions are raw ROM images; which one you get is only a naming
convention. Changing it re-reads the loaded paks so the cards show the names
that will actually be written.

The GUI never overwrites: converting the same pak twice leaves the first file
alone and writes `...-2.hex` beside it, so a ROM you have since edited cannot be
replaced by accident. The CLI does overwrite, which is what scripts expect.

### CLI

```bash
subaru-pak info  <pak>...                 # what is inside, writes nothing
subaru-pak convert <pak>... --out DIR     # convert, auto-named
subaru-pak recover <pak>                  # brute-force the key for an unknown pak
subaru-pak keys                           # list the swap-cipher keys tried
```

`pak2bin.exe` is one binary with two personalities, decided by how it is
launched:

* **from Explorer** -- double-clicked, or with `.pak` files dropped on it -- it
  opens the window, with anything dropped already loaded;
* **from a shell**, or given a subcommand or option, it is the CLI above.

So there is one file to download and it does the right thing either way. It
detects this by asking Windows whether it owns its console, which means a shell
script or CI job never gets a window.

Useful flags:

| Flag | Effect |
| --- | --- |
| `--json` | one JSON record per ROM on **stdout** (logs go to stderr) |
| `--hex` / `--bin` | force the output extension |
| `--no-name` | name outputs after the archive member instead of the CALID |
| `--key HEX` | supply the RC2 pack key when the database lacks the pak |
| `--db PATH` | consult another regional `Pack File Database_*.csv` |
| `--swap-key NAME` | force a swap-cipher key instead of detecting one |
| `--download 0x2000` | force the flash offset instead of inferring it |
| `--fix-checksum` | rewrite failing subarudbw block checksums |
| `--dry-run` | convert but write nothing |

Arguments may be files, globs or directories (searched recursively).

Exit codes: `0` all converted, `1` something failed, `2` usage error.

```json
[
  {
    "status": "ok",
    "member": "EB4I350A_r.sob",
    "filename": "EB4I350A-2016-CDM-Subaru-Legacy-2.5i-MT.hex",
    "key": "denso_can", "key_method": "calid",
    "download": "0x8000", "download_source": "inferred-tight",
    "covered": "0x137f00", "size": 1310720,
    "checksum": "ok",
    "sha256": "...",
    "cid": "EB4I350A", "model": "Legacy", "year": "2016",
    "market": "CDM", "transmission": "MT", "unit": "ECM",
    "path": "bins/EB4I350A-2016-CDM-Subaru-Legacy-2.5i-MT.hex"
  }
]
```

## How a pak becomes a ROM

1. **Container** (`pak.py`) — a `.pak` is an MFC `CArchive`: a magic word, an
   encrypted header CSV, then serialized `CClFileDataInfo` objects, each an
   S-record file. A pak carries the flash writer and kernel alongside the ROM,
   and sometimes several ROMs (an AT and an MT build of the same car).
2. **RC2** (`rc2.py`) — every member is RC2-encrypted with the pack's key from
   the FlashWrite pack database. FlashWrite used Windows CryptoAPI, so the key
   is `MD5(keyword)[:5]` zero-salted to 16 bytes, run as **RC2-CBC with a zero
   IV at an effective key length of 40 bits**, PKCS#5 padded. Decrypting yields
   Motorola S-record text.
3. **S-records** (`srec.py`) — parsed to a flat image plus a coverage mask; S1
   records address the first 64 KB and S2 records the rest.
4. **Swap cipher** (`swapcipher.py`) — the ROM itself is encrypted again with
   Denso's four-round 32-bit block cipher. Which of the [12 known keys](#keys)
   applies is recorded nowhere, so it is detected: the right key makes the CALID
   appear in the plaintext, and for modules that carry no CALID, it is the only
   key that leaves flash padding as long runs of `0xFF`.
5. **Placement** — the cal region is laid into an `0xFF`-filled image at its
   flash offset (`0x2000` on an SH7058, `0x8000` on an SH72531).
6. **Checksum** (`checksum.py`) — the subarudbw 32-bit block table is validated,
   and can be repaired with `--fix-checksum`.

### Keys

`subaru-pak keys` lists them. Seven are the long-known Denso/Hitachi engine and
TCU keys; five are module keys (BIU, EyeSight camera, DMCM, BRZ TCM) recovered
by known-plaintext bruteforce against flash padding.

## Recovering a key for an unknown pak

A pak that is in no database, or an **engine ROM** whose swap key is none of the
twelve, can have its key **brute-forced**. Both searches are 2³² -- minutes on a
modern multi-core box, not the millennia a blind search would take -- because
each has free known-plaintext:

* the RC2 keyword is eight hex characters, and the plaintext is always S-record
  text, so the search recognises the key the moment a decrypt begins `S…`;
* an engine ROM's swap key collapses to a 2³² search (fix two of the four key
  words, solve the other two), anchored and verified by the CALID at the start
  of the cal.

**Module** swap keys (BIU, camera, TCM, …) are *not* brute-forced: a module cal
is dominated by erased `0xFF` flash, which in ECB is satisfied by many keys, so a
brute-force result can't be verified. `recover` reports those as not found rather
than return a plausible wrong key; a genuinely new module key needs known
plaintext beyond erased flash. Known module keys still convert via detection.

```bash
subaru-pak recover 22XXXAX99X.pak          # tries known keywords, then brute-forces
subaru-pak convert unknown.pak --recover   # convert, brute-forcing a missing key
```

In the **GUI**, a pak with no known key shows a **⚔ Battle for the key** button.
It opens a (very on-brand) encounter: a wild PAK appears, `GRAPHICS CARD` (your
CPU, levelled to its core count) attacks, and the PAK's HP bar drains as the
keyspace is searched -- because the HP bar *is* the keyspace. A faint is a real
recovered key, which the app then remembers for future paks of that family.

This recovers content-protection keys; use it on files you are authorised to
work with.

## Known limitation: the in-pak header CSV

Each pak begins with a small `header.csv` that names every member, marks which
are flashable ROMs (`DataType=EcuData`), and records the authoritative
`DownloadAddress`. **It is RC2-encrypted under a fixed key that this project has
not recovered** — the same ciphertext prefix appears in paks whose pack keys
differ, so it is a constant compiled into FlashWrite rather than anything
derived from the pak.

Everything that CSV would provide is therefore obtained another way, and each
substitute is verified bit-exactly against known-good conversions:

| From the header | Substitute |
| --- | --- |
| which members are ROMs | S-record size and load address (a writer loads at `0x800000`; kernels are a few KB) |
| `DownloadAddress` | inferred: the offset that makes the cal region fill its flash part exactly (`infer_download_address`) |
| CALID, model, year, market | the FlashWrite pack database, matched on pack number and CALID |

`metadata.parse_header_csv()` is already written and tested against the real
schema, so if the fixed key turns up it becomes the authoritative source with no
other changes. Recovering it needs the key itself: RC2's 40-bit effective length
puts a known-plaintext bruteforce at 2⁴⁰ — hours on a GPU, not something the
library attempts.

## Development

```bash
git clone <repo> && cd subaru-pak
pip install -e ".[dev,gui]"
pytest                        # 100+ tests, ~1 minute
```

The suite's backbone is `tests/test_convert.py`: four known-good pak→ROM pairs
in `test_data/` that must come back **bit for bit**, covering an SH72531 engine
ROM, a multi-ROM SH7058 pak, and a BIU module that needs the `0xFF` structural
key detection. `tests/test_rc2.py` checks all eight RFC 2268 vectors, and
`tests/test_swapcipher.py` checks the table-driven cipher against a line-by-line
transcription of the original C.

Layout:

```
subaru_pak/
  pak.py         MFC CArchive reader
  rc2.py         RC2 / CryptoAPI key derivation
  swapcipher.py  Denso 32-bit swap cipher
  srec.py        S-record parsing
  checksum.py    subarudbw validate / fix
  keys.py        swap keys + pack database
  metadata.py    identity, flash offset, output naming
  convert.py     the pipeline
  cli.py         Click CLI
  gui/app.py     PySide6 window
```

The core imports no GUI code and shells out to nothing.

### Packaging a release

```powershell
.\packaging\build.ps1              # wheel + sdist + compiled GUI (folder)
.\packaging\build.ps1 -OneFile     # ...as a single .exe instead
```

Nuitka compiles to C — smaller and far less prone to antivirus false positives
than PyInstaller.

The build always writes `dist/SHA256SUMS.txt` in `sha256sum` format, so
`sha256sum -c SHA256SUMS.txt` works and Windows users can compare against
`Get-FileHash`. Publish it with every release.

### Signing (optional)

Releases are currently **unsigned**, which costs users one *More info → Run
anyway* click on first run and nothing after that. Signing is worth buying when
that friction starts costing adoption, or when distributing into shops whose IT
blocks unsigned executables outright.

Nothing needs to change to add it later — a signature is a post-build step:

```powershell
.\packaging\sign.ps1 -Thumbprint <cert thumbprint> -Path build-nuitka\pak2bin.exe
```

The script finds `signtool.exe` from the Windows SDK, signs SHA-256, timestamps
against a list of authorities with fallback, and verifies afterwards. It takes a
store certificate (`-Thumbprint` / `-Subject` / `-AutoSelect`) or a cloud signing
service's signtool plugin (`-Dlib` / `-Metadata`).

Three things worth knowing before buying a certificate:

* **Since June 2023 the private key must live on certified hardware.** No CA
  will email you a `.pfx` any more. You get a USB token, an HSM, or a cloud
  signing service — which is what decides how your build pipeline is shaped.
* **Timestamping is not optional, and it is what makes a signature outlive its
  certificate.** A timestamped signature stays valid forever; without `/tr`,
  everything you have shipped stops validating the day the certificate expires.
  The script always timestamps.
* **The publisher name should match the certificate.** `packaging\build.ps1`
  stamps the binary as `DITCH-HOOK LLC`; if a CA styles the organisation
  differently, follow the certificate.

Signing is Windows-only and applies to the `.exe` and any installer. Wheels on
PyPI are not Authenticode-signed; use PyPI's trusted publishing instead.

A self-signed certificate is not a cheaper substitute — users would have to
install your root certificate, which is worse friction than the click it saves.

If Defender or another engine flags a build — plausible for a tool that rewrites
ECU images — signing alone will not fix it. Submit the binary to the vendor's
false-positive process; for Microsoft that is the Defender sample submission
portal.

## Credits

Builds on the reverse engineering behind `unpak.py`, `rc2decode` and `crypt` from
the pak-tools work. The Denso swap cipher — the algorithm and its transformation
constants — comes from [FastECU](https://github.com/miikasyvanen/fastecu) by
Miika Syvänen; `swapcipher.py` is an independent reimplementation of it.

> **Note on the cipher's licence.** FastECU is GPLv3. This project is MIT on the
> understanding that `swapcipher.py` is a clean reimplementation of a
> (non-copyrightable) algorithm rather than a copy of FastECU's source. If you
> redistribute this code, satisfy yourself that this holds for your use.

## Licence

MIT — see [LICENSE](LICENSE).

Reading and converting calibration files you are licensed to use is the intended
purpose here. Flashing an ECU with a modified image is entirely at your own risk.
