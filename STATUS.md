# Status — scaffold session

Everything in HANDOFF.md's "First steps" is done and verified. What follows is
the state of play plus the facts this session established, so none of it has to
be re-derived.

## Done

| Handoff item | State |
| --- | --- |
| `pyproject.toml` + package skeleton | done; wheel builds, console script verified from an installed wheel |
| Port `swapcipher.py`, `rc2.py` | done, pure Python, no exe calls anywhere |
| Copy `srec.py` / `checksum.py`, wire `convert.py` | done |
| Green tests, bit-exact | **all four known-good pairs match byte for byte** |
| Click CLI with `--json` | done, plus `info`, `keys`, exit codes |
| PySide6 GUI | done: drop zone, per-ROM cards, batch convert, progress, light/dark |
| Nuitka binary | built and smoke-tested; `packaging/build.ps1`, signing script alongside |

152 tests, ~18 seconds with the C backend installed (~2 minutes without). `tests/test_convert.py` is the safety net.

Three things worth knowing about how the code guards itself:

* **The metadata scan can decline to answer.** Sizing an image from the last
  8 KB of a member assumes the tail holds its highest address. That assumption
  is checked, not trusted: S-record text expands the image by a ratio measurable
  from the sample itself, so a tail that is not the end fails the cross-check
  and the scan reports the size as unknown rather than a confident wrong number.
  Conversion always parses the whole member and is unaffected.
* **`--fix-checksum` is tested on a genuinely corrupted ROM**, not just on the
  checksum module in isolation, and it is tested to leave every known-good ROM
  byte-identical. It can only fire where a plausible checksum table exists, so
  it cannot rewrite a module.
* **The optional pycryptodome backend proves itself before use**, matching the
  pure-Python result byte for byte at import or being ignored. It is also
  bypassed for keys under 40 bits, which it refuses and RC2 allows -- installing
  it must not change what the library accepts.

## Facts established this session (not in HANDOFF.md)

**RC2 key derivation.** `rc2decode.exe` used CryptoAPI on the *Base* provider,
which means: key = `MD5(keyword)[:5]` padded with 11 zero salt bytes to 16, then
RC2-CBC, zero IV, PKCS#5 — at an **effective key length of 40 bits, not 128**.
At 128 the same key produces noise. This was settled empirically against a real
`.sob`, and is pinned by `tests/test_rc2.py::test_effective_key_length_40_not_128`.

**The container has more in it than `unpak.py` reported.** Its
`0x8000 + num_files` "finish" marker is really an MFC class tag, so its loop
stopped early and silently dropped trailing members. A pak ends with a second
class, `CClDataInfo`, holding `EcuDataMap` (a table of applicable part numbers)
and `PcVerData`. Both decrypt with the pack key. `pak.py` parses to EOF and
asserts the member count matches the declared object count.

**The in-pak `header.csv` is encrypted under a fixed key that is still unknown.**
Every other member uses the pack's database keyword; the header does not — paks
with different keywords share an identical 56-byte ciphertext prefix, so it is a
constant compiled into FlashWrite. A ~80-word dictionary attack found nothing.
See the README for what is used in its place. RC2's 40-bit effective length puts
a known-plaintext bruteforce at 2⁴⁰ — feasible on a GPU, not in this library.

**The flash offset can be inferred, and it is not a guess.** A cal region plus
its offset fills its flash part: `0x2000 + 0xFE000` = 1 MB (SH7058),
`0x8000 + 0xF8000` = 1 MB (BIU module), `0x8000 + 0x137F00` just under 1.25 MB
(SH72531), `0x2000 + 0x7E000` = 512 KB (SH7055). Picking the offset that fills
the part reproduces all four, confirmed against the first non-`0xFF` byte of each
expected output.

**Which members are ROMs, without the header's `DataType`.** The flash writer
(`FW084000.MOT`) loads at `0x800000`; kernels (`EGISBLJ*.sob`) and small modules
cover ≤ 32 KB; real ROMs cover ≥ 504 KB and load from 0. Classification uses the
load address and size, and decrypts only a 4 KB head to decide.

**Metadata comes from the pack database**, matched on pack number *and* CALID —
that is what tells the AT and MT ROMs of a multi-ROM pak apart. A module's rows
carry `CID = ---`, so they describe the pack, not the ROM; those are marked
`database-pack` and deliberately excluded from output naming.

## Open

1. **The header key.** Everything else is a workaround for it, honest but a
   workaround. Best leads: pull the constant out of `FlashWrite.exe` (look for
   `CryptDeriveKey`/`CryptHashData` call sites), or a GPU bruteforce on the
   40-bit derived key with the CSV header row as known plaintext.
2. **Code signing -- deliberately deferred.** The Nuitka build is done and
   verified: `packaging/build.ps1` produces a 12 MB `subaru-pak-gui.exe` in a
   73 MB folder, stamped `DITCH-HOOK LLC`, pack database bundled, launches
   clean. Releases ship unsigned for now, with `dist/SHA256SUMS.txt` for
   integrity; users get one "More info -> Run anyway" click. Revisit when that
   friction costs adoption, or for shops whose IT blocks unsigned binaries.
   `packaging/sign.ps1` is ready and signing is a post-build step, so nothing
   has to change to adopt it. When buying: an OV certificate issued to
   DITCH-HOOK LLC, from a traditional CA on a 1-3 year term with a hardware
   token (not the Azure monthly service, whose organisation-history requirement
   a young LLC may not meet). Since June 2023 no CA issues a plain `.pfx`.
   Timestamped signatures stay valid after the certificate expires, so a lapsed
   cert never breaks already-published binaries.
3. **Other regional databases.** Only `N_AMERICA` is bundled. `--db` already
   takes another CSV; `keys.py` reads columns by name, so EC/AU/GE should work.
4. **More vectors.** `22611AG83D.pak` converts cleanly (`E6PF101A`, 512 KB,
   `denso`, checksum ok) but has no expected file, so it is only covered as a
   metadata/negative case. A known-good output for it would add an SH7055 vector.
5. **Licence.** MIT was chosen as the default (HANDOFF left it to the dev);
   `LICENSE` and `pyproject.toml` both say so. Change both if GPL is preferred.
