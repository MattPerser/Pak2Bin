"""Command line interface -- ``subaru-pak convert`` and ``subaru-pak info``.

Machine-readable by design: with ``--json`` the records go to stdout and every
log line to stderr, so a caller can pipe one and watch the other.

Exit codes
----------
0   everything asked for was converted
1   at least one pak or ROM failed (details in the output)
2   usage error
"""

from __future__ import annotations

import glob
import json
import os
import sys

import click

from . import __version__
from .convert import ConversionError, convert_pak, write_results
from .keys import CRYPT_KEYS, default_database
from . import pak as pakmod
from .pak import PakError

EXIT_OK, EXIT_FAILED, EXIT_USAGE = 0, 1, 2

_CHECKSUM_MARK = {"ok": "checksum ok", "bad": "CHECKSUM BAD",
                  "disabled": "checksum disabled", "n/a": "no checksum table",
                  "unknown": "checksum unknown"}


def _echo(message, quiet=False, err=True):
    if not quiet:
        click.echo(message, err=err)


def _expand(inputs) -> list[str]:
    """Expand directories and glob patterns into a sorted list of pak files."""
    paths: list[str] = []
    for item in inputs:
        if os.path.isdir(item):
            paths.extend(sorted(glob.glob(os.path.join(item, "**", "*.pak"),
                                          recursive=True)))
        elif any(ch in item for ch in "*?["):
            paths.extend(sorted(glob.glob(item, recursive=True)))
        else:
            paths.append(item)
    seen, unique = set(), []
    for path in paths:
        key = os.path.normcase(os.path.abspath(path))
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def _load_database(extra):
    try:
        return default_database(extra)
    except OSError as exc:
        raise click.ClickException(f"cannot read pack database: {exc}") from exc


def _describe(rom) -> str:
    """One line identifying a ROM, without overclaiming.

    A module's database row describes the pack rather than the ROM, so its
    vehicle details are labelled as such instead of being read as the module's
    own year and transmission.
    """
    meta = rom.metadata
    bits = [meta.cid or rom.member]
    if meta.unit:
        bits.append(meta.unit)
    vehicle = [v for v in (meta.model, meta.year, meta.market, meta.transmission)
               if v and v != "-"]
    if vehicle:
        bits.append("pack fits " + " ".join(vehicle)
                    if meta.source == "database-pack" else " | ".join(vehicle))
    return " | ".join(bits)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="subaru-pak")
def main():
    """Convert Subaru FlashWrite .pak files to raw ROM images."""


@main.command()
@click.argument("paks", nargs=-1, required=True, type=click.Path())
@click.option("-o", "--out", "out_dir", default=".", show_default=True,
              type=click.Path(file_okay=False),
              help="Directory to write ROMs into.")
@click.option("--json", "as_json", is_flag=True,
              help="Emit one JSON record per ROM on stdout.")
@click.option("--hex", "extension", flag_value=".hex",
              help="Force the .hex extension.")
@click.option("--bin", "extension", flag_value=".bin",
              help="Force the .bin extension.")
@click.option("--no-name", is_flag=True,
              help="Name outputs after the archive member, not the CALID.")
@click.option("--key", "rc2_key", metavar="HEX",
              help="RC2 pack key, when the pack database does not have it.")
@click.option("--db", "database_path", type=click.Path(exists=True, dir_okay=False),
              help="Additional Pack File Database CSV to consult.")
@click.option("--swap-key", type=click.Choice([name for name, _ in CRYPT_KEYS]),
              help="Force a swap-cipher key instead of detecting it.")
@click.option("--download", "download", metavar="ADDR",
              help="Force the flash offset (e.g. 0x2000) instead of inferring it.")
@click.option("--fix-checksum", is_flag=True,
              help="Rewrite failing subarudbw block checksums in the output.")
@click.option("--recover", is_flag=True,
              help="Brute-force a missing RC2 or swap key (minutes, uses all cores).")
@click.option("--dry-run", is_flag=True, help="Convert but write nothing.")
@click.option("-q", "--quiet", is_flag=True, help="Only report failures.")
def convert(paks, out_dir, as_json, extension, no_name, rc2_key, database_path,
            swap_key, download, fix_checksum, recover, dry_run, quiet):
    """Convert one or more PAKS (files, globs or directories) to ROM images."""
    targets = _expand(paks)
    if not targets:
        raise click.ClickException("no .pak files matched")
    try:
        address = int(download, 0) if download else None
    except ValueError:
        raise click.BadParameter(f"not an address: {download}", param_hint="--download")

    database = _load_database(database_path)
    records, failed = [], False

    for path in targets:
        try:
            recover_kwargs = None
            if recover:
                recover_kwargs = {"progress": _progress_printer(path, quiet or as_json)}
            result = convert_pak(path, database=database, rc2_key=rc2_key,
                                 download=address, swap_key=swap_key,
                                 extension=extension, fix_checksum=fix_checksum,
                                 recover=recover, recover_kwargs=recover_kwargs)
        except (ConversionError, PakError, OSError, ValueError) as exc:
            failed = True
            _echo(click.style(f"{os.path.basename(path)}: {exc}", fg="red"))
            if as_json:
                records.append({"status": "error", "pak": path, "message": str(exc)})
            continue

        written = [] if dry_run else write_results(result, out_dir,
                                                   use_names=not no_name)
        written_by_member = dict(zip([r.member for r in result.roms if r.ok], written))

        _echo(click.style(f"{os.path.basename(path)}", bold=True)
              + f"  ({len(result.roms)} ROM(s), key {result.rc2_key})", quiet)
        for rom in result.roms:
            record = rom.to_dict()
            record["pak"] = path
            record["path"] = written_by_member.get(rom.member, "")
            records.append(record)
            if rom.ok:
                out_path = record["path"] or rom.filename
                _echo(f"  {click.style('OK', fg='green')}  {_describe(rom)}\n"
                      f"      {rom.size // 1024} KB | key {rom.key} ({rom.key_method}) "
                      f"| offset {rom.download:#x} ({rom.download_source}) "
                      f"| {_CHECKSUM_MARK.get(rom.checksum, rom.checksum)}\n"
                      f"      -> {out_path}", quiet)
            else:
                failed = True
                _echo(f"  {click.style('FAIL', fg='red')} {rom.member}: "
                      f"{rom.status} -- {rom.message}")
        for entry in result.skipped:
            _echo(click.style(f"  skip {entry['member']}: {entry['reason']}",
                              fg="bright_black"), quiet)
        if not result.roms:
            failed = True
            _echo(click.style(f"  no ROM found in {os.path.basename(path)}", fg="red"))

    if as_json:
        click.echo(json.dumps(records, indent=2))
    sys.exit(EXIT_FAILED if failed else EXIT_OK)


@main.command()
@click.argument("paks", nargs=-1, required=True, type=click.Path())
@click.option("--json", "as_json", is_flag=True, help="Emit JSON on stdout.")
@click.option("--key", "rc2_key", metavar="HEX", help="RC2 pack key override.")
@click.option("--db", "database_path", type=click.Path(exists=True, dir_okay=False),
              help="Additional Pack File Database CSV to consult.")
def info(paks, as_json, rc2_key, database_path):
    """Show what is inside PAKS without converting or writing anything."""
    targets = _expand(paks)
    if not targets:
        raise click.ClickException("no .pak files matched")
    database = _load_database(database_path)
    records, failed = [], False

    for path in targets:
        try:
            result = convert_pak(path, database=database, rc2_key=rc2_key,
                                 metadata_only=True)
        except (ConversionError, PakError, OSError, ValueError) as exc:
            failed = True
            _echo(click.style(f"{os.path.basename(path)}: {exc}", fg="red"))
            if as_json:
                records.append({"status": "error", "pak": path, "message": str(exc)})
            continue

        if not as_json:
            click.echo(click.style(os.path.basename(path), bold=True))
            click.echo(f"  pack {result.pack_number} | RC2 key {result.rc2_key}")
            for rom in result.roms:
                click.echo(f"  ROM  {_describe(rom)}")
                if rom.download_source == "unknown":
                    click.echo(f"       member {rom.member} | size and offset "
                               f"unknown until converted")
                else:
                    click.echo(f"       member {rom.member} | cal {rom.covered:#x}"
                               f" | offset {rom.download:#x} ({rom.download_source})"
                               f" | image {rom.size // 1024} KB")
                click.echo(f"       would write {rom.filename}")
            for entry in result.skipped:
                click.echo(click.style(f"  skip {entry['member']}: {entry['reason']}",
                                       fg="bright_black"))
        for rom in result.roms:
            record = rom.to_dict()
            record["pak"] = path
            records.append(record)
        if not result.roms:
            failed = True
            _echo(click.style(f"  no ROM found in {os.path.basename(path)}", fg="red"))

    if as_json:
        click.echo(json.dumps(records, indent=2))
    sys.exit(EXIT_FAILED if failed else EXIT_OK)


def _progress_printer(path, silent):
    """A throttled progress callback that draws a one-line status to stderr."""
    state = {"last": 0.0}

    def report(p):
        if silent:
            return
        now = __import__("time").monotonic()
        if now - state["last"] < 0.5 and p.fraction < 1.0:
            return
        state["last"] = now
        bar = int(p.fraction * 24)
        eta = "" if p.eta == float("inf") else f" eta {int(p.eta)//60}m{int(p.eta)%60:02d}s"
        click.echo(f"\r  [{'#'*bar}{'.'*(24-bar)}] {p.fraction*100:5.1f}% "
                   f"{p.rate/1e6:.1f}M/s{eta}   ", nl=False, err=True)
    return report


@main.command(name="recover")
@click.argument("pak", type=click.Path())
@click.option("--db", "database_path", type=click.Path(exists=True, dir_okay=False),
              help="Additional Pack File Database CSV to consult.")
@click.option("--workers", type=int, default=None,
              help="Worker processes (default: every core).")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON on stdout.")
def recover_cmd(pak, database_path, workers, as_json):
    """Brute-force the key(s) for a PAK no database covers.

    Tries the known keywords first, then searches the 8-hex RC2 keyspace, then
    the swap-cipher key of each ROM if that too is unknown. Minutes, not seconds.
    """
    from . import recover as rec
    from .keys import default_database

    database = _load_database(database_path)
    try:
        archive = pakmod.read(pak)
    except (PakError, OSError) as exc:
        raise click.ClickException(str(exc))

    payloads = sorted((m for m in archive.members if m.is_payload),
                      key=lambda m: m.length, reverse=True)
    if not payloads:
        raise click.ClickException("no ROM-shaped members in this pak")

    _echo(click.style(f"{os.path.basename(pak)}", bold=True)
          + f" -- searching {rec.HEX_KEYSPACE:,} keywords across "
          f"{workers or os.cpu_count()} cores", as_json)

    def note(stage):
        _echo(click.style(f"  {stage}...", fg="cyan"), as_json)

    summary = rec.recover_pak_keys(pak, database=database, workers=workers,
                                   stage=note,
                                   progress=_progress_printer(pak, as_json))
    _echo("", as_json)
    summary["pak"] = pak
    summary["pack_number"] = archive.pack_number

    if summary.get("error") or not summary.get("rc2"):
        _echo(click.style(f"  {summary.get('error', 'nothing recovered')}",
                          fg="red"), as_json)
        if as_json:
            _json_swap(summary)
            click.echo(json.dumps(summary, indent=2))
        sys.exit(EXIT_FAILED)

    _echo(click.style(f"  RC2 key: {summary['rc2']}", fg="green")
          + f"  ({summary.get('rc2_stage', '')})", as_json)
    for rom in summary.get("roms", []):
        if rom.get("swap_key"):
            words = " ".join(f"0x{w:04X}" for w in rom["swap_key"])
            _echo(click.style(f"  {rom['cid']}: swap key "
                              f"{rom['swap_key_name']} {words}", fg="green"), as_json)
        else:
            _echo(click.style(f"  {rom['cid']}: swap key NOT found", fg="red"),
                  as_json)
    if as_json:
        _json_swap(summary)
        click.echo(json.dumps(summary, indent=2))
    sys.exit(EXIT_OK)


def _json_swap(summary):
    """Render swap-key tuples as hex strings for JSON output."""
    for rom in summary.get("roms", []):
        if rom.get("swap_key"):
            rom["swap_key"] = [f"0x{w:04X}" for w in rom["swap_key"]]


@main.command(name="keys")
def list_keys():
    """List the swap-cipher keys the converter tries."""
    for name, words in CRYPT_KEYS:
        click.echo(f"{name:<20} " + " ".join(f"0x{word:04X}" for word in words))


@main.command(name="gui")
def launch_gui():
    """Open the drag-and-drop window (needs the [gui] extra)."""
    try:
        from .gui.app import main as gui_main
    except ImportError as exc:                      # pragma: no cover
        raise click.ClickException(
            "the GUI needs PySide6: pip install 'subaru-pak[gui]'") from exc
    gui_main()


# ---------------------------------------------------------------------------
# Being launched from Explorer rather than a shell

_COMMANDS = {"convert", "info", "keys", "gui", "recover"}


def owns_its_console() -> bool:
    """True when this process created the console window it is printing to.

    Double-clicking a console program, or dropping files on it, gives it a
    console of its own that closes the instant it exits -- so any output flashes
    past unread. Launched from an existing shell, that shell is attached to the
    same console and there is nothing to wait for.
    """
    if os.name != "nt":
        return False
    try:
        import ctypes
        buffer = (ctypes.c_uint * 8)()
        count = ctypes.windll.kernel32.GetConsoleProcessList(buffer, 8)
        return count <= 1
    except Exception:                               # pragma: no cover - defensive
        return False


def implicit_convert(argv: list[str]) -> list[str]:
    """Let ``pak2bin.exe some.pak`` and drag-and-drop mean "convert this".

    Dropping files on an executable passes them as bare arguments, which would
    otherwise be read as a missing subcommand. Output goes beside the first pak,
    because the working directory of a drag-and-drop is not somewhere anyone
    wants ROMs written.
    """
    if not argv or argv[0] in _COMMANDS or argv[0].startswith("-"):
        return argv
    argv = ["convert", *argv]
    if not any(a in ("--out", "-o") or a.startswith("--out=") for a in argv):
        paks = [a for a in argv[1:] if not a.startswith("-")]
        if paks:
            argv += ["--out", os.path.dirname(os.path.abspath(paks[0])) or "."]
    return argv


def _launch_gui() -> bool:
    """Open the window, passing on anything dropped. False if there is no GUI."""
    try:
        from .gui.app import main as gui_main
    except ImportError:
        return False
    gui_main()
    return True


def run() -> None:
    """Entry point. A shell tool from a shell, an app from Explorer.

    Double-clicked, or with paks dropped on it, this opens the window -- which
    is what a Windows user expects, and a console program that flashes and
    vanishes is not. Run from a shell, or given an explicit subcommand or
    option, it stays a command line tool.
    """
    # Without this the bruteforce's worker processes would re-launch the whole
    # frozen app instead of running a search chunk.
    import multiprocessing
    multiprocessing.freeze_support()
    argv = sys.argv[1:]
    from_explorer = owns_its_console()
    asked_for_cli = bool(argv) and (argv[0] in _COMMANDS or argv[0].startswith("-"))

    if from_explorer and not asked_for_cli and _launch_gui():
        return

    if from_explorer:
        import atexit

        def wait():
            try:
                input("\nPress Enter to close this window...")
            except (EOFError, KeyboardInterrupt, OSError):
                pass

        atexit.register(wait)
    main(args=implicit_convert(argv))


if __name__ == "__main__":                          # pragma: no cover
    run()
