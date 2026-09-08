"""The CLI contract: output shape, JSON on stdout, and exit codes."""

import json
import os

import pytest
from click.testing import CliRunner

from conftest import VECTORS, expected_bytes, pak_path, requires_test_data
from subaru_pak import cli

pytestmark = requires_test_data


@pytest.fixture
def run():
    runner = CliRunner()
    return lambda *args, **kwargs: runner.invoke(cli.main, list(args), **kwargs)


def test_info_writes_nothing_and_succeeds(run, tmp_path):
    result = run("info", pak_path("22765AJ13F.pak"))
    assert result.exit_code == 0
    assert "EB4I350A" in result.output
    assert "EB4I350A-2016-CDM-Subaru-Legacy-2.5i-MT.hex" in result.output
    assert not list(tmp_path.iterdir())


def test_info_json_is_parseable(run):
    result = run("info", "--json", pak_path("UD-S211B.pak"))
    assert result.exit_code == 0
    records = json.loads(result.stdout)
    assert [r["cid"] for r in records] == ["A2WC412D", "A2WC412I"]
    assert {r["transmission"] for r in records} == {"AT", "MT"}
    assert all(r["status"] == "ok" for r in records)


def test_convert_writes_named_roms(run, tmp_path):
    result = run("convert", pak_path("22765AJ13F.pak"), "--out", str(tmp_path))
    assert result.exit_code == 0
    name = VECTORS["22765AJ13F.pak"]["EB4I350A_r.sob"]
    written = tmp_path / name
    assert written.exists()
    assert written.read_bytes() == expected_bytes(name)


def test_convert_json_records_carry_the_output_path(run, tmp_path):
    result = run("convert", pak_path("82201AL30D.pak"), "--out", str(tmp_path),
                 "--json")
    assert result.exit_code == 0
    records = json.loads(result.stdout)
    assert len(records) == 1
    record = records[0]
    assert record["status"] == "ok"
    assert record["key"] == "module_biu_82201"
    assert record["checksum"] == "n/a"
    assert os.path.basename(record["path"]) == \
        "DF105742_SKE_REPchg2__82201AL30D.bin"
    assert os.path.exists(record["path"])


def test_dry_run_converts_without_writing(run, tmp_path):
    result = run("convert", pak_path("22765AJ13F.pak"), "--out", str(tmp_path),
                 "--dry-run")
    assert result.exit_code == 0
    assert not list(tmp_path.iterdir())


def test_extension_can_be_forced(run, tmp_path):
    run("convert", pak_path("22765AJ13F.pak"), "--out", str(tmp_path), "--bin")
    assert [p.suffix for p in tmp_path.iterdir()] == [".bin"]


def test_no_name_uses_the_member_name(run, tmp_path):
    run("convert", pak_path("22765AJ13F.pak"), "--out", str(tmp_path), "--no-name")
    assert [p.name for p in tmp_path.iterdir()] == ["EB4I350A_r.hex"]


def test_directory_argument_is_expanded(run, tmp_path):
    result = run("convert", os.path.dirname(pak_path("22765AJ13F.pak")),
                 "--out", str(tmp_path), "--json")
    assert result.exit_code == 0
    records = json.loads(result.stdout)
    assert len(records) == 5              # four paks, one of which holds two ROMs
    assert len(list(tmp_path.iterdir())) == 5


def test_a_bad_file_fails_with_exit_1(run, tmp_path):
    junk = tmp_path / "notreally.pak"
    junk.write_bytes(b"nope")
    result = run("convert", str(junk), "--out", str(tmp_path))
    assert result.exit_code == 1
    assert "not a PAK" in result.output


def test_missing_input_is_a_usage_error(run):
    assert run("convert").exit_code == 2


def test_no_match_reports_cleanly(run, tmp_path):
    result = run("convert", str(tmp_path / "*.pak"), "--out", str(tmp_path))
    assert result.exit_code == 1
    assert "no .pak files matched" in result.output


def test_bad_download_address_is_rejected(run, tmp_path):
    result = run("convert", pak_path("22765AJ13F.pak"), "--out", str(tmp_path),
                 "--download", "banana")
    assert result.exit_code == 2
    assert "not an address" in result.output


def test_forced_offset_changes_the_image(run, tmp_path):
    run("convert", pak_path("22765AJ13F.pak"), "--out", str(tmp_path),
        "--download", "0x2000")
    written = next(tmp_path.iterdir())
    assert written.read_bytes() != expected_bytes(
        VECTORS["22765AJ13F.pak"]["EB4I350A_r.sob"])


def test_keys_command_lists_every_key(run):
    result = run("keys")
    assert result.exit_code == 0
    assert "denso_can" in result.output
    assert "module_biu_82201" in result.output
    assert len(result.output.strip().splitlines()) == 12


# -- launched from Explorer rather than a shell -----------------------------

def test_bare_paths_are_treated_as_convert(tmp_path):
    """Dropping paks on the exe passes them as bare arguments."""
    dropped = str(tmp_path / "thing.pak")
    argv = cli.implicit_convert([dropped])
    assert argv[0] == "convert"
    assert dropped in argv
    assert argv[-2] == "--out"
    # Beside the pak, not the working directory a drag-and-drop happens to have.
    assert argv[-1] == os.path.dirname(os.path.abspath(dropped))


def test_multiple_dropped_paks_share_the_first_ones_folder(tmp_path):
    first, second = str(tmp_path / "one.pak"), str(tmp_path / "two.pak")
    argv = cli.implicit_convert([first, second])
    assert argv.count("--out") == 1
    assert argv[-1] == os.path.dirname(os.path.abspath(first))


def test_an_explicit_out_is_not_overridden(tmp_path):
    argv = cli.implicit_convert(["some.pak", "--out", str(tmp_path)])
    assert argv.count("--out") == 1
    assert argv[-1] == str(tmp_path)


def test_real_subcommands_and_options_pass_through_untouched():
    for argv in (["convert", "x.pak"], ["info", "x.pak"], ["keys"],
                 ["--version"], ["-h"], []):
        assert cli.implicit_convert(list(argv)) == argv


def test_console_detection_does_not_explode():
    assert cli.owns_its_console() in (True, False)


@requires_test_data
def test_implicit_convert_actually_converts(tmp_path):
    """End to end: the drag-and-drop argv shape must really work."""
    import shutil
    dropped = tmp_path / "UD-S211B.pak"
    shutil.copy(pak_path("UD-S211B.pak"), dropped)
    result = CliRunner().invoke(cli.main, cli.implicit_convert([str(dropped)]))
    assert result.exit_code == 0
    written = sorted(p.name for p in tmp_path.glob("*.hex"))
    assert written == sorted(VECTORS["UD-S211B.pak"].values())


# -- one binary, two personalities ------------------------------------------

def _run_entry(monkeypatch, argv, from_explorer, gui_available=True):
    """Drive run() with the environment faked, recording which path it took."""
    import atexit
    taken = {}
    monkeypatch.setattr(cli.sys, "argv", ["pak2bin.exe", *argv])
    monkeypatch.setattr(cli, "owns_its_console", lambda: from_explorer)
    monkeypatch.setattr(cli, "_launch_gui",
                        lambda: (taken.__setitem__("gui", True), gui_available)[1])
    monkeypatch.setattr(cli, "main",
                        lambda args=None, **kw: taken.__setitem__("cli", args))
    # The real handler waits on input() at interpreter exit -- correct in the
    # binary, fatal in a test runner, which would hang forever at teardown.
    monkeypatch.setattr(atexit, "register",
                        lambda fn, *a, **k: taken.setdefault("pause", True))
    cli.run()
    return taken


def test_double_click_opens_the_window(monkeypatch):
    assert _run_entry(monkeypatch, [], from_explorer=True) == {"gui": True}


def test_dropped_paks_open_the_window_too(monkeypatch):
    taken = _run_entry(monkeypatch, ["C:/x/some.pak"], from_explorer=True)
    assert taken == {"gui": True}


def test_a_shell_with_no_arguments_gets_the_help(monkeypatch):
    taken = _run_entry(monkeypatch, [], from_explorer=False)
    assert "gui" not in taken and taken["cli"] == []


def test_an_explicit_subcommand_always_stays_cli(monkeypatch):
    for argv in (["convert", "x.pak"], ["info", "x.pak"], ["--version"], ["-h"]):
        taken = _run_entry(monkeypatch, list(argv), from_explorer=True)
        assert "gui" not in taken, argv
        assert taken["cli"] == argv


def test_without_a_gui_built_in_it_falls_back_to_the_cli(monkeypatch):
    """The CLI-only build must not silently do nothing when double-clicked."""
    taken = _run_entry(monkeypatch, [], from_explorer=True, gui_available=False)
    assert taken["gui"] is True          # tried the window
    assert taken["cli"] == []            # then printed the help
    assert taken["pause"] is True        # and held the console open to read it
