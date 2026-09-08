"""GUI smoke test: drop a pak in, get a converted ROM out.

Runs headless (``QT_QPA_PLATFORM=offscreen``) and is skipped where PySide6 is
not installed, so the core test suite never depends on Qt.
"""

import os

import pytest

from conftest import VECTORS, expected_bytes, pak_path, requires_test_data

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="GUI extra not installed")
pytestmark = requires_test_data

from PySide6.QtCore import QSettings           # noqa: E402
from PySide6.QtWidgets import QApplication, QDialog   # noqa: E402

from subaru_pak.gui import app as gui           # noqa: E402


def gui_battle_input(dialog):
    """The QInputDialog class as the battle module sees it, for monkeypatching."""
    from subaru_pak.gui import battle
    return battle.QInputDialog


@pytest.fixture(scope="module")
def qapp():
    application = QApplication.instance() or QApplication([])
    yield application
    application.processEvents()


def pump(application, window, timeout_ms=120_000):
    """Run the event loop until every queued job has reported back."""
    waited = 0
    while window.pending and waited < timeout_ms:
        window.pool.waitForDone(50)
        application.processEvents()
        waited += 50
    for _ in range(5):
        application.processEvents()
    assert not window.pending, "jobs did not finish in time"


@pytest.fixture
def settings(tmp_path):
    """Isolated settings: tests must never touch the user's real registry."""
    return QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)


@pytest.fixture
def window(qapp, tmp_path, settings):
    win = gui.MainWindow(settings=settings)
    win.out_dir = str(tmp_path)
    yield win
    win.close()


def test_dropping_a_pak_shows_its_roms(qapp, window):
    window.add_paths([pak_path("UD-S211B.pak")])
    pump(qapp, window)
    card = window.cards[pak_path("UD-S211B.pak")]
    assert "2 ROMs ready" in card.status.text()
    assert window.convert_button.isEnabled()


def test_convert_writes_the_expected_bytes(qapp, window, tmp_path):
    window.add_paths([pak_path("22765AJ13F.pak")])
    pump(qapp, window)
    window.convert_all()
    pump(qapp, window)

    card = window.cards[pak_path("22765AJ13F.pak")]
    assert card.status.text() == "converted"
    name = VECTORS["22765AJ13F.pak"]["EB4I350A_r.sob"]
    assert (tmp_path / name).read_bytes() == expected_bytes(name)
    assert len(card.written) == 1


def test_a_folder_of_paks_is_expanded(qapp, window):
    window.add_paths([os.path.dirname(pak_path("22765AJ13F.pak"))])
    pump(qapp, window)
    assert len(window.cards) == 4


def test_a_bad_file_reports_instead_of_crashing(qapp, window, tmp_path):
    junk = tmp_path / "broken.pak"
    junk.write_bytes(b"not a pak")
    window.add_paths([str(junk)])
    pump(qapp, window)
    assert "cannot read" in window.cards[str(junk)].status.text()
    assert not window.convert_button.isEnabled()


def test_non_pak_files_are_refused_politely(qapp, window, tmp_path):
    other = tmp_path / "notes.txt"
    other.write_text("hello")
    window.add_paths([str(other)])
    assert not window.cards
    assert "not .pak" in window.message.text()


def test_clear_empties_the_list(qapp, window):
    window.add_paths([pak_path("22765AJ13F.pak")])
    pump(qapp, window)
    window.clear()
    assert not window.cards and not window.results


def test_both_themes_produce_a_stylesheet(qapp, window):
    window.theme = "light"
    window.apply_theme()
    light = window.styleSheet()
    window.theme = "dark"
    window.apply_theme()
    assert window.dark and window.styleSheet() != light
    for palette in gui.PALETTES.values():
        assert set(palette) == set(gui.PALETTES["light"])


def test_system_theme_follows_windows(qapp, window):
    window.theme = "system"
    assert window.dark == gui.system_prefers_dark()


def test_settings_dialog_shows_the_current_choices(qapp, window):
    window.theme, window.extension = "dark", ".bin"
    dialog = gui.SettingsDialog(window.theme, window.extension, window)
    assert dialog.values() == ("dark", ".bin")
    dialog.deleteLater()


def test_settings_dialog_defaults_to_automatic_and_system(qapp):
    dialog = gui.SettingsDialog("system", "", None)
    assert dialog.values() == ("system", "")
    dialog.deleteLater()


def test_settings_are_applied_and_persisted(qapp, window, settings, monkeypatch):
    monkeypatch.setattr(gui.SettingsDialog, "exec", lambda self: QDialog.Accepted)
    monkeypatch.setattr(gui.SettingsDialog, "values", lambda self: ("dark", ".bin"))
    window.open_settings()

    assert (window.theme, window.extension) == ("dark", ".bin")
    assert window.dark
    assert settings.value("theme") == "dark"
    assert settings.value("extension") == ".bin"

    # A fresh window on the same settings comes up the same way.
    reopened = gui.MainWindow(settings=settings)
    assert (reopened.theme, reopened.extension) == ("dark", ".bin")
    reopened.close()


def test_cancelling_settings_changes_nothing(qapp, window, monkeypatch):
    before = (window.theme, window.extension)
    monkeypatch.setattr(gui.SettingsDialog, "exec", lambda self: QDialog.Rejected)
    monkeypatch.setattr(gui.SettingsDialog, "values", lambda self: ("dark", ".bin"))
    window.open_settings()
    assert (window.theme, window.extension) == before


def test_extension_choice_reaches_the_card_names(qapp, window, monkeypatch):
    """Changing the extension must re-scan: cards show what will be written."""
    window.add_paths([pak_path("22765AJ13F.pak")])
    pump(qapp, window)
    card = window.cards[pak_path("22765AJ13F.pak")]
    assert window.results[card.path].roms[0].filename.endswith(".hex")

    monkeypatch.setattr(gui.SettingsDialog, "exec", lambda self: QDialog.Accepted)
    monkeypatch.setattr(gui.SettingsDialog, "values", lambda self: ("system", ".bin"))
    window.open_settings()
    pump(qapp, window)
    assert window.results[card.path].roms[0].filename.endswith(".bin")


def test_chosen_extension_is_what_gets_written(qapp, window, tmp_path):
    window.extension = ".bin"
    window.add_paths([pak_path("22765AJ13F.pak")])
    pump(qapp, window)
    window.convert_all()
    pump(qapp, window)
    written = [p.name for p in tmp_path.iterdir() if p.suffix == ".bin"]
    assert written == ["EB4I350A-2016-CDM-Subaru-Legacy-2.5i-MT.bin"]
    assert (tmp_path / written[0]).read_bytes() == expected_bytes(
        "EB4I350A-2016-CDM-Subaru-Legacy-2.5i-MT.hex")


def test_output_folder_choice_is_remembered(qapp, window, settings, tmp_path,
                                            monkeypatch):
    target = str(tmp_path / "chosen")
    monkeypatch.setattr(gui.QFileDialog, "getExistingDirectory",
                        staticmethod(lambda *a, **k: target))
    window.choose_output()
    assert window.out_dir == target
    assert settings.value("out_dir") == target


# -- the PAK battle (key recovery UI) ---------------------------------------

def _pump_worker(qapp, dialog, timeout_ms=30000):
    waited = 0
    while dialog.summary is None and waited < timeout_ms:
        if dialog._thread is not None:
            dialog._thread.wait(50)
        qapp.processEvents()
        waited += 50
    for _ in range(10):
        qapp.processEvents()


def test_battle_recovers_and_reports(qapp):
    from subaru_pak.gui.battle import BattleDialog
    dialog = BattleDialog(pak_path("UD-S211B.pak"), dark=True)
    got = {}
    dialog.recovered.connect(lambda s: got.update(s))
    dialog.on_fight()                       # skip the intro timers, start at once
    _pump_worker(qapp, dialog)
    assert got.get("rc2") == "EC10FDDB"
    cids = {r["cid"]: r["swap_key_name"] for r in got.get("roms", [])}
    assert cids == {"A2WC412D": "denso", "A2WC412I": "denso"}   # writer excluded
    dialog.close()


def test_battle_foe_is_named_from_the_database(qapp):
    from subaru_pak.gui.battle import BattleDialog
    dialog = BattleDialog(pak_path("UD-S211B.pak"))
    assert dialog.foe_name == "FORESTER"
    dialog.close()


def test_battle_run_cancels_without_crashing(qapp):
    from subaru_pak.gui.battle import BattleDialog
    dialog = BattleDialog(pak_path("22765AJ13F.pak"))
    dialog.on_run()                         # RUN before fighting
    qapp.processEvents()
    dialog.close()


def test_winning_a_battle_registers_the_keys(qapp, window, monkeypatch):
    """A recovered swap key must join the candidate set so detection finds it."""
    from subaru_pak import keys
    before = len(keys.all_swap_keys())
    fake_words = (0x1111, 0x2222, 0x3333, 0x4444)
    summary = {"rc2": "DEADBEEF",
               "roms": [{"cid": "ZZ9Z999Z", "swap_key": fake_words,
                         "swap_key_name": "recovered_ZZ9Z999Z"}]}
    window.cards[pak_path("22765AJ13F.pak")] = type(
        "Stub", (), {"set_status": lambda *a, **k: None,
                     "path": pak_path("22765AJ13F.pak")})()
    window._on_recovered(pak_path("22765AJ13F.pak"), summary)
    assert window.recovered_rc2[pak_path("22765AJ13F.pak")] == "DEADBEEF"
    assert any(k == fake_words for _, k in keys.all_swap_keys())
    keys.EXTRA_SWAP_KEYS.clear()            # don't leak into other tests


def test_battle_sprite_matches_rom_type(qapp):
    """Cat-eared sprite for an engine ROM (.sob), the angry one for a module."""
    from subaru_pak.gui.battle import BattleDialog
    engine = BattleDialog(pak_path("22765AJ13F.pak"))     # EB4I350A_r.sob
    assert engine.foe_sprite_file == "pak_file_pokemon2.jpg"
    engine.close()
    module = BattleDialog(pak_path("82201AL30D.pak"))      # DF105742...mot
    assert module.foe_sprite_file == "pak_file_pokemon1.jpg"
    module.close()


def test_enter_key_accepts_a_valid_keyword(qapp, monkeypatch):
    from subaru_pak.gui.battle import BattleDialog
    dialog = BattleDialog(pak_path("22765AJ13F.pak"))
    got = {}
    dialog.recovered.connect(lambda s: got.update(s))
    monkeypatch.setattr(gui_battle_input(dialog), "getText",
                        staticmethod(lambda *a, **k: ("88295d8a", True)))
    dialog.on_enter_key()
    assert dialog.summary == {"rc2": "88295D8A"}      # upper-cased
    assert got == {"rc2": "88295D8A"}
    dialog.close()


def test_enter_key_rejects_non_hex_without_false_success(qapp, monkeypatch):
    from subaru_pak.gui.battle import BattleDialog
    dialog = BattleDialog(pak_path("22765AJ13F.pak"))
    monkeypatch.setattr(gui_battle_input(dialog), "getText",
                        staticmethod(lambda *a, **k: ("not a key", True)))
    dialog.on_enter_key()
    assert dialog.summary is None                     # nothing adopted
    assert "hex" in dialog.message.text().lower()
    dialog.close()
