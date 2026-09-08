"""Drag-and-drop PAK converter for technicians.

Drop paks (or a folder) on the window, read the card for each ROM it found, hit
Convert.  Scanning and converting both run on a thread pool so the window never
freezes on a 3 MB RC2 pass.
"""

from __future__ import annotations

import os
import sys
import traceback

from PySide6.QtCore import (QObject, QRunnable, QSettings, QThreadPool, Qt,
                            QTimer, Signal, Slot)
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (QApplication, QComboBox, QDialog,
                               QDialogButtonBox, QFileDialog, QFrame,
                               QHBoxLayout, QLabel, QMainWindow, QMessageBox,
                               QProgressBar, QPushButton, QScrollArea,
                               QSizePolicy, QVBoxLayout, QWidget)

from .. import __version__
from ..convert import ConversionError, convert_pak, inspect_pak, write_results
from ..pak import PakError

# --------------------------------------------------------------------------
# theme

PALETTES = {
    "light": {
        "bg": "#f4f5f7", "panel": "#ffffff", "line": "#dcdfe4",
        "text": "#1c1f24", "dim": "#6b727d", "accent": "#0b63c5",
        "accent_text": "#ffffff", "drop": "#eef3fb", "drop_line": "#9dbde8",
        "ok": "#1a7f3c", "warn": "#a35c00", "bad": "#c22f2f",
    },
    "dark": {
        "bg": "#191b1f", "panel": "#23262b", "line": "#34383f",
        "text": "#e7e9ec", "dim": "#9aa1ac", "accent": "#4d9bf0",
        "accent_text": "#0d1117", "drop": "#1e2530", "drop_line": "#3a5a86",
        "ok": "#55c07a", "warn": "#d99b3a", "bad": "#e9686b",
    },
}


def stylesheet(colors: dict) -> str:
    return f"""
    QWidget {{ background: {colors['bg']}; color: {colors['text']};
               font-size: 13px; }}
    /* Labels and rom blocks sit on cards and the drop zone, so they must take
       whatever is behind them rather than repainting the window colour. */
    QLabel, QWidget#romBlock {{ background: transparent; }}
    QScrollArea, QScrollArea > QWidget > QWidget {{ background: {colors['bg']};
               border: none; }}
    QFrame#card {{ background: {colors['panel']}; border: 1px solid {colors['line']};
               border-radius: 10px; }}
    QFrame#dropzone {{ background: {colors['drop']};
               border: 2px dashed {colors['drop_line']}; border-radius: 14px; }}
    QFrame#dropzone[hot="true"] {{ border-color: {colors['accent']};
               background: {colors['panel']}; }}
    QLabel#title {{ font-size: 22px; font-weight: 600; }}
    QLabel#dim, QLabel#path {{ color: {colors['dim']}; }}
    QLabel#ready {{ color: {colors['ok']}; font-weight: 700; }}
    QLabel#romTitle {{ font-size: 15px; font-weight: 600; }}
    QLabel#ok {{ color: {colors['ok']}; font-weight: 600; }}
    QLabel#warn {{ color: {colors['warn']}; font-weight: 600; }}
    QLabel#bad {{ color: {colors['bad']}; font-weight: 600; }}
    QPushButton {{ background: {colors['panel']}; border: 1px solid {colors['line']};
               border-radius: 7px; padding: 7px 14px; }}
    QPushButton:hover {{ border-color: {colors['accent']}; }}
    QPushButton:disabled {{ color: {colors['dim']}; border-color: {colors['line']}; }}
    QPushButton#primary {{ background: {colors['accent']};
               color: {colors['accent_text']}; border: none; font-weight: 600;
               padding: 10px 22px; font-size: 14px; }}
    QPushButton#primary:disabled {{ background: {colors['line']};
               color: {colors['dim']}; }}
    QProgressBar {{ background: {colors['panel']}; border: 1px solid {colors['line']};
               border-radius: 7px; height: 14px; text-align: center; }}
    QProgressBar::chunk {{ background: {colors['accent']}; border-radius: 6px; }}
    """


def system_prefers_dark() -> bool:
    try:                                            # Qt 6.5+
        return QGuiApplication.styleHints().colorScheme() == Qt.ColorScheme.Dark
    except (AttributeError, TypeError):             # pragma: no cover
        return False


# --------------------------------------------------------------------------
# background work


class Signals(QObject):
    scanned = Signal(str, object, str)      # path, PakResult|None, error
    converted = Signal(str, object, object, str)   # path, PakResult|None, written, error
    finished = Signal(str)                  # path


class ScanJob(QRunnable):
    """Read a pak's metadata -- cheap, no swap decryption, nothing written."""

    def __init__(self, path: str, signals: Signals, extension: str = "",
                 rc2_key: str | None = None):
        super().__init__()
        self.path, self.signals = path, signals
        self.extension = extension
        self.rc2_key = rc2_key

    @Slot()
    def run(self):
        try:
            result = inspect_pak(self.path, extension=self.extension or None,
                                 rc2_key=self.rc2_key)
            self.signals.scanned.emit(self.path, result, "")
        except (ConversionError, PakError, OSError, ValueError) as exc:
            self.signals.scanned.emit(self.path, None, str(exc))
        except Exception:                           # pragma: no cover - never crash a worker
            self.signals.scanned.emit(self.path, None, traceback.format_exc(limit=3))
        finally:
            self.signals.finished.emit(self.path)


class ConvertJob(QRunnable):
    """The slow one: RC2 the payloads, detect the key, write the images."""

    def __init__(self, path: str, out_dir: str, options: dict, signals: Signals):
        super().__init__()
        self.path, self.out_dir, self.options = path, out_dir, options
        self.signals = signals

    @Slot()
    def run(self):
        try:
            result = convert_pak(self.path, **self.options)
            written = write_results(result, self.out_dir, overwrite=False)
            self.signals.converted.emit(self.path, result, written, "")
        except (ConversionError, PakError, OSError, ValueError) as exc:
            self.signals.converted.emit(self.path, None, [], str(exc))
        except Exception:                           # pragma: no cover
            self.signals.converted.emit(self.path, None, [],
                                        traceback.format_exc(limit=3))
        finally:
            self.signals.finished.emit(self.path)


# --------------------------------------------------------------------------
# widgets


#: Theme choices, as (stored value, label).
THEMES = (("system", "Match Windows"), ("light", "Light"), ("dark", "Dark"))

#: Output extension choices. "" means decide per ROM: .hex for an engine ROM,
#: .bin for a module, which is how the known-good conversions are named.
EXTENSIONS = (("", "Automatic (.hex for ECUs, .bin for modules)"),
              (".hex", "Always .hex"), (".bin", "Always .bin"))


class SettingsDialog(QDialog):
    """Theme and output extension. Small on purpose."""

    def __init__(self, theme: str, extension: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(380)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(8)

        heading = QLabel("Appearance")
        heading.setObjectName("romTitle")
        layout.addWidget(heading)
        self.theme = QComboBox()
        for value, label in THEMES:
            self.theme.addItem(label, value)
        self.theme.setCurrentIndex(max(0, [v for v, _ in THEMES].index(theme)
                                       if theme in [v for v, _ in THEMES] else 0))
        layout.addWidget(self.theme)

        layout.addSpacing(10)
        heading2 = QLabel("Output file extension")
        heading2.setObjectName("romTitle")
        layout.addWidget(heading2)
        self.extension = QComboBox()
        for value, label in EXTENSIONS:
            self.extension.addItem(label, value)
        values = [v for v, _ in EXTENSIONS]
        self.extension.setCurrentIndex(values.index(extension) if extension in values else 0)
        layout.addWidget(self.extension)
        note = QLabel("Both are raw ROM images; the extension is only a naming "
                      "convention.")
        note.setObjectName("dim")
        note.setWordWrap(True)
        layout.addWidget(note)

        layout.addSpacing(12)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def values(self) -> tuple[str, str]:
        return self.theme.currentData(), self.extension.currentData()


class DropZone(QFrame):
    """The big target. Accepts .pak files and folders of them."""

    dropped = Signal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("dropzone")
        self.setAcceptDrops(True)
        self.setMinimumHeight(130)
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        headline = QLabel("Drop .pak files or a folder here")
        headline.setObjectName("title")
        headline.setAlignment(Qt.AlignCenter)
        hint = QLabel("FlashWrite pack files become raw ROM images")
        hint.setObjectName("dim")
        hint.setAlignment(Qt.AlignCenter)
        self.browse = QPushButton("Browse...")
        self.browse.setCursor(Qt.PointingHandCursor)
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(self.browse)
        row.addStretch()
        layout.addStretch()
        layout.addWidget(headline)
        layout.addWidget(hint)
        layout.addSpacing(6)
        layout.addLayout(row)
        layout.addStretch()

    def _set_hot(self, hot: bool):
        self.setProperty("hot", "true" if hot else "false")
        self.style().unpolish(self)
        self.style().polish(self)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._set_hot(True)

    def dragLeaveEvent(self, event):
        self._set_hot(False)

    def dropEvent(self, event):
        self._set_hot(False)
        paths = [url.toLocalFile() for url in event.mimeData().urls()]
        if paths:
            event.acceptProposedAction()
            self.dropped.emit(paths)


class PakCard(QFrame):
    """One pak: its ROMs, their identity, and what happened to them."""

    def __init__(self, path: str, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.path = path
        self.written: list[str] = []
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(16, 14, 16, 14)
        self.layout.setSpacing(6)

        header = QHBoxLayout()
        self.name = QLabel(os.path.basename(path))
        self.name.setObjectName("romTitle")
        self.status = QLabel("reading...")
        self.status.setObjectName("dim")
        header.addWidget(self.name)
        header.addStretch()
        header.addWidget(self.status)
        self.layout.addLayout(header)

        self.body = QVBoxLayout()
        self.body.setSpacing(10)
        self.layout.addLayout(self.body)

    # -- helpers ----------------------------------------------------------
    def _clear_body(self):
        while self.body.count():
            item = self.body.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
            elif item.layout() is not None:
                self._clear_layout(item.layout())

    def _clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()
            elif item.layout() is not None:
                self._clear_layout(item.layout())

    def _line(self, text, object_name="dim"):
        label = QLabel(text)
        label.setObjectName(object_name)
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        return label

    def set_status(self, text, kind="dim"):
        self.status.setText(text)
        self.status.setObjectName(kind)
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)

    # -- states -----------------------------------------------------------
    def show_error(self, message: str, on_battle=None):
        self._clear_body()
        missing_key = "no RC2 key" in message
        if missing_key:
            self.set_status("no key on file", "warn")
            stem = os.path.splitext(os.path.basename(self.path))[0]
            self.body.addWidget(self._line(
                f"No key on file for {stem}. Your Graphics Card is about to "
                f"gain some Exp.", "warn"))
        else:
            self.set_status("cannot read", "bad")
            self.body.addWidget(self._line(message, "bad"))
        if missing_key and on_battle is not None:
            row = QHBoxLayout()
            battle = QPushButton("⚔  Battle for the key")
            battle.setObjectName("primary")
            battle.setCursor(Qt.PointingHandCursor)
            battle.clicked.connect(on_battle)
            row.addWidget(battle)
            row.addStretch()
            holder = QWidget()
            holder.setObjectName("romBlock")
            holder.setLayout(row)
            self.body.addWidget(holder)

    def show_scan(self, result):
        """Metadata only -- what we would write, before any conversion."""
        self._clear_body()
        if not result.roms:
            self.set_status("no ROM inside", "warn")
            reasons = ", ".join(f"{e['member']} ({e['reason']})"
                                for e in result.skipped) or "nothing readable"
            self.body.addWidget(self._line(f"skipped: {reasons}"))
            return
        n = len(result.roms)
        self.set_status(f"{n} {'ROM' if n == 1 else 'ROMs'} ready to convert",
                        "ready")
        for rom in result.roms:
            self.body.addWidget(self._rom_block(rom))

    def show_result(self, result, written: list[str]):
        self._clear_body()
        self.written = list(written)
        failures = [rom for rom in result.roms if not rom.ok]
        if not result.roms:
            self.set_status("no ROM inside", "warn")
        elif failures:
            self.set_status(f"{len(failures)} of {len(result.roms)} failed", "bad")
        else:
            self.set_status("converted", "ok")
        paths = dict(zip([r.member for r in result.roms if r.ok], written))
        for rom in result.roms:
            self.body.addWidget(self._rom_block(rom, paths.get(rom.member)))

    def _rom_block(self, rom, written_path=None) -> QWidget:
        block = QWidget()
        block.setObjectName("romBlock")
        layout = QVBoxLayout(block)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        meta = rom.metadata
        title = QLabel(meta.cid or rom.member)
        title.setObjectName("romTitle")
        badge = QLabel(_checksum_text(rom))
        badge.setObjectName(_checksum_kind(rom))
        row = QHBoxLayout()
        row.addWidget(title)
        row.addStretch()
        row.addWidget(badge)
        layout.addLayout(row)

        if not rom.ok:
            layout.addWidget(self._line(f"{rom.status}: {rom.message}", "bad"))
            return block

        vehicle = " ".join(v for v in (meta.year, meta.model, _engine(meta),
                                       meta.transmission, meta.market)
                           if v and v != "-")
        if vehicle:
            layout.addWidget(self._line(
                ("fits " + vehicle) if meta.source == "database-pack" else vehicle,
                "dim"))
        facts = [meta.unit or "ECU"]
        if rom.size:
            facts += [f"{rom.size // 1024} KB", f"offset {rom.download:#x}"]
        else:                            # the scan could not size this one
            facts.append("size known after converting")
        if rom.key:                      # unknown until the ROM is converted
            facts.append(f"key {rom.key}")
        layout.addWidget(self._line(" | ".join(facts), "dim"))
        layout.addWidget(self._line(
            f"-> {os.path.basename(written_path) if written_path else rom.filename}",
            "path"))
        return block


def _engine(meta) -> str:
    from ..metadata import engine_name
    return engine_name(meta)


def _checksum_text(rom) -> str:
    """Blank before conversion: there is no verdict to give until then."""
    if not rom.ok:
        return "failed"
    return {"ok": "checksum ok", "bad": "checksum BAD", "disabled": "checksum off",
            "n/a": "no checksum"}.get(rom.checksum, "")


def _checksum_kind(rom) -> str:
    if not rom.ok:
        return "bad"
    return {"ok": "ok", "bad": "bad", "disabled": "warn"}.get(rom.checksum, "dim")


# --------------------------------------------------------------------------
# main window


class MainWindow(QMainWindow):
    def __init__(self, settings: QSettings | None = None):
        super().__init__()
        self.setWindowTitle(f"Subaru PAK to BIN  {__version__}")
        self.resize(880, 720)
        self.setAcceptDrops(True)

        self.cards: dict[str, PakCard] = {}
        self.results: dict[str, object] = {}
        self.pool = QThreadPool.globalInstance()
        # Jobs and their signal objects must stay referenced from Python, or the
        # collector can take them out from under the thread they run on.
        self._jobs: list[QRunnable] = []
        self.pending = 0
        self.total_jobs = 0
        self.out_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Subaru ROMs")
        self.settings = settings if settings is not None else QSettings(
            "DITCH-HOOK LLC", "Subaru PAK converter")
        self.theme = str(self.settings.value("theme", "system"))
        self.extension = str(self.settings.value("extension", ""))
        self.out_dir = str(self.settings.value("out_dir", self.out_dir))
        self.recovered_rc2: dict[str, str] = {}
        self._restore_recovered_keys()

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(18, 14, 18, 14)
        root.setSpacing(12)

        root.addLayout(self._build_header())
        self.drop = DropZone()
        self.drop.dropped.connect(self.add_paths)
        self.drop.browse.clicked.connect(self.browse)
        root.addWidget(self.drop)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        holder = QWidget()
        self.card_layout = QVBoxLayout(holder)
        self.card_layout.setContentsMargins(0, 0, 0, 0)
        self.card_layout.setSpacing(10)
        self.card_layout.addStretch()
        self.scroll.setWidget(holder)
        root.addWidget(self.scroll, 1)

        root.addLayout(self._build_footer())
        self.apply_theme()
        self.refresh_actions()

    def _build_header(self):
        row = QHBoxLayout()
        title = QLabel("Subaru PAK converter")
        title.setObjectName("title")
        self.out_label = QLabel()
        self.out_label.setObjectName("path")
        self.out_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        change = QPushButton("Output folder...")
        change.clicked.connect(self.choose_output)
        self.settings_button = QPushButton("Settings...")
        self.settings_button.clicked.connect(self.open_settings)
        row.addWidget(title)
        row.addSpacing(16)
        row.addWidget(self.out_label, 1)
        row.addWidget(change)
        row.addWidget(self.settings_button)
        self._update_out_label()
        return row

    def _build_footer(self):
        row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.message = QLabel("Drop a pak to begin")
        self.message.setObjectName("dim")
        # Without this a long output path widens the whole window and pushes the
        # buttons off the right edge.
        self.message.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear)
        self.open_button = QPushButton("Open output folder")
        self.open_button.clicked.connect(self.open_output)
        self.convert_button = QPushButton("Convert")
        self.convert_button.setObjectName("primary")
        self.convert_button.clicked.connect(self.convert_all)
        row.addWidget(self.message, 1)
        row.addWidget(self.progress, 1)
        row.addWidget(self.clear_button)
        row.addWidget(self.open_button)
        row.addWidget(self.convert_button)
        return row

    # -- settings ---------------------------------------------------------
    @property
    def dark(self) -> bool:
        """Whether to paint dark, resolving "match Windows" to what it is now."""
        if self.theme in ("light", "dark"):
            return self.theme == "dark"
        return system_prefers_dark()

    def apply_theme(self):
        self.setStyleSheet(stylesheet(PALETTES["dark" if self.dark else "light"]))

    def open_settings(self):
        dialog = SettingsDialog(self.theme, self.extension, self)
        if dialog.exec() != QDialog.Accepted:
            return
        theme, extension = dialog.values()
        changed_extension = extension != self.extension
        self.theme, self.extension = theme, extension
        self.settings.setValue("theme", theme)
        self.settings.setValue("extension", extension)
        self.apply_theme()
        if changed_extension:
            # The cards show the names that will be written, so they are stale.
            self.rescan()

    def rescan(self):
        """Re-read every loaded pak, e.g. after the extension changed."""
        for path, card in self.cards.items():
            card.set_status("reading...")
            self._start(ScanJob(path, self._signals(), self.extension))

    def _restore_recovered_keys(self):
        """Re-load keys won in past sessions: swap keys into the detector, and
        per-pak RC2 keys keyed by pak filename, so a recovered pak converts
        straight away next time instead of being re-cracked."""
        from ..keys import register_swap_key
        for i, packed in enumerate(self.settings.value("swap_keys", []) or []):
            words = [int(w, 16) for w in str(packed).split()]
            if len(words) == 4:
                register_swap_key(f"recovered_{i}", words)
        self.settings.beginGroup("rc2")
        for name in self.settings.childKeys():
            self.recovered_rc2[name] = str(self.settings.value(name))
        self.settings.endGroup()

    # -- key recovery, as a battle ----------------------------------------
    def start_battle(self, path):
        """Open the PAK battle to brute-force this pak's missing key."""
        from .battle import BattleDialog
        dialog = BattleDialog(path, dark=self.dark, parent=self)
        dialog.recovered.connect(lambda summary: self._on_recovered(path, summary))
        dialog.exec()

    def _on_recovered(self, path, summary):
        """Adopt keys won in battle: remember the RC2 key, register swap keys."""
        from ..keys import register_swap_key
        rc2_key = summary.get("rc2") or summary.get("manual_key")
        if rc2_key and len(rc2_key.replace(" ", "")) == 8:
            name = os.path.basename(path)            # a pak's key follows its name
            self.recovered_rc2[name] = rc2_key.strip().upper()
            self.settings.setValue(f"rc2/{name}", self.recovered_rc2[name])
        stored = list(self.settings.value("swap_keys", []) or [])
        for rom in summary.get("roms", []):
            words = rom.get("swap_key")
            if words:
                name = rom.get("swap_key_name") or f"recovered_{rom.get('cid','')}"
                register_swap_key(name, words)
                packed = " ".join(f"{int(w) & 0xFFFF:04X}" for w in words)
                if packed not in stored:
                    stored.append(packed)
        self.settings.setValue("swap_keys", stored)
        # The card can now be scanned for real.
        card = self.cards.get(path)
        if card:
            card.set_status("reading...")
            self._start(ScanJob(path, self._signals(), self.extension,
                                rc2_key=self.recovered_rc2.get(os.path.basename(path))))

    # -- input ------------------------------------------------------------
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        self.add_paths([url.toLocalFile() for url in event.mimeData().urls()])

    def browse(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Choose pak files", "", "FlashWrite paks (*.pak);;All files (*)")
        if paths:
            self.add_paths(paths)

    def choose_output(self):
        chosen = QFileDialog.getExistingDirectory(self, "Choose output folder",
                                                  self.out_dir)
        if chosen:
            self.out_dir = chosen
            self.settings.setValue("out_dir", chosen)
            self._update_out_label()

    def _update_out_label(self):
        self.out_label.setText(f"Saving to  {self.out_dir}")
        self.out_label.setToolTip(self.out_dir)

    def open_output(self):
        os.makedirs(self.out_dir, exist_ok=True)
        QDesktopServices.openUrl(_file_url(self.out_dir))

    def add_paths(self, paths):
        found = []
        for path in paths:
            if os.path.isdir(path):
                for root, _, names in os.walk(path):
                    found.extend(os.path.join(root, n) for n in sorted(names)
                                 if n.lower().endswith(".pak"))
            elif path.lower().endswith(".pak"):
                found.append(path)
        new = [p for p in found if p not in self.cards]
        if not found:
            self.message.setText("Those files are not .pak packs")
            return
        for path in new:
            card = PakCard(path)
            self.cards[path] = card
            self.card_layout.insertWidget(self.card_layout.count() - 1, card)
            self._start(ScanJob(path, self._signals(), self.extension))
        self.refresh_actions()

    def _signals(self) -> Signals:
        """One Signals object per job, connected to this window."""
        signals = Signals()
        signals.scanned.connect(self.on_scanned)
        signals.converted.connect(self.on_converted)
        signals.finished.connect(self.on_finished)
        return signals

    def _start(self, job):
        self.pending += 1
        self.total_jobs += 1
        self._jobs.append(job)
        self.progress.setVisible(True)
        self.progress.setRange(0, self.total_jobs)
        self.progress.setValue(self.total_jobs - self.pending)
        self.pool.start(job)
        self.refresh_actions()

    # -- results ----------------------------------------------------------
    @Slot(str, object, str)
    def on_scanned(self, path, result, error):
        card = self.cards.get(path)
        if card is None:
            return
        if error:
            card.show_error(error, on_battle=lambda: self.start_battle(path))
        else:
            self.results[path] = result
            card.show_scan(result)

    @Slot(str, object, object, str)
    def on_converted(self, path, result, written, error):
        card = self.cards.get(path)
        if card is None:
            return
        if error:
            card.show_error(error)
        else:
            self.results[path] = result
            card.show_result(result, written)

    @Slot(str)
    def on_finished(self, path):
        self.pending = max(0, self.pending - 1)
        self.progress.setValue(self.total_jobs - self.pending)
        if self.pending == 0:
            self.progress.setVisible(False)
            self.total_jobs = 0
            self._jobs.clear()
            written = sum(len(c.written) for c in self.cards.values())
            if written:
                self.message.setText(
                    f"Wrote {written} ROM{'' if written == 1 else 's'} to "
                    f"{os.path.basename(self.out_dir) or self.out_dir}")
                self.message.setToolTip(self.out_dir)
            else:
                self.message.setText(f"{len(self.cards)} pak"
                                     f"{'' if len(self.cards) == 1 else 's'} ready")
                self.message.setToolTip("")
        self.refresh_actions()

    # -- actions ----------------------------------------------------------
    def refresh_actions(self):
        busy = self.pending > 0
        convertible = any(getattr(r, "roms", None) for r in self.results.values())
        self.convert_button.setEnabled(convertible and not busy)
        self.convert_button.setText("Working..." if busy else "Convert")
        self.clear_button.setEnabled(bool(self.cards) and not busy)
        if busy:
            self.message.setText(f"{self.pending} pak"
                                 f"{'' if self.pending == 1 else 's'} to go...")

    def convert_all(self):
        try:
            os.makedirs(self.out_dir, exist_ok=True)
        except OSError as exc:
            QMessageBox.warning(self, "Cannot write there",
                                f"{self.out_dir}\n\n{exc}")
            return
        for path, card in self.cards.items():
            result = self.results.get(path)
            if result is None or not getattr(result, "roms", None):
                continue
            card.set_status("converting...", "dim")
            options = {"extension": self.extension or None,
                       "rc2_key": self.recovered_rc2.get(os.path.basename(path))}
            self._start(ConvertJob(path, self.out_dir, options, self._signals()))

    def clear(self):
        for card in self.cards.values():
            card.setParent(None)
            card.deleteLater()
        self.cards.clear()
        self.results.clear()
        self.message.setText("Drop a pak to begin")
        self.refresh_actions()


def _file_url(path):
    from PySide6.QtCore import QUrl
    return QUrl.fromLocalFile(path)


def main():
    """Entry point for ``subaru-pak-gui``."""
    app = QApplication(sys.argv)
    app.setApplicationName("Subaru PAK converter")
    window = MainWindow()
    window.show()
    if len(sys.argv) > 1:                 # opened with files, e.g. "Open with"
        QTimer.singleShot(0, lambda: window.add_paths(sys.argv[1:]))
    sys.exit(app.exec())


if __name__ == "__main__":                # pragma: no cover
    main()
