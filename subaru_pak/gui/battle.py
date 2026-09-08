"""The key-recovery UI, as a Pokemon battle.

A brute-force is a long wait with a progress bar; dressing it as a battle makes
the wait legible and, frankly, fun. Nothing here is cosmetic-only: the wild
PAK's HP *is* the fraction of the keyspace still unsearched, every "attack" is a
real chunk of work, and a faint is a real recovered key.

The battle runs the :mod:`subaru_pak.recover` engine on a worker thread and is
driven entirely by its genuine progress callbacks.
"""

from __future__ import annotations

import os
import random

import re
from collections import deque

from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QImage, QPixmap
from PySide6.QtWidgets import (QDialog, QFrame, QGraphicsOpacityEffect, QHBoxLayout,
                               QInputDialog, QLabel, QProgressBar, QPushButton,
                               QVBoxLayout, QWidget)

from .. import pak as pakmod
from .. import recover as rec
from ..keys import default_database

# The trainer's lone Pokemon. It is really the CPU, but "GRAPHICS CARD" is funnier
# and it is what a tech expects to be doing the cracking.
FIGHTER = "GRAPHICS CARD"

_ART = os.path.join(os.path.dirname(__file__), "art")
_SPRITE_HEIGHT = 150


def _knockout_white(image: QImage, threshold: int = 224) -> QImage:
    """Make the surrounding white background transparent, edges inward.

    A flood fill from the border removes only white *connected to the edge*, so
    white that is enclosed by the sprite's dark outline -- the ".pak" text, the
    sparkle eyes, the GPU fan -- survives. Tolerant of JPEG edge noise.

    Works on the raw ARGB32 buffer (bytes are B, G, R, A) rather than per-pixel
    QColor objects, so it is fast enough to run on the GUI thread at open.
    """
    image = image.convertToFormat(QImage.Format_ARGB32)
    w, h = image.width(), image.height()
    stride = image.bytesPerLine()
    buf = memoryview(image.bits()).cast("B")

    seen = bytearray(w * h)
    queue = deque()
    for x in range(w):
        queue.append((x, 0))
        queue.append((x, h - 1))
    for y in range(h):
        queue.append((0, y))
        queue.append((w - 1, y))
    while queue:
        x, y = queue.popleft()
        if not (0 <= x < w and 0 <= y < h) or seen[y * w + x]:
            continue
        seen[y * w + x] = 1
        i = y * stride + x * 4
        if buf[i] >= threshold and buf[i + 1] >= threshold and buf[i + 2] >= threshold:
            buf[i + 3] = 0                       # alpha -> transparent
            queue.extend(((x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)))
    return image


def _sprite_label(filename: str, fallback: str) -> QLabel:
    """A battle sprite from the art folder, white background knocked out.

    Falls back to an emoji if the image is missing (e.g. a slimmed build), so the
    battle always has *something* to show.
    """
    label = QLabel()
    label.setObjectName("sprite")
    label.setAlignment(Qt.AlignCenter)
    image = QImage(os.path.join(_ART, filename))
    if image.isNull():
        label.setText(fallback)
        return label
    image = image.scaledToHeight(_SPRITE_HEIGHT, Qt.SmoothTransformation)
    label.setPixmap(QPixmap.fromImage(_knockout_white(image)))
    return label

# Flavour lines cycled during the grind, keyed to what is actually happening.
_TAUNTS = [
    "{foe} is unfazed!",
    "{foe} used ENCRYPTION!",
    "It's not very effective...",
    "{me} is charging up!",
    "{me} used BRUTE-FORCE!",
    "A critical hit!",
    "{foe} used 40-BIT RC2!",
    "It's super effective!",
    "{me} is trying every key!",
    "{foe} clings on with FF padding!",
]


class _Worker(QObject):
    """Runs a recovery on its own thread; re-emits progress into the GUI thread."""

    progressed = Signal(object)          # recover.Progress
    stage = Signal(str)                  # human note, e.g. "attacking the ROM"
    finished = Signal(object)            # dict summary

    def __init__(self, path: str):
        super().__init__()
        self.path = path
        self._stop = False

    def cancel(self):
        self._stop = True

    def run(self):
        try:
            summary = rec.recover_pak_keys(
                self.path, progress=self.progressed.emit,
                stage=self.stage.emit, stop=lambda: self._stop)
            self.finished.emit(summary)
        except Exception as exc:                     # pragma: no cover - defensive
            self.finished.emit({"error": str(exc)})


class HealthBar(QWidget):
    """A Pokemon HP bar: label, HP/HP, and a green->yellow->red gauge."""

    def __init__(self, name: str, subtitle: str, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)
        top = QHBoxLayout()
        self.name = QLabel(name)
        self.name.setObjectName("battleName")
        self.level = QLabel(subtitle)
        self.level.setObjectName("battleLevel")
        top.addWidget(self.name)
        top.addStretch()
        top.addWidget(self.level)
        layout.addLayout(top)
        self.bar = QProgressBar()
        self.bar.setRange(0, 1000)
        self.bar.setValue(1000)
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(12)
        layout.addWidget(self.bar)
        self.hp = QLabel("HP  ---- / ----")
        self.hp.setObjectName("battleHp")
        layout.addWidget(self.hp)
        self._paint(1.0)

    def set_fraction(self, remaining: float):
        remaining = max(0.0, min(1.0, remaining))
        self.bar.setValue(int(remaining * 1000))
        self._paint(remaining)

    def set_hp_text(self, text: str):
        self.hp.setText(text)

    def _paint(self, remaining: float):
        color = "#4caf50" if remaining > 0.5 else "#f4c020" if remaining > 0.2 else "#e04030"
        self.bar.setStyleSheet(
            f"QProgressBar {{ background:#2a2f38; border:2px solid #11151c;"
            f" border-radius:6px; }}"
            f"QProgressBar::chunk {{ background:{color}; border-radius:4px; }}")


class BattleDialog(QDialog):
    """The whole encounter. Opens on a pak with no known key."""

    #: Emitted when the battle recovers keys the app should adopt.
    recovered = Signal(object)           # the worker summary dict

    def __init__(self, path: str, dark: bool = True, parent=None):
        super().__init__(parent)
        self.path = path
        self.setWindowTitle("PAK Battle")
        self.setModal(True)
        self.setFixedSize(560, 460)
        self.summary = None
        self._thread = None
        self._worker = None

        # Read the container once and derive both the foe name and its sprite
        # from it, rather than parsing the pak twice on the GUI thread.
        try:
            members = pakmod.read(path).members
        except Exception:
            members = []
        self.foe_name = self._foe_name(path, members)
        self.foe_sprite_file = self._foe_sprite_file(members)
        self._build()
        self.setStyleSheet(_BATTLE_QSS)
        # Each intro line gets ~1.4s so it can actually be read before the next.
        self._line(f"A wild {self.foe_name} PAK appeared!")
        QTimer.singleShot(1400, lambda: self._line(f"Go! {FIGHTER}!"))
        QTimer.singleShot(2800, self._show_menu)

    # -- construction -----------------------------------------------------
    def _foe_sprite_file(self, members) -> str:
        """Cat-eared sprite for an engine ROM (.sob), the angry one otherwise.

        The member names are plaintext in the container, so the ROM type is
        known before any key is -- engine ECUs are ``.sob``, modules ``.mot``.
        """
        for member in members:
            if member.is_payload and member.name.lower().endswith(".sob"):
                return "pak_file_pokemon2.jpg"           # engine -> cat-eared
        return "pak_file_pokemon1.jpg"                   # module / unknown -> angry

    def _foe_name(self, path: str, members) -> str:
        base = os.path.splitext(os.path.basename(path))[0]
        if any(m.is_payload for m in members):
            rows = default_database().rows_for(base)
            if rows and rows[0].vehicle:
                return rows[0].vehicle.upper()
        return base.upper()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        arena = QFrame()
        arena.setObjectName("arena")
        arena_l = QVBoxLayout(arena)
        arena_l.setContentsMargins(18, 16, 18, 16)

        # Foe, top-right.
        foe_row = QHBoxLayout()
        self.foe_hp = HealthBar(f"{self.foe_name} PAK", "Lv.??")
        foe_row.addWidget(self.foe_hp, 1)
        foe_row.addStretch()
        self.foe_sprite = _sprite_label(self.foe_sprite_file,
                                        fallback="\U0001F4E6")   # package
        foe_row.addWidget(self.foe_sprite)
        arena_l.addLayout(foe_row)
        arena_l.addSpacing(10)

        # Fighter, bottom-left.
        me_row = QHBoxLayout()
        self.me_sprite = _sprite_label("gpu_pokemon.jpg",
                                       fallback="\U0001F5A5")   # desktop computer
        me_row.addWidget(self.me_sprite)
        me_row.addStretch()
        cores = os.cpu_count() or 1
        self.me_hp = HealthBar(FIGHTER, f"Lv.{cores}")
        self.me_hp.set_hp_text(f"{cores} CORES")
        me_row.addWidget(self.me_hp, 1)
        arena_l.addLayout(me_row)
        root.addWidget(arena, 1)

        # Message box + menu, the classic two-pane bottom.
        bottom = QFrame()
        bottom.setObjectName("textbox")
        bl = QHBoxLayout(bottom)
        bl.setContentsMargins(16, 12, 16, 12)
        self.message = QLabel("")
        self.message.setObjectName("battleText")
        self.message.setWordWrap(True)
        self.message.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        bl.addWidget(self.message, 3)

        self.menu = QWidget()
        menu_l = QVBoxLayout(self.menu)
        menu_l.setContentsMargins(0, 0, 0, 0)
        menu_l.setSpacing(6)
        self.fight_btn = QPushButton("FIGHT")
        self.fight_btn.setObjectName("fight")
        self.fight_btn.clicked.connect(self.on_fight)
        self.key_btn = QPushButton("ENTER KEY")
        self.key_btn.clicked.connect(self.on_enter_key)
        self.run_btn = QPushButton("RUN")
        self.run_btn.clicked.connect(self.on_run)
        for b in (self.fight_btn, self.key_btn, self.run_btn):
            menu_l.addWidget(b)
        bl.addWidget(self.menu, 2)
        self.menu.hide()
        root.addWidget(bottom)

    # -- battle text ------------------------------------------------------
    def _line(self, text: str):
        self.message.setText(text)

    def _faint(self, sprite: QLabel):
        """Fade a sprite to show it has fainted (works for image or emoji)."""
        if sprite.pixmap() and not sprite.pixmap().isNull():
            effect = QGraphicsOpacityEffect(sprite)
            effect.setOpacity(0.3)
            sprite.setGraphicsEffect(effect)
        else:
            sprite.setText("\U0001F4A5")             # collision/faint

    def _show_menu(self):
        self._line(f"What will {FIGHTER} do?")
        self.menu.show()

    # -- actions ----------------------------------------------------------
    def on_fight(self):
        self.menu.hide()
        self.key_btn.setEnabled(False)
        self._line(f"{FIGHTER} used BRUTE-FORCE!")
        self.foe_hp.level.setText("Lv.2³²")     # Lv.2^32
        self._start_worker()

    def on_enter_key(self):
        text, ok = QInputDialog.getText(
            self, "Enter key", "RC2 keyword (8 hex characters):")
        if not ok:
            return
        kw = text.strip().upper()
        if not re.fullmatch(r"[0-9A-F]{8}", kw):
            self._line("That is not an 8-character hex keyword.")
            return
        self.summary = {"rc2": kw}
        self._line(f"You handed {FIGHTER} the key!")
        self.foe_hp.set_fraction(0.0)
        self._faint(self.foe_sprite)
        self.recovered.emit(self.summary)
        QTimer.singleShot(600, self.accept)

    def on_run(self):
        # If a search is running, cancel it and let its finished(cancelled)
        # signal drive the reject -- non-blocking. Otherwise just leave.
        if self._thread is not None and self._thread.isRunning():
            self._worker.cancel()
            self._line("Got away safely!")
            for button in (self.fight_btn, self.key_btn, self.run_btn):
                button.setEnabled(False)
        else:
            self._line("Got away safely!")
            QTimer.singleShot(400, self.reject)

    # -- the worker -------------------------------------------------------
    def _start_worker(self):
        self._thread = QThread(self)
        self._worker = _Worker(self.path)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progressed.connect(self._on_progress)
        self._worker.stage.connect(self._on_stage)
        self._worker.finished.connect(self._on_finished)
        self._taunt_timer = QTimer(self)
        self._taunt_timer.timeout.connect(self._taunt)
        self._taunt_timer.start(1600)
        self.run_btn.setText("RUN")
        self._thread.start()

    def _on_stage(self, note: str):
        self._line(f"{FIGHTER} is {note}!")
        self.foe_hp.set_fraction(1.0)

    def _on_progress(self, p):
        self.foe_hp.set_fraction(1.0 - p.fraction)
        left = int((1.0 - p.fraction) * 9999)
        self.foe_hp.set_hp_text(f"HP  {left:04d} / 9999")

    def _taunt(self):
        self._line(random.choice(_TAUNTS).format(me=FIGHTER, foe="Foe PAK"))

    def _on_finished(self, summary: dict):
        if hasattr(self, "_taunt_timer"):
            self._taunt_timer.stop()
        self._shutdown_worker()
        if summary.get("cancelled"):
            self._line("Got away safely!")
            QTimer.singleShot(500, self.reject)
            return
        if summary.get("error"):
            self.foe_hp.set_fraction(1.0)
            self._line(f"But it failed! {summary['error']}")
            QTimer.singleShot(400, self._show_menu)
            self.key_btn.setEnabled(True)
            return
        self.summary = summary
        self.foe_hp.set_fraction(0.0)
        self.foe_hp.set_hp_text("HP  0000 / 9999")
        self._faint(self.foe_sprite)                 # dim the fainted PAK
        n = len([r for r in summary.get("roms", []) if r.get("swap_key")])
        self._line(f"{self.foe_name} PAK fainted!\n"
                   f"{FIGHTER} recovered the key ({summary['rc2']}) "
                   f"and {n} ROM key(s)!")
        self.recovered.emit(summary)
        self.run_btn.setText("CLOSE")
        self.run_btn.clicked.disconnect()
        self.run_btn.clicked.connect(self.accept)
        self.menu.show()
        self.fight_btn.setEnabled(False)
        self.key_btn.setEnabled(False)

    def _shutdown_worker(self):
        """Stop the search and join its thread before the dialog is destroyed.

        The worker checks the stop flag between chunks (~1-2s), so cancel then
        wait joins cleanly; the terminate is a last resort so a wedged search
        can never outlive the dialog and crash Qt.
        """
        if self._worker is not None:
            self._worker.cancel()
        if self._thread is not None:
            self._thread.quit()
            if not self._thread.wait(10000):        # pragma: no cover - safety net
                self._thread.terminate()
                self._thread.wait()
        self._thread = None
        self._worker = None

    def closeEvent(self, event):
        self._shutdown_worker()
        super().closeEvent(event)


_BATTLE_QSS = """
QDialog { background: #0d1117; }
QFrame#arena { background: #dfe9f2; border-bottom: 4px solid #11151c; }
QFrame#textbox { background: #0d1117; border-top: 4px solid #2a3340; }
QLabel#battleText { color: #eef2f7; font-size: 15px; }
QLabel#battleName { color: #11151c; font-size: 14px; font-weight: 700; }
QLabel#battleLevel { color: #33404f; font-size: 12px; font-weight: 600; }
QLabel#battleHp { color: #11151c; font-size: 11px; font-weight: 700; }
QLabel#sprite { font-size: 56px; }
HealthBar { background: #eef4fa; border: 3px solid #11151c; border-radius: 10px; }
QPushButton { background: #f4f7fb; color: #11151c; border: 3px solid #11151c;
              border-radius: 8px; padding: 8px 14px; font-weight: 700;
              font-size: 14px; }
QPushButton:hover { background: #ffe9a8; }
QPushButton:disabled { color: #8a929c; border-color: #55606d; background: #cdd4dc; }
QPushButton#fight { background: #ffd23f; }
"""
