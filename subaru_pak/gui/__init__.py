"""PySide6 desktop front end.

Deliberately import-free at package level: the core library must never pull Qt
in, so ``subaru_pak.gui.app`` is the only module that imports PySide6.
"""
