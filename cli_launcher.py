"""Entry point for the standalone CLI binary (``pak2bin.exe``).

Same reason as ``gui_launcher.py``: Nuitka compiles a top-level script, and the
package uses relative imports internally. No Qt is pulled in here -- this build
deliberately excludes the GUI so the CLI binary stays small.

``run`` rather than the Click group itself, so a double-click or a drag-and-drop
behaves the way a Windows user expects instead of flashing a console.
"""

from subaru_pak.cli import run

if __name__ == "__main__":
    run()
