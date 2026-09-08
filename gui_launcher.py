"""Entry point for the compiled GUI binary.

Nuitka compiles a *script*, and ``subaru_pak/gui/app.py`` uses package-relative
imports, so it cannot be the compiled entry point itself. This launcher gives
Nuitka a plain top-level script that pulls in the package properly.
"""

import multiprocessing

from subaru_pak.gui.app import main

if __name__ == "__main__":
    # The key-recovery bruteforce spawns worker processes; without this they
    # would re-run the whole frozen GUI instead of doing the search.
    multiprocessing.freeze_support()
    main()
