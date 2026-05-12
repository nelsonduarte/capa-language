"""Entry point for the PyInstaller-bundled Capa binary.

PyInstaller cannot start from ``capa/__main__.py`` because that file
uses a package-relative import (``from .cli import main``), which has
no package context when invoked as a standalone script. This wrapper
imports the CLI absolutely, which works both during a regular Python
invocation and inside the bundled binary.

Build with ``pyinstaller deploy/capa.spec``.
"""

import sys

from capa.cli import main


if __name__ == "__main__":
    sys.exit(main())
