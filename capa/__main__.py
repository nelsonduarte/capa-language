"""Allows the CLI to be invoked via ``python -m capa``.

Equivalent to ``python -m capa.cli``, but more idiomatic.
"""

from .cli import main
import sys


if __name__ == "__main__":
    sys.exit(main())
