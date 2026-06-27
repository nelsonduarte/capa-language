"""Make sibling script modules importable when pytest collects from
the repo root.

The empirical-study test modules import their sibling scripts with a
bare ``import run_study`` (and, in ``depth/``, ``import extract``).
Because this directory is a package (it has an ``__init__.py``), pytest
under its default ``prepend`` import mode roots the test module at the
repo and inserts the repo root - not this directory - onto ``sys.path``.
The bare sibling import then fails at collection from the root, even
though it resolves fine when the suite is run in-situ.

pytest imports the nearest ``conftest.py`` before the test modules in
its directory, so prepending this directory to ``sys.path`` here makes
the sibling scripts importable regardless of the rootdir. The in-situ
behaviour is unchanged: the directory simply ends up on the path twice,
which is harmless.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = str(Path(__file__).resolve().parent)
if HERE not in sys.path:
    sys.path.insert(0, HERE)
