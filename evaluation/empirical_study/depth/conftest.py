"""Make the sibling ``extract`` module importable when pytest collects
from the repo root.

See the sibling ``conftest.py`` one directory up for the full
rationale: this directory is a package, so pytest roots the test module
at the repo and the bare ``import extract`` in ``test_extract.py`` fails
at collection from the root. Prepending this directory to ``sys.path``
here fixes that without touching the in-situ behaviour.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = str(Path(__file__).resolve().parent)
if HERE not in sys.path:
    sys.path.insert(0, HERE)
