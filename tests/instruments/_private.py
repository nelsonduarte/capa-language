"""Loader of the OPTIONAL private extensions.

An instrument's public configuration is complete on its own. A private
tree, when present, adds grammar kinds, cases, positions and register
entries whose shapes are not public yet. This is the ONE module that knows
where that tree lives; everything else asks it.

The location is ``.claude/instruments_private`` under the repository root
(a directory git ignores), or the directory named by the environment
variable ``CAPA_INSTRUMENTS_PRIVATE``; setting that variable to an empty
string disables the private tree, which is how the public configuration
is exercised on a machine that has it.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Optional

from tests.instruments._provenance import REPO_ROOT

ENV_VAR = "CAPA_INSTRUMENTS_PRIVATE"
_DEFAULT = REPO_ROOT / ".claude" / "instruments_private"


def private_root() -> Optional[Path]:
    """The private tree, or ``None`` when there is none (or it is disabled)."""
    if ENV_VAR in os.environ:
        value = os.environ[ENV_VAR]
        if not value:
            return None
        root = Path(value)
        return root if root.is_dir() else None
    return _DEFAULT if _DEFAULT.is_dir() else None


def private_path(*parts: str) -> Optional[Path]:
    root = private_root()
    if root is None:
        return None
    path = root.joinpath(*parts)
    return path if path.exists() else None


def load_module(name: str) -> Optional[ModuleType]:
    """Import ``<private root>/<name>.py`` under a private module name, or
    return ``None`` when the tree or the file is absent."""
    path = private_path(name + ".py")
    if path is None:
        return None
    modname = "capa_instruments_private." + name
    if modname in sys.modules:
        return sys.modules[modname]
    spec = importlib.util.spec_from_file_location(modname, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[modname] = module
    spec.loader.exec_module(module)
    return module
