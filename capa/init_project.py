"""capa/init_project.py, project scaffolding for ``capa init``.

Creates a minimal but representative starter project: a single
``main.capa`` file with a Stdio-using ``fun main`` so the capability
discipline is visible from the first line, a ``README.md`` that
tells the user how to run and check the program, a ``.gitignore``
covering Python bytecode and common editor cruft, and a
``.capa-version`` file pinning the Capa version used at scaffold
time (so a future ``capa-up`` could detect drift, and so the
project is self-describing for reproducibility).

The starter is deliberately tiny. Anything more ambitious belongs
in ``examples/``; ``capa init`` is meant to land users in a
working program in under five seconds.

Public entry point:

``init_project(target: Path, *, capa_version: str, force: bool = False) -> int``
    Create the project at ``target``. ``target`` may be an existing
    empty directory, a non-existent directory (created on demand),
    or ``Path('.')`` for the current directory if it is empty.
    Returns 0 on success, non-zero on failure with a message
    already printed to stderr.
"""

from __future__ import annotations

import sys
from pathlib import Path


_MAIN_TEMPLATE = """\
/// {name}, scaffolded by `capa init`.
///
/// Try it:
///   capa --run main.capa
///
/// Type-check and verify capability use:
///   capa --check main.capa

fun main(stdio: Stdio)
    stdio.println("Hello from Capa!")
"""


_README_TEMPLATE = """\
# {name}

A Capa project.

## Run

```
capa --run main.capa
```

## Check types and capabilities

```
capa --check main.capa
```

## Learn more

- Language tour: <https://capa-language.com/tour.html>
- Get started: <https://capa-language.com/start.html>
- Reference: <https://capa-language.com/reference.html>
"""


_GITIGNORE_TEMPLATE = """\
# Python bytecode (the Capa transpiler targets Python)
__pycache__/
*.pyc
*.pyo

# Editor
.vscode/
.idea/
*.swp
*~

# OS
.DS_Store
Thumbs.db
"""


_DEFAULT_NAME = "capa-project"


def _is_safe_target(target: Path) -> tuple[bool, str]:
    """Decide whether ``target`` is acceptable as a scaffold root.

    Returns ``(ok, message)``. The message is the reason on
    failure; it is empty on success.
    """
    if target.exists():
        if not target.is_dir():
            return False, f"{target} exists and is not a directory"
        # Existing directory: must be empty.
        if any(target.iterdir()):
            return False, f"{target} is not empty"
        return True, ""
    # Does not exist: parent must be a directory we can write to.
    parent = target.parent if str(target.parent) else Path(".")
    if not parent.exists():
        return False, f"parent directory {parent} does not exist"
    if not parent.is_dir():
        return False, f"parent {parent} is not a directory"
    return True, ""


def _derive_name(target: Path) -> str:
    """Derive the project's display name from the target path.

    Uses the directory's basename, resolving ``Path('.')`` to its
    actual current directory name. Falls back to ``capa-project``
    if the name would be empty or otherwise unusable.
    """
    name = target.resolve().name
    if not name:
        return _DEFAULT_NAME
    return name


def init_project(
    target: Path,
    *,
    capa_version: str,
    force: bool = False,
) -> int:
    """Scaffold a new Capa project at ``target``.

    ``capa_version`` is written verbatim to ``.capa-version``.
    ``force`` is not currently used: an existing non-empty
    directory is always rejected (better to error out loudly than
    overwrite a real project). The parameter is kept for forward
    compatibility with a future ``--force`` flag.
    """
    del force  # reserved

    ok, msg = _is_safe_target(target)
    if not ok:
        print(f"capa init: {msg}", file=sys.stderr)
        return 2

    name = _derive_name(target)

    # Create the directory (no-op if it already exists empty).
    target.mkdir(parents=True, exist_ok=True)

    files: list[tuple[str, str]] = [
        ("main.capa", _MAIN_TEMPLATE.format(name=name)),
        ("README.md", _README_TEMPLATE.format(name=name)),
        (".gitignore", _GITIGNORE_TEMPLATE),
        (".capa-version", capa_version + "\n"),
    ]
    for relpath, content in files:
        path = target / relpath
        try:
            path.write_text(content, encoding="utf-8")
        except OSError as e:
            print(f"capa init: cannot write {path}: {e}", file=sys.stderr)
            return 2

    # Friendly confirmation pointing the user at the next command.
    rel = target if not target.is_absolute() else target.resolve()
    print(f"Created Capa project at {rel}", file=sys.stderr)
    if str(rel) == ".":
        next_step = "capa --run main.capa"
    else:
        next_step = f"cd {rel} && capa --run main.capa"
    print(f"Next: {next_step}", file=sys.stderr)
    return 0
