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

from .pkg._floor import parse_version


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

## Dependencies

Declared in `capa.toml`, vendored into `vendor/`:

```
capa search <query>   # find a package in the registry
capa add <name>       # resolve via the registry, fetch, lock, verify
capa install          # re-fetch everything from capa.toml
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

# Vendored dependencies (re-fetched by `capa install`)
vendor/

# Editor
.vscode/
.idea/
*.swp
*~

# OS
.DS_Store
Thumbs.db
"""


# Package manifest. A scaffolded project ships with an empty
# dependency set; `capa add <name>` appends [dependencies.<name>]
# blocks and `capa install` vendors them into vendor/ and writes
# capa.lock. Without this file `capa add` / `capa install` have
# nothing to read, so it is part of the default scaffold.
_CAPA_TOML_TEMPLATE = """\
[package]
name = "{name}"
version = "0.1.0"
capa = ">={capa_version}"
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

    ``capa_version`` is written verbatim to ``.capa-version`` and as
    the enforced ``capa = ">=..."`` floor in ``capa.toml``. It must be
    an ``X.Y.Z`` release; a build reporting the ``0+unknown`` sentinel
    is refused before anything is written (see below).
    ``force`` is not currently used: an existing non-empty
    directory is always rejected (better to error out loudly than
    overwrite a real project). The parameter is kept for forward
    compatibility with a future ``--force`` flag.
    """
    del force  # reserved

    # The scaffold stamps ``capa = ">={capa_version}"`` into capa.toml,
    # and since 1.19.0 that floor is ENFORCED. On a build that cannot
    # report its own version, ``capa_version`` is the ``0+unknown``
    # sentinel, and the manifest we would write is one the compiler that
    # wrote it could not then parse: every subsequent `capa --check` in
    # the new project would refuse it as an unreadable requirement.
    # Refuse up front rather than leaving that file on disk. Nothing has
    # been created at this point, so there is nothing to clean up.
    if parse_version(capa_version) is None:
        print(
            f"capa init: refusing to scaffold: this build reports its "
            f"version as {capa_version!r}, not an X.Y.Z release, so the "
            f"`capa = \">={capa_version}\"` floor it would write into "
            f"capa.toml is one this same compiler cannot read. An "
            f"official Capa build never reports this; reinstall the "
            f"compiler (`pip install --force-reinstall capa-language`) or "
            f"run from a source checkout with its pyproject.toml intact.",
            file=sys.stderr,
        )
        return 2

    ok, msg = _is_safe_target(target)
    if not ok:
        print(f"capa init: {msg}", file=sys.stderr)
        return 2

    name = _derive_name(target)

    # Create the directory (no-op if it already exists empty).
    target.mkdir(parents=True, exist_ok=True)

    files: list[tuple[str, str]] = [
        ("main.capa", _MAIN_TEMPLATE.format(name=name)),
        ("capa.toml", _CAPA_TOML_TEMPLATE.format(
            name=name, capa_version=capa_version,
        )),
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
    print(
        f"capa.toml declares capa = \">={capa_version}\" (the compiler "
        f"that scaffolded it). This floor is enforced: building the "
        f"project with an older Capa is an error.",
        file=sys.stderr,
    )
    if str(rel) == ".":
        next_step = "capa --run main.capa"
    else:
        next_step = f"cd {rel} && capa --run main.capa"
    print(f"Next: {next_step}", file=sys.stderr)
    return 0
