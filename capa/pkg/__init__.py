"""Capa package manager.

A small dependency resolver that reads ``capa.toml`` from a
project root, fetches the declared dependencies (git URL +
tag/rev pin, or a local path), materialises git deps under
``vendor/`` next to the manifest, and writes ``capa.lock`` so
the resolution is reproducible.

The loader consults ``vendor/`` (when ``capa.toml`` exists in
the cwd) automatically, so a project that runs through
``capa install`` does not need to set ``CAPA_PATH``.

Public surface:

- ``Manifest`` + ``Dependency``: in-memory parsed shape.
- ``read_manifest(path)``: load + validate a ``capa.toml``.
- ``read_lock(path)``: load a ``capa.lock`` if present.
- ``install(project_dir, *, write_lock=True)``: run a full
  resolve + fetch pass and write the lock file.
- ``InstallError``: the only error variant exposed.

The CLI entry point ``capa install`` calls into this module.
"""

from __future__ import annotations

from ._manifest import (
    Dependency,
    Manifest,
    ManifestError,
    read_manifest,
    read_lock,
    LOCK_FILENAME,
    MANIFEST_FILENAME,
)
from ._install import InstallError, install

__all__ = [
    "Dependency",
    "Manifest",
    "ManifestError",
    "InstallError",
    "read_manifest",
    "read_lock",
    "install",
    "MANIFEST_FILENAME",
    "LOCK_FILENAME",
]
