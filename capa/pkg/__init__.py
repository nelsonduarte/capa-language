"""Capa package manager.

A small dependency resolver that reads ``capa.toml`` from a
project root, fetches the declared dependencies (git URL +
tag/rev pin, or a local path), materialises git deps under
``vendor/`` next to the manifest, and writes ``capa.lock`` so
the resolution is reproducible.

The loader consults ``vendor/`` (when ``capa.toml`` exists in
the cwd) automatically, so a project that runs through
``capa install`` does not need to set ``CAPA_PATH``.

``[dev-dependencies]`` share the schema and validation of
``[dependencies]`` and vendor into the same ``vendor/`` dir,
but only when the manifest is the install root: consuming a
package as a dependency never pulls in its dev-deps (v1 reads
only the root manifest, so this holds by construction). Lock
entries for dev-deps carry ``dev = true``.

Public surface:

- ``Manifest`` + ``Dependency``: in-memory parsed shape.
- ``read_manifest(path)``: load + validate a ``capa.toml``.
- ``read_lock(path)``: load a ``capa.lock`` if present.
- ``install(project_dir, *, write_lock=True,
  allow_lock_update=False)``: run a full resolve + fetch pass
  and write the lock file. Raises ``LockMismatchError`` (a
  subclass of ``InstallError``) when a pre-existing
  ``capa.lock`` pins a SHA that the freshly cloned tag does
  not produce -- the canonical "upstream tag was moved"
  signal.
- ``InstallError`` / ``LockMismatchError``: error variants.
- ``enforce_root_floor(project_dir)``: honour the root manifest's
  ``[package].capa`` floor. Raises ``CapaFloorError`` when the running
  compiler is older than the declared floor. A missing ``capa`` key is
  unconstrained. ``CAPA_IGNORE_CAPA_FLOOR=1`` downgrades the refusal to
  a loud warning. Dependency floors WARN instead, via
  ``warn_dependency_floor``. See ``capa/pkg/_floor.py``.
- ``verify_vendored_deps(project_dir, manifest)``: re-verify the
  vendored git deps against ``capa.lock`` on the read/build path.
  Fail-closed; raises ``VendorVerificationError`` on a missing
  lock, a missing / non-git vendor dir, a SHA mismatch, or a
  declared git dep absent from the lock. Skipped (with a warning)
  under ``CAPA_NO_VERIFY=1``.

The CLI entry point ``capa install`` calls into this module.
"""

from __future__ import annotations

from ._manifest import (
    CapabilityCeiling,
    Dependency,
    Manifest,
    ManifestError,
    read_manifest,
    read_lock,
    LOCK_FILENAME,
    MANIFEST_FILENAME,
)
from ._floor import (
    CapaFloorError,
    IGNORE_ENV as CAPA_FLOOR_IGNORE_ENV,
    check_root_floor,
    enforce_root_floor,
    warn_dependency_floor,
)
from ._install import InstallError, LockMismatchError, VerificationError, install
from ._verify import VendorVerificationError, verify_vendored_deps
from ._add import add_dependency
from ._registry import (
    RegistryEntry,
    RegistryError,
    resolve_name,
    search_packages,
)

__all__ = [
    "CapabilityCeiling",
    "CapaFloorError",
    "CAPA_FLOOR_IGNORE_ENV",
    "check_root_floor",
    "enforce_root_floor",
    "warn_dependency_floor",
    "Dependency",
    "Manifest",
    "ManifestError",
    "InstallError",
    "LockMismatchError",
    "VerificationError",
    "VendorVerificationError",
    "read_manifest",
    "read_lock",
    "install",
    "verify_vendored_deps",
    "add_dependency",
    "RegistryEntry",
    "RegistryError",
    "resolve_name",
    "search_packages",
    "MANIFEST_FILENAME",
    "LOCK_FILENAME",
]
