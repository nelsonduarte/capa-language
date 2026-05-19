"""Resolve + fetch the dependencies declared in ``capa.toml``.

For each git dependency, ``install``:

1. Clones the URL into ``vendor/<name>`` (shallow when a tag
   is given, otherwise a regular clone).
2. Checks out the pin (``tag`` or ``rev``).
3. Captures the resolved commit SHA for the lockfile.

For each path dependency, nothing is fetched - the loader
later reads the path directly off the manifest. Path deps do
not appear in the lockfile.

The implementation shells out to ``git`` so the runtime does
not pull in a heavyweight git library. ``git`` must be on the
caller's PATH.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from ._manifest import (
    Dependency,
    LOCK_FILENAME,
    LockedDependency,
    MANIFEST_FILENAME,
    Manifest,
    ManifestError,
    read_manifest,
    write_lock,
)


VENDOR_DIRNAME = "vendor"


class InstallError(Exception):
    """Raised when ``install`` cannot complete (git failure, missing
    pin in the remote, path dep that does not exist on disk, etc).
    """


def install(project_dir: Path, *, write_lock_file: bool = True) -> Manifest:
    """Run a full resolve + fetch over the project at ``project_dir``.

    Returns the parsed ``Manifest`` on success. Writes
    ``vendor/<name>`` for every git dep and ``capa.lock`` (unless
    ``write_lock_file=False``, useful in tests).
    """
    manifest_path = project_dir / MANIFEST_FILENAME
    if not manifest_path.exists():
        raise InstallError(
            f"no {MANIFEST_FILENAME} in {project_dir}; nothing to install"
        )
    manifest = read_manifest(manifest_path)
    vendor_dir = project_dir / VENDOR_DIRNAME
    vendor_dir.mkdir(exist_ok=True)

    locked: list[LockedDependency] = []
    for dep in manifest.dependencies:
        if dep.is_path:
            _check_path_dep(manifest, dep)
            continue
        locked.append(_fetch_git_dep(vendor_dir, dep))

    if write_lock_file:
        lock_path = project_dir / LOCK_FILENAME
        write_lock(lock_path, locked)

    return manifest


def _check_path_dep(manifest: Manifest, dep: Dependency) -> None:
    assert dep.path is not None
    p = (manifest.manifest_dir / dep.path).resolve()
    if not p.exists():
        raise InstallError(
            f"path dependency {dep.name!r}: {p} does not exist"
        )
    if not p.is_dir():
        raise InstallError(
            f"path dependency {dep.name!r}: {p} is not a directory"
        )


def _fetch_git_dep(vendor_dir: Path, dep: Dependency) -> LockedDependency:
    """Clone, checkout, and resolve the SHA for one git dependency."""
    assert dep.git is not None
    dest = vendor_dir / dep.name
    # Drop any previous checkout so re-runs of ``install`` are
    # idempotent against pin changes. Cheaper than git fetch +
    # branch reset and avoids stale state on a tag-moved remote.
    # ``onexc`` (3.12+) / ``onerror`` (older) clears the read-only
    # bit Windows applies to ``.git/objects/pack/*.idx`` pack files,
    # which would otherwise make ``shutil.rmtree`` fail with
    # WinError 5.
    if dest.exists():
        _rmtree_force(dest)

    pin = dep.tag if dep.tag is not None else dep.rev
    pin_kind = "tag" if dep.tag is not None else "rev"
    assert pin is not None

    # Shallow clone of the specific tag is fastest. For rev pins
    # we fall back to a regular clone + checkout, since `git clone
    # --branch` only accepts tag/branch names, not arbitrary SHAs.
    if pin_kind == "tag":
        _run_git(
            ["clone", "--depth", "1", "--branch", pin, dep.git, str(dest)],
            f"clone {dep.git} (tag {pin})",
        )
    else:
        _run_git(
            ["clone", dep.git, str(dest)],
            f"clone {dep.git}",
        )
        _run_git(
            ["-C", str(dest), "checkout", "--detach", pin],
            f"checkout {pin}",
        )

    commit = _run_git(
        ["-C", str(dest), "rev-parse", "HEAD"],
        f"resolve HEAD of {dep.name}",
    ).strip()

    return LockedDependency(
        name=dep.name,
        git=dep.git,
        pin=pin,
        pin_kind=pin_kind,
        commit=commit,
    )


def _rmtree_force(path: Path) -> None:
    """``shutil.rmtree`` that strips the read-only bit on Windows.

    Git pack files under ``.git/objects/pack/`` ship with the
    read-only attribute on Windows; a plain ``rmtree`` then trips
    on ``WinError 5``. We chmod-and-retry per offending file.
    """
    def _clear_readonly(func, target, exc_info):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            pass
    # Python 3.12 renamed ``onerror`` to ``onexc``. Pick whichever
    # the current interpreter offers.
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_clear_readonly)
    else:
        shutil.rmtree(path, onerror=_clear_readonly)


def _run_git(args: list[str], what: str) -> str:
    """Invoke ``git`` and return stdout. Raises ``InstallError`` on
    non-zero exit with the captured stderr appended.
    """
    try:
        r = subprocess.run(
            ["git", *args],
            capture_output=True, text=True, encoding="utf-8",
        )
    except FileNotFoundError:
        raise InstallError(
            "'git' executable not found on PATH; the package manager needs "
            "git to fetch dependencies"
        ) from None
    if r.returncode != 0:
        raise InstallError(
            f"git {args[0]} failed while trying to {what}:\n"
            f"{r.stderr.strip()}"
        )
    return r.stdout
