"""Re-verify vendored git dependencies against ``capa.lock`` on build.

The supply-chain checks that ``capa install`` runs (lock-SHA
enforcement, GPG signature verification, SLSA provenance) all happen
INSIDE the install command. But the read/build path (``capa --check``
/ ``--run`` / ``--transpile``, ``capa migrate``, and the ``capa --run``
subprocesses ``capa test`` spawns) reaches the vendored sources
through the loader's search path WITHOUT re-consulting ``capa.lock``.
That makes ``vendor/`` a re-entry point into the trusted computing
base that nothing re-validates: code tampered with after install (a
rebase of ``vendor/<name>`` onto a malicious commit, a direct edit of
the checked-out files, a stale checkout) would execute on the next
build with no detection.

This module closes that gap. Before the loader is allowed to read
``vendor/``, every git dependency declared in ``capa.toml`` is matched
against ``capa.lock``. Two conditions must both hold for ``vendor/<name>``:

  1. its current HEAD commit must equal the SHA frozen in the lockfile
     for that dep (catches a rebase / checkout onto a different commit
     and a stale checkout); and
  2. its working tree must be CLEAN at that commit (catches an
     in-place edit, deletion, or substitution of a checked-out,
     importable file that leaves HEAD untouched but changes the code
     the loader actually reads).

HEAD-only matching is not enough on its own: editing a tracked file in
``vendor/<name>`` without committing leaves HEAD equal to the locked
SHA, so the adulterated code would run undetected. The working-tree
check is what closes that, the most trivial post-install tamper vector.

The check is deliberately CHEAP and OFFLINE: per dep, a single
``git -C vendor/<name> rev-parse HEAD`` plus a single ``git -C
vendor/<name> status --porcelain``, no clone, no network, no re-run of
GPG. The premise is that ``capa.lock`` is committed and is part of the
project's trusted computing base: its ``commit`` was already GPG /
SLSA-verified at install time, so re-checking the SHA AND the working
tree on every build is exactly what catches post-install vendor
tampering.

What this does NOT catch (by stated premise): an attacker who
adulterates ``vendor/<name>``, commits the change coherently so HEAD
moves, AND rewrites ``capa.lock`` to match the new commit. The
committed lockfile is part of the project's trusted computing base; an
attacker who can rewrite it has already breached that boundary, and
this build-time check does not defend against it. In the same
out-of-model class: an attacker who runs ``git update-index
--assume-unchanged`` / ``--skip-worktree`` on a vendor file (or leaves
a vendored submodule uninitialised) can make ``git status --porcelain``
report clean over an edit. That requires an attacker who already has
local write access and runs git locally; the lockfile and the local
git state are part of the project's trusted computing base, so this is
the same class of threat as a coherently rewritten lock, not a new gap.

POSTURE: fail-closed by default, with an explicit opt-out. The build
is refused (``VendorVerificationError``) when, for any git dep:

  (a) ``capa.lock`` is absent while git deps are declared;
  (b) ``vendor/<name>`` is missing or has no ``.git`` (unverifiable);
  (c) the current HEAD of ``vendor/<name>`` differs from the locked
      commit (rebase / checkout onto a different commit / stale
      checkout);
  (d) the working tree of ``vendor/<name>`` is not clean at HEAD
      (an in-place edit, deletion, or substitution of a checked-out
      file: HEAD still matches but the code on disk does not);
  (e) the working tree of ``vendor/<name>`` cannot be inspected (git
      absent / transient git error: unverifiable, so fail-closed);
  (f) a git dep in ``capa.toml`` has no entry in ``capa.lock``.

Each error names the offending dependency and the failure kind, tells
the user to run ``capa install``, and mentions the opt-out.

Path dependencies are never verified: they carry no locked commit (by
design ``capa install`` does not vendor them and they never appear in
``capa.lock``), so they fall entirely outside this check.

OPT-OUT: ``CAPA_NO_VERIFY=1`` skips the verification with a single
once-per-process warning. Setting it ANNULS the build-time
supply-chain guarantee; it exists for the rare case (offline
bisecting against a hand-checked-out vendor tree, etc.) where the
re-verification is genuinely in the way.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

from ._manifest import (
    LOCK_FILENAME,
    LockedDependency,
    Manifest,
    read_lock,
)

VENDOR_DIRNAME = "vendor"

# Explicit opt-out. When set to "1", build-time vendor verification is
# skipped (with a one-shot warning). Mirrors the
# ``CAPA_REGISTRY_ALLOW_UNSIGNED`` escape hatch in _registry.py: an
# environment variable, value "1", that turns a fail-closed gate into
# a warn-and-continue. Unlike that one, this opt-out covers the WHOLE
# check, so its warning is unambiguous that the guarantee is off.
_NO_VERIFY_ENV = "CAPA_NO_VERIFY"

# Once-per-process warning guard so a search loop (or repeated CLI
# entry within one process, e.g. the test harness) does not spam
# stderr with the opt-out notice.
_warned_opt_out = False


class VendorVerificationError(Exception):
    """Raised when a vendored git dependency cannot be verified against
    ``capa.lock`` (missing lock, missing / non-git vendor dir, SHA
    mismatch, or a declared git dep absent from the lock)."""


def _vendor_head_sha(vendor_path: Path) -> Optional[str]:
    """Return the current HEAD commit SHA of ``vendor_path`` via
    ``git -C <path> rev-parse HEAD``, or ``None`` when the path is not
    a git checkout / git is unavailable.

    Factored out so tests can patch SHA acquisition without a real git
    repo, and so the rest of the verification logic is testable in
    isolation. Read-only: ``rev-parse`` never writes."""
    git_dir = vendor_path / ".git"
    if not git_dir.exists():
        return None
    try:
        r = subprocess.run(
            ["git", "-C", str(vendor_path), "rev-parse", "HEAD"],
            capture_output=True, text=True, encoding="utf-8",
        )
    except FileNotFoundError:
        return None
    if r.returncode != 0:
        return None
    return r.stdout.strip()


def _vendor_tree_clean(vendor_path: Path) -> Optional[bool]:
    """Return whether the working tree of ``vendor_path`` is clean at
    HEAD, via ``git -C <path> status --porcelain``: ``True`` when there
    is no output (no modifications, deletions, or untracked files),
    ``False`` when there is, and ``None`` when the status cannot be
    obtained (path is not a git checkout / git is unavailable / git
    errored) so the caller can fail closed.

    ``status --porcelain`` (rather than ``diff --quiet HEAD``) is used
    deliberately: it catches the full post-install execution vector,
    not only in-place edits of tracked files but also their deletion
    and substitution-via-untracked, and a planted untracked importable
    module. A freshly cloned vendor tree (``git clone --depth 1
    --branch <tag>``) reports empty here, and a normal Capa check / run
    / test cycle writes no artifacts into ./vendor source dirs, so the
    untracked-file sensitivity strengthens the check without a false
    positive on a healthy install.

    Factored out (like ``_vendor_head_sha``) so tests can patch the
    cleanliness verdict without a real git repo. Read-only: ``status``
    never writes."""
    git_dir = vendor_path / ".git"
    if not git_dir.exists():
        return None
    try:
        r = subprocess.run(
            ["git", "-C", str(vendor_path), "status", "--porcelain"],
            capture_output=True, text=True, encoding="utf-8",
        )
    except FileNotFoundError:
        return None
    if r.returncode != 0:
        return None
    return r.stdout.strip() == ""


def verify_vendored_deps(
    project_dir: Path,
    manifest: Manifest,
    *,
    head_sha: Callable[[Path], Optional[str]] = _vendor_head_sha,
    tree_clean: Callable[[Path], Optional[bool]] = _vendor_tree_clean,
    warn: Optional[Callable[[str], None]] = None,
) -> None:
    """Re-verify the vendored git deps of ``manifest`` against
    ``capa.lock`` in ``project_dir``. Fail-closed: raises
    ``VendorVerificationError`` on the first unverifiable dep.

    No-op when the manifest declares no git deps (a path-only or
    dependency-free project is untouched). No-op (with a one-shot
    warning) when ``CAPA_NO_VERIFY=1``.

    ``head_sha`` resolves a vendor dir to its HEAD commit and
    ``tree_clean`` resolves it to a working-tree cleanliness verdict;
    both default to git shell-outs, tests inject pure functions.
    ``warn`` receives the opt-out notice; defaults to a once-per-process
    stderr line."""
    git_deps = [
        d for d in (manifest.dependencies + manifest.dev_dependencies)
        if d.is_git
    ]
    if not git_deps:
        return

    if os.environ.get(_NO_VERIFY_ENV) == "1":
        _warn_opt_out_once(warn)
        return

    lock_path = project_dir / LOCK_FILENAME
    if not lock_path.exists():
        names = ", ".join(sorted(d.name for d in git_deps))
        raise VendorVerificationError(
            f"git dependencies are declared in capa.toml ({names}) but "
            f"there is no {LOCK_FILENAME} to verify the vendored sources "
            f"against. The build refuses to read ./vendor without a lock "
            f"to check it against (the lock's commit was supply-chain "
            f"verified at install time). Run `capa install` to resolve "
            f"and lock the dependencies.\n\n"
            f"To bypass this check (which annuls the build-time "
            f"supply-chain guarantee), set {_NO_VERIFY_ENV}=1."
        )

    locked_by_name: dict[str, LockedDependency] = {
        d.name: d for d in read_lock(lock_path)
    }

    for dep in git_deps:
        locked = locked_by_name.get(dep.name)
        if locked is None:
            raise VendorVerificationError(
                f"git dependency {dep.name!r} is declared in capa.toml but "
                f"has no entry in {LOCK_FILENAME}; the vendored sources "
                f"cannot be verified. The lockfile is out of sync with the "
                f"manifest. Run `capa install` to resolve and lock it.\n\n"
                f"To bypass this check (which annuls the build-time "
                f"supply-chain guarantee), set {_NO_VERIFY_ENV}=1."
            )

        vendor_path = project_dir / VENDOR_DIRNAME / dep.name
        actual = head_sha(vendor_path)
        if actual is None:
            raise VendorVerificationError(
                f"git dependency {dep.name!r} is not a verifiable vendored "
                f"checkout: {vendor_path} is missing or has no .git, so its "
                f"commit cannot be read and compared against {LOCK_FILENAME}. "
                f"Run `capa install` to (re)vendor it.\n\n"
                f"To bypass this check (which annuls the build-time "
                f"supply-chain guarantee), set {_NO_VERIFY_ENV}=1."
            )

        if actual != locked.commit:
            raise VendorVerificationError(
                f"vendored dependency {dep.name!r} does not match "
                f"{LOCK_FILENAME}:\n"
                f"    locked  {locked.commit}\n"
                f"    vendor  {actual}\n\n"
                f"vendor/{dep.name} has been rebased or checked out onto a "
                f"different commit, or left stale since `capa install`. The "
                f"build refuses to read code that the lockfile did not "
                f"verify. Run `capa install` to restore the locked commit "
                f"(investigate first if you did not change this dependency "
                f"yourself).\n\n"
                f"To bypass this check (which annuls the build-time "
                f"supply-chain guarantee), set {_NO_VERIFY_ENV}=1."
            )

        clean = tree_clean(vendor_path)
        if clean is None:
            raise VendorVerificationError(
                f"git dependency {dep.name!r} cannot be verified: the "
                f"working tree of {vendor_path} could not be inspected "
                f"(git is unavailable or errored), so build-time tamper "
                f"detection is not possible. Run `capa install` to "
                f"(re)vendor it.\n\n"
                f"To bypass this check (which annuls the build-time "
                f"supply-chain guarantee), set {_NO_VERIFY_ENV}=1."
            )
        if not clean:
            raise VendorVerificationError(
                f"vendored dependency {dep.name!r} is at the locked commit "
                f"{locked.commit} but its working tree has uncommitted "
                f"changes:\n"
                f"    vendor/{dep.name} has files modified, deleted, or "
                f"added since `capa install` checked out the locked "
                f"commit.\n\n"
                f"A direct edit of the checked-out files leaves HEAD "
                f"matching the lock while changing the code the build "
                f"actually reads. The build refuses to read code that the "
                f"lockfile did not verify. Run `capa install` to restore "
                f"the locked checkout, or `git -C vendor/{dep.name} status` "
                f"to inspect the changes (investigate first if you did not "
                f"change this dependency yourself).\n\n"
                f"To bypass this check (which annuls the build-time "
                f"supply-chain guarantee), set {_NO_VERIFY_ENV}=1."
            )


def _warn_opt_out_once(warn: Optional[Callable[[str], None]]) -> None:
    global _warned_opt_out
    if _warned_opt_out:
        return
    _warned_opt_out = True
    message = (
        f"{_NO_VERIFY_ENV}=1: skipping build-time verification of "
        f"vendored dependencies against {LOCK_FILENAME}. The "
        f"supply-chain guarantee that ./vendor matches the locked, "
        f"verified commits is OFF for this run."
    )
    if warn is not None:
        warn(message)
    else:
        print(f"capa: warning: {message}", file=sys.stderr)
