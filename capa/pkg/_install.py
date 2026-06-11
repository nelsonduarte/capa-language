"""Resolve + fetch the dependencies declared in ``capa.toml``.

For each git dependency, ``install``:

1. Clones the URL into ``vendor/<name>`` (shallow when a tag
   is given, otherwise a regular clone).
2. Checks out the pin (``tag`` or ``rev``).
3. Captures the resolved commit SHA for the lockfile.

For each path dependency, nothing is fetched - the loader
later reads the path directly off the manifest. Path deps do
not appear in the lockfile.

``[dev-dependencies]`` are treated exactly like
``[dependencies]`` here: ``install`` always operates on the
manifest of the project it was invoked on (the root), and that
is precisely the only place dev-deps should be materialised.
They are never fetched transitively because Capa v1 never reads
a vendored dependency's own ``capa.toml`` at all. In the
lockfile a dev-dep entry carries ``dev = true``.

When a ``capa.lock`` already exists, ``install`` *enforces* the
recorded SHA. For tag pins the check runs BEFORE the clone (via
``git ls-remote``), so a moved upstream tag does not overwrite
``vendor/<name>`` with attacker content while the user is staring
at the error message. For rev pins the same check runs after the
clone (a rev pin is itself a SHA, so the only way to mismatch is
a deliberate edit, not a tag move). A mismatch raises
``LockMismatchError`` in both cases. To accept new commits
intentionally, delete ``capa.lock`` before re-running ``install``
(or use ``allow_lock_update=True`` from a CLI flag).

When a dep declares ``verify_key`` (a 40-char GPG fingerprint),
``install`` runs two independent verification layers:

  1. ``git verify-tag`` (or ``verify-commit``) against the
     consumer's GPG keyring (the publisher-identity layer).
  2. ``gh attestation verify`` against the public Sigstore
     Rekor log, against the source tarball attached to the
     GitHub release for this tag (the SLSA L2 build-provenance
     layer). Implicit; runs only on GitHub-hosted tag pins
     when the ``gh`` CLI is available, and skips silently for
     other hosts / for releases that don't ship attestations.

The implementation shells out to ``git`` so the runtime does
not pull in a heavyweight git library. ``git`` must be on the
caller's PATH.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

from ._manifest import (
    Dependency,
    LOCK_FILENAME,
    LockedDependency,
    MANIFEST_FILENAME,
    Manifest,
    ManifestError,
    read_lock,
    read_manifest,
    write_lock,
)


VENDOR_DIRNAME = "vendor"


class InstallError(Exception):
    """Raised when ``install`` cannot complete (git failure, missing
    pin in the remote, path dep that does not exist on disk, etc).
    """


class LockMismatchError(InstallError):
    """Raised when a freshly cloned dependency's HEAD SHA does not
    match the SHA recorded in ``capa.lock`` for the same name +
    git URL + pin. Strong signal that the upstream tag has moved
    since the lockfile was written; surface it to the caller
    rather than silently overwrite the lockfile."""


class VerificationError(InstallError):
    """Raised when a dependency declares ``verify_key`` in its
    ``capa.toml`` entry but the cloned tag/commit fails GPG
    verification (unsigned, signed with an unknown key, signed
    with a different key, or invalid signature)."""


def install(
    project_dir: Path,
    *,
    write_lock_file: bool = True,
    allow_lock_update: bool = False,
) -> Manifest:
    """Run a full resolve + fetch over the project at ``project_dir``.

    Returns the parsed ``Manifest`` on success. Writes
    ``vendor/<name>`` for every git dep and ``capa.lock`` (unless
    ``write_lock_file=False``, useful in tests).

    When ``capa.lock`` exists, the freshly resolved commit SHA for
    each git dep must match the lockfile entry (same name + git +
    pin). A mismatch raises ``LockMismatchError`` so a force-pushed
    upstream tag does not slip through unnoticed. Pass
    ``allow_lock_update=True`` (CLI surface: ``--update``) to
    accept the new SHAs and overwrite the lockfile."""
    manifest_path = project_dir / MANIFEST_FILENAME
    if not manifest_path.exists():
        raise InstallError(
            f"no {MANIFEST_FILENAME} in {project_dir}; nothing to install"
        )
    manifest = read_manifest(manifest_path)
    vendor_dir = project_dir / VENDOR_DIRNAME
    vendor_dir.mkdir(exist_ok=True)

    lock_path = project_dir / LOCK_FILENAME
    existing_lock = read_lock(lock_path) if lock_path.exists() else []
    existing_by_name = {d.name: d for d in existing_lock}

    # Regular deps first, then dev-deps. Dev-deps follow the exact
    # same fetch / verify / lock pipeline; the only difference is
    # the ``dev = true`` marker on their lockfile entries. The
    # manifest parser already guarantees the two name sets are
    # disjoint.
    all_deps: list[tuple[Dependency, bool]] = (
        [(d, False) for d in manifest.dependencies]
        + [(d, True) for d in manifest.dev_dependencies]
    )

    # First pass: when the lockfile already pins a commit for a
    # tag dep, verify the remote tag still points at that commit
    # BEFORE we touch ``vendor/<name>``. The pre-2026-05-25 shape
    # cloned first and compared SHAs second, so a moved tag
    # overwrote the vendored sources with attacker content even
    # when the lock check would then refuse the install. Any
    # editor / IDE / language server reading the working tree in
    # the window between the overwrite and the error message saw
    # the new sources. Audit 2026-05-25 H3.
    #
    # ``git ls-remote`` does not write anywhere; it reads the
    # remote's ref table. Only tag pins are checkable this way
    # (a rev pin IS the SHA, so the deliberate-edit path is the
    # only way the lock would mismatch). Path deps and rev pins
    # skip the pre-check.
    for dep, _ in all_deps:
        if dep.is_path or dep.tag is None:
            continue
        prior = existing_by_name.get(dep.name)
        if prior is None or prior.git != dep.git or prior.pin != dep.tag:
            continue
        if allow_lock_update:
            continue
        remote_sha = _resolve_remote_tag(dep.git, dep.tag)
        if remote_sha is None:
            # Cannot reach the remote or the tag no longer exists.
            # Fall through to the regular clone path, which will
            # surface the underlying git failure with a normal
            # InstallError. We refuse to silently swap to a missing
            # tag, but we also do not invent a LockMismatchError for
            # a network-level failure.
            continue
        if remote_sha != prior.commit:
            raise LockMismatchError(
                f"capa.lock SHA mismatch on {dep.name!r} "
                f"({dep.git} @ {dep.tag}):\n"
                f"    locked  {prior.commit}\n"
                f"    remote  {remote_sha}\n\n"
                f"The upstream tag has moved since the lockfile was "
                f"written. ``vendor/{dep.name}`` has NOT been touched. "
                f"A moved tag is a supply-chain signal worth "
                f"investigating. If this is a deliberate upstream "
                f"update, either:\n"
                f"  * delete capa.lock and re-run ``capa install``, or\n"
                f"  * pin the dependency to a specific commit SHA in "
                f"capa.toml (``rev = \"<sha>\"`` instead of ``tag = ...``).\n"
                f"\nFor automation that wants to refresh the lockfile, "
                f"the API takes ``allow_lock_update=True``."
            )

    locked: list[LockedDependency] = []
    mismatches: list[tuple[str, str, str, str, str]] = []
    for dep, is_dev in all_deps:
        if dep.is_path:
            _check_path_dep(manifest, dep)
            continue
        fresh = _fetch_git_dep(vendor_dir, dep, dev=is_dev)
        prior = existing_by_name.get(dep.name)
        # Second-pass safety net for rev pins (and any tag-pin
        # path that slipped through the pre-check above, e.g. a
        # network-level skip). A rev mismatch here implies the
        # lockfile and capa.toml disagree about the SHA the same
        # rev should resolve to, which is the deliberate-edit
        # path. Same allow-lock-update knob.
        if (
            prior is not None
            and prior.git == fresh.git
            and prior.pin == fresh.pin
            and prior.commit != fresh.commit
            and not allow_lock_update
        ):
            mismatches.append(
                (dep.name, fresh.git, fresh.pin, prior.commit, fresh.commit),
            )
        locked.append(fresh)

    if mismatches:
        details = "\n".join(
            f"  {name} ({git} @ {pin}):\n"
            f"      locked  {old}\n"
            f"      fresh   {new}"
            for name, git, pin, old, new in mismatches
        )
        raise LockMismatchError(
            f"capa.lock SHA mismatch on "
            f"{[m[0] for m in mismatches]}: the upstream tag(s) have "
            f"moved since the lockfile was written.\n\n"
            f"{details}\n\n"
            f"A moved tag is a supply-chain signal worth investigating. "
            f"If this is a deliberate upstream update, either:\n"
            f"  * delete capa.lock and re-run ``capa install``, or\n"
            f"  * pin the dependency to a specific commit SHA in "
            f"capa.toml (``rev = \"<sha>\"`` instead of ``tag = ...``).\n"
            f"\nFor automation that wants to refresh the lockfile, "
            f"the API takes ``allow_lock_update=True``."
        )

    if write_lock_file:
        write_lock(lock_path, locked)

    return manifest


def _resolve_remote_tag(url: str, tag: str) -> Optional[str]:
    """Return the commit SHA the remote currently has for ``tag``,
    without writing anything to disk.

    Audit 2026-05-25 H3: the install loop used to clone first and
    compare SHAs second, so a force-pushed tag overwrote
    ``vendor/<name>`` with attacker content before the lockfile
    check refused. Pre-checking via ``git ls-remote`` is read-only
    on the local side and lets the lock-mismatch check fire before
    any destructive operation.

    For annotated tags ``ls-remote`` reports BOTH the tag object
    and the commit it points at (``<sha>\\trefs/tags/<t>`` plus
    ``<sha>\\trefs/tags/<t>^{}``). The peeled ``^{}`` form is the
    commit SHA we recorded in the lockfile via ``rev-parse HEAD``
    on a cloned checkout. Prefer that when present; fall back to
    the bare line for lightweight tags.

    Returns ``None`` when the remote is unreachable, the tag does
    not exist, or ``git`` is not on PATH. Caller treats ``None``
    as ``skip the pre-check and let the regular clone path raise
    the underlying error``.
    """
    try:
        r = subprocess.run(
            ["git", "ls-remote", "--tags", url, f"refs/tags/{tag}",
             f"refs/tags/{tag}^" + "{}"],
            capture_output=True, text=True, encoding="utf-8",
        )
    except FileNotFoundError:
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None
    peeled: Optional[str] = None
    bare: Optional[str] = None
    for line in r.stdout.splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        sha, ref = parts[0].strip(), parts[1].strip()
        if ref.endswith("^{}"):
            peeled = sha
        else:
            bare = sha
    return peeled or bare


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


def _fetch_git_dep(
    vendor_dir: Path, dep: Dependency, *, dev: bool = False,
) -> LockedDependency:
    """Clone, checkout, and resolve the SHA for one git dependency.
    ``dev`` marks the resulting lock entry as a dev-dependency."""
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

    # Optional GPG signature check. Runs against the consumer's
    # GPG keyring; the trust anchor is the fingerprint declared
    # in ``capa.toml``. Returns an empty string when no
    # ``verify_key`` is declared (no verification requested).
    signing_key = ""
    if dep.verify_key is not None:
        signing_key = _verify_signed_pin(
            dest, pin_kind, pin, dep.verify_key, dep.name,
        )
        # Layer 3 of the supply-chain stack: try SLSA L2 build
        # provenance via Sigstore when the dep is GitHub-hosted
        # and pinned to a tag. The verification is implicit
        # (no separate opt-in field): if you already trust this
        # publisher with verify_key + the repo is on GitHub, we
        # also check the build came through the attested CI path.
        # See _verify_slsa_provenance for the graceful-skip rules.
        _verify_slsa_provenance(dep, pin, pin_kind)

    return LockedDependency(
        name=dep.name,
        git=dep.git,
        pin=pin,
        pin_kind=pin_kind,
        commit=commit,
        signing_key=signing_key,
        dev=dev,
    )


def _verify_signed_pin(
    dest: Path, pin_kind: str, pin: str,
    expected_fingerprint: str, dep_name: str,
) -> str:
    """Verify the signature on a git ref via GPG and return the
    fingerprint that produced it. Raises VerificationError on
    any failure (unsigned ref, unknown key, mismatched key,
    invalid signature). The expected fingerprint must already
    be uppercase + space-stripped (the manifest parser
    normalises it on read)."""
    git_cmd = "verify-tag" if pin_kind == "tag" else "verify-commit"
    try:
        r = subprocess.run(
            ["git", "-C", str(dest), git_cmd, "--raw", pin],
            capture_output=True, text=True, encoding="utf-8",
        )
    except FileNotFoundError:
        raise InstallError(
            "'git' executable not found on PATH; the package manager "
            "needs git for signature verification too"
        ) from None
    if r.returncode != 0:
        raise VerificationError(
            f"signature verification failed on {dep_name!r} pin "
            f"{pin!r}: ``git {git_cmd}`` returned non-zero. Either the "
            f"ref is unsigned, the signing key is not in your GPG "
            f"keyring, or the signature is invalid.\n\n"
            f"git output:\n{r.stderr.strip()}\n\n"
            f"To bring the publisher's key into your keyring:\n"
            f"  gpg --recv-keys {expected_fingerprint}\n"
            f"or import from a file you obtained out of band:\n"
            f"  gpg --import path/to/publisher.asc"
        )
    # --raw emits machine-readable status lines to stderr; look for
    # ``VALIDSIG <fingerprint>``.
    fingerprint = None
    for line in r.stderr.splitlines():
        if line.startswith("[GNUPG:] VALIDSIG "):
            parts = line.split()
            if len(parts) >= 3:
                fingerprint = parts[2].upper()
                break
    if fingerprint is None:
        raise VerificationError(
            f"signature verification on {dep_name!r}: ``git "
            f"{git_cmd}`` succeeded but no VALIDSIG line in the GPG "
            f"raw output. This is unusual; please report the case.\n\n"
            f"git stderr:\n{r.stderr.strip()}"
        )
    if fingerprint != expected_fingerprint:
        raise VerificationError(
            f"signature on {dep_name!r} pin {pin!r}: signed by "
            f"{fingerprint}, capa.toml declares verify_key "
            f"{expected_fingerprint}. Either (a) the upstream rotated "
            f"its signing key -- confirm out of band and update the "
            f"verify_key field; or (b) someone else signed a tag "
            f"with this name. Refusing the install."
        )
    return fingerprint


_GITHUB_URL_RE = re.compile(
    r"^(?:https?://(?:www\.)?github\.com/|git@github\.com:)"
    r"(?P<owner>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?/?$"
)


def _parse_github_owner_repo(url: str) -> Optional[tuple[str, str]]:
    """Return ``(owner, repo)`` for a GitHub git URL, or None when
    the URL does not point at GitHub. Accepts both the https and
    ssh forms (``https://github.com/<o>/<r>[.git]`` and
    ``git@github.com:<o>/<r>[.git]``). Used to decide whether
    SLSA-provenance verification is even applicable: non-GitHub
    hosts have no attestation publishing pipeline today."""
    m = _GITHUB_URL_RE.match(url.strip())
    if m is None:
        return None
    return m.group("owner"), m.group("repo")


def _verify_slsa_provenance(
    dep: Dependency, pin: str, pin_kind: str,
) -> None:
    """Try to verify a SLSA L2 build-provenance attestation for the
    just-cloned dependency against the public Sigstore Rekor log.

    Implicit verification: this runs only when the dep already
    declares ``verify_key`` (the GPG layer is the trigger) AND the
    git URL points at GitHub AND the pin is a tag. The two layers
    are independent supply-chain claims; if GPG passes but SLSA
    fails, the install refuses.

    The verifier is the ``gh`` CLI's ``attestation verify``
    subcommand. Skipping silently rather than raising when:

      * the dep is not GitHub-hosted (no attestation pipeline);
      * the pin is a ``rev`` (releases live on tags);
      * the ``gh`` CLI is not installed on the caller's PATH;
      * the GitHub release for this tag exists but has no source
        tarball asset (publisher pre-dates the workflow, or hasn't
        adopted it yet);
      * the release endpoint is unreachable (offline / network
        glitch).

    Raising ``VerificationError`` when the release tarball IS
    present but ``gh attestation verify`` returns non-zero (the
    attestation in Rekor was tampered, or the workflow that signed
    it was not run from this owner's identity).

    A future iteration can add a ``verify_provenance = "required"``
    field to flip every graceful-skip path to fail-closed.
    """
    if pin_kind != "tag":
        return
    assert dep.git is not None
    owner_repo = _parse_github_owner_repo(dep.git)
    if owner_repo is None:
        return
    owner, repo = owner_repo

    if shutil.which("gh") is None:
        return

    tarball_name = f"{repo}-{pin}.tar.gz"
    with tempfile.TemporaryDirectory(prefix="capa_slsa_") as td:
        td_path = Path(td)
        r = subprocess.run(
            [
                "gh", "release", "download", pin,
                "--repo", f"{owner}/{repo}",
                "--pattern", tarball_name,
                "--dir", str(td_path),
            ],
            capture_output=True, text=True, encoding="utf-8",
        )
        # Release missing, no matching asset, no auth, or offline.
        # All graceful skips: an honest publisher just hasn't
        # adopted SLSA yet, or this user is offline. We never
        # downgrade trust because of these.
        if r.returncode != 0:
            return
        tarball_path = td_path / tarball_name
        if not tarball_path.exists():
            return

        r = subprocess.run(
            [
                "gh", "attestation", "verify", str(tarball_path),
                "--owner", owner,
            ],
            capture_output=True, text=True, encoding="utf-8",
        )
        if r.returncode == 0:
            return

        raise VerificationError(
            f"SLSA provenance verification failed on {dep.name!r} "
            f"pin {pin!r}: ``gh attestation verify`` returned "
            f"non-zero against the published source tarball at "
            f"{owner}/{repo} ({tarball_name}).\n\n"
            f"gh output:\n{(r.stderr or r.stdout).strip()}\n\n"
            f"The release ships a tarball but its SLSA attestation "
            f"in Sigstore Rekor is either missing, tampered, or "
            f"was issued by a different identity than {owner!r}. "
            f"Refusing the install."
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
