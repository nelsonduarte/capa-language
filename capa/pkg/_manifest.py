"""``capa.toml`` parser + validator and the ``capa.lock`` reader.

A capa.toml manifest declares the package's identity and its
dependencies. Each dependency is either:

  * **git**: a URL plus a pin (``tag = "v0.1"`` or
    ``rev = "abc123"``). Cloned into ``vendor/<name>``.
  * **path**: a filesystem path (relative to the manifest).
    No vendoring; the path is added to the loader's search
    paths directly. Useful during development of a library
    alongside its consumers.

A dependency must use exactly one of those sources. The
parser is intentionally strict: any unrecognised key, missing
required key, or wrong type is a ``ManifestError`` with a
pinpoint message, so a typo in a config file does not become
a silent classpath surprise at run time.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

if sys.version_info >= (3, 11):
    import tomllib as _toml
else:  # pragma: no cover - Capa requires 3.10; this branch is dev-only
    try:
        import tomli as _toml  # type: ignore
    except ImportError:
        _toml = None  # type: ignore


MANIFEST_FILENAME = "capa.toml"
LOCK_FILENAME = "capa.lock"

# Keys recognised in each table; anything else is an error.
_PACKAGE_KEYS = frozenset({"name", "version", "capa"})
_DEP_GIT_KEYS = frozenset({"git", "tag", "rev", "verify_key"})
_DEP_PATH_KEYS = frozenset({"path"})

# Allow-list of URL schemes that ``git clone`` is willing to handle
# without triggering one of the historical RCE classes around the
# ``ext::`` transport (CVE-2017-1000117 / CVE-2022-39253 family) or
# the option-injection path where a URL starting with ``-`` ends up
# parsed as a git command-line option. Anything outside this list
# is refused at manifest-load time so a malicious capa.toml never
# reaches ``_run_git`` in the first place.
_ALLOWED_GIT_SCHEMES = ("https://", "http://", "ssh://", "git://", "file://")


class ManifestError(Exception):
    """Raised on invalid ``capa.toml`` or ``capa.lock`` contents."""


@dataclass(frozen=True)
class Dependency:
    """One declared dependency.

    Exactly one of ``git`` (with one of ``tag`` / ``rev``) or
    ``path`` is set; this is enforced by ``read_manifest``.

    ``verify_key`` is an optional GPG fingerprint (40 hex chars,
    spaces allowed and stripped). When set, ``capa install``
    runs ``git verify-tag`` / ``git verify-commit`` against the
    cloned dep and rejects the install unless the signature
    matches that fingerprint. The fingerprint is the trust
    anchor: it must already be present in the consumer's GPG
    keyring (``gpg --import`` or ``gpg --recv-keys``)."""
    name: str
    git: Optional[str] = None
    tag: Optional[str] = None
    rev: Optional[str] = None
    path: Optional[str] = None
    verify_key: Optional[str] = None

    @property
    def is_git(self) -> bool:
        return self.git is not None

    @property
    def is_path(self) -> bool:
        return self.path is not None


@dataclass
class Manifest:
    """A parsed ``capa.toml``.

    ``manifest_dir`` is the directory containing the manifest;
    relative paths in ``[dependencies]`` resolve against it.
    """
    name: str
    version: str
    capa_requirement: Optional[str]
    dependencies: list[Dependency] = field(default_factory=list)
    manifest_dir: Path = field(default_factory=Path.cwd)


@dataclass(frozen=True)
class LockedDependency:
    """A resolved git dependency, frozen in ``capa.lock``."""
    name: str
    git: str
    pin: str               # the tag or rev from the manifest
    pin_kind: str          # "tag" or "rev"
    commit: str            # the full SHA the pin resolved to
    # The GPG fingerprint that signed the tag / commit, captured
    # on successful verification. Empty string when verification
    # was not requested (no ``verify_key`` in capa.toml). Recorded
    # so an auditor can confirm what key signed each frozen pin
    # without re-running the verification.
    signing_key: str = ""


def read_manifest(path: Path) -> Manifest:
    """Load and validate ``capa.toml``."""
    if _toml is None:
        raise ManifestError(
            "capa.toml support requires tomllib (Python >= 3.11) or "
            "the 'tomli' backport; install one to use the package manager"
        )
    text = path.read_text(encoding="utf-8")
    try:
        data = _toml.loads(text)
    except _toml.TOMLDecodeError as e:
        raise ManifestError(f"{path}: {e}") from None

    if not isinstance(data, dict):
        raise ManifestError(f"{path}: manifest root must be a table")

    package = data.get("package")
    if not isinstance(package, dict):
        raise ManifestError(
            f"{path}: missing [package] table"
        )
    _check_keys(path, "[package]", package, _PACKAGE_KEYS)
    name = _require_str(path, package, "name", "[package]")
    version = _require_str(path, package, "version", "[package]")
    capa_req = package.get("capa")
    if capa_req is not None and not isinstance(capa_req, str):
        raise ManifestError(
            f"{path}: [package].capa must be a string (version requirement)"
        )

    deps_raw = data.get("dependencies", {})
    if not isinstance(deps_raw, dict):
        raise ManifestError(
            f"{path}: [dependencies] must be a table"
        )
    deps: list[Dependency] = []
    for dep_name, spec in deps_raw.items():
        if not isinstance(spec, dict):
            raise ManifestError(
                f"{path}: dependency {dep_name!r} must be a table "
                f"(use the inline form: {dep_name} = {{ git = \"...\", tag = \"...\" }})"
            )
        deps.append(_parse_dep(path, dep_name, spec))

    # Remaining unknown top-level keys: a strict parser rejects them
    # so a typo in the manifest cannot turn into a silent ignore.
    allowed_top = {"package", "dependencies"}
    extras = set(data.keys()) - allowed_top
    if extras:
        raise ManifestError(
            f"{path}: unknown top-level key(s): {sorted(extras)}"
        )

    return Manifest(
        name=name,
        version=version,
        capa_requirement=capa_req,
        dependencies=deps,
        manifest_dir=path.parent.resolve(),
    )


def _validate_git_url(path: Path, name: str, url: str) -> None:
    """Reject git URLs that historically gave ``git clone`` an
    RCE primitive. The two attack shapes we close here:

    - **The ``ext::`` transport** (and any non-allow-listed
      scheme). ``git clone ext::'sh -c <command>'`` runs the
      command as the remote-helper child. The fix is an
      allow-list of well-known transports; if a real-world need
      for a custom transport appears, widen the list deliberately
      rather than letting unknown schemes through by default.

    - **Option injection at the URL position**. ``git clone``
      treats any URL starting with ``-`` as a command-line
      option, and a few flags carry remote-side execution
      semantics (``--upload-pack=<cmd>``, ``--exec=<cmd>``).
      Refuse URLs that start with ``-`` outright, and refuse the
      ``git@host:path`` SSH shortcut when the ``path`` segment
      starts with ``-``.
    """
    if url.startswith("-"):
        raise ManifestError(
            f"{path}: dependencies.{name}.git starts with '-'; "
            f"this would be parsed as a git command-line option, "
            f"not a URL. Got {url!r}"
        )
    if url.startswith("git@"):
        # The ``git@host:path`` SSH shortcut has no explicit scheme.
        # Allow it but reject path segments that re-introduce the
        # option-injection class via the ``:`` separator.
        _, _, path_segment = url.partition(":")
        if path_segment.startswith("-"):
            raise ManifestError(
                f"{path}: dependencies.{name}.git path segment after "
                f"':' starts with '-' (would be parsed as a git "
                f"command-line option). Got {url!r}"
            )
        return
    if not any(url.startswith(s) for s in _ALLOWED_GIT_SCHEMES):
        raise ManifestError(
            f"{path}: dependencies.{name}.git must use one of the "
            f"allow-listed transports "
            f"(https://, http://, ssh://, git://, file://, or the "
            f"git@host:path shortcut). Got {url!r}. This blocks the "
            f"ext:: transport (CVE-2017-1000117 class), among other "
            f"git URL injection patterns."
        )


def _parse_dep(path: Path, name: str, spec: dict) -> Dependency:
    """One ``[dependencies]`` entry. Exactly one source kind allowed."""
    if "git" in spec and "path" in spec:
        raise ManifestError(
            f"{path}: dependency {name!r} declares both 'git' and 'path'; "
            f"pick one"
        )
    if "git" not in spec and "path" not in spec:
        raise ManifestError(
            f"{path}: dependency {name!r} needs a source ('git = ...' or "
            f"'path = ...')"
        )
    if "git" in spec:
        _check_keys(path, f"dependencies.{name}", spec, _DEP_GIT_KEYS)
        git = _require_str(path, spec, "git", f"dependencies.{name}")
        _validate_git_url(path, name, git)
        tag = spec.get("tag")
        rev = spec.get("rev")
        if tag is None and rev is None:
            raise ManifestError(
                f"{path}: git dependency {name!r} needs a pin "
                f"('tag = \"v0.1\"' or 'rev = \"abc123\"')"
            )
        if tag is not None and rev is not None:
            raise ManifestError(
                f"{path}: git dependency {name!r} cannot have both "
                f"'tag' and 'rev'; pick one"
            )
        if tag is not None and not isinstance(tag, str):
            raise ManifestError(
                f"{path}: dependencies.{name}.tag must be a string"
            )
        if rev is not None and not isinstance(rev, str):
            raise ManifestError(
                f"{path}: dependencies.{name}.rev must be a string"
            )
        verify_key = spec.get("verify_key")
        if verify_key is not None:
            if not isinstance(verify_key, str):
                raise ManifestError(
                    f"{path}: dependencies.{name}.verify_key must be a string"
                )
            normalised = verify_key.replace(" ", "").replace(":", "").upper()
            if (len(normalised) != 40
                    or any(c not in "0123456789ABCDEF" for c in normalised)):
                raise ManifestError(
                    f"{path}: dependencies.{name}.verify_key must be a "
                    f"40-character GPG fingerprint (hex, spaces optional). "
                    f"Got {verify_key!r}"
                )
            verify_key = normalised
        return Dependency(
            name=name, git=git, tag=tag, rev=rev, verify_key=verify_key,
        )
    # path source
    _check_keys(path, f"dependencies.{name}", spec, _DEP_PATH_KEYS)
    p = _require_str(path, spec, "path", f"dependencies.{name}")
    return Dependency(name=name, path=p)


def _check_keys(
    path: Path, where: str, table: dict, allowed: frozenset,
) -> None:
    extras = set(table.keys()) - allowed
    if extras:
        raise ManifestError(
            f"{path}: unknown key(s) in {where}: {sorted(extras)}; "
            f"allowed: {sorted(allowed)}"
        )


def _require_str(path: Path, table: dict, key: str, where: str) -> str:
    if key not in table:
        raise ManifestError(f"{path}: {where} is missing required key {key!r}")
    v = table[key]
    if not isinstance(v, str):
        raise ManifestError(f"{path}: {where}.{key} must be a string")
    return v


def read_lock(path: Path) -> list[LockedDependency]:
    """Load ``capa.lock`` if present. Missing file is not an error."""
    if not path.exists():
        return []
    if _toml is None:
        raise ManifestError(
            "capa.lock parsing requires tomllib (Python >= 3.11) or 'tomli'"
        )
    text = path.read_text(encoding="utf-8")
    try:
        data = _toml.loads(text)
    except _toml.TOMLDecodeError as e:
        raise ManifestError(f"{path}: {e}") from None
    arr = data.get("dependencies", [])
    if not isinstance(arr, list):
        raise ManifestError(
            f"{path}: 'dependencies' must be an array of tables"
        )
    out: list[LockedDependency] = []
    for entry in arr:
        if not isinstance(entry, dict):
            raise ManifestError(
                f"{path}: each lockfile entry must be a table"
            )
        signing_key = entry.get("signing_key", "")
        if not isinstance(signing_key, str):
            raise ManifestError(
                f"{path}: lock entry 'signing_key' must be a string"
            )
        out.append(LockedDependency(
            name=_require_str(path, entry, "name", "lock entry"),
            git=_require_str(path, entry, "git", "lock entry"),
            pin=_require_str(path, entry, "pin", "lock entry"),
            pin_kind=_require_str(path, entry, "pin_kind", "lock entry"),
            commit=_require_str(path, entry, "commit", "lock entry"),
            signing_key=signing_key,
        ))
    return out


def write_lock(path: Path, locked: list[LockedDependency]) -> None:
    """Emit ``capa.lock``. Format is hand-rolled so the file stays
    diff-friendly and human-readable without a TOML writer dependency.
    """
    lines = [
        "# capa.lock - AUTO-GENERATED by `capa install`. DO NOT EDIT.",
        "# Re-running `capa install` rewrites this file from capa.toml.",
        "",
    ]
    for d in locked:
        lines.append("[[dependencies]]")
        lines.append(f'name = "{d.name}"')
        lines.append(f'git = "{d.git}"')
        lines.append(f'pin = "{d.pin}"')
        lines.append(f'pin_kind = "{d.pin_kind}"')
        lines.append(f'commit = "{d.commit}"')
        if d.signing_key:
            lines.append(f'signing_key = "{d.signing_key}"')
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
