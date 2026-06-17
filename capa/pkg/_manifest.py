"""``capa.toml`` parser + validator and the ``capa.lock`` reader.

A capa.toml manifest declares the package's identity and its
dependencies. Each dependency is either:

  * **git**: a URL plus a pin (``tag = "v0.1"`` or
    ``rev = "abc123"``). Cloned into ``vendor/<name>``.
  * **path**: a filesystem path (relative to the manifest).
    No vendoring; the path is added to the loader's search
    paths directly. Useful during development of a library
    alongside its consumers.

Besides ``[dependencies]`` the manifest may declare a
``[dev-dependencies]`` table with exactly the same per-entry
schema and the same validation rules. Dev-dependencies are
test/tooling-only deps: ``capa install`` fetches them when run
on the project itself (the invocation root), and they are never
pulled in when the package is consumed as a dependency of
another project (Capa v1 reads only the root manifest, so a
consumer never sees them by construction). A name declared in
both tables is a hard error.

A dependency must use exactly one of those sources. The
parser is intentionally strict: any unrecognised key, missing
required key, or wrong type is a ``ManifestError`` with a
pinpoint message, so a typo in a config file does not become
a silent classpath surprise at run time.
"""

from __future__ import annotations

import re
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

# Dependency names are used verbatim as a directory name under
# ``vendor/`` at install time. TOML's lexical syntax allows
# arbitrary quoted keys (``[dependencies."../evil"]``), so without
# a manifest-level allow-list a malicious upstream can pivot the
# eventual ``vendor/<name>`` write outside the project tree.
# Audit 2026-05-25 C1: locked down to a conservative identifier
# shape that matches Capa module names. Any quoted-TOML escape
# (path separator, leading dot, NUL, whitespace, ...) is refused
# at parse time, before ``_install`` can touch the filesystem.
_DEP_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")

# Git pins (``tag`` / ``rev``) flow into ``git`` argv as
# positionals (``clone --branch <pin>``, ``checkout --detach <pin>``,
# ``verify-tag --raw <pin>``). Audit 2026-05-25 H2: even with the
# URL allow-list closing the option-injection-at-URL-position
# class, a pin shaped like ``--no-such-flag`` lands in an option
# position for ``verify-tag``. Lock pins down to the characters
# that real-world tag / commit-id syntax actually uses, with no
# leading ``-`` (so it cannot be parsed as a flag).
_PIN_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._+\-]{0,127}$")


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
    # ``[dev-dependencies]`` entries. Same shape and validation as
    # ``dependencies``; installed only when this manifest is the
    # invocation root (see capa.pkg._install).
    dev_dependencies: list[Dependency] = field(default_factory=list)
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
    # True when the dependency came from ``[dev-dependencies]``.
    # Recorded in the lockfile (``dev = true``) so an auditor can
    # tell which frozen pins are test/tooling-only and a future
    # ``--no-dev`` install mode can skip them without re-reading
    # the manifest.
    dev: bool = False


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

    deps = _parse_dep_table(path, data, "dependencies")
    dev_deps = _parse_dep_table(path, data, "dev-dependencies")

    # A name in both tables would race for the same ``vendor/<name>``
    # directory (and make the import surface ambiguous); refuse it
    # at parse time with both kinds named.
    dep_names = {d.name for d in deps}
    for d in dev_deps:
        if d.name in dep_names:
            raise ManifestError(
                f"{path}: {d.name!r} is declared in both [dependencies] "
                f"and [dev-dependencies]; a name can appear in only one "
                f"table (both would vendor into vendor/{d.name})"
            )

    # Remaining unknown top-level keys: a strict parser rejects them
    # so a typo in the manifest cannot turn into a silent ignore.
    allowed_top = {"package", "dependencies", "dev-dependencies"}
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
        dev_dependencies=dev_deps,
        manifest_dir=path.parent.resolve(),
    )


def _parse_dep_table(path: Path, data: dict, table: str) -> list[Dependency]:
    """Parse one dependency table (``[dependencies]`` or
    ``[dev-dependencies]``). Both share the exact same per-entry
    schema and security validation; only the table name differs.
    """
    raw = data.get(table, {})
    if not isinstance(raw, dict):
        raise ManifestError(
            f"{path}: [{table}] must be a table"
        )
    deps: list[Dependency] = []
    for dep_name, spec in raw.items():
        _validate_dep_name(path, dep_name)
        if not isinstance(spec, dict):
            raise ManifestError(
                f"{path}: dependency {dep_name!r} must be a table "
                f"(use the inline form: {dep_name} = {{ git = \"...\", tag = \"...\" }})"
            )
        deps.append(_parse_dep(path, dep_name, spec))
    return deps


def _validate_dep_name(path: Path, name: str) -> None:
    """Refuse dependency names that would let a malicious upstream
    escape ``vendor/`` at install time.

    Audit 2026-05-25 C1: TOML accepts arbitrary quoted keys
    (``[dependencies."../evil"]``), so without a regex anchor the
    string ``dep.name`` flows straight into ``vendor_dir / name``
    and is then ``_rmtree_force``-ed before being clobbered by the
    fresh clone. Reject anything that is not an obvious Capa
    identifier shape - path separators, parent traversal, leading
    dots, NUL bytes, absolute paths, whitespace, and so on all
    fail the regex and never reach the install layer.
    """
    if not isinstance(name, str):
        raise ManifestError(
            f"{path}: dependency key must be a string, got {type(name).__name__}"
        )
    if not _DEP_NAME_RE.match(name):
        raise ManifestError(
            f"{path}: invalid dependency name {name!r}; names must match "
            f"{_DEP_NAME_RE.pattern} (letters, digits, ``_`` and ``-``; "
            f"must start with a letter or underscore; max 64 chars). "
            f"This blocks ``vendor/`` path-traversal at install time."
        )


def _validate_pin(path: Path, name: str, kind: str, pin: str) -> None:
    """Refuse git pins (tag / rev) that could be parsed as a git
    command-line flag or break out of an argv positional.

    Audit 2026-05-25 H2: pins flow into ``git clone --branch <pin>``,
    ``git checkout --detach <pin>``, and ``git verify-tag --raw <pin>``.
    The URL allow-list already closed the option-position-at-URL hole,
    but the pin still ends up at an option position for ``verify-tag``.
    Lock pins down to characters that real-world refs actually use
    (``[A-Za-z0-9._+\\-]``), no leading ``-``, no whitespace, no NUL,
    no path separators.
    """
    if not _PIN_RE.match(pin):
        raise ManifestError(
            f"{path}: dependencies.{name}.{kind} = {pin!r} is not a valid "
            f"git ref shape. Pins must match {_PIN_RE.pattern} (letters, "
            f"digits, ``._+-``; first char cannot be ``-`` or punctuation). "
            f"This blocks git argv injection via the pin position."
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

    - **Option injection at the host component of a scheme URL**.
      A scheme like ``ssh://-oProxyCommand=calc/repo`` does not
      start with ``-`` (it starts with ``ssh://``), but the host
      that ``git`` / the ssh transport eventually sees does. Modern
      git mitigates the ``ssh://-...`` shape, but the promised
      defence-in-depth means we also reject any URL whose host
      component (after ``scheme://`` and an optional ``user@``)
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
    matched_scheme = next(
        (s for s in _ALLOWED_GIT_SCHEMES if url.startswith(s)), None,
    )
    if matched_scheme is None:
        raise ManifestError(
            f"{path}: dependencies.{name}.git must use one of the "
            f"allow-listed transports "
            f"(https://, http://, ssh://, git://, file://, or the "
            f"git@host:path shortcut). Got {url!r}. This blocks the "
            f"ext:: transport (CVE-2017-1000117 class), among other "
            f"git URL injection patterns."
        )
    # ``file://`` is allow-listed for legitimate local mirrors / test
    # repos, but it must not become a path-traversal primitive: a dep
    # like ``file://../../../etc/passwd`` would pull arbitrary local
    # content (and, once vendored, attacker-chosen code) into the
    # build. Refuse any ``..`` component in a file:// path while
    # keeping plain absolute paths (``file:///home/user/repo``,
    # ``file:///C:/abs/path/repo``) accepted.
    if matched_scheme == "file://":
        file_path = url[len(matched_scheme):]
        # Normalise both separators so ``..\..`` is caught on every OS.
        for component in file_path.replace("\\", "/").split("/"):
            if component == "..":
                raise ManifestError(
                    f"{path}: dependencies.{name}.git is a file:// URL "
                    f"containing a '..' path component, which is a "
                    f"path-traversal vector (it can escape the intended "
                    f"directory and vendor arbitrary local content). "
                    f"Use an absolute file:// path with no '..'. "
                    f"Got {url!r}"
                )
        return
    # Reject a host component that starts with '-'. The host is the
    # text after ``scheme://`` and an optional ``user@`` prefix, up to
    # the first path / port separator. A leading '-' there reintroduces
    # the option-injection class one level down from the URL position
    # (e.g. ``ssh://-oProxyCommand=calc/repo``). The file:// case
    # already returned above.
    authority = url[len(matched_scheme):]
    # Drop an optional ``user[:pass]@`` prefix; the host is what
    # follows. Then cut at the first '/', ':' (port), or '?'.
    host = authority.split("@", 1)[-1]
    host = host.split("/", 1)[0].split(":", 1)[0].split("?", 1)[0]
    if host.startswith("-"):
        raise ManifestError(
            f"{path}: dependencies.{name}.git host component "
            f"{host!r} starts with '-'; this would be parsed as a "
            f"command-line option by git / the ssh transport. "
            f"Got {url!r}"
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
        if tag is not None:
            _validate_pin(path, name, "tag", tag)
        if rev is not None:
            _validate_pin(path, name, "rev", rev)
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
        dev = entry.get("dev", False)
        if not isinstance(dev, bool):
            raise ManifestError(
                f"{path}: lock entry 'dev' must be a boolean"
            )
        dep_name = _require_str(path, entry, "name", "lock entry")
        _validate_dep_name(path, dep_name)
        pin_kind = _require_str(path, entry, "pin_kind", "lock entry")
        pin = _require_str(path, entry, "pin", "lock entry")
        _validate_pin(path, dep_name, pin_kind, pin)
        out.append(LockedDependency(
            name=dep_name,
            git=_require_str(path, entry, "git", "lock entry"),
            pin=pin,
            pin_kind=pin_kind,
            commit=_require_str(path, entry, "commit", "lock entry"),
            signing_key=signing_key,
            dev=dev,
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
        if d.dev:
            lines.append("dev = true")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
