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
_DEP_GIT_KEYS = frozenset({"git", "tag", "rev"})
_DEP_PATH_KEYS = frozenset({"path"})


class ManifestError(Exception):
    """Raised on invalid ``capa.toml`` or ``capa.lock`` contents."""


@dataclass(frozen=True)
class Dependency:
    """One declared dependency.

    Exactly one of ``git`` (with one of ``tag`` / ``rev``) or
    ``path`` is set; this is enforced by ``read_manifest``.
    """
    name: str
    git: Optional[str] = None
    tag: Optional[str] = None
    rev: Optional[str] = None
    path: Optional[str] = None

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
        return Dependency(name=name, git=git, tag=tag, rev=rev)
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
        out.append(LockedDependency(
            name=_require_str(path, entry, "name", "lock entry"),
            git=_require_str(path, entry, "git", "lock entry"),
            pin=_require_str(path, entry, "pin", "lock entry"),
            pin_kind=_require_str(path, entry, "pin_kind", "lock entry"),
            commit=_require_str(path, entry, "commit", "lock entry"),
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
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
