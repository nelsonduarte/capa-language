"""Resolve a package name to a git URL via the public registry index.

``capa add <name>`` (without ``--git``) names a package and lets the
registry supply the git URL, an optional GPG verify key, and the
latest published tag. This module fetches the registry index JSON,
looks the name up, and returns a ``RegistryEntry``.

The index is a single JSON document::

    {
      "registry_version": 1,
      "updated": "2026-05-27",
      "packages": {
        "capa_http": {
          "git": "https://github.com/nelsonduarte/capa_http",
          "verify_key": "6C1D...",
          "latest": "v0.1.3",
          "description": "..."
        }
      }
    }

The git URL that comes back from the index is validated through the
same ``_validate_git_url`` allow-list the manifest parser uses: a
poisoned index entry must not slip a dangerous transport (``ext::``,
option-injection, ...) past the checks that protect a hand-written
capa.toml.

Fetching uses the stdlib ``urllib.request`` only (no third-party HTTP
dependency). The fetched index is cached under ``~/.capa/`` with a
short TTL: within the TTL the cache is read without a network
round-trip; past it the network is tried and the cache is used as a
fallback when the fetch fails (stale-but-available beats hard-fail).
"""

from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ._manifest import MANIFEST_FILENAME, _validate_git_url


DEFAULT_REGISTRY_URL = (
    "https://raw.githubusercontent.com/nelsonduarte/capa-registry/"
    "main/index.json"
)

# Highest ``registry_version`` this toolchain knows how to read. An
# index that declares a newer version may use fields or semantics this
# build does not understand, so refuse it and tell the user to upgrade
# rather than silently mis-resolving.
SUPPORTED_REGISTRY_VERSION = 1

# Network timeout for the index fetch, in seconds.
_FETCH_TIMEOUT = 10

# How long a cached index stays fresh, in seconds. Within this window
# the cache is read directly; past it the network is consulted.
_CACHE_TTL = 3600

_CACHE_FILENAME = "registry-index.json"


class RegistryError(Exception):
    """Raised when the registry cannot resolve a name.

    Covers an unknown package, an index whose ``registry_version`` is
    newer than this toolchain supports, a malformed index, a fetch
    failure with no usable cache, and a poisoned index entry whose git
    URL fails the shared allow-list.
    """


@dataclass
class RegistryEntry:
    """One resolved package from the registry index."""
    name: str
    git: str
    verify_key: Optional[str] = None
    latest: Optional[str] = None
    description: Optional[str] = None


def _fetch_index(url: str) -> dict:
    """GET the registry index and parse it as JSON.

    Factored out so tests can monkeypatch the network round-trip
    without a live server. Raises any ``urllib`` / ``OSError`` /
    JSON error to the caller, which decides whether to fall back to a
    cached copy.
    """
    with urllib.request.urlopen(url, timeout=_FETCH_TIMEOUT) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8"))


def _default_cache_dir() -> Path:
    return Path.home() / ".capa"


def _read_cache(cache_path: Path) -> Optional[dict]:
    try:
        return json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _write_cache(cache_path: Path, index: dict) -> None:
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(
            json.dumps(index, indent=2), encoding="utf-8"
        )
    except OSError:
        # A cache that cannot be written is not fatal; the resolve
        # already succeeded against the freshly fetched index.
        pass


def _load_index(url: str, cache_path: Path) -> dict:
    """Return the index dict, honouring the cache TTL.

    Fresh cache (within TTL): used without a network round-trip.
    Stale or missing cache: fetch from the network, refresh the cache
    on success, fall back to a stale cache on failure. Only when the
    network fails and no cache exists is a fetch failure fatal.
    """
    cached = _read_cache(cache_path)
    if cached is not None:
        try:
            age = time.time() - cache_path.stat().st_mtime
        except OSError:
            age = _CACHE_TTL + 1
        if age < _CACHE_TTL:
            return cached

    try:
        index = _fetch_index(url)
    except Exception as e:  # noqa: BLE001 - network/parse errors vary
        if cached is not None:
            return cached
        raise RegistryError(
            f"could not fetch the registry index from {url} and no "
            f"cached copy is available: {e}"
        ) from None

    _write_cache(cache_path, index)
    return index


def resolve_name(
    name: str,
    *,
    registry_url: Optional[str] = None,
    cache_dir: Optional[Path] = None,
) -> RegistryEntry:
    """Resolve a package name to its registry entry.

    Fetches the registry index JSON, looks up ``name``, and returns a
    ``RegistryEntry`` (git URL plus optional verify_key and latest
    tag). Raises ``RegistryError`` on an unknown name, an index whose
    ``registry_version`` exceeds this toolchain's support, a malformed
    index, a fetch failure with no usable cache, or a git URL in the
    index that fails the shared allow-list.

    The index URL is, in priority order: the ``registry_url``
    argument, the ``CAPA_REGISTRY_URL`` env var, then
    ``DEFAULT_REGISTRY_URL``.
    """
    import os

    url = (
        registry_url
        or os.environ.get("CAPA_REGISTRY_URL")
        or DEFAULT_REGISTRY_URL
    )
    base = cache_dir if cache_dir is not None else _default_cache_dir()
    cache_path = base / _CACHE_FILENAME

    index = _load_index(url, cache_path)

    if not isinstance(index, dict):
        raise RegistryError(
            f"registry index at {url} is malformed: top-level value "
            f"must be a JSON object"
        )

    version = index.get("registry_version")
    if not isinstance(version, int):
        raise RegistryError(
            f"registry index at {url} is malformed: 'registry_version' "
            f"must be an integer, got {version!r}"
        )
    if version > SUPPORTED_REGISTRY_VERSION:
        raise RegistryError(
            f"registry index declares registry_version {version}, but "
            f"this Capa toolchain understands up to "
            f"{SUPPORTED_REGISTRY_VERSION}. Upgrade your Capa toolchain "
            f"to use this registry."
        )

    packages = index.get("packages")
    if not isinstance(packages, dict):
        raise RegistryError(
            f"registry index at {url} is malformed: 'packages' must be "
            f"a JSON object"
        )

    spec = packages.get(name)
    if spec is None:
        available = ", ".join(sorted(packages)) or "(none)"
        raise RegistryError(
            f"package {name!r} is not in the registry. Known packages: "
            f"{available}. Pass --git <url> to add an unregistered "
            f"dependency."
        )
    if not isinstance(spec, dict):
        raise RegistryError(
            f"registry entry for {name!r} is malformed: expected a JSON "
            f"object, got {type(spec).__name__}"
        )

    git = spec.get("git")
    if not isinstance(git, str) or not git:
        raise RegistryError(
            f"registry entry for {name!r} has no usable 'git' URL"
        )

    # Defence in depth: a registry entry must clear the same
    # allow-list a hand-written capa.toml does, so a poisoned index
    # cannot smuggle a dangerous transport (ext::, option injection)
    # into the add flow. ``_validate_git_url`` raises ManifestError;
    # re-wrap it as a RegistryError so the CLI catches one error type
    # for the registry path.
    try:
        _validate_git_url(Path(MANIFEST_FILENAME), name, git)
    except Exception as e:  # ManifestError
        raise RegistryError(
            f"registry entry for {name!r} has a disallowed git URL: {e}"
        ) from None

    return RegistryEntry(
        name=name,
        git=git,
        verify_key=_opt_str(spec.get("verify_key")),
        latest=_opt_str(spec.get("latest")),
        description=_opt_str(spec.get("description")),
    )


def _opt_str(value: object) -> Optional[str]:
    """Coerce an optional registry field to a non-empty string or None."""
    if isinstance(value, str) and value:
        return value
    return None
