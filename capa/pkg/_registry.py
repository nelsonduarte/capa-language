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
import subprocess
import sys
import tempfile
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

# Transports the registry-index URL may use. The index is the trust
# root for the whole add flow: it supplies both the git URL AND the
# ``verify_key`` GPG fingerprint that anchors every downstream
# signature check. A cleartext fetch lets a network attacker swap
# both in one coherent entry, so the GPG layer then "passes" against
# the attacker's own key. We therefore require an authenticated
# transport for the index even though git deps themselves may use
# ``http://`` (a moved git dep is still caught by the lockfile SHA;
# a swapped index is not caught by anything below it). ``file://`` is
# allowed so the test suite (and air-gapped / self-hosted mirrors)
# can point at a local index. Audit slice 27 (2026-05-31).
_ALLOWED_INDEX_SCHEMES = ("https://", "file://")

# How long a cached index stays fresh, in seconds. Within this window
# the cache is read directly; past it the network is consulted.
_CACHE_TTL = 3600

_CACHE_FILENAME = "registry-index.json"

# Detached-signature filename, alongside the index (network) and the
# cache. ASCII-armoured GPG detached signature of the exact index bytes.
_SIG_SUFFIX = ".asc"
_CACHE_SIG_FILENAME = _CACHE_FILENAME + _SIG_SUFFIX

# Root-key fingerprint that anchors trust in the registry index itself.
# Out-of-band: it ships with the toolchain binary, NOT with the index,
# so a MITM / cache-poisoning attacker cannot substitute it. The index
# carries a detached ``index.json.asc`` (signed with this key); the
# toolchain verifies the exact index bytes against this fingerprint
# before trusting any entry.
#
# Slice 27 enforcement (2026-06-01): capa-registry now ships
# index.json.asc signed by this key, so it is baked in and the index
# is ENFORCED. A signed-and-valid index is accepted; a missing,
# invalid, mismatched, or unverifiable-because-tampered signature is
# refused (fail-closed). The only fail-open paths left are (a) gpg not
# on PATH -- an environment limitation, not an attacker-controllable
# vector, so it warns rather than blocks; and (b) the explicit
# ``CAPA_REGISTRY_ALLOW_UNSIGNED=1`` escape hatch for air-gapped /
# self-hosted mirrors that legitimately serve an unsigned index. See
# docs/design/signed-registry-index.md.
_REGISTRY_ROOT_KEY = "6C1D222D491FB88031E041A536CFB426101AA24B"

# Explicit opt-out for an unsigned index (air-gapped / self-hosted
# mirror). When set to "1", a MISSING signature warns instead of
# failing closed. A PRESENT-but-invalid signature still fails closed
# regardless -- the escape hatch is for "no signature at all", never
# for "a signature that does not validate".
_ALLOW_UNSIGNED_ENV = "CAPA_REGISTRY_ALLOW_UNSIGNED"

# Once-per-process warning guards (fail-open paths warn once, not per
# call, so a search loop does not spam stderr).
_warned_unconfigured = False
_warned_reasons: set[str] = set()


def _warn(message: str) -> None:
    print(f"capa: warning: {message}", file=sys.stderr)


def _warn_once(reason: str, message: str) -> None:
    """Emit ``message`` to stderr at most once per process for ``reason``."""
    if reason in _warned_reasons:
        return
    _warned_reasons.add(reason)
    _warn(message)


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


def _diagnose_lineending_mismatch(
    index_bytes: bytes, sig_text: str, expected: str
) -> bool:
    """Diagnostic-only re-check for a CRLF/LF publishing slip.

    Re-verify line-ending-NORMALISED copies of ``index_bytes`` (one with
    CRLF collapsed to LF, one with LF expanded to CRLF) against the SAME
    detached signature and the SAME pinned ``expected`` root key, each in
    its own temp file. Returns ``True`` iff one of those forms produces a
    VALIDSIG whose fingerprint equals ``expected``.

    SECURITY INVARIANT: this function NEVER accepts an index. Its caller
    has already decided to fail-closed over the raw bytes; the only effect
    of a ``True`` return is a clearer diagnostic sentence. A normalised
    form validating does not make the raw served bytes trustworthy, it
    only signals a likely CRLF/LF mangling after signing. Do not wire this
    into the accept path.
    """
    raw = index_bytes
    # Normalise to a canonical LF form first so both transforms are
    # well-defined regardless of the input's current line endings.
    lf = raw.replace(b"\r\n", b"\n")
    candidates = {lf, lf.replace(b"\n", b"\r\n")}
    candidates.discard(raw)  # the raw form already failed; skip it.

    for candidate in candidates:
        try:
            with tempfile.TemporaryDirectory(prefix="capa_idxdiag_") as td:
                tmp = Path(td)
                index_file = tmp / "index.json"
                sig_file = tmp / "index.json.asc"
                index_file.write_bytes(candidate)
                sig_file.write_text(sig_text, encoding="utf-8")
                r = subprocess.run(
                    [
                        "gpg", "--status-fd", "1", "--verify",
                        str(sig_file), str(index_file),
                    ],
                    capture_output=True, text=True, encoding="utf-8",
                )
        except FileNotFoundError:
            return False
        if r.returncode != 0:
            continue
        for line in r.stdout.splitlines():
            if line.startswith("[GNUPG:] VALIDSIG "):
                parts = line.split()
                # parts[-1] is the primary-key fpr (see doc/DETAILS);
                # match the accept gate, which anchors on the primary.
                if len(parts) >= 3 and parts[-1].upper() == expected:
                    return True
    return False


def _verify_index_signature(
    index_bytes: bytes, sig_text: Optional[str]
) -> None:
    """Verify a detached GPG signature over the raw index bytes.

    Enforced trust gate (slice 27 enforcement, see
    docs/design/signed-registry-index.md). Decision table:

      * root key not configured (``_REGISTRY_ROOT_KEY`` empty)
            -> warn once, return (FAIL-OPEN). Pre-1.0 builds only;
               the shipped toolchain bakes the key.
      * signature absent (``sig_text is None``):
            - with ``CAPA_REGISTRY_ALLOW_UNSIGNED=1`` set
                  -> warn once, return (explicit opt-out for
                     air-gapped / self-hosted unsigned mirrors).
            - otherwise
                  -> raise RegistryError (FAIL-CLOSED). A missing
                     signature is a downgrade-attack vector when the
                     toolchain knows the key, so absence is refused.
      * signature present, gpg binary missing (FileNotFoundError)
            - with ``CAPA_REGISTRY_ALLOW_UNSIGNED=1`` set
                  -> warn once, return (explicit air-gapped /
                     self-hosted opt-out).
            - otherwise
                  -> raise RegistryError (FAIL-CLOSED). The index is
                     the trust root; an unverifiable signed index is
                     refused, matching the tag-verification path in
                     _install.py which fails closed when git/gpg is
                     absent.
      * signature present, gpg non-zero / no VALIDSIG / fingerprint
        mismatch
            -> raise RegistryError (FAIL-CLOSED; an attack signal).
               The opt-out does NOT apply: a present-but-invalid
               signature is always refused.
      * signature present, VALIDSIG fingerprint == root key
            -> return (accepted).

    The verification runs over the EXACT bytes ``index_bytes`` (not a
    re-serialised dict): GPG signs bytes. Uses the caller's default
    GNUPGHOME, since the published root key lives in the user's
    keyring; no isolated keyring is invented for production verification.
    """
    import os

    global _warned_unconfigured

    if not _REGISTRY_ROOT_KEY:
        if not _warned_unconfigured:
            _warned_unconfigured = True
            _warn(
                "registry index signing is not configured in this "
                "toolchain (no root key); the index is being trusted "
                "without signature verification. See "
                "docs/design/signed-registry-index.md."
            )
        return

    if sig_text is None:
        if os.environ.get(_ALLOW_UNSIGNED_ENV) == "1":
            _warn_once(
                "unsigned",
                "registry index is unsigned and "
                f"{_ALLOW_UNSIGNED_ENV}=1 is set; trusting it without "
                "verification (air-gapped / self-hosted mirror "
                "opt-out).",
            )
            return
        raise RegistryError(
            "registry index is unsigned: no detached signature "
            "(index.json.asc) was found alongside it, but this "
            "toolchain enforces index signing. A missing signature is "
            "refused because an attacker who can swap the index can "
            "also strip its signature.\n\n"
            "If you are pointing at an air-gapped or self-hosted "
            f"mirror that legitimately serves an unsigned index, set "
            f"{_ALLOW_UNSIGNED_ENV}=1 to opt out. The official "
            "registry is signed; an unsigned official index is a "
            "tampering signal."
        )

    expected = _REGISTRY_ROOT_KEY.upper().replace(" ", "")

    with tempfile.TemporaryDirectory(prefix="capa_idxsig_") as td:
        tmp = Path(td)
        index_file = tmp / "index.json"
        sig_file = tmp / "index.json.asc"
        index_file.write_bytes(index_bytes)
        sig_file.write_text(sig_text, encoding="utf-8")
        try:
            r = subprocess.run(
                [
                    "gpg", "--status-fd", "1", "--verify",
                    str(sig_file), str(index_file),
                ],
                capture_output=True, text=True, encoding="utf-8",
            )
        except FileNotFoundError:
            # The index is the registry trust root: a signature is
            # present but gpg cannot verify it. Fail closed, matching
            # the tag-verification path in _install.py (which refuses
            # when git/gpg is missing). Trusting an unverifiable signed
            # index would silently downgrade the trust root. The
            # explicit air-gapped / self-hosted opt-out still rescues
            # callers who knowingly cannot run gpg.
            if os.environ.get(_ALLOW_UNSIGNED_ENV) == "1":
                _warn_once(
                    "nogpg",
                    "registry index carries a signature but 'gpg' is not "
                    f"on PATH; {_ALLOW_UNSIGNED_ENV}=1 is set, so it is "
                    "trusted unverified (air-gapped / self-hosted "
                    "opt-out).",
                )
                return
            raise RegistryError(
                "registry index carries a signature but 'gpg' is not on "
                "PATH, so the signature cannot be verified. The index is "
                "the registry trust root, so an unverifiable signed index "
                "is refused (fail-closed), the same way tag signature "
                "verification refuses a missing verifier.\n\n"
                "Install GnuPG and put 'gpg' on PATH, or, if you are "
                "pointing at an air-gapped / self-hosted mirror you trust "
                f"out of band, set {_ALLOW_UNSIGNED_ENV}=1 to opt out."
            )

    if r.returncode != 0:
        # Defence-in-depth diagnostic ONLY. The accept gate above
        # (write_bytes of the RAW index + this gpg --verify) has already
        # failed and we WILL fail-closed below no matter what. The
        # following re-check verifies LINE-ENDING-NORMALISED copies of the
        # index against the SAME signature and the SAME pinned root key,
        # in a separate temp file, purely to pick a clearer diagnostic
        # sentence. It NEVER accepts the index: a normalised form that
        # validates only tells us the publisher likely mangled CRLF/LF
        # after signing, not that the raw bytes are trustworthy. Refusing
        # the raw bytes is the security-relevant outcome and is preserved.
        crlf_hint = ""
        if _diagnose_lineending_mismatch(index_bytes, sig_text, expected):
            crlf_hint = (
                "\n\nDIAGNOSTIC: the signature DOES validate over a "
                "line-ending-normalised form of these exact bytes "
                "(CRLF<->LF), under the correct root key. This strongly "
                "suggests a CRLF/LF conversion in how the index is "
                "published or served (for example a git autocrlf or a "
                "proxy rewriting line endings AFTER signing), rather than "
                "deliberate tampering. The toolchain still refuses the "
                "index, because acceptance is only ever over the raw "
                "signed bytes. Please report this to the registry "
                "maintainer so the published index matches what was "
                "signed."
            )
        raise RegistryError(
            "registry index signature verification FAILED: ``gpg "
            "--verify`` returned non-zero. The detached signature does "
            "not validate. Either the index/signature was tampered with "
            "in transit or in the cache, or the signing key is not in "
            "your GPG keyring.\n\n"
            f"gpg output:\n{(r.stdout + r.stderr).strip()}\n\n"
            f"The expected root key is {expected}; import it out of band:\n"
            f"  gpg --recv-keys {expected}"
            f"{crlf_hint}"
        )

    # ``--status-fd 1`` routes the machine-readable status lines to
    # stdout; look for ``[GNUPG:] VALIDSIG <fingerprint>``. Per GnuPG
    # doc/DETAILS the LAST field of VALIDSIG is the primary-key
    # fingerprint; the root key is a publisher identity (the primary),
    # so anchor on parts[-1]. This accepts a signature made by a
    # dedicated signing subkey under the pinned root primary (gpg
    # already proved the subkey<-primary binding), so the root key can
    # rotate to a signing subkey without breaking index verification.
    fingerprint = None
    for line in r.stdout.splitlines():
        if line.startswith("[GNUPG:] VALIDSIG "):
            parts = line.split()
            if len(parts) >= 3:
                fingerprint = parts[-1].upper()
                break
    if fingerprint is None:
        raise RegistryError(
            "registry index signature verification FAILED: ``gpg "
            "--verify`` succeeded but emitted no VALIDSIG line, so the "
            "signing fingerprint cannot be confirmed. Refusing the "
            "index.\n\n"
            f"gpg output:\n{(r.stdout + r.stderr).strip()}"
        )
    if fingerprint != expected:
        raise RegistryError(
            f"registry index is signed by {fingerprint}, but this "
            f"toolchain pins the registry root key to {expected}. A "
            f"mismatched signature is an attack signal (swapped index / "
            f"poisoned cache / mirror compromise). Refusing the index."
        )


def _fetch_index(url: str) -> tuple[bytes, Optional[str]]:
    """GET the registry index and its detached signature.

    Returns ``(raw_index_bytes, sig_text_or_none)``. The raw bytes are
    returned (not a parsed dict) because the signature verifier needs
    the exact bytes GPG signed; JSON parsing happens in the caller after
    verification. The ``.asc`` is best-effort: a 404 / fetch error on it
    is treated as "no signature" (``None``), which the verifier handles
    per the warn-then-enforce phasing.

    Factored out so tests can monkeypatch the network round-trip without
    a live server. Raises any ``urllib`` / ``OSError`` error on the
    INDEX fetch to the caller, which decides whether to fall back to a
    cached copy.
    """
    with urllib.request.urlopen(url, timeout=_FETCH_TIMEOUT) as resp:
        raw = resp.read()
    sig_text: Optional[str] = None
    try:
        with urllib.request.urlopen(
            url + _SIG_SUFFIX, timeout=_FETCH_TIMEOUT
        ) as sresp:
            sig_text = sresp.read().decode("utf-8")
    except Exception:  # noqa: BLE001 - any sig fetch failure => unsigned
        sig_text = None
    return raw, sig_text


def _default_cache_dir() -> Path:
    return Path.home() / ".capa"


def _read_cache(cache_path: Path) -> Optional[tuple[bytes, Optional[str]]]:
    """Read the cached index bytes and its cached detached signature.

    Returns ``(raw_index_bytes, sig_text_or_none)`` or ``None`` when no
    cached index exists. The signature is read from the sibling
    ``registry-index.json.asc`` so the cache read re-verifies against the
    same bytes that were verified on write (cache-poisoning defence).
    """
    try:
        raw = cache_path.read_bytes()
    except OSError:
        return None
    sig_path = cache_path.with_name(_CACHE_SIG_FILENAME)
    try:
        sig_text: Optional[str] = sig_path.read_text(encoding="utf-8")
    except OSError:
        sig_text = None
    return raw, sig_text


def _write_cache(
    cache_path: Path, index_bytes: bytes, sig_text: Optional[str]
) -> None:
    """Persist the raw index bytes and its detached signature.

    Writes the EXACT fetched bytes (not a re-serialised dict) so the
    cached ``.asc`` keeps verifying against them. The sibling signature
    is written when present and removed when absent, so a later
    unsigned refresh cannot leave a stale ``.asc`` behind that would
    falsely fail verification.
    """
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(index_bytes)
        sig_path = cache_path.with_name(_CACHE_SIG_FILENAME)
        if sig_text is not None:
            sig_path.write_text(sig_text, encoding="utf-8")
        else:
            try:
                sig_path.unlink()
            except OSError:
                pass
    except OSError:
        # A cache that cannot be written is not fatal; the resolve
        # already succeeded against the freshly fetched index.
        pass


def _load_index(url: str, cache_path: Path) -> dict:
    """Return the index dict, honouring the cache TTL and verifying the
    detached signature over the raw bytes (network OR cache) before any
    JSON parse.

    Fresh cache (within TTL): used without a network round-trip, but
    still signature-verified (a poisoned cache must not slip through).
    Stale or missing cache: fetch from the network, verify, refresh the
    cache on success, fall back to a (verified) stale cache on failure.
    Only when the network fails and no cache exists is a fetch failure
    fatal. A present-but-invalid signature (cache or network) is
    fail-closed and is never swallowed by the stale-fallback path.
    """
    cached = _read_cache(cache_path)
    if cached is not None:
        try:
            age = time.time() - cache_path.stat().st_mtime
        except OSError:
            age = _CACHE_TTL + 1
        if age < _CACHE_TTL:
            raw, sig = cached
            _verify_index_signature(raw, sig)
            return _parse_index_bytes(raw, url)

    try:
        raw, sig = _fetch_index(url)
    except Exception as e:  # noqa: BLE001 - network/parse errors vary
        if cached is not None:
            raw, sig = cached
            _verify_index_signature(raw, sig)
            return _parse_index_bytes(raw, url)
        raise RegistryError(
            f"could not fetch the registry index from {url} and no "
            f"cached copy is available: {e}"
        ) from None

    # Verify BEFORE parsing/caching: GPG signs the exact bytes, and a
    # bad signature must fail closed rather than be persisted.
    _verify_index_signature(raw, sig)
    index = _parse_index_bytes(raw, url)
    _write_cache(cache_path, raw, sig)
    return index


def _parse_index_bytes(raw: bytes, url: str) -> dict:
    """Decode + JSON-parse verified index bytes into a dict.

    Kept separate from verification so the verify-then-parse order is
    explicit at the call sites. A decode/JSON error is surfaced the same
    way the rest of ``_load_packages`` reports a malformed index.
    """
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise RegistryError(
            f"registry index at {url} is malformed: {e}"
        ) from None


def _load_packages(
    registry_url: Optional[str],
    cache_dir: Optional[Path],
) -> tuple[str, dict]:
    """Fetch + cache + validate the index, returning ``(url, packages)``.

    The single code path both ``resolve_name`` and ``search_packages``
    use to get the index: it resolves the index URL, loads it (cache /
    network / stale fallback via ``_load_index``), checks the
    ``registry_version`` against this toolchain's support, and returns
    the validated ``packages`` table. Raises ``RegistryError`` on a
    malformed index, an unsupported version, or a fetch failure with no
    usable cache.

    The index URL is, in priority order: the ``registry_url`` argument,
    the ``CAPA_REGISTRY_URL`` env var, then ``DEFAULT_REGISTRY_URL``.
    """
    import os

    url = (
        registry_url
        or os.environ.get("CAPA_REGISTRY_URL")
        or DEFAULT_REGISTRY_URL
    )
    # The index is the trust root (it carries the verify_key that
    # anchors every GPG check below it), so it must arrive over an
    # authenticated transport. Reject a cleartext or otherwise
    # unexpected scheme regardless of whether it came from the
    # argument, the CAPA_REGISTRY_URL env var, or the default.
    if not url.startswith(_ALLOWED_INDEX_SCHEMES):
        raise RegistryError(
            f"registry index URL must use an authenticated transport "
            f"({' or '.join(s.rstrip(':/') for s in _ALLOWED_INDEX_SCHEMES)}); "
            f"got {url!r}. A cleartext index can be swapped in transit, "
            f"and the index supplies the GPG verify_key that anchors "
            f"package signature verification."
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

    return url, packages


def _entry_from_spec(name: str, spec: object) -> RegistryEntry:
    """Validate one registry ``spec`` and build a ``RegistryEntry``.

    Raises ``RegistryError`` when the spec is not an object, has no
    usable git URL, or carries a git URL that fails the shared
    allow-list a hand-written capa.toml is held to.
    """
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
    _url, packages = _load_packages(registry_url, cache_dir)

    spec = packages.get(name)
    if spec is None:
        available = ", ".join(sorted(packages)) or "(none)"
        raise RegistryError(
            f"package {name!r} is not in the registry. Known packages: "
            f"{available}. Pass --git <url> to add an unregistered "
            f"dependency."
        )

    return _entry_from_spec(name, spec)


def search_packages(
    query: str,
    *,
    registry_url: Optional[str] = None,
    cache_dir: Optional[Path] = None,
) -> list[RegistryEntry]:
    """Return registry entries matching ``query``, sorted by name.

    Matches case-insensitively on a substring of either the package
    name or its description. An empty / whitespace-only query returns
    every package in the registry, so ``capa search`` with no term
    lists the whole index. Shares the fetch + cache + version-check
    code path with ``resolve_name`` via ``_load_packages``.

    Malformed individual entries (a poisoned git URL, a non-object
    spec) are skipped rather than aborting the whole search: a single
    bad entry should not blind a user to the rest of the registry.
    """
    _url, packages = _load_packages(registry_url, cache_dir)

    needle = query.strip().lower()
    results: list[RegistryEntry] = []
    for name in sorted(packages):
        try:
            entry = _entry_from_spec(name, packages[name])
        except RegistryError:
            continue
        if not needle:
            results.append(entry)
            continue
        haystack = f"{entry.name}\n{entry.description or ''}".lower()
        if needle in haystack:
            results.append(entry)
    return results


def _opt_str(value: object) -> Optional[str]:
    """Coerce an optional registry field to a non-empty string or None."""
    if isinstance(value, str) and value:
        return value
    return None
