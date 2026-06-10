"""Concrete capability classes shipped with the Capa runtime.

Each class represents an authority a Capa program holds, instantiated
in ``main`` and threaded through function arguments. Capabilities are
the load-bearing primitive of the language: a function that doesn't
receive ``Fs`` cannot touch the filesystem, no matter what.

This module bundles all capabilities together because they share a
small set of conventions (first-class attenuation, ``allows`` queries,
fail-closed denied behaviour) and the boundary between them is
narrower than the boundary between "the capabilities as a group" and
the rest of the runtime.

Classes:

- ``IoError`` - shared error type for IO-shaped capabilities.
- ``Stdio`` - terminal IO.
- ``Fs`` - filesystem with prefix-set attenuation.
- ``Env`` - environment variables with key-set attenuation.
- ``Clock`` - time with a not-before threshold.
- ``Random`` - RNG with optional seeding.
- ``_StubCapability`` - placeholder for not-yet-implemented caps.
- ``Db`` - SQLite-backed key-value + tabular store with prefix-set
  attenuation (slice 11, 2026-05).
- ``Proc`` - sandboxed subprocess execution with basename-prefix
  attenuation (slice 15, 2026-05).
- ``Net`` - HTTP GET with host-set attenuation.
- ``Unsafe`` - the Python-interop trust boundary (method-less).
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import _fs_guard
from ._list import CapaList
from ._result import Err, None_, Ok, Some


@dataclass(frozen=True)
class IoError:
    """Generic IO error. In production, one would have specific variants."""
    message: str
    cause: str = ""

    def __str__(self) -> str:
        if self.cause:
            return f"{self.message}: {self.cause}"
        return self.message


def _write_safe(stream, text: str) -> None:
    """Write ``text`` to ``stream``, falling back to replacement
    characters if the terminal codec cannot encode it.

    Windows consoles default to cp1252 (or another non-UTF-8 OEM
    codec); writing e.g. the fox emoji raises ``UnicodeEncodeError``
    out of the runtime. To avoid crashing a Capa program on an
    encoding mismatch, we re-encode with ``errors="replace"`` and
    write the surrogated form. Same convention as the Wasm host's
    UTF-8 decode side (audit fix H3): silent crashes are worse than
    a visible replacement character.

    Both backends share this helper so a program that prints a
    non-cp1252 character produces byte-identical output on the
    Python and Wasm paths.
    """
    try:
        stream.write(text)
    except UnicodeEncodeError:
        encoding = getattr(stream, "encoding", None) or "ascii"
        safe = text.encode(encoding, errors="replace").decode(
            encoding, errors="replace",
        )
        stream.write(safe)


class Stdio:
    """Capability for standard input and output."""

    def print(self, text: str) -> None:
        """Prints without trailing newline."""
        _write_safe(sys.stdout, text)
        sys.stdout.flush()

    def println(self, text: str) -> None:
        """Prints with trailing newline."""
        _write_safe(sys.stdout, text + "\n")
        sys.stdout.flush()

    def eprintln(self, text: str) -> None:
        """Prints to stderr with newline."""
        _write_safe(sys.stderr, text + "\n")
        sys.stderr.flush()

    def read_line(self) -> "Result[str, IoError]":
        """Reads a line from stdin (without the trailing newline)."""
        try:
            line = sys.stdin.readline()
            if not line:
                return Err(IoError("end of input"))
            return Ok(line.rstrip("\n"))
        except OSError as e:
            return Err(IoError("read failed", str(e)))


class Fs:
    """Capability for filesystem access, with first-class attenuation.

    An instance carries either ``None`` (unrestricted authority, the
    fresh capability supplied by ``main``) or a frozen set of allowed
    path prefixes. ``restrict_to`` returns a new ``Fs`` whose
    authority is narrowed: the new restriction is *added* to the set,
    and a path is permitted only if it lies within every prefix in
    the set. Attenuation is monotonic by construction.

    Prefix matching is **path-aware**, not string-prefix. Both the
    stored allowed prefixes and the queried path are passed through
    ``os.path.realpath`` (resolves ``..`` / ``.`` segments and
    follows symlinks to their final target) before comparison; the
    contains check uses ``pathlib.Path.is_relative_to``. This stops
    the classic traversal attacks:

        Fs().restrict_to("data/").allows("data/../etc/passwd")  # False
        Fs().restrict_to("data/").allows(<symlink to /etc/passwd>)  # False

    TOCTOU hardening (2026-06-10), closing the symlink-swap race:
    the data operations ``read`` and ``write`` no longer trust the
    pre-open ``allows()`` check alone. After opening, the
    symlink-resolved path of the open *handle* is obtained
    (Linux ``/proc/self/fd``, macOS ``fcntl F_GETPATH``, Windows
    ``GetFinalPathNameByHandle``; see ``_fs_guard``) and re-validated
    against the allowed prefixes; on mismatch the handle is closed
    and the usual deny ``Err`` returned, with nothing read or
    written. ``write`` opens without truncating and truncates only
    after the handle passes, so a symlink swapped mid-race can never
    destroy data outside the prefixes. ``O_NOFOLLOW`` is applied to
    the final component where supported, as defence in depth.
    Unrestricted ``Fs`` instances skip the guard entirely.

    Known residuals: the query/metadata operations (``exists``,
    ``is_dir``, ``list_dir``, ``mkdir``) still check-then-act, so
    their TOCTOU window remains; on a platform with none of the
    three handle-path mechanisms, ``read``/``write`` fall back to
    the pre-open check alone (explicit fallback in
    ``_fs_guard._verify_fd``); a denied ``write`` may leave
    behind an empty file it created when the swapped target did not
    previously exist (pre-existing bytes are never touched); and
    hard links are not distinguished: a hard link created inside a
    prefix to an out-of-prefix file passes both checks, because the
    OS reports the link's own in-prefix name (the same blind spot
    the realpath-only check always had).
    """

    __slots__ = ("_allowed_prefixes",)

    def __init__(self, _allowed_prefixes=None):
        # ``_allowed_prefixes`` is either None (unrestricted) or a
        # frozenset of canonical absolute paths produced by
        # ``os.path.realpath``.
        self._allowed_prefixes = _allowed_prefixes

    def restrict_to(self, prefix: str) -> "Fs":
        canon = os.path.realpath(prefix)
        existing = self._allowed_prefixes or frozenset()
        return Fs(_allowed_prefixes=existing | {canon})

    def allows(self, path: str) -> bool:
        if self._allowed_prefixes is None:
            return True
        try:
            canon = Path(os.path.realpath(path))
        except (OSError, ValueError):
            return False
        for p in self._allowed_prefixes:
            if not canon.is_relative_to(p):
                return False
        return True

    def _deny(self, op: str, path: str) -> "Err":
        return Err(IoError(
            f"Fs capability does not permit {op} on {path!r}",
            f"current allowed prefixes: {sorted(self._allowed_prefixes)}",
        ))

    def _post_open_allows(self, true_path: str) -> bool:
        """Containment check for the kernel-resolved path of an
        already-open handle. The path arrives symlink-free from the
        OS (see ``_fs_guard.fd_true_path``), so it is compared
        directly against the stored canonical prefixes; it must NOT
        be re-resolved through ``realpath`` (that would walk the
        filesystem again and reopen the race)."""
        if self._allowed_prefixes is None:
            return True
        try:
            canon = Path(true_path)
        except ValueError:
            return False
        for p in self._allowed_prefixes:
            if not canon.is_relative_to(p):
                return False
        return True

    def _open_read(self, path: str):
        """Open ``path`` for UTF-8 text reading. Restricted caps get
        the post-open handle verification (raises
        ``_fs_guard.PostOpenDenied`` on a swapped target);
        unrestricted caps take the plain ``open`` and pay nothing.
        Shared with the Wasm host bridges so both backends close the
        same TOCTOU window."""
        if self._allowed_prefixes is None:
            return open(path, encoding="utf-8")
        return _fs_guard.open_verified_read(path, self._post_open_allows)

    def _open_write(self, path: str):
        """Open ``path`` for UTF-8 text writing with ``open(p, "w")``
        semantics. Restricted caps open WITHOUT truncating, verify
        the handle, then truncate (so a denied write never destroys
        out-of-prefix data); unrestricted caps take the plain
        ``open``. Shared with the Wasm host bridges."""
        if self._allowed_prefixes is None:
            return open(path, "w", encoding="utf-8")
        return _fs_guard.open_verified_write(path, self._post_open_allows)

    def read(self, path: str) -> "Result[str, IoError]":
        if not self.allows(path):
            return self._deny("read", path)
        try:
            with self._open_read(path) as f:
                return Ok(f.read())
        except _fs_guard.PostOpenDenied:
            return self._deny("read", path)
        except OSError as e:
            return Err(IoError(f"failed to read {path!r}", str(e)))

    def write(self, path: str, content: str) -> "Result[None, IoError]":
        if not self.allows(path):
            return self._deny("write", path)
        try:
            with self._open_write(path) as f:
                f.write(content)
            return Ok(None)
        except _fs_guard.PostOpenDenied:
            return self._deny("write", path)
        except OSError as e:
            return Err(IoError(f"failed to write {path!r}", str(e)))

    def exists(self, path: str) -> bool:
        # `exists` is treated as a query, gated like a read.
        # A denied path reports False, which is the same answer a
        # caller would get for a path that genuinely does not exist.
        # The Fs cap therefore does not leak the existence of paths
        # outside its allowed prefixes.
        if not self.allows(path):
            return False
        return os.path.exists(path)

    def is_dir(self, path: str) -> bool:
        # Same fail-closed-as-absent convention as ``exists``: a
        # denied path reports False, so the cap does not leak the
        # type of a path outside its allowed prefixes.
        if not self.allows(path):
            return False
        return os.path.isdir(path)

    def mkdir(self, path: str) -> "Result[None, IoError]":
        # ``exist_ok=True`` makes this idempotent: re-running
        # ``capa install`` or any other tool that creates its
        # output dir does not fail on a second pass.
        if not self.allows(path):
            return self._deny("mkdir", path)
        try:
            os.makedirs(path, exist_ok=True)
            return Ok(None)
        except OSError as e:
            return Err(IoError(f"failed to mkdir {path!r}", str(e)))

    def list_dir(self, path: str) -> "Result[CapaList[str], IoError]":
        # Returns the entry names (basenames) of ``path``, sorted
        # alphabetically for deterministic output. Symlinks are
        # listed as their own name; the caller can call
        # ``is_dir`` / ``allows`` if they need to follow.
        if not self.allows(path):
            return self._deny("list_dir", path)
        try:
            entries = sorted(os.listdir(path))
            return Ok(CapaList(entries))
        except OSError as e:
            return Err(IoError(f"failed to list {path!r}", str(e)))


class Env:
    """Capability for reading environment variables, with first-class
    attenuation.

    An instance carries either ``None`` (unrestricted authority) or a
    frozen set of allowed variable names. ``restrict_to_keys`` returns
    a new ``Env`` whose authority is narrowed to the intersection of
    the current restriction (if any) and the requested key set -
    monotonic narrowing, same contract as ``Net.restrict_to``.

    A denied variable looks like an unset variable to the caller
    (``get`` returns ``None``). This is deliberate: it prevents the
    cap from leaking the existence of variables outside its allowed
    set. Callers that need to distinguish denied from absent can
    consult ``allows(name)``.

    .. warning::
        **Leak-by-default.** A fresh, unrestricted ``Env`` reads from
        the host's ``os.environ`` verbatim: a Capa program that holds
        an unrestricted ``Env`` sees every environment variable on
        the host, including secrets (``OPENAI_API_KEY``, ``AWS_*``,
        ``GITHUB_TOKEN``, the shell's ``PATH``, ...). The trust
        boundary is the cap itself; the attenuation system narrows
        it. **For any production / untrusted-code use, call
        ``env.restrict_to_keys([...])`` to project the cap down to
        the allow-list the program actually needs before passing it
        on.** The audit recommendation (audit item M1, 2026-05) is
        that any handler crossing a trust boundary must restrict
        first; the analyzer enforces monotonic narrowing so the
        restriction cannot be widened downstream.

        The Wasm host bridges (``capa.runtime._wasm_host`` and
        ``capa.runtime._wasm_component_host``) carry the same
        leak-by-default property: ``env.get`` on a wasm-side
        unrestricted cap reads ``os.environ.get(name)`` unfiltered.
        The Wasm attenuation enforcement (audit C2) closes the gap
        for restrictions Capa can statically resolve to a literal
        allow-list; unrestricted caps still pass through.
    """

    __slots__ = ("_allowed_keys",)

    # Windows env-var names are case-insensitive (``os.environ.get("path")``
    # returns the same value as ``os.environ.get("PATH")``). Audit slice 25 F4
    # (2026-05-30): a Capa program that calls
    # ``env.restrict_to_keys(["path"])`` was getting a different surface from
    # the same call on Linux (where ``path`` and ``PATH`` are distinct).
    # Canonicalise the allow-list and the lookup key consistently so the
    # restriction means the same thing on both platforms.
    _CASE_INSENSITIVE = sys.platform == "win32"

    @classmethod
    def _canon_key(cls, name):
        return name.upper() if cls._CASE_INSENSITIVE else name

    def __init__(self, _allowed_keys=None):
        self._allowed_keys = _allowed_keys

    def restrict_to_keys(self, keys) -> "Env":
        # Accept any iterable (CapaList, list, set, frozenset).
        new = frozenset(self._canon_key(k) for k in keys)
        if self._allowed_keys is not None:
            new = new & self._allowed_keys
        return Env(_allowed_keys=new)

    def allows(self, name: str) -> bool:
        return (
            self._allowed_keys is None
            or self._canon_key(name) in self._allowed_keys
        )

    def get(self, name: str) -> "Option[str]":
        if not self.allows(name):
            return None_
        v = os.environ.get(name)
        return Some(v) if v is not None else None_

    def args(self) -> "CapaList":
        return CapaList(sys.argv[1:])


class Clock:
    """Capability for accessing time, with first-class attenuation.

    An instance carries either ``None`` (unrestricted authority) or
    a ``not_before`` threshold: the time, in seconds since the
    epoch, at which the capability becomes active. Chaining
    ``restrict_to_after`` raises the threshold (monotonic narrowing,
    never widens).

    Reading the current time (``now_secs``, ``now_monotonic``) is
    treated as a pure query and is not gated: anyone with a wall
    clock can observe the time. The action method ``sleep`` is
    gated: on a denied Clock (threshold in the future) it becomes
    a silent no-op, consistent with the fail-closed information-
    hiding pattern used by ``Fs.exists`` and ``Env.get``.
    """

    __slots__ = ("_not_before",)

    def __init__(self, _not_before=None):
        self._not_before = _not_before

    def restrict_to_after(self, t: float) -> "Clock":
        existing = self._not_before
        new_threshold = t if existing is None else max(existing, t)
        return Clock(_not_before=new_threshold)

    def allows(self) -> bool:
        return self._not_before is None or time.time() >= self._not_before

    def now_secs(self) -> float:
        return time.time()

    def now_monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        if not self.allows():
            return
        time.sleep(seconds)


class Random:
    """Capability for generating random numbers, with first-class
    seeding.

    The unrestricted form ``Random()`` is seeded from system entropy
    (``os.urandom(8)``). ``with_seed(seed)`` returns a fresh
    ``Random`` whose sequence is a deterministic function of the
    integer ``seed``. Chained calls (``r.with_seed(a).with_seed(b)``)
    simply re-seed via fresh instances; the last seed wins. The
    manifest tracks the calls in source order so an auditor sees that
    an RNG was made deterministic before being handed onward.

    Unlike ``Net``, ``Fs``, ``Env``, and ``Clock``, ``Random`` has
    no "denied" state. A seeded Random still generates numbers; it
    just generates them reproducibly. The narrowing semantic is
    over the *space of possible sequences*, not over the
    *authority to generate*.

    PRNG algorithm (D1, 2026-05): **SplitMix64**. Tiny (one i64 of
    state), fast, and crucially it is the same algorithm the Wasm
    backend ships in linear memory, so a seeded ``Random(42)``
    produces a byte-identical sequence on both backends. The
    previous implementation delegated to Python's ``random.Random``
    (Mersenne Twister); seeded outputs changed when this switch
    landed.
    """

    __slots__ = ("_state",)

    _SPLITMIX_INCREMENT = 0x9E3779B97F4A7C15
    _SPLITMIX_MIX_1 = 0xBF58476D1CE4E5B9
    _SPLITMIX_MIX_2 = 0x94D049BB133111EB
    _U64_MASK = 0xFFFFFFFFFFFFFFFF

    def __init__(self, seed: int | None = None):
        if seed is None:
            # Draw 8 bytes of OS entropy as the initial state; matches
            # the Wasm-side ``system-seed`` host import.
            self._state = int.from_bytes(os.urandom(8), "little")
        else:
            self._state = seed & self._U64_MASK

    def _next_u64(self) -> int:
        """SplitMix64 step. Updates ``self._state`` and returns the
        mixed 64-bit value."""
        self._state = (self._state + self._SPLITMIX_INCREMENT) & self._U64_MASK
        z = self._state
        z = ((z ^ (z >> 30)) * self._SPLITMIX_MIX_1) & self._U64_MASK
        z = ((z ^ (z >> 27)) * self._SPLITMIX_MIX_2) & self._U64_MASK
        return z ^ (z >> 31)

    def with_seed(self, seed: int) -> "Random":
        return Random(seed=seed)

    def int_range(self, low: int, high: int) -> int:
        """Return a value in ``[low, high)`` (half-open).

        Uses Lemire-style rejection sampling for an unbiased
        distribution: reject any draw that falls in the partial
        "tail" of the u64 range that would otherwise fold unevenly
        across the bound. Bias for typical small ranges (e.g.
        ``int_range(0, 100)``) over a u64 is vanishingly small in
        practice; the rejection loop keeps the contract honest
        without measurable cost.
        """
        bound = high - low
        if bound <= 0:
            # Mirrors Python's ``random.randrange`` which raises on
            # an empty range; surfacing the same shape keeps the
            # programmer-visible contract identical.
            raise ValueError(
                f"int_range bounds must satisfy low < high; "
                f"got low={low}, high={high}"
            )
        # Largest multiple of bound that fits in u64 (exclusive
        # upper limit for the accepted region). The Wasm side
        # mirrors this exactly.
        limit = ((1 << 64) // bound) * bound
        rng = self._next_u64()
        while rng >= limit:
            rng = self._next_u64()
        return low + (rng % bound)

    def float_unit(self) -> float:
        """Return a value in ``[0.0, 1.0)``.

        Standard 53-bit-mantissa trick: shift the u64 down to the
        top 53 bits, divide by 2**53. Same operation the Wasm side
        performs with ``i64.shr_u`` + ``f64.convert_i64_u`` + a
        constant ``f64.div``.
        """
        return (self._next_u64() >> 11) * (1.0 / (1 << 53))


# Stubs for capabilities not yet implemented; instantiating them yields a
# runtime error if any method is called.
class _StubCapability:
    def __init__(self, name: str):
        self._name = name

    def __getattr__(self, attr: str):
        raise NotImplementedError(
            f"capability {self._name!r} is not yet implemented in the runtime "
            f"(method {attr!r} called)"
        )


class Net:
    """Capability for network access, with first-class attenuation.

    An instance carries either ``None`` (unrestricted authority, the
    fresh capability supplied by ``main``) or a frozen set of allowed
    host names. ``restrict_to`` returns a new ``Net`` whose authority
    is the *intersection* of the current restrictions with the newly
    requested one: attenuation is monotonic by construction
    (restrictions can only narrow, never widen).

    The actual HTTP transport uses ``urllib.request`` from the Python
    stdlib. Restriction is enforced *before* any system call, so a
    rejected host never reaches the network layer.

    Capa code uses the capability through four methods:
    - ``restrict_to(host: String) -> Net``, attenuation
    - ``allows(host: String) -> Bool``, query, without performing IO
    - ``get(url: String) -> Result<String, IoError>``, real HTTP GET,
      gated by the current restriction set
    - ``post(url: String, body: String) -> Result<String, IoError>``,
      HTTP POST with a UTF-8 body (Content-Type
      ``application/octet-stream``); same attenuation gate as ``get``
    """

    __slots__ = ("_allowed",)

    def __init__(self, _allowed=None):
        # _allowed: None means "no restriction" (full authority);
        # frozenset means the only hosts this Net may reach.
        self._allowed = _allowed

    def restrict_to(self, host: str) -> "Net":
        new = frozenset({host})
        if self._allowed is not None:
            new = new & self._allowed
        return Net(_allowed=new)

    def allows(self, host: str) -> bool:
        return self._allowed is None or host in self._allowed

    def get(self, url: str):
        from urllib.parse import urlparse
        from urllib.request import Request, urlopen

        try:
            host = urlparse(url).hostname or ""
        except ValueError as e:
            return Err(IoError("invalid URL", str(e)))

        if not self.allows(host):
            allowed_repr = (
                sorted(self._allowed) if self._allowed is not None else "unrestricted"
            )
            return Err(IoError(
                f"Net capability does not permit access to host {host!r}",
                f"current restrictions: {allowed_repr}",
            ))

        try:
            with urlopen(Request(url), timeout=10) as resp:
                data = resp.read().decode("utf-8", errors="replace")
                return Ok(data)
        except (OSError, ValueError) as e:
            return Err(IoError("HTTP GET failed", str(e)))

    def post(self, url: str, body: str):
        """HTTP POST: same attenuation gate as ``get``, sends ``body``
        as a UTF-8 byte string with Content-Type
        ``application/octet-stream``. Errors lower into the same
        ``IoError`` shape as ``get`` so both backends agree on the
        diagnostic when the request fails (network, host-deny, or
        URL-parse).

        ``urllib.request.urlopen`` triggers a POST automatically when
        ``data`` is supplied; the Wasm host bridge mirrors that
        exactly via ``Request(url, data=body.encode(\"utf-8\"))``."""
        from urllib.parse import urlparse
        from urllib.request import Request, urlopen

        try:
            host = urlparse(url).hostname or ""
        except ValueError as e:
            return Err(IoError("invalid URL", str(e)))

        if not self.allows(host):
            allowed_repr = (
                sorted(self._allowed) if self._allowed is not None else "unrestricted"
            )
            return Err(IoError(
                f"Net capability does not permit access to host {host!r}",
                f"current restrictions: {allowed_repr}",
            ))

        try:
            body_bytes = body.encode("utf-8")
            req = Request(
                url, data=body_bytes,
                headers={"Content-Type": "application/octet-stream"},
            )
            with urlopen(req, timeout=10) as resp:
                data = resp.read().decode("utf-8", errors="replace")
                return Ok(data)
        except (OSError, ValueError) as e:
            return Err(IoError("HTTP POST failed", str(e)))


class Proc:
    """Capability for sandboxed subprocess execution, with first-
    class attenuation that mirrors :class:`Net` (the underlying
    membership predicate is a basename + suffix-boundary check
    rather than a host substring search, but the intersect-style
    monotonic-attenuation shape is identical).

    An instance carries either ``None`` (unrestricted authority,
    the fresh capability supplied by ``main``) or a frozen set of
    allowed command basename prefixes. ``restrict_to`` returns a
    new ``Proc`` whose authority is the *intersection* of the
    current restrictions with the newly requested prefix:
    attenuation is monotonic by construction (restrictions can
    only narrow, never widen).

    The actual execution is via ``subprocess.run(argv,
    capture_output=True, timeout=30, shell=False)``. ``shell=False``
    is always enforced -- a ``Proc.exec("rm -rf /")`` call would
    pass ``"rm -rf /"`` as ``argv[0]`` and fail with ENOENT rather
    than spawning a shell that interprets the string. The cap is
    stateless from the program's POV (no persistent subprocess
    handle); each call spawns a fresh child and waits for it.

    Methods:
    - ``restrict_to(cmd_prefix: String) -> Proc``: attenuation
    - ``allows(cmd: String) -> Bool``: query without IO
    - ``exec(cmd: String, args_json: String) -> Result<String, IoError>``:
      run the command. ``args_json`` is a JSON-encoded array of
      strings consumed as the argv tail (so
      ``Proc.exec("git", '["status", "--short"]')`` runs
      ``git status --short``). Returns ``Ok(stdout)`` on zero
      exit; ``Err(IoError(...))`` on non-zero exit, timeout,
      malformed argv JSON, or denial.

    Attenuation rule (matches the Wasm-side ``$proc_allows``
    runtime helper): match on ``os.path.basename(cmd)`` so a
    fully-qualified ``/usr/bin/git`` still gates correctly
    against a ``restrict_to("git")`` cap. The boundary is the
    basename plus a ``-`` suffix: ``restrict_to("git")`` admits
    ``git`` and ``git-lfs`` (a git plugin) but rejects
    ``gitlab`` (a different binary that happens to share a
    prefix). The same rule lives in both backends so a
    ``Proc.allows(cmd)`` query returns the same Bool on Python,
    core Wasm, and the Component Model.
    """

    __slots__ = ("_allowed",)

    def __init__(self, _allowed=None):
        self._allowed = _allowed

    def restrict_to(self, cmd_prefix: str) -> "Proc":
        new = frozenset({cmd_prefix})
        if self._allowed is not None:
            new = new & self._allowed
        return Proc(_allowed=new)

    def allows(self, cmd: str) -> bool:
        if self._allowed is None:
            return True
        import os
        base = os.path.basename(cmd)
        for p in self._allowed:
            if base == p:
                return True
            if base.startswith(p + "-"):
                return True
        return False

    def _deny(self, cmd: str):
        allowed_repr = (
            sorted(self._allowed) if self._allowed is not None else "unrestricted"
        )
        return Err(IoError(
            f"Proc capability does not permit exec of {cmd!r}",
            f"current restrictions: {allowed_repr}",
        ))

    def exec(self, cmd: str, args_json: str):
        import json
        import subprocess
        if not self.allows(cmd):
            return self._deny(cmd)
        try:
            tail = json.loads(args_json)
        except (ValueError, TypeError) as e:
            return Err(IoError(
                "Proc.exec args_json parse failed", str(e),
            ))
        if not isinstance(tail, list) or not all(
                isinstance(x, str) for x in tail):
            return Err(IoError(
                "Proc.exec args_json parse failed",
                "expected a JSON array of strings",
            ))
        argv = [cmd, *tail]
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                timeout=30,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return Err(IoError("timed out", "30s elapsed"))
        except (OSError, ValueError) as e:
            return Err(IoError("Proc.exec spawn failed", str(e)))
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace")
            return Err(IoError(
                "non-zero exit",
                f"code={completed.returncode} stderr={stderr!r}",
            ))
        return Ok(completed.stdout.decode("utf-8", errors="replace"))


# SQLite authorizer action codes (stable across SQLite versions;
# documented at https://www.sqlite.org/c3ref/c_alter_table.html).
# Spelled out here rather than imported from ``sqlite3`` because
# Python's stdlib doesn't expose the action-code constants as
# named attributes; both Db (Python runtime) and the Wasm host
# bridges use the same numbers.
_SQLITE_ATTACH = 24
_SQLITE_DETACH = 25
_SQLITE_OK = 0
_SQLITE_DENY = 1


def _install_sqlite_authorizer(conn) -> None:
    """Lock down ``conn`` so ATTACH / DETACH return ``not
    authorized`` at SQLite's parser level. Mitigates the
    documented Db.exec ATTACH-bypass: a Db cap scoped to ``/tmp/``
    could otherwise run ``ATTACH DATABASE '/etc/secret.db' AS
    evil`` to open a second file outside the cap's prefix.

    Both Python ``Db.exec``/``Db.query`` and the Wasm host
    bridges call this on every fresh connection so the path
    attenuation is the only cap-mediated path to a SQLite file.
    Everything else (CREATE / SELECT / INSERT / UPDATE / DELETE /
    DROP / transactions) stays allowed.
    """
    def auth(action, _arg1, _arg2, _dbname, _source):
        if action in (_SQLITE_ATTACH, _SQLITE_DETACH):
            return _SQLITE_DENY
        return _SQLITE_OK
    conn.set_authorizer(auth)


class Db:
    """Capability for SQLite database access, with first-class
    attenuation that mirrors :class:`Fs`.

    An instance carries either ``None`` (unrestricted authority,
    the fresh capability supplied by ``main``) or a frozen set of
    allowed file-path prefixes. ``restrict_to`` returns a new
    ``Db`` whose authority is the *intersection* of the current
    restrictions with the newly requested one: attenuation is
    monotonic by construction (restrictions can only narrow, never
    widen).

    The actual storage is SQLite via Python's stdlib ``sqlite3``
    module. Each call opens a fresh connection, executes, and
    closes; the cap is stateless from the program's POV. Wasm
    host mirror keeps the same shape (a per-call ``sqlite3.connect``
    on the host side) so both backends agree on outcomes for the
    same on-disk file.

    Methods:
    - ``restrict_to(path: String) -> Db``: attenuation
    - ``allows(path: String) -> Bool``: query without IO
    - ``exec(path: String, sql: String) -> Result<Unit, IoError>``:
      run a single statement (DDL or DML). Multiple statements via
      ``;`` are supported through ``executescript``.
    - ``query(path: String, sql: String) -> Result<String, IoError>``:
      run a SELECT and return the rows as a JSON-encoded
      ``[[col1, col2, ...], ...]`` string. Every value is
      stringified (caller parses + casts as needed). JSON is the
      cheapest cross-backend wire shape; Capa's
      ``parse_json`` makes consumption ergonomic.

    Path-attenuation hardening (audit 2026-05-29, slice 13):
    ``ATTACH DATABASE '/etc/secret.db' AS evil; SELECT * FROM
    evil.x`` would bypass the path prefix attenuation by opening
    a second connection from inside SQL. Both backends now
    install a ``set_authorizer`` callback on every connection
    that denies ``SQLITE_ATTACH`` and ``SQLITE_DETACH``; the
    statement fails with ``OperationalError: not authorized``
    which becomes ``Err(IoError("SQLite ... failed", "not
    authorized"))`` on both sides. Other operations
    (CREATE / SELECT / INSERT / UPDATE / DELETE / DROP /
    transactions) remain allowed; the authorizer is narrowly
    scoped to the two bypass-shaped opcodes.
    """

    __slots__ = ("_allowed",)

    def __init__(self, _allowed=None):
        self._allowed = _allowed

    def restrict_to(self, path: str) -> "Db":
        new = frozenset({path})
        if self._allowed is not None:
            new = new & self._allowed
        return Db(_allowed=new)

    def allows(self, path: str) -> bool:
        if self._allowed is None:
            return True
        # Boundary-aware prefix match (audit 2026-05-29): a
        # naive ``path.startswith(p)`` would admit
        # ``/var/data_evil/secrets.db`` when restricted to
        # ``/var/data``. Require either an exact match or a
        # following ``/`` so the prefix lines up with a path
        # component boundary. Mirrors the Wasm-side
        # ``_emit_path_prefix_check`` semantics.
        for p in self._allowed:
            if path == p:
                return True
            sep = p if p.endswith("/") else p + "/"
            if path.startswith(sep):
                return True
        return False

    def _deny(self, path: str, op: str):
        allowed_repr = (
            sorted(self._allowed) if self._allowed is not None else "unrestricted"
        )
        return Err(IoError(
            f"Db capability does not permit {op} on path {path!r}",
            f"current restrictions: {allowed_repr}",
        ))

    def exec(self, path: str, sql: str):
        import sqlite3
        if not self.allows(path):
            return self._deny(path, "exec")
        try:
            conn = sqlite3.connect(path)
            _install_sqlite_authorizer(conn)
            try:
                conn.executescript(sql)
                conn.commit()
                return Ok(None)
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as e:
            return Err(IoError("SQLite exec failed", str(e)))

    def query(self, path: str, sql: str):
        import json
        import sqlite3
        if not self.allows(path):
            return self._deny(path, "query")
        try:
            conn = sqlite3.connect(path)
            _install_sqlite_authorizer(conn)
            try:
                cur = conn.execute(sql)
                rows = cur.fetchall()
                # Every column value is stringified so the cross-
                # backend wire format stays a single shape (JSON array
                # of arrays of strings). NULL becomes the JSON string
                # "null" so the consumer can disambiguate via a
                # match on the exact bytes if needed; a richer
                # encoding (typed JSON) is a v2 surface decision.
                stringified = [
                    [
                        "null" if v is None else
                        v if isinstance(v, str) else str(v)
                        for v in row
                    ]
                    for row in rows
                ]
                return Ok(json.dumps(stringified))
            finally:
                conn.close()
        except (sqlite3.Error, OSError, ValueError) as e:
            return Err(IoError("SQLite query failed", str(e)))


class Unsafe:
    """Capability that materialises the trust boundary between Capa and
    Python. Functions that cross this boundary (``py_import``,
    ``py_invoke``) require an ``Unsafe`` instance as the first argument.

    Like any capability, it can only be obtained in ``main`` or
    propagated as an argument by functions that already hold it. The
    static type system rejects uses of ``py_import`` / ``py_invoke`` in
    functions that do not declare ``unsafe: Unsafe`` in their parameters.

    The capability is deliberately method-less: its only role is to
    serve as proof of authority that the static checker verifies.
    """
