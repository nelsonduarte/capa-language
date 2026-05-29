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
- ``_StubCapability`` / ``Proc`` / ``Db`` - placeholders.
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

    Known residual: a TOCTOU race between ``allows()`` and the
    actual ``open()`` call can be exploited by swapping a symlink in
    between. Fully closing that gap needs ``O_NOFOLLOW`` + open-at-
    dirfd, which is outside the v1 surface.
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

    def read(self, path: str) -> "Result[str, IoError]":
        if not self.allows(path):
            return self._deny("read", path)
        try:
            with open(path, encoding="utf-8") as f:
                return Ok(f.read())
        except OSError as e:
            return Err(IoError(f"failed to read {path!r}", str(e)))

    def write(self, path: str, content: str) -> "Result[None, IoError]":
        if not self.allows(path):
            return self._deny("write", path)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            return Ok(None)
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

    def __init__(self, _allowed_keys=None):
        self._allowed_keys = _allowed_keys

    def restrict_to_keys(self, keys) -> "Env":
        # Accept any iterable (CapaList, list, set, frozenset).
        new = frozenset(keys)
        if self._allowed_keys is not None:
            new = new & self._allowed_keys
        return Env(_allowed_keys=new)

    def allows(self, name: str) -> bool:
        return self._allowed_keys is None or name in self._allowed_keys

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


class Proc(_StubCapability):
    def __init__(self):
        super().__init__("Proc")


class Db(_StubCapability):
    def __init__(self):
        super().__init__("Db")


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
