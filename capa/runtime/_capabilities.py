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
import random
import sys
import time
from dataclasses import dataclass
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


class Stdio:
    """Capability for standard input and output."""

    def print(self, text: str) -> None:
        """Prints without trailing newline."""
        sys.stdout.write(text)
        sys.stdout.flush()

    def println(self, text: str) -> None:
        """Prints with trailing newline."""
        print(text)

    def eprintln(self, text: str) -> None:
        """Prints to stderr with newline."""
        print(text, file=sys.stderr)

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
    and a path is permitted only if every prefix in the set is a
    prefix of it. Attenuation is monotonic by construction, adding
    a prefix can only narrow.

    Prefix matching is performed on the raw string. Callers should
    pass absolute paths (or be consistent in their use of relative
    paths); v1 does not normalise ``./`` or symlinks.
    """

    __slots__ = ("_allowed_prefixes",)

    def __init__(self, _allowed_prefixes=None):
        self._allowed_prefixes = _allowed_prefixes

    def restrict_to(self, prefix: str) -> "Fs":
        existing = self._allowed_prefixes or frozenset()
        return Fs(_allowed_prefixes=existing | {prefix})

    def allows(self, path: str) -> bool:
        if self._allowed_prefixes is None:
            return True
        return all(path.startswith(p) for p in self._allowed_prefixes)

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

    The unrestricted form ``Random()`` is seeded from system entropy.
    ``with_seed(seed)`` returns a fresh ``Random`` whose sequence is
    a deterministic function of the integer ``seed``. Chained calls
    (``r.with_seed(a).with_seed(b)``) simply re-seed; the last seed
    wins. The manifest tracks the calls in source order so an
    auditor sees that an RNG was made deterministic before being
    handed onward.

    Unlike ``Net``, ``Fs``, ``Env``, and ``Clock``, ``Random`` has
    no "denied" state. A seeded Random still generates numbers; it
    just generates them reproducibly. The narrowing semantic is
    over the *space of possible sequences*, not over the
    *authority to generate*.
    """

    __slots__ = ("_rng", "_seed")

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)
        self._seed = seed

    def with_seed(self, seed: int) -> "Random":
        return Random(seed=seed)

    def int_range(self, low: int, high: int) -> int:
        return self._rng.randrange(low, high)

    def float_unit(self) -> float:
        return self._rng.random()

    def choice(self, items: list) -> Any:
        return self._rng.choice(items)


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

    Capa code uses the capability through three methods:
    - ``restrict_to(host: String) -> Net``, attenuation
    - ``allows(host: String) -> Bool``, query, without performing IO
    - ``get(url: String) -> Result<String, IoError>``, real HTTP GET,
      gated by the current restriction set
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
