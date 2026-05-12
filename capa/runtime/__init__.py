"""Minimal runtime for Capa programs transpiled to Python.

This module provides the primitives that Capa programs need at runtime but
which are not part of the Python language:

- ``Result[T, E]`` — sum type with variants ``Ok(value)`` and ``Err(error)``,
  used by functions that may fail.
- ``Option[T]`` — sum type with variants ``Some(value)`` and ``None_``,
  used for optional values. (The name ``None_`` is a necessary suffix
  to avoid a clash with Python's builtin ``None``.)
- Concrete capabilities: ``Stdio``, ``Fs``, ``Net``, ``Env``, ``Clock``,
  ``Random``, ``Proc``, ``Db`` — real implementations that perform IO
  against the operating system. In real programs, they are instantiated at
  the entry point (``main``) and explicitly propagated as arguments.

Design conventions:

- Sum variants are simple *dataclasses*, without a complex hierarchy.
  Python 3.10+ match natively matches against these classes.
- Capability methods return ``Result`` when they can fail (real IO), and
  direct values when they cannot.
- There are no "ambient capabilities" — a Python program that imports this
  runtime does not gain capacities by a simple import. It must instantiate
  ``Stdio()``, ``Fs()``, etc. and pass them explicitly. That discipline is
  what gives meaning to Capa's signatures.
"""

from __future__ import annotations

import os
import random
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Generic, TypeVar

T = TypeVar("T")
E = TypeVar("E")
U = TypeVar("U")


# ===========================================================
# Result
# ===========================================================


@dataclass(frozen=True)
class Ok(Generic[T]):
    value: T

    def __str__(self) -> str:
        return f"Ok({self.value})"

    def is_ok(self) -> bool:
        return True

    def is_err(self) -> bool:
        return False

    def unwrap(self) -> T:
        return self.value

    def unwrap_or(self, default: T) -> T:
        return self.value

    def map(self, f: Callable[[T], U]) -> "Result[U, Any]":
        return Ok(f(self.value))

    def map_err(self, f):
        return self

    def and_then(self, f):
        return f(self.value)


@dataclass(frozen=True)
class Err(Generic[E]):
    error: E

    def __str__(self) -> str:
        return f"Err({self.error})"

    def is_ok(self) -> bool:
        return False

    def is_err(self) -> bool:
        return True

    def unwrap(self) -> Any:
        raise RuntimeError(f"called unwrap() on Err: {self.error!r}")

    def unwrap_or(self, default: T) -> T:
        return default

    def map(self, f: Callable[[Any], Any]) -> "Result[Any, E]":
        return self

    def map_err(self, f):
        return Err(f(self.error))

    def and_then(self, f):
        return self


# Type alias for annotations.
Result = Ok | Err


# ===========================================================
# Option
# ===========================================================


@dataclass(frozen=True)
class Some(Generic[T]):
    value: T

    def __str__(self) -> str:
        return f"Some({self.value})"

    def is_some(self) -> bool:
        return True

    def is_none(self) -> bool:
        return False

    def unwrap(self) -> T:
        return self.value

    def unwrap_or(self, default: T) -> T:
        return self.value

    def map(self, f):
        return Some(f(self.value))

    def and_then(self, f):
        return f(self.value)

    def ok_or(self, err):
        return Ok(self.value)


@dataclass(frozen=True)
class _NoneType:
    """Singleton for the None variant of Option. Use the None_ constant."""

    def __str__(self) -> str:
        return "None"

    def is_some(self) -> bool:
        return False

    def is_none(self) -> bool:
        return True

    def unwrap(self) -> Any:
        raise RuntimeError("called unwrap() on None_")

    def unwrap_or(self, default: T) -> T:
        return default

    def map(self, f):
        return self

    def and_then(self, f):
        return self

    def ok_or(self, err):
        return Err(err)


# Singleton — in Capa, ``None`` is the variant. In Python, we add a suffix
# to avoid clashing with the builtin ``None``.
None_ = _NoneType()

Option = Some | _NoneType


# ===========================================================
# IoError — used by the IO capabilities
# ===========================================================


@dataclass(frozen=True)
class IoError:
    """Generic IO error. In production, one would have specific variants."""
    message: str
    cause: str = ""

    def __str__(self) -> str:
        if self.cause:
            return f"{self.message}: {self.cause}"
        return self.message


# ===========================================================
# Capabilities
# ===========================================================


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
    prefix of it. Attenuation is monotonic by construction — adding
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
    the current restriction (if any) and the requested key set —
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
    """Capability for generating random numbers."""

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)

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
    requested one — attenuation is monotonic by construction (WhitePaper
    R4: restrictions can only narrow, never widen).

    The actual HTTP transport uses ``urllib.request`` from the Python
    stdlib. Restriction is enforced *before* any system call, so a
    rejected host never reaches the network layer.

    Capa code uses the capability through three methods:
    - ``restrict_to(host: String) -> Net`` — attenuation
    - ``allows(host: String) -> Bool`` — query, without performing IO
    - ``get(url: String) -> Result<String, IoError>`` — real HTTP GET,
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


def _require_unsafe(unsafe, op: str):
    if not isinstance(unsafe, Unsafe):
        raise RuntimeError(
            f"{op} requires an Unsafe capability as first argument; "
            f"got {type(unsafe).__name__}. This should have been caught "
            f"by the Capa type checker."
        )


def py_import(unsafe, name: str):
    """Import a Python module by name (e.g. ``"os.path"``), returning the
    module object. Equivalent to ``import name`` in Python, but requires
    the ``Unsafe`` capability.

    The return type is deliberately untyped (``TyUnknown`` in the
    checker): anything coming from the Python side of the boundary has
    no guarantees from the capability system, and the language reflects
    this loss of guarantee by letting the programmer navigate dynamically.
    """
    import importlib
    _require_unsafe(unsafe, "py_import")
    return importlib.import_module(name)


def py_invoke(unsafe, callable_, args):
    """Invoke a Python ``callable`` with the argument list ``args``.
    Requires the ``Unsafe`` capability. ``args`` can be a list/CapaList
    or any iterable.
    """
    _require_unsafe(unsafe, "py_invoke")
    return callable_(*args)


# ===========================================================
# Helpers exposed to Capa programs
# ===========================================================


def _propagate_err(result):
    """Helper used by the transpilation of the `?` operator.

    If ``result`` is Err, returns None and signals the caller to return.
    If it is Ok, returns the unwrapped value.
    The caller must check whether it received a _PROPAGATE sentinel.
    """
    if isinstance(result, Err):
        return result, True
    if isinstance(result, Ok):
        return result.value, False
    raise RuntimeError(f"`?` applied to non-Result value: {result!r}")


__all__ = [
    "Ok",
    "Err",
    "Result",
    "Some",
    "None_",
    "Option",
    "IoError",
    "Stdio",
    "Fs",
    "Env",
    "Clock",
    "Random",
    "Net",
    "Proc",
    "Db",
    "Unsafe",
    "py_import",
    "py_invoke",
    "to_float",
    "to_int",
    "_propagate_err",
]


# ===========================================================
# CapaList: subclass of list with Capa methods
# ===========================================================


class CapaList(list):
    """Subclass of ``list`` that exposes methods expected by the Capa
    checker: ``length``, ``push``, ``contains``, ``map``, ``filter``,
    ``fold``.

    Higher-order functions (`map`, `filter`, `fold`) take Python
    callables and return new ``CapaList`` instances for chaining.
    """

    def length(self):
        return len(self)

    def push(self, x):
        self.append(x)

    def contains(self, x):
        return x in self

    def map(self, f):
        return CapaList(f(x) for x in self)

    def filter(self, p):
        return CapaList(x for x in self if p(x))

    def fold(self, init, f):
        acc = init
        for x in self:
            acc = f(acc, x)
        return acc

    def is_empty(self):
        return len(self) == 0

    def first(self):
        return Some(self[0]) if len(self) > 0 else None_

    def last(self):
        return Some(self[-1]) if len(self) > 0 else None_

    def get(self, i):
        if 0 <= i < len(self):
            return Some(self[i])
        return None_


# ===========================================================
# Builtin conversion functions
# ===========================================================


def parse_int(s):
    """Tries to convert ``s`` to Int. Returns ``Some(n)`` on success,
    ``None_`` on failure (non-numeric, empty, etc.)."""
    try:
        return Some(int(s.strip()))
    except (ValueError, AttributeError):
        return None_


def parse_float(s):
    """Tries to convert ``s`` to Float. Returns ``Some(f)`` on success,
    ``None_`` on failure."""
    try:
        return Some(float(s.strip()))
    except (ValueError, AttributeError):
        return None_


def to_float(i):
    """Convert an Int to a Float. Total — every Int has an exact Float
    representation within the range Capa cares about. Used to bridge the
    Int/Float divide in arithmetic when implicit coercion would hide
    intent (Capa has no implicit numeric promotion)."""
    return float(i)


def to_int(f):
    """Truncate a Float to an Int (toward zero). Total. The fractional
    part is discarded; for round-to-nearest use a different primitive
    when one is added."""
    return int(f)


# ===========================================================
# JSON: JsonValue type and parse/serialize
# ===========================================================

import json as _stdlib_json


class _JsonBase:
    """Base class for JsonValue. Defines default extraction methods that
    return ``None_`` (Option) — overridden by each variant that matches
    the extracted type.

    The methods here are called via the normal method dispatch — the
    user writes ``j.as_string()`` in Capa, and the transpiler emits
    ``j.as_string()`` in Python, which resolves via MRO to the right
    class.
    """

    def is_null(self) -> bool:
        return False

    def as_bool(self):
        return None_

    def as_num(self):
        return None_

    def as_string(self):
        return None_

    def as_array(self):
        return None_

    def as_object(self):
        return None_


@dataclass(frozen=True)
class JNull(_JsonBase):
    """JSON null."""
    def __str__(self) -> str:
        return "JNull"

    def is_null(self) -> bool:
        return True


@dataclass(frozen=True)
class JBool(_JsonBase):
    """JSON boolean."""
    value: bool
    def __str__(self) -> str:
        return f"JBool({self.value})"

    def as_bool(self):
        return Some(self.value)


@dataclass(frozen=True)
class JNum(_JsonBase):
    """JSON number (unifies int and float into float).

    Capa unifies the two JSON numeric types into a single variant,
    represented as Float. For integer values, the user can use
    ``int(n.value)`` at runtime or match against a specific value.
    """
    value: float
    def __str__(self) -> str:
        return f"JNum({self.value})"

    def as_num(self):
        return Some(self.value)


@dataclass(frozen=True)
class JStr(_JsonBase):
    """JSON string."""
    value: str
    def __str__(self) -> str:
        return f"JStr({self.value!r})"

    def as_string(self):
        return Some(self.value)


@dataclass(frozen=True)
class JArr(_JsonBase):
    """JSON array (list of JsonValues)."""
    value: list  # CapaList[JsonValue]
    def __str__(self) -> str:
        return f"JArr({len(self.value)} items)"

    def as_array(self):
        return Some(self.value)


@dataclass(frozen=True)
class JObj(_JsonBase):
    """JSON object (map from String to JsonValue)."""
    value: dict  # dict[str, JsonValue]
    def __str__(self) -> str:
        return f"JObj({len(self.value)} keys)"

    def as_object(self):
        return Some(self.value)


# Static union for type hints; at runtime, any of these classes.
JsonValue = JNull | JBool | JNum | JStr | JArr | JObj


def _python_to_json_value(v):
    """Converts a Python value (result of json.loads) to JsonValue."""
    if v is None:
        return JNull()
    if isinstance(v, bool):
        return JBool(v)
    if isinstance(v, (int, float)):
        return JNum(float(v))
    if isinstance(v, str):
        return JStr(v)
    if isinstance(v, list):
        return JArr(CapaList(_python_to_json_value(x) for x in v))
    if isinstance(v, dict):
        return JObj({k: _python_to_json_value(x) for k, x in v.items()})
    return JNull()  # fallback for unexpected types


def _json_value_to_python(j):
    """Converts a JsonValue to Python (to feed json.dumps)."""
    if isinstance(j, JNull):
        return None
    if isinstance(j, JBool):
        return j.value
    if isinstance(j, JNum):
        # Keep integers whenever possible for cleaner output.
        if j.value == int(j.value):
            return int(j.value)
        return j.value
    if isinstance(j, JStr):
        return j.value
    if isinstance(j, JArr):
        return [_json_value_to_python(x) for x in j.value]
    if isinstance(j, JObj):
        return {k: _json_value_to_python(v) for k, v in j.value.items()}
    raise TypeError(f"not a JsonValue: {j!r}")


def parse_json(s):
    """Parses a JSON string. Returns ``Ok(JsonValue)`` on success or
    ``Err(message)`` on syntax error."""
    try:
        return Ok(_python_to_json_value(_stdlib_json.loads(s)))
    except (ValueError, AttributeError) as e:
        return Err(str(e))


def to_json(j):
    """Serializes a JsonValue as a JSON string. Always returns String."""
    return _stdlib_json.dumps(_json_value_to_python(j), ensure_ascii=False)
