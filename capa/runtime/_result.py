"""Result and Option sum types.

Both are represented as ordinary frozen dataclasses so Python's
``match/case`` and ``isinstance`` work without special support.

- ``Ok(value)`` / ``Err(error)``: variants of ``Result[T, E]``.
- ``Some(value)`` / ``None_``: variants of ``Option[T]``. The
  singleton has the ``_`` suffix to avoid clashing with Python's
  builtin ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Generic, TypeVar

from ._panic import panic

T = TypeVar("T")
E = TypeVar("E")
U = TypeVar("U")

# Fixed panic messages for ``unwrap()`` on the value-less variant.
# These strings are byte-identical to the ones the Wasm backend
# interns in capa/ir/_emit_wasm/_option.py, so a ``None.unwrap()`` /
# ``Err.unwrap()`` panic produces the same ``panic: <message>`` line
# on both backends. ``Result.unwrap()`` deliberately does NOT embed
# the Err value: formatting an arbitrary E identically across the two
# backends is not guaranteed, and parity is the central promise.
_UNWRAP_NONE_MSG = "called unwrap() on a None value"
_UNWRAP_ERR_MSG = "called unwrap() on an Err value"


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

    def expect(self, msg: str) -> T:
        return self.value

    def unwrap_or(self, default: T) -> T:
        return self.value

    def map(self, f: Callable[[T], U]) -> "Result[U, Any]":
        return Ok(f(self.value))

    def map_err(self, f):
        return self

    def and_then(self, f):
        return f(self.value)

    def or_else(self, f):
        return self

    def ok(self):
        return Some(self.value)

    def err(self):
        return None_


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
        panic(_UNWRAP_ERR_MSG)

    def expect(self, msg: str) -> Any:
        panic(msg)

    def unwrap_or(self, default: T) -> T:
        return default

    def map(self, f: Callable[[Any], Any]) -> "Result[Any, E]":
        return self

    def map_err(self, f):
        return Err(f(self.error))

    def and_then(self, f):
        return self

    def or_else(self, f):
        return f(self.error)

    def ok(self):
        return None_

    def err(self):
        return Some(self.error)


# Type alias for annotations.
Result = Ok | Err


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

    def expect(self, msg: str) -> T:
        return self.value

    def unwrap_or(self, default: T) -> T:
        return self.value

    def map(self, f):
        return Some(f(self.value))

    def and_then(self, f):
        return f(self.value)

    def ok_or(self, err):
        return Ok(self.value)

    def or_else(self, f):
        return self

    def filter(self, p):
        return self if p(self.value) else None_


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
        panic(_UNWRAP_NONE_MSG)

    def expect(self, msg: str) -> Any:
        panic(msg)

    def unwrap_or(self, default: T) -> T:
        return default

    def map(self, f):
        return self

    def and_then(self, f):
        return self

    def ok_or(self, err):
        return Err(err)

    def or_else(self, f):
        return f()

    def filter(self, p):
        return self


# Singleton, in Capa, ``None`` is the variant. In Python, we add a suffix
# to avoid clashing with the builtin ``None``.
None_ = _NoneType()

Option = Some | _NoneType
