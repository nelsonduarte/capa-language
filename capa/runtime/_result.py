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

T = TypeVar("T")
E = TypeVar("E")
U = TypeVar("U")


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


# Singleton, in Capa, ``None`` is the variant. In Python, we add a suffix
# to avoid clashing with the builtin ``None``.
None_ = _NoneType()

Option = Some | _NoneType
