# Python feature version matrix

> **Capa floor is Python 3.10; do not use features tagged 3.11+.**

Fastest lookup for "can I use this in core?" **At floor = yes** means it
works on Python 3.10 and is safe to use in the compiler. **NO** means it
needs 3.11 or newer; do not use it in core.

| Feature | PEP / source | Min version | At floor (3.10) |
| --- | --- | --- | --- |
| Type hints | PEP 484 | 3.5 | yes |
| Variable annotations | PEP 526 | 3.6 | yes |
| f-strings | PEP 498 | 3.6 | yes |
| dataclasses | PEP 557 | 3.7 | yes |
| dataclass `slots=True` | PEP 557 (added 3.10) | 3.10 | yes |
| dataclass `kw_only=True` | PEP 557 (added 3.10) | 3.10 | yes |
| `from __future__ import annotations` | PEP 563 | 3.7 (opt-in, all 3.10+) | yes (opt-in) |
| Protocols (structural typing) | PEP 544 | 3.8 | yes |
| Builtin generics `list[int]` | PEP 585 | 3.9 | yes |
| `X \| Y` unions | PEP 604 | 3.10 | yes (exactly at floor) |
| ParamSpec, Concatenate | PEP 612 | 3.10 | yes (exactly at floor) |
| `TypeAlias` | PEP 613 | 3.10 | yes |
| `match` / `case` | PEP 634/635/636 | 3.10 | yes (exactly at floor) |
| enum.Enum / IntEnum / Flag | stdlib | pre-3.10 | yes |
| pathlib.Path | stdlib | pre-3.10 | yes |
| Variadic generics `TypeVarTuple` | PEP 646 | 3.11 | **NO** |
| `enum.StrEnum` | stdlib | 3.11 | **NO** |
| Type-param syntax `class C[T]` / `def f[T]` / `type X =` | PEP 695 | 3.12 | **NO** |
| f-string conveniences (same-quote reuse, backslashes, nested/multiline) | PEP 701 | 3.12 | **NO** |
| Lazy annotations as DEFAULT | PEP 649/749 | 3.14 (default) | not default at floor |

## Annotation-evaluation note (version-spanning)

At 3.10 to 3.13, annotations evaluate **eagerly** at definition time by
default. At 3.14, they are **lazy** by default (PEP 649/749). Do not write
code assuming lazy semantics; use `from __future__ import annotations` if you
want string annotations on every supported version. Details and the resolved
Capa recommendation are in [python-typing.md](python-typing.md).

## Substitutions at the floor

| Want (3.11+) | Use instead at 3.10 |
| --- | --- |
| `enum.StrEnum` | `class X(str, Enum):` |
| `class C[T]` (PEP 695) | `T = TypeVar("T")` + `class C(Generic[T]):` |
| `type Alias = int \| str` (PEP 695) | `Alias: TypeAlias = int \| str` |
| PEP 701 nested/same-quote f-strings | switch quote style; pre-compute the value into a variable |
| `TypeVarTuple` (PEP 646) | not available; restructure to avoid variadic generics |

## Cross-links

- [python-style.md](python-style.md)
- [python-typing.md](python-typing.md)
- [python-docstrings.md](python-docstrings.md)
- [python-packaging.md](python-packaging.md)
- [python-constructs.md](python-constructs.md)
