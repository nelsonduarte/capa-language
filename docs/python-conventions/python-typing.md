# Python typing

> **Capa floor is Python 3.10; do not use features tagged 3.11+.**

See [python-version-matrix.md](python-version-matrix.md) for the at-a-glance
version table.

## Status and minimum version

| PEP | Feature | Status | Min version | At floor (3.10) |
| --- | --- | --- | --- | --- |
| 484 | Type hints | Final | 3.5 | yes |
| 526 | Variable annotations | Final | 3.6 | yes |
| 544 | Protocols (structural) | Final | 3.8 | yes |
| 585 | Builtin generics `list[int]` | Final | 3.9 | yes |
| 604 | `X \| Y` unions | Final | 3.10 | yes (exactly at floor) |
| 612 | ParamSpec, Concatenate | Final | 3.10 | yes (exactly at floor) |
| 646 | Variadic generics `TypeVarTuple` | Final | 3.11 | **NO** |
| 695 | `class C[T]` / `def f[T]` / `type X =` | Final | 3.12 | **NO** |
| 563 | `from __future__ import annotations` | Superseded (by 649/749) | opt-in 3.7+ | opt-in yes |
| 649 | Deferred (lazy) annotations | Final | default in 3.14 | not default |
| 749 | Implements 649 | Final | 3.14 | no |

## Rules usable at the floor

| Rule | PEP | Note |
| --- | --- | --- |
| Annotate all public signatures and returns | 484 | |
| Annotate non-obvious module and class variables | 526 | obvious literals may be left implicit |
| Use builtin generics: `list[int]`, `dict[str, Node]`, `tuple[int, ...]` | 585 | not `typing.List` / `Dict` / `Tuple` (soft-deprecated since 3.9) |
| Prefer `X \| Y` and `X \| None` | 604 | over `typing.Union` / `typing.Optional`; lands exactly at the 3.10 floor |
| Use `typing.Protocol` for structural interfaces | 544 | add `@runtime_checkable` only when an `isinstance` check is actually needed |
| Use `ParamSpec` + `Concatenate` for signature-preserving decorators | 612 | |
| Use `TypeVar` + `Generic[T]` for generics | 484 | this is the ONLY generics syntax at the floor and it is correct and idiomatic on 3.10 |
| Declare aliases as `MyAlias: TypeAlias = int \| str` | 613 | `TypeAlias` is available at 3.10 |

## Annotation evaluation across 3.10-3.14 (the rule that changes)

This is the one behavior that differs by version, so it needs an explicit
rule:

- **3.10 to 3.13**: annotations are evaluated **eagerly at definition time**
  by default. A forward reference that is not yet defined raises at import
  time unless quoted.
- **3.14**: annotations are **lazy** by default (PEP 649/749). PEP 563 is
  superseded; do not describe it as "the coming default."
- `from __future__ import annotations` (PEP 563) is available on every 3.10+
  interpreter. It turns all annotations into strings: free forward
  references, no import-time evaluation cost.
- **Caveat**: with the future-import active, annotations are strings, so any
  code that reads them back at runtime (`typing.get_type_hints`, some
  dataclass edge cases, pydantic-style validators) must resolve them
  explicitly. If you never introspect annotations, this caveat does not
  affect you.
- **Do NOT** write code that assumes 649 lazy semantics as a given; that is
  false on 3.10 to 3.13, which are in the support window.

### Resolved recommendation for Capa core

**Adopt `from __future__ import annotations` at the top of new modules.**

Evidence (measured in this repo):

- `capa/` has **zero** uses of `typing.get_type_hints`, no
  `__annotations__` read for program logic, and no `inspect.signature`
  reliance on resolved annotation objects. The core is standard-library
  only and does not introspect annotations at runtime.
- The future-import is **already present in 184 files** under `capa/`, so
  adopting it in new modules matches the established codebase pattern.

Because nothing in core resolves annotation objects at runtime, the string
form is free of risk here and buys forward-reference freedom plus faster
import. If a future module does need runtime annotation resolution, scope
the future-import out of that module (or call `get_type_hints(..., )` with
the module globals) rather than relying on eager evaluation implicitly.

## NOT at floor (do not use in core)

- **PEP 646** variadic generics (`TypeVarTuple`, `Unpack`): 3.11.
- **PEP 695** type-parameter syntax (`class C[T]`, `def f[T]`,
  `type Alias = ...`): 3.12. Use `TypeVar` / `Generic` and
  `MyAlias: TypeAlias = ...` instead.

## Discouraged

- Describing PEP 563 as "coming default." It was abandoned in favor of 649.
- `typing.Optional` / `typing.Union` in new code. Prefer `|`.
- `typing.List` / `Dict` / `Set` / `Tuple` / `Type`. Soft-deprecated since
  3.9; use the builtin generics.

## Name collision

`typing.Protocol` is **not** `asyncio.Protocol`. Write `typing.Protocol`
explicitly (or import it under a clear name) so the two are never confused.
