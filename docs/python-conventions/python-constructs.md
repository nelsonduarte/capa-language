# Python language constructs

> **Capa floor is Python 3.10; do not use features tagged 3.11+.**

See [python-version-matrix.md](python-version-matrix.md) for the version
lookup table.

## Status and minimum version

| PEP | Feature | Status | Min version | At floor (3.10) |
| --- | --- | --- | --- | --- |
| 557 | dataclasses | Final | 3.7 | yes |
| 634/635/636 | structural pattern matching (`match`/`case`) | Final | 3.10 | yes (exactly at floor) |
| 498 | f-strings | Final | 3.6 | yes |
| 701 | f-string formalization (conveniences) | Final | 3.12 | **NO** |
| - | `enum.StrEnum` | stdlib | 3.11 | **NO** |

## Usable at the floor

### dataclasses (PEP 557, 3.7)

- Use `@dataclass` for data carriers instead of hand-writing `__init__`,
  `__repr__`, `__eq__`.
- `frozen=True` for immutable value objects.
- Never use a bare mutable default; use `field(default_factory=list)`.
- `slots=True` and `kw_only=True` are **both available at 3.10**, so both
  are in scope for core.

### match / case (PEP 634/635/636, 3.10, exactly at floor)

- Directly relevant to a compiler: AST-node-shape dispatch, capture
  patterns, class patterns, guards.
- Exhaustiveness: include a catch-all `case _:` where the checker cannot
  prove totality, **or** deliberately omit it to force a match error on an
  unexpected shape. Decide per call site; both are legitimate.

### f-strings (PEP 498, 3.6)

- Prefer `f"{name}={value!r}"` over `%`-formatting and `str.format`.

### enum (stdlib)

- Use `enum.Enum` / `IntEnum` / `Flag` for closed sets of named constants.

### pathlib (stdlib)

- Use `pathlib.Path` over `os.path` string operations. Capa already uses
  `Path` across the codebase; match that.

## NOT at floor (flag, do not use in core)

- **PEP 701 f-string conveniences** (same-quote reuse inside the expression,
  backslashes in expressions, nested/multiline expressions) need **3.12**.
  On 3.10 and 3.11, avoid same-quote nesting and backslashes inside f-string
  expressions, or you get a `SyntaxError`.
- **`enum.StrEnum`** needs **3.11**. At the floor, write
  `class X(str, Enum):` instead.

## Discouraged / neutral

- Mutable default arguments (`def f(x=[]):`). Use a `None` sentinel or
  `field(default_factory=...)`.
- No PEP requires `match` over `if`/`elif`. It is a readability choice;
  `if`/`elif` stays idiomatic for a two-branch decision.

## Name collision

PEP 634 `match` is **structural pattern matching**, not regular-expression
matching. It is unrelated to the `re` module. Do not confuse "pattern
matching" (`match`/`case`) with regex patterns (`re.match`).
