# Python style and idioms

> **Capa floor is Python 3.10; do not use features tagged 3.11+.**

Source PEPs: PEP 8 (Active, Process), PEP 20 (Active, Informational),
PEP 257 (Active, Informational). See also
[python-docstrings.md](python-docstrings.md) for PEP 257 in full and
[python-version-matrix.md](python-version-matrix.md) for the version lookup.

## PEP-normative rules (PEP 8, all versions)

Follow these. They are stated in an Active PEP.

| Rule | Detail |
| --- | --- |
| Indentation | 4 spaces per level, never tabs |
| Naming: functions, variables, modules | `snake_case` |
| Naming: classes | `PascalCase` |
| Naming: constants | `UPPER_SNAKE` |
| Naming: internal | single `_leading_underscore` |
| Naming: reserved | `__dunder__` is reserved, do not invent new ones |
| Imports | one per line; order stdlib / third-party / local, blank-line-separated; absolute imports preferred |
| Blank lines | two around top-level defs, one around methods |
| None comparison | `is` / `is not` (write `if x is not None:`) |
| Emptiness test | `if not seq:`, not `if len(seq) == 0:` |
| Exceptions | no bare `except:` |

### Line length (read carefully)

- **PEP-normative number: 79 columns for code, 72 for docstrings and
  comments.** This is the rule PEP 8 actually states.
- **88 is a convention, not a PEP rule.** 88 is the Black / Ruff default.
  PEP 8 permits a team to raise the limit (up to 99 by consensus), but it
  does not endorse 88 specifically. Do not write "PEP 8 says 88"; it does
  not.
- **Capa has no formatter config today.** There is no `[tool.black]` or
  `[tool.ruff]` section in `pyproject.toml` (measured). So the effective
  line-length rule in this repo is PEP 8's 79 until the team decides
  otherwise. "Let the formatter decide layout" is a convention that does
  not yet apply here because no formatter is configured.

`CONTRIBUTING.md` records the same baseline: no autoformatter, "PEP 8 with
exceptions for long descriptive identifiers."

## PEP 20 (The Zen of Python)

Informational guidance, not enforceable rules. Useful tie-breakers:
explicit over implicit, readability counts, flat over nested, special cases
are not special enough to break the rules. The Capa codebase already leans
this way: "terse, explicit Python, no over-engineering" (`CONTRIBUTING.md`).

## Do NOT

- Cite 88 as "PEP 8 says 88" (see above).
- Use wildcard imports `from module import *` (PEP 8 discourages them).
- Introduce a `[tool.black]` / `[tool.ruff]` config as a drive-by; that is a
  team decision, not a style fix.
