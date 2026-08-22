# Python conventions for Capa contributors

> **Capa floor is Python 3.10; do not use features tagged 3.11+.**

The Capa compiler is written in Python. These reference files tell
contributors (human and sub-agent) which Python idioms are in scope, which
are out of scope at the 3.10 floor, and which rules are PEP-normative versus
project convention. They exist to keep the ongoing modularization consistent.

Each file is authored from a verified curation of the relevant PEPs, then
checked against this repository before shipping. Where a rule depends on a
repo fact (pyproject fields, formatter config, annotation introspection),
that fact was measured, not assumed.

## Files

| File | Covers |
| --- | --- |
| [python-style.md](python-style.md) | Layout, naming, imports, line length (PEP 8 / 20 / 257) |
| [python-typing.md](python-typing.md) | Annotations, `\|`-unions, builtin generics, Protocols, ParamSpec, annotation-evaluation across 3.10-3.14 |
| [python-docstrings.md](python-docstrings.md) | PEP 257 conventions and the docstring-format choice |
| [python-packaging.md](python-packaging.md) | pyproject metadata, build backend, versioning, lockfiles (PEP 517 / 518 / 621 / 660 / 440 / 508 / 751) |
| [python-constructs.md](python-constructs.md) | dataclasses, `match`, f-strings, enum, pathlib |
| [python-version-matrix.md](python-version-matrix.md) | One feature -> min-version -> at-floor lookup table |

## How to read the tags

- **PEP-normative**: the rule is stated in an Active PEP. Follow it.
- **Convention**: common practice with no PEP behind it. Labelled as such;
  do not cite it as a PEP rule.
- **NOT at floor**: the feature needs Python 3.11 or newer. Do not use it in
  core compiler code; see [python-version-matrix.md](python-version-matrix.md).

## House style already on record

`CONTRIBUTING.md` states the project runs no autoformatter and asks
contributors to "Match the style of the surrounding code: PEP 8 with
exceptions for long descriptive identifiers." These files expand on that
baseline; they do not replace it.
