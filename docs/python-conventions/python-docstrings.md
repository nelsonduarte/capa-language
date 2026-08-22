# Python docstrings

> **Capa floor is Python 3.10; do not use features tagged 3.11+.**

Source PEP: PEP 257 (Active, Informational).

## PEP 257 conventions (follow these)

| Rule | Detail |
| --- | --- |
| Coverage | Every public module, class, function, and method gets a docstring |
| Quoting | Always `"""triple double quotes"""`, even for one-liners |
| One-line form | Summary on one line, closing quotes on the same line, no blank line before or after |
| Multi-line form | Summary line, then a blank line, then the body |
| Mood | Imperative: "Return the parsed node", not "Returns the parsed node" |
| Content | Describe behavior, arguments, return value, side effects, and what it raises |

## Docstring FORMAT is a project choice (no PEP governs it)

PEP 257 covers **conventions** (quoting, mood, blank lines, one-line vs
multi-line). It does **not** mandate a field format. There is no PEP that
requires Google, NumPy, or reST style. Do not attribute the format choice to
a PEP.

The three common formats, as options:

- **reST / Sphinx**: `:param name:`, `:returns:`, `:raises:` fields, with
  double-backtick `` ``inline`` `` markup.
- **Google**: `Args:`, `Returns:`, `Raises:` sections.
- **NumPy**: `Parameters`, `Returns` sections with underline separators.

### What Capa already leans toward (measured)

The existing `capa/` docstrings lean **reST / Sphinx-flavored narrative**:
prose descriptions with double-backtick inline code markup (for example
```` ``TyUnknown`` ````, ```` ``analyze(module, source, filename)`` ````),
and no Google/NumPy `Args:` / `Returns:` sections (the analyzer package has
zero of them). See `capa/analyzer/__init__.py` and
`capa/analyzer/_linear.py` for representative examples.

**Recommendation**: adopt the reST-flavored narrative style already in use,
so new docstrings match the corpus. If the team prefers explicit
`:param:` / `:returns:` fields for public APIs, that is a compatible
refinement of the same family. Pick one and record it here; do not mix
Google and NumPy sections into a reST codebase.
