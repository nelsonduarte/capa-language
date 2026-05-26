"""A naive Python ASCII-table formatter, of the shape that
appears in many Python CLI tools (PyPI's `tabulate` has ~50M
downloads/month; this is the core of its public API).

The signature `tabulate(rows: list[list], headers: list | None = None) -> str`
exercises NO capabilities at all - the function is pure. Unlike
`slugify`, the top-level import block does not even reach a
stdlib module that could plausibly be capability-bearing: the
file imports nothing beyond `typing` (a pure type-only module).
A PURL-based SBOM emitted by syft / pip-licenses for this file
therefore has nothing to say beyond "this script depends on
Python itself".

The Capa equivalent (see `capa.capa`) proves that every helper
involved in building the table - column-width computation, row
formatting, separator construction, and the public composition
point - is purity-verified by the compiler. The asymmetry this
pair makes visible is not over-attribution (as with `slugify`'s
`re` and `unicodedata`) but the opposite: PURL says nothing,
while Capa names every function as compiler-verified pure.

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""

from typing import Iterable


def _column_widths(rows: list[list], headers: list | None) -> list[int]:
    # Width of each column = max length of any cell (including the
    # header, if present) in that column. Empty input yields an
    # empty width list.
    all_rows: list[list] = list(rows)
    if headers is not None:
        all_rows = [headers] + all_rows
    if not all_rows:
        return []
    n_cols = max(len(r) for r in all_rows)
    widths = [0] * n_cols
    for r in all_rows:
        for i, cell in enumerate(r):
            s = str(cell)
            if len(s) > widths[i]:
                widths[i] = len(s)
    return widths


def _format_row(cells: Iterable, widths: list[int]) -> str:
    # Pad each cell to its column width and join with `| ... |`
    # separators. Cells beyond the known column count are dropped
    # silently; missing cells are padded as empty strings.
    parts = []
    for i, w in enumerate(widths):
        cell = ""
        for j, c in enumerate(cells):
            if j == i:
                cell = str(c)
                break
        parts.append(cell.ljust(w))
    return "| " + " | ".join(parts) + " |"


def _format_separator(widths: list[int]) -> str:
    # `+---+---+...+` line, one segment per column, sized to the
    # column width plus the two padding spaces inside each cell.
    segments = ["-" * (w + 2) for w in widths]
    return "+" + "+".join(segments) + "+"


def tabulate(rows: list[list], headers: list | None = None) -> str:
    widths = _column_widths(rows, headers)
    if not widths:
        return ""
    sep = _format_separator(widths)
    lines: list[str] = [sep]
    if headers is not None:
        lines.append(_format_row(headers, widths))
        lines.append(sep)
    for r in rows:
        lines.append(_format_row(r, widths))
    lines.append(sep)
    return "\n".join(lines)


# A PURL-based SBOM emitted by syft / pip-licenses for this file
# would list nothing capability-bearing: `typing` is the only
# import and it is a pure type-only stdlib module. The PURL SBOM
# is silent. That silence is itself a comparison failure: it
# cannot distinguish "this file does nothing" from "this file
# imports nothing PURL recognises as a capability". The Capa
# equivalent names each function and declares zero capabilities
# per function, with the compiler enforcing the absence of any
# Fs / Env / Net / Stdio call inside the helpers.
