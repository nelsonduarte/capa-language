"""A naive Python CSV parser, of the shape that appears in
essentially every Python data tool that ingests tabular text
(the stdlib `csv` module is the canonical reference; this is
the core of its `reader` API in a single function).

The signature
`parse_csv(text: str, delimiter: str = ',') -> list[list[str]]`
exercises NO capabilities at all - the function is pure. The
top-level import block does not reach a stdlib module that
could plausibly be capability-bearing: the file imports
nothing. A PURL-based SBOM emitted by syft / pip-licenses for
this file therefore has nothing to say beyond "this script
depends on Python itself".

The Capa equivalent (see `capa.capa`) proves that not only the
public `parse_csv` but every helper involved in scanning quoted
and unquoted cells is purity-verified by the compiler. The
shape exercised here is a character-by-character state machine
(quoted vs. unquoted, `""` as a literal-quote escape, `\\n` as
the row terminator), which is distinct from the simpler
line-split shape of `ini_loader/` and `dotenv/`. The output is
a `list[list[str]]`, which exercises the nested-collection
handling that the other pure cases (`slugify`, `textwrap`,
`tabulate`, `humanize`) do not.

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""


def parse_csv(text: str, delimiter: str = ",") -> list[list[str]]:
    # Step 1: walk the text character by character. The state
    # machine has two modes: unquoted (delimiter ends the cell,
    # `\n` ends the row) and quoted (a `"` exits the field,
    # except `""` which is a literal quote inside the cell).
    rows: list[list[str]] = []
    current_row: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] == '"':
            # Quoted cell: the opening `"` is consumed; the
            # scan starts at the first content character.
            cell, i = _parse_cell_quoted(text, i + 1)
        else:
            cell, i = _parse_cell_unquoted(text, i, delimiter)
        # Strip a trailing `\r` from the cell so that Windows
        # `\r\n` line endings collapse cleanly to `\n`.
        if cell.endswith("\r"):
            cell = cell[:-1]
        current_row.append(cell)
        # Decide what the terminator was. `i` either points at
        # the delimiter (more cells in this row), at a `\n` (row
        # complete, advance and reset), or past the end (final
        # row, flush if non-empty and exit).
        if i >= n:
            break
        if text[i] == delimiter:
            i += 1
            continue
        if text[i] == "\n":
            rows.append(current_row)
            current_row = []
            i += 1
            continue
    # An empty trailing line (the file ended with `\n`) leaves
    # `current_row` empty; drop it rather than emitting a row of
    # one empty cell.
    if current_row:
        rows.append(current_row)
    return rows


def _parse_cell_unquoted(text: str, start: int, delimiter: str) -> tuple[str, int]:
    # Scan forward until we hit `delimiter`, `\n`, or end of
    # text. The returned index points AT the terminator (or at
    # `len(text)`); the caller advances past it.
    i = start
    n = len(text)
    while i < n and text[i] != delimiter and text[i] != "\n":
        i += 1
    return text[start:i], i


def _parse_cell_quoted(text: str, start: int) -> tuple[str, int]:
    # Scan forward inside a quoted field. `""` is a literal
    # quote; a lone `"` ends the field. The returned index
    # points just AFTER the closing quote.
    out: list[str] = []
    i = start
    n = len(text)
    while i < n:
        if text[i] == '"':
            if i + 1 < n and text[i + 1] == '"':
                out.append('"')
                i += 2
                continue
            return "".join(out), i + 1
        out.append(text[i])
        i += 1
    # Unterminated quoted field: return what we have. The naive
    # version is permissive here; a stricter parser would raise.
    return "".join(out), i


# A PURL-based SBOM emitted by syft / pip-licenses for this file
# would list nothing capability-bearing: the file has no imports
# at all. The PURL SBOM is silent. That silence is itself a
# comparison failure: it cannot distinguish "this file does
# nothing" from "this file imports nothing PURL recognises as a
# capability". The Capa equivalent names each function and
# declares zero capabilities per function, with the compiler
# enforcing the absence of any Fs / Env / Net / Stdio call
# inside the helpers.
