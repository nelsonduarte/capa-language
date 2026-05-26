"""``textDocument/formatting`` and ``textDocument/rangeFormatting``
handlers backed by ``capa.formatter.format_source``.

The formatter is byte-exact idempotent (see ``capa/formatter/__init__.py``)
and never raises: on lex/parse failure it falls back to the v1+v2
line-level pipeline, which always returns a normalised result.
The LSP handlers consequently never raise either; they return an
empty list of edits when the source is already canonical.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..formatter import format_source


@dataclass
class TextEdit:
    """A whole-document or range-bounded text edit, in Capa-native
    1-based line / column coordinates.

    The LSP server translates to the wire format (0-based positions)
    in ``server.py``.
    """
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    new_text: str


def compute_formatting(source: str) -> list[TextEdit]:
    """Format the whole document.

    Returns a single TextEdit replacing the entire source if it
    needs reformatting, or an empty list if it is already in
    canonical form.
    """
    formatted = format_source(source)
    if formatted == source:
        return []
    end_line, end_col = _end_of_source(source)
    return [TextEdit(
        start_line=1, start_col=1,
        end_line=end_line, end_col=end_col,
        new_text=formatted,
    )]


def compute_range_formatting(
    source: str,
    start_line: int, start_col: int,
    end_line: int, end_col: int,
) -> list[TextEdit]:
    """Format a range. Scope cut: the v3 formatter operates on the
    whole document (it is parse-then-emit, not a streaming
    re-formatter), so we conservatively format the whole document
    and return the edit. Editors that ask for range formatting
    typically still accept whole-document edits.
    """
    return compute_formatting(source)


def _end_of_source(source: str) -> tuple[int, int]:
    """1-based (line, col) of the position just past the last
    character of ``source``. Empty source returns (1, 1)."""
    if not source:
        return (1, 1)
    lines = source.split("\n")
    # If the source ends in ``\n``, split produces a trailing empty
    # string; the past-end position is at the start of that
    # imaginary next line.
    last = lines[-1]
    return (len(lines), len(last) + 1)
