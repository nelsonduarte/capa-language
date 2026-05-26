"""Capa source-code formatter.

The package is split into four layers:

- :mod:`._lines` (v1 + v2): purely textual, line-level normalisation
  with an intra-line state machine for spacing. Never invokes the
  lexer or parser, so it is safe on malformed source. This is the
  fallback path when the AST-roundtrip layer cannot run (parse
  errors, in-progress edits).
- :mod:`._comments` (v3 phase 2): :class:`CommentMap` attachment
  pass that ties every plain ``//`` and ``/* */`` comment to an AST
  node, so the pretty-printer can re-emit them in the right place.
- :mod:`._emit` (v3 phase 3): pretty-printer that walks the AST and
  emits canonical Capa source, consulting the :class:`CommentMap`
  for comment placement.
- This module (v3 phase 4): the dispatch layer. Tries the AST
  round-trip first; on any lex / parse / emit failure falls back
  to the line-level pipeline so even malformed sources are
  cleaned up safely.

Public entry points:

``format_source(text: str) -> str``
    Return the canonical formatting of ``text``. Idempotent:
    applying it twice yields the same result as applying it once.
    Strategy: AST round-trip first, line-level fallback on
    failure.

``is_formatted(text: str) -> bool``
    Cheap byte-exact comparison: ``True`` iff
    ``text == format_source(text)``.

``format_source_emit(text: str) -> str``
    Run the v3 AST-roundtrip pipeline directly. Raises on lex /
    parse failure. Available for callers that want a hard error
    rather than the silent fallback.
"""

from __future__ import annotations

from ._lines import format_source as _format_source_lines
from ._emit import format_source_emit


def format_source(text: str) -> str:
    """Apply the canonical Capa formatting to ``text``.

    Strategy:

    1. Try the AST round-trip pipeline (:func:`format_source_emit`).
       This is the v3 path: lex + parse + walk the AST + emit
       canonical source, consulting the CommentMap so plain
       comments (``//`` and ``/* */``) land back in their original
       place.
    2. On any exception from lex / parse / emit, fall back to the
       line-level pipeline (:func:`._lines.format_source`). The
       fallback is purely textual and cannot raise; it always
       returns a normalised result.

    The fallback path is what makes the formatter safe to point
    at a file mid-edit, mid-refactor, or with a syntax error: the
    user still gets indentation + trailing-whitespace + intra-line
    spacing cleanup, just not the AST-driven canonicalisation.
    """
    try:
        emit_result = format_source_emit(text)
    except Exception:
        # Any failure in lex / parse / build_comment_map / emit
        # falls through to the textual pipeline. The textual
        # pipeline never raises, so this is a complete fallback.
        return _format_source_lines(text)
    # Guard against degenerate sources that lex to an empty token
    # stream (e.g. a lone ``\`` line-continuation followed by EOF)
    # but had non-whitespace input. The AST round-trip would emit
    # ``""`` and lose data; fall back to the textual pipeline,
    # which preserves the literal characters.
    if emit_result == "" and text.strip() != "":
        return _format_source_lines(text)
    return emit_result


def is_formatted(text: str) -> bool:
    """Return ``True`` iff ``text`` is already in canonical form."""
    return text == format_source(text)
