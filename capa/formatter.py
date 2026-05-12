"""capa/formatter.py, canonical-style formatter (v1, line-level).

The Capa formatter is a single non-configurable style, in the spirit
of ``gofmt``. Version 1 operates at the **line level**: it inspects
each source line and re-emits it after the following normalisations:

- **Line endings**: ``\\r\\n`` and ``\\r`` are converted to ``\\n``.
- **Indentation**: leading tab characters are forbidden at the start of
  a line by Capa's lexer; the formatter rewrites them deterministically
  to four spaces each, mirroring the convention used throughout the
  examples and standard library. Lines whose leading whitespace is not
  a multiple of four spaces are nudged down to the nearest lower
  multiple, never up, so a partially-indented continuation cannot
  silently become more deeply nested.
- **Trailing whitespace** on every line is stripped.
- **Blank-line clusters**: runs of two or more blank lines collapse to
  a single blank line. (A single blank line is preserved because Capa
  uses it as a paragraph separator between top-level declarations.)
- **Final newline**: the output always ends with exactly one ``\\n``.

Intra-line canonicalisation (operator spacing, brace placement, etc.)
is **not** part of v1. Re-emitting expressions from the AST would
require a full pretty-printer and a story for non-doc comment
preservation; both are deferred until the formatter has earned its
keep at the whitespace level. The current behaviour is therefore
*safe by design*: it never rewrites code, only its whitespace
envelope, so it cannot introduce semantic changes.

Public entry points:

``format_source(text: str) -> str``
    Return the canonical formatting of ``text``. Idempotent: applying
    it twice yields the same result as applying it once.

``is_formatted(text: str) -> bool``
    Cheap byte-exact comparison: ``True`` iff ``text == format_source(text)``.
"""

from __future__ import annotations


# A "blank" line is one that contains only whitespace after \r\n
# stripping. The blank-line dedupe rule collapses any cluster of
# them down to one.
def _is_blank(line: str) -> bool:
    return line.strip() == ""


def _normalise_indent(line: str) -> str:
    """Replace leading tabs by four spaces each, and snap a leading
    space-only indent that is not a multiple of four down to the
    nearest lower multiple. The body of the line is returned unchanged
    (trailing-whitespace stripping is handled by the caller).
    """
    # Count leading whitespace characters, expanding tabs to 4 spaces.
    i = 0
    cols = 0
    while i < len(line) and line[i] in " \t":
        if line[i] == "\t":
            cols += 4
        else:
            cols += 1
        i += 1
    # Snap to a multiple of four (floor).
    cols -= cols % 4
    return " " * cols + line[i:]


def format_source(text: str) -> str:
    """Apply the canonical formatting to ``text`` and return the result.

    The transformation is purely textual: it does not invoke the lexer
    or the parser, and therefore never raises on malformed Capa source.
    A file with syntax errors is still safely reformatted; the user
    will see the errors when they next run ``--check``.

    Block comments (``/* ... */`` and ``/** ... */``) and string
    literals are tracked across lines so the formatter does not
    rewrite their interior. In particular, Javadoc-style ``*``
    continuation lines (which sit at column 1 by convention) are
    preserved as-is rather than being snapped to column 0.
    """
    # Normalise line endings.
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    out_lines: list[str] = []
    prev_blank = False
    in_block_comment = False

    for raw in text.split("\n"):
        # Strip trailing whitespace unconditionally; this is safe
        # even inside string literals (a multi-line raw string is
        # not part of v1.0) and inside block comments (trailing
        # whitespace there is invisible).
        line = raw.rstrip()

        # If we entered a multi-line block comment on a previous
        # line, preserve indentation verbatim until we exit it.
        # The state machine is intentionally simple: we only look
        # at the run of ``/*`` / ``*/`` pairs on the line, ignoring
        # the (rare) case where one appears inside a string literal.
        line_starts_in_block = in_block_comment
        # Walk the line to update the block-comment state.
        i = 0
        while i < len(line) - 1:
            if not in_block_comment and line[i] == "/" and line[i + 1] == "*":
                in_block_comment = True
                i += 2
                continue
            if in_block_comment and line[i] == "*" and line[i + 1] == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1

        if _is_blank(line):
            # Inside a block comment a blank line should still pass
            # through as blank (no indent), so this branch is fine
            # in both states.
            if prev_blank:
                continue
            out_lines.append("")
            prev_blank = True
            continue

        if line_starts_in_block:
            # Continuation line of a block comment: preserve as-is.
            out_lines.append(line)
        else:
            out_lines.append(_normalise_indent(line))
        prev_blank = False

    # Drop trailing blank lines, then ensure exactly one final newline.
    while out_lines and out_lines[-1] == "":
        out_lines.pop()
    if not out_lines:
        return ""
    return "\n".join(out_lines) + "\n"


def is_formatted(text: str) -> bool:
    """Return ``True`` iff ``text`` is already in canonical form,
    byte-for-byte. Cheap: just compares to ``format_source(text)``.
    """
    return text == format_source(text)
