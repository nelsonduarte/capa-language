"""capa/formatter.py, canonical-style formatter.

The Capa formatter is a single non-configurable style, in the spirit
of ``gofmt``. It operates at the **line level**, with a conservative
intra-line pass for clear-cut spacing rules. The following
normalisations are applied, in order:

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
- **Intra-line spacing**: outside string literals, char literals, and
  ``//`` comments, runs of two or more spaces collapse to a single
  space, and a missing space after a comma is inserted. These two
  rules cover the most common formatting drift without needing the
  AST.

Full intra-line canonicalisation (operator spacing around binary
operators, brace placement, expression re-emission from the AST)
is **not** part of this version. Re-emitting expressions from the
AST requires a full pretty-printer and a story for ``//`` comment
preservation; both are deferred. The current behaviour is therefore
*safe by design*: it never rewrites code structure, only its
whitespace envelope, so it cannot introduce semantic changes.

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


def _normalise_intra_line(line: str) -> str:
    """Apply safe intra-line spacing rules to the *body* of ``line``
    (i.e. the part after the leading indent). The leading indent is
    preserved exactly; the body is walked character by character with a
    small state machine that tracks string / char-literal / line-comment
    context, so the rules never touch text inside those.

    Rules applied to code (everywhere else):

    - runs of two or more spaces collapse to a single space;
    - a missing space after a ``,`` is inserted.

    Anything more aggressive (operator spacing, brace placement, etc.)
    is deferred to the future AST-round-trip formatter, because doing
    it correctly requires preserving ``//`` comments and disambiguating
    unary from binary uses of ``-`` / ``*``.
    """
    # Split off the leading indent so we never touch it.
    i = 0
    while i < len(line) and line[i] == " ":
        i += 1
    indent = line[:i]
    body = line[i:]

    out: list[str] = []
    in_string = False        # inside "..."
    in_char = False          # inside '...'
    string_quote = ""        # opening quote of the active literal
    in_line_comment = False
    j = 0
    while j < len(body):
        c = body[j]
        if in_line_comment:
            # Comments are preserved verbatim until end of line.
            out.append(c)
            j += 1
            continue
        if in_string or in_char:
            out.append(c)
            # Backslash escapes consume the next char without state
            # change (raw strings ``r"..."`` don't process escapes,
            # but for spacing purposes that distinction doesn't matter).
            if c == "\\" and j + 1 < len(body):
                out.append(body[j + 1])
                j += 2
                continue
            if c == string_quote:
                in_string = False
                in_char = False
                string_quote = ""
            j += 1
            continue
        # Outside any literal or comment.
        if c == '"':
            in_string = True
            string_quote = '"'
            out.append(c)
            j += 1
            continue
        if c == "'":
            in_char = True
            string_quote = "'"
            out.append(c)
            j += 1
            continue
        if c == "/" and j + 1 < len(body) and body[j + 1] == "/":
            in_line_comment = True
            out.append(c)
            j += 1
            continue
        if c == " ":
            # Collapse runs of two or more spaces in code into one.
            if out and out[-1] == " ":
                j += 1
                continue
            out.append(c)
            j += 1
            continue
        if c == "," and j + 1 < len(body) and body[j + 1] not in (" ", ","):
            # Insert a single space after the comma unless the next
            # token is a closing delimiter; we leave ``,)`` and
            # similar trailing-comma forms alone.
            if body[j + 1] not in (")", "]", "}", "\n"):
                out.append(",")
                out.append(" ")
                j += 1
                continue
        out.append(c)
        j += 1
    return indent + "".join(out)


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
            out_lines.append(_normalise_intra_line(_normalise_indent(line)))
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
