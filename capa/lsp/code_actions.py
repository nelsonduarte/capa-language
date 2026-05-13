"""``textDocument/codeAction``: Quick Fixes for the analyzer's
``did you mean 'X'?`` hints.

Five analyzer error families append ``; did you mean 'X'?`` to
their message (undefined name, undefined type, no method on
type, no field on struct, unknown variant). For each such
diagnostic this module returns a Quick Fix that replaces the
misspelled token with the suggestion.

The diagnostic position is the start of the *construct* the
error belongs to (the receiver for a method call, the struct
literal head for a field, ...), not always the start of the
misspelled token. We therefore extract the typo from the
message itself (the quoted string immediately preceding
``; did you mean``) and search the source line for it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


# Matches both the typo and the suggestion. The typo is always
# the quoted string immediately preceding ``;`` followed by
# ``did you mean``.
_DID_YOU_MEAN_RE = re.compile(
    r"'([^']+)'\s*;\s*did you mean '([^']+)'\?"
)


@dataclass
class CodeActionEdit:
    """A text replacement, in 1-based Capa coordinates."""
    line: int
    col_start: int
    col_end: int
    new_text: str


@dataclass
class CodeAction:
    """A Quick Fix the server offers for a diagnostic."""
    title: str
    edit: CodeActionEdit


def compute_code_actions(
    source: str, diagnostic_message: str, diagnostic_line: int,
) -> list[CodeAction]:
    """Return the Quick Fixes available for a single diagnostic.

    Empty list when the message has no ``did you mean 'X'?``
    suffix, or when the typo cannot be located on the diagnostic's
    line (mid-edit, or the diagnostic position is approximate as
    for typos inside ``${...}`` interpolation).
    """
    match = _DID_YOU_MEAN_RE.search(diagnostic_message)
    if match is None:
        return []
    typo, suggestion = match.group(1), match.group(2)

    lines = source.split("\n")
    if diagnostic_line < 1 or diagnostic_line > len(lines):
        return []
    line_text = lines[diagnostic_line - 1]
    col = _find_token_column(line_text, typo)
    if col is None:
        return []

    return [
        CodeAction(
            title=f"Replace with {suggestion!r}",
            edit=CodeActionEdit(
                line=diagnostic_line,
                col_start=col,
                col_end=col + len(typo),
                new_text=suggestion,
            ),
        )
    ]


def _find_token_column(line_text: str, token: str) -> Optional[int]:
    """Find the 1-based column where ``token`` appears on the
    given source line, matched as a whole word so a typo like
    ``in`` does not pick up the ``in`` inside ``println``."""
    pattern = re.compile(r"\b" + re.escape(token) + r"\b")
    match = pattern.search(line_text)
    if match is None:
        return None
    return match.start() + 1
