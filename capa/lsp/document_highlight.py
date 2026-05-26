"""``textDocument/documentHighlight`` handler.

When the user's cursor sits on an identifier, return every
in-file occurrence of the same binding so the editor can
highlight them. Backed by ``compute_references`` (which already
does the resolve-binding + collect-occurrences walk), with one
addition: per-occurrence kind (``"text"``, ``"read"``, or
``"write"``) so editors that distinguish reads from writes can
colour them differently. v1 uses ``"text"`` for everything;
read / write distinction is left as future polish since it
requires walking the parent context (LHS of assignment vs.
elsewhere).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .references import compute_references


@dataclass
class DocumentHighlight:
    """One in-document occurrence to highlight. 1-based line/col."""
    line: int
    col: int
    name: str
    kind: str  # "text" | "read" | "write"


def compute_document_highlights(
    source: str, filename: str, line: int, col: int,
) -> Optional[list[DocumentHighlight]]:
    """Return one DocumentHighlight per same-binding occurrence in
    the document, or ``None`` when the cursor is not on a
    resolvable identifier.

    Internally just wraps ``compute_references`` with
    ``include_declaration=True`` and converts the returned
    identifiers to ``DocumentHighlight`` (kind always ``"text"``
    in v1).
    """
    idents = compute_references(
        source, filename, line, col, include_declaration=True,
    )
    if idents is None:
        return None
    return [
        DocumentHighlight(
            line=i.pos.line, col=i.pos.col, name=i.name, kind="text",
        )
        for i in idents
    ]
