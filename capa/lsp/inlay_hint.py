"""``textDocument/inlayHint`` implementation.

Inline type hints for ``let`` / ``var`` bindings that carry no
explicit type annotation. The hint text is the type the analyzer
inferred for the binding's value expression (read straight from
``AnalysisResult.types``, the same table hover surfaces), so an
inlay hint never disagrees with what hover reports for the same
binding.

Scope decisions for v1:

* Only un-annotated ``let pattern = value`` (where the pattern is
  a plain ``IdentPat``) and ``var name = value`` are hinted. A
  binding with an explicit annotation already shows its type, so
  it is skipped.
* Only bindings whose value type the analyzer actually resolved
  are hinted. An unresolved / error type produces no hint (no
  ``?`` / ``Unknown`` noise).
* Hints outside the requested ``[start_line, end_line]`` range
  are not emitted.

Deliberately left out: parameter-name hints at call sites. They
require mapping each positional argument back to a resolved
parameter name and are noisy on Capa's named-argument calls
(``f(age: 30)``), where the name is already in the source. The
risk-to-value ratio is poor, so v1 ships type hints only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .. import capa_ast as A
from ..typesys import (
    Ty, TyFun, TyName, TyTuple, TyVar, _TyUnknownSingleton, ty_str,
)
from .context import LspContext, walk


@dataclass
class InlayHint:
    """Capa-native inlay hint. ``line`` / ``col`` are the 1-based
    position the hint anchors to (just past the binding name);
    ``label`` is the rendered ``: T`` text."""
    line: int
    col: int
    label: str


def compute_inlay_hints(
    source: str, filename: str,
    start_line: int, end_line: int,
) -> list[InlayHint]:
    """Return type hints for un-annotated ``let`` / ``var``
    bindings whose value type the analyzer resolved and that fall
    within ``[start_line, end_line]`` (1-based, inclusive).

    Returns an empty list on lex / parse / analyse failure."""
    ctx = LspContext.parse(source, filename)
    if ctx is None:
        return []

    out: list[InlayHint] = []
    for n in walk(ctx.module):
        hint = _hint_for_binding(n, ctx)
        if hint is None:
            continue
        if hint.line < start_line or hint.line > end_line:
            continue
        out.append(hint)
    return out


def _hint_for_binding(node, ctx: LspContext) -> Optional[InlayHint]:
    """Build a hint for a single ``let`` / ``var`` node, or
    ``None`` when the node is not an un-annotated binding with a
    resolved value type."""
    if isinstance(node, A.LetStmt):
        if node.type_expr is not None:
            return None
        pat = node.pattern
        if not isinstance(pat, A.IdentPat):
            return None
        ty = ctx.result.types.get(id(node.value))
        if not _is_concrete(ty):
            return None
        anchor_line = pat.pos.line
        anchor_col = pat.pos.col + len(pat.name)
        return InlayHint(
            line=anchor_line, col=anchor_col, label=f": {ty_str(ty)}",
        )

    if isinstance(node, A.VarStmt):
        if node.type_expr is not None:
            return None
        ty = ctx.result.types.get(id(node.value))
        if not _is_concrete(ty):
            return None
        if node.name_pos is None:
            return None
        anchor_line = node.name_pos.line
        anchor_col = node.name_pos.col + len(node.name)
        return InlayHint(
            line=anchor_line, col=anchor_col, label=f": {ty_str(ty)}",
        )

    return None


def _is_concrete(ty: Optional[Ty]) -> bool:
    """True when ``ty`` is a fully resolved type worth showing as a
    hint: not ``None``, not the ``TyUnknown`` escape hatch, and not
    containing an unresolved ``TyVar``. Skipping these keeps ``?`` /
    placeholder hints out of the editor."""
    if ty is None or isinstance(ty, _TyUnknownSingleton):
        return False
    return not _has_unresolved(ty)


def _has_unresolved(ty: Ty) -> bool:
    """Recursively detect ``TyUnknown`` / ``TyVar`` anywhere inside
    a composite type (``List<?>``, ``(A, ?)``, function types)."""
    if isinstance(ty, (_TyUnknownSingleton, TyVar)):
        return True
    if isinstance(ty, TyName):
        return any(_has_unresolved(a) for a in ty.args)
    if isinstance(ty, TyTuple):
        return any(_has_unresolved(e) for e in ty.elements)
    if isinstance(ty, TyFun):
        return (
            any(_has_unresolved(p) for p in ty.params)
            or _has_unresolved(ty.ret)
        )
    return False
