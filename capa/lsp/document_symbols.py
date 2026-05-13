"""``textDocument/documentSymbol`` implementation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .. import capa_ast as A
from ..tokens import Pos
from .context import LspContext


# Tag strings the server handler maps onto ``lsp.SymbolKind``.
LSP_KIND_TAGS = frozenset({
    "constant", "function", "struct", "sum", "field", "variant",
    "trait", "capability", "method", "impl",
})


@dataclass
class DocSymbol:
    """One node of the outline tree."""
    name: str
    detail: str
    kind: str   # one of ``LSP_KIND_TAGS``
    pos: Pos
    children: list["DocSymbol"] = field(default_factory=list)


def compute_document_symbols(
    source: str, filename: str,
) -> Optional[list[DocSymbol]]:
    """Walk the module and return its outline. Returns ``None``
    on lexer / parser failure so the editor can render a
    sensible empty outline rather than a stale guess."""
    ctx = LspContext.parse(source, filename)
    if ctx is None:
        return None
    out: list[DocSymbol] = []
    for item in ctx.module.items:
        sym = _item_to_doc_symbol(item)
        if sym is not None:
            out.append(sym)
    return out


def _item_to_doc_symbol(item: A.Item) -> Optional[DocSymbol]:
    if isinstance(item, A.ConstDecl):
        return DocSymbol(
            name=item.name, detail=_type_expr_to_text(item.type_expr),
            kind="constant", pos=item.pos,
        )
    if isinstance(item, A.TypeStruct):
        children = [
            DocSymbol(
                name=f.name, detail=_type_expr_to_text(f.type_expr),
                kind="field", pos=f.pos,
            )
            for f in item.fields
        ]
        return DocSymbol(
            name=item.name, detail="struct", kind="struct",
            pos=item.pos, children=children,
        )
    if isinstance(item, A.TypeSum):
        children = []
        for v in item.variants:
            detail = (
                f"({_type_expr_to_text(v.payload)})"
                if v.payload is not None else ""
            )
            children.append(
                DocSymbol(
                    name=v.name, detail=detail,
                    kind="variant", pos=v.pos,
                )
            )
        return DocSymbol(
            name=item.name, detail="sum", kind="sum",
            pos=item.pos, children=children,
        )
    if isinstance(item, A.TraitDecl):
        kind = "capability" if item.is_capability else "trait"
        children = []
        for m in item.methods:
            params = ", ".join(
                f"{p.name}: {_type_expr_to_text(p.type_expr)}"
                if p.type_expr is not None and p.name != "self"
                else p.name
                for p in m.params
            )
            ret = (
                f" -> {_type_expr_to_text(m.return_type)}"
                if m.return_type is not None else ""
            )
            children.append(
                DocSymbol(
                    name=m.name, detail=f"({params}){ret}",
                    kind="method", pos=m.pos,
                )
            )
        return DocSymbol(
            name=item.name, detail=kind, kind=kind,
            pos=item.pos, children=children,
        )
    if isinstance(item, A.FunDecl):
        return DocSymbol(
            name=item.name, detail=_fun_detail(item),
            kind="function", pos=item.pos,
        )
    if isinstance(item, A.ImplBlock):
        if item.trait_name is not None:
            display_name = f"impl {item.trait_name} for {item.type_name}"
        else:
            display_name = f"impl {item.type_name}"
        children = [
            DocSymbol(
                name=m.name, detail=_fun_detail(m),
                kind="method", pos=m.pos,
            )
            for m in item.methods
        ]
        return DocSymbol(
            name=display_name, detail="", kind="impl",
            pos=item.pos, children=children,
        )
    return None


def _fun_detail(fn: A.FunDecl) -> str:
    """Capa-style signature for the outline detail column.
    ``self`` is omitted from impl methods."""
    parts: list[str] = []
    for p in fn.params:
        if p.name == "self":
            continue
        if p.type_expr is None:
            parts.append(p.name)
        else:
            parts.append(f"{p.name}: {_type_expr_to_text(p.type_expr)}")
    sig = "(" + ", ".join(parts) + ")"
    if fn.return_type is not None:
        sig += f" -> {_type_expr_to_text(fn.return_type)}"
    return sig


def _type_expr_to_text(t: A.TypeExpr) -> str:
    """Best-effort, single-line render of a ``TypeExpr``."""
    if isinstance(t, A.TypeName):
        if t.args:
            inner = ", ".join(_type_expr_to_text(a) for a in t.args)
            return f"{t.name}<{inner}>"
        return t.name
    if isinstance(t, A.FunType):
        params = ", ".join(_type_expr_to_text(p) for p in t.param_types)
        return f"Fun({params}) -> {_type_expr_to_text(t.return_type)}"
    if isinstance(t, A.TupleType):
        if not t.elements:
            return "()"
        if len(t.elements) == 1:
            return f"({_type_expr_to_text(t.elements[0])},)"
        return "(" + ", ".join(_type_expr_to_text(e) for e in t.elements) + ")"
    if isinstance(t, A.UnitType):
        return "()"
    return "?"
