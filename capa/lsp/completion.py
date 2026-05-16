"""``textDocument/completion`` implementation.

v1 has two paths:

* **Method context** (``receiver.<cursor>``): the receiver's
  type is resolved through the AST and only its methods are
  offered. No keyword / built-in noise.
* **General context** (anywhere else): a floor of keywords +
  built-in types, capabilities, variants, and functions is
  always returned; module-level names and function-scope
  locals are appended when the buffer parses cleanly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .. import capa_ast as A
from ..analyzer import AnalysisResult, Symbol, SymbolKind, analyze
from ..errors import LexerError
from ..lexer import Lexer
from ..parser import Parser, ParserError
from ..tokens import KEYWORDS
from ..typesys import TyFun, TyName, ty_str
from .context import LspContext, walk


# Built-in names users routinely complete to. Curated rather
# than scraped from the runtime so the completion list stays
# small and high-signal.
_BUILTIN_TYPES = [
    "Int", "Float", "Bool", "String", "Char", "Unit",
    "List", "Option", "Result", "Map", "Set", "Fun", "JsonValue",
    "IoError",
]
_BUILTIN_CAPABILITIES = [
    "Stdio", "Fs", "Net", "Env", "Clock", "Random", "Unsafe",
]
_BUILTIN_VARIANTS = ["Some", "None", "Ok", "Err"]
_BUILTIN_FUNCTIONS = [
    "parse_int", "parse_float", "to_int", "to_float",
    "new_map", "new_set", "parse_json", "to_json",
    "py_import", "py_invoke",
]


@dataclass
class Completion:
    """One entry in the completion list. ``kind`` tags map to
    ``lsp.CompletionItemKind`` in the server handler."""
    label: str
    kind: str       # see _to_completion_kind in server.py
    detail: str = ""
    insert_text: Optional[str] = None


def compute_completions(
    source: str, filename: str, line: int, col: int,
) -> list[Completion]:
    """Return the completion list at the cursor position."""
    dot = _scan_dot_context(source, line, col)
    if dot is not None:
        dot_line, dot_col = dot
        parsed = _parse_with_method_placeholder(source, filename, line, col)
        if parsed is None:
            return []
        module, result = parsed
        sym = _resolve_receiver_type(module, result, dot_line, dot_col)
        if sym is None:
            return []
        return _method_completions(sym)

    completions = _floor_completions()
    ctx = LspContext.parse(source, filename)
    if ctx is None:
        return completions
    completions.extend(_module_completions(ctx.module, ctx.result))
    completions.extend(
        _local_completions(ctx.module, ctx.result, line, col)
    )

    # De-dup by label (a user binding shadowing a built-in
    # collapses to one entry, the later, richer one).
    by_label: dict[str, Completion] = {}
    for c in completions:
        by_label[c.label] = c
    return list(by_label.values())


# ---------------------------------------------------------------
# General context: floor + module + locals
# ---------------------------------------------------------------


def _floor_completions() -> list[Completion]:
    """Keywords + curated built-ins. Always present so the
    suggestion list never goes dark on a half-typed line."""
    out: list[Completion] = []
    for kw in KEYWORDS:
        out.append(Completion(label=kw, kind="keyword"))
    for name in _BUILTIN_CAPABILITIES:
        out.append(Completion(
            label=name, kind="capability",
            detail="built-in capability",
        ))
    for name in _BUILTIN_TYPES:
        out.append(Completion(
            label=name, kind="type", detail="built-in type",
        ))
    for name in _BUILTIN_VARIANTS:
        out.append(Completion(
            label=name, kind="variant", detail="built-in variant",
        ))
    for name in _BUILTIN_FUNCTIONS:
        out.append(Completion(
            label=name, kind="function", detail="built-in",
        ))
    return out


def _module_completions(
    module: A.Module, result: AnalysisResult,
) -> list[Completion]:
    """Top-level names from the analyzed module. When the module is
    the linker output, mangled private items
    (``_capa_m<N>__<name>``) are skipped so the suggestion list
    only carries the names the importer's source actually has
    access to.
    """
    out: list[Completion] = []
    floor_labels = {c.label for c in _floor_completions()}
    for name, sym in result.global_symbols.items():
        if name in floor_labels:
            continue
        if name.startswith("_capa_m") and "__" in name:
            # Mangled private from an imported module; the
            # importer can't reach it by name and it should not
            # appear in completions.
            continue
        if sym.kind == SymbolKind.FUNCTION:
            detail = ""
            if isinstance(sym.ty, TyFun) and sym.param_names:
                params = ", ".join(
                    f"{pn}: {ty_str(pt)}"
                    for pn, pt in zip(sym.param_names, sym.ty.params)
                )
                detail = f"fun({params}) -> {ty_str(sym.ty.ret)}"
            out.append(Completion(label=name, kind="function", detail=detail))
        elif sym.kind == SymbolKind.CONSTANT:
            detail = ty_str(sym.ty) if sym.ty else ""
            out.append(Completion(label=name, kind="constant", detail=detail))
        elif sym.kind == SymbolKind.TYPE_STRUCT:
            out.append(Completion(label=name, kind="type", detail="struct"))
        elif sym.kind == SymbolKind.TYPE_SUM:
            out.append(Completion(label=name, kind="type", detail="sum"))
            for vname in sym.sum_variants.keys():
                out.append(Completion(
                    label=vname, kind="variant",
                    detail=f"variant of {name}",
                ))
        elif sym.kind == SymbolKind.CAPABILITY:
            out.append(Completion(
                label=name, kind="capability",
                detail="user-defined capability",
            ))
        elif sym.kind == SymbolKind.TRAIT:
            out.append(Completion(label=name, kind="type", detail="trait"))
    return out


def _local_completions(
    module: A.Module, result: AnalysisResult, line: int, col: int,
) -> list[Completion]:
    """Parameters and let / var bindings visible at the cursor."""
    out: list[Completion] = []
    seen: set[str] = set()

    def collect_from(fn: A.FunDecl) -> None:
        if not _fundecl_contains_line(fn, line):
            return
        for p in fn.params:
            if p.name == "self" or p.name.startswith("_"):
                continue
            if p.name in seen:
                continue
            seen.add(p.name)
            detail = ""
            if p.type_expr is not None:
                detail = _type_expr_text(p.type_expr)
            out.append(Completion(label=p.name, kind="value", detail=detail))
        for n in walk(fn.body):
            if isinstance(n, A.LetStmt):
                pat = n.pattern
                if isinstance(pat, A.IdentPat):
                    if pat.pos.line < line and pat.name not in seen:
                        seen.add(pat.name)
                        ty = result.types.get(id(n.value))
                        detail = ty_str(ty) if ty is not None else ""
                        out.append(Completion(
                            label=pat.name, kind="value", detail=detail,
                        ))
            elif isinstance(n, A.VarStmt):
                if n.pos.line < line and n.name not in seen:
                    seen.add(n.name)
                    ty = result.types.get(id(n.value))
                    detail = ty_str(ty) if ty is not None else ""
                    out.append(Completion(
                        label=n.name, kind="value", detail=detail,
                    ))

    for item in module.items:
        if isinstance(item, A.FunDecl):
            collect_from(item)
        elif isinstance(item, A.ImplBlock):
            for m in item.methods:
                collect_from(m)
    return out


def _fundecl_contains_line(fn: A.FunDecl, line: int) -> bool:
    """The cursor is inside this function if the body's last
    statement (plus a 10-line slack) covers it. Without end
    positions on FunDecl, this is the cheapest reasonable check."""
    if fn.pos.line > line:
        return False
    last_line = fn.pos.line
    for stmt in fn.body.stmts:
        if stmt.pos.line > last_line:
            last_line = stmt.pos.line
    return line <= last_line + 10


def _type_expr_text(t: A.TypeExpr) -> str:
    """Compact single-line render of a TypeExpr for the detail
    column. (Duplicated from document_symbols intentionally to
    keep the modules independent.)"""
    if isinstance(t, A.TypeName):
        if t.args:
            inner = ", ".join(_type_expr_text(a) for a in t.args)
            return f"{t.name}<{inner}>"
        return t.name
    if isinstance(t, A.FunType):
        params = ", ".join(_type_expr_text(p) for p in t.param_types)
        return f"Fun({params}) -> {_type_expr_text(t.return_type)}"
    if isinstance(t, A.TupleType):
        if not t.elements:
            return "()"
        if len(t.elements) == 1:
            return f"({_type_expr_text(t.elements[0])},)"
        return "(" + ", ".join(_type_expr_text(e) for e in t.elements) + ")"
    if isinstance(t, A.UnitType):
        return "()"
    return "?"


# ---------------------------------------------------------------
# Method context: ``receiver.<cursor>``
# ---------------------------------------------------------------


_PLACEHOLDER = "__CAPA_COMPL__"


def _scan_dot_context(
    source: str, line: int, col: int,
) -> Optional[tuple[int, int]]:
    """If the cursor sits in a ``<receiver>.<partial><cursor>``
    shape, return the (1-based) source position of the ``.``.
    Operates purely on text so it works on mid-edit buffers."""
    lines = source.split("\n")
    if line < 1 or line > len(lines):
        return None
    text = lines[line - 1]
    idx = min(col - 1, len(text))

    # Skip the partial method name under the cursor.
    while idx > 0 and (text[idx - 1].isalnum() or text[idx - 1] == "_"):
        idx -= 1

    # The previous char must be a dot.
    if idx == 0 or text[idx - 1] != ".":
        return None
    return line, idx  # 1-based; ``text[idx - 1]`` is the dot


def _parse_with_method_placeholder(
    source: str, filename: str, line: int, col: int,
) -> Optional[tuple[A.Module, AnalysisResult]]:
    """Try parsing the buffer twice: as-is first, and on failure
    with a synthetic identifier inserted at the cursor so a
    trailing ``stdio.`` still produces a FieldAccess. Returns
    ``None`` if both attempts fail."""
    try:
        tokens = Lexer(source, filename=filename).lex()
        module = Parser(tokens, source=source, filename=filename).parse_module()
        result = analyze(module, source=source, filename=filename)
        return module, result
    except (LexerError, ParserError):
        pass

    lines = source.split("\n")
    if line < 1 or line > len(lines):
        return None
    target = lines[line - 1]
    idx = min(col - 1, len(target))
    patched_line = target[:idx] + _PLACEHOLDER + target[idx:]
    patched_lines = list(lines)
    patched_lines[line - 1] = patched_line
    patched = "\n".join(patched_lines)

    try:
        tokens = Lexer(patched, filename=filename).lex()
        module = Parser(tokens, source=patched, filename=filename).parse_module()
        result = analyze(module, source=patched, filename=filename)
        return module, result
    except (LexerError, ParserError):
        return None


def _resolve_receiver_type(
    module: A.Module, result: AnalysisResult,
    dot_line: int, dot_col: int,
) -> Optional[Symbol]:
    """Find the type Symbol whose methods should be offered for
    the FieldAccess / MethodCall at the dot's position."""
    best: Optional[A.Expr] = None

    for n in walk(module):
        if not isinstance(n, (A.FieldAccess, A.MethodCall)):
            continue
        if n.pos.line != dot_line or n.pos.col > dot_col:
            continue
        # Deepest match wins (latest in walk order, same line,
        # column at or before the dot).
        best = n.receiver

    if best is None:
        return None
    ty = result.types.get(id(best))
    if isinstance(ty, TyName):
        sym = result.global_symbols.get(ty.name)
        if sym is not None and sym.methods:
            return sym
    return None


def _method_completions(method_sym: Symbol) -> list[Completion]:
    """Render the methods of a type as completion entries."""
    out: list[Completion] = []
    for mname, m in method_sym.methods.items():
        if mname.startswith("_"):
            continue
        detail = ""
        if isinstance(m.ty, TyFun):
            param_names = m.param_names or [
                f"arg{i + 1}" for i in range(len(m.ty.params))
            ]
            params = ", ".join(
                f"{pn}: {ty_str(pt)}"
                for pn, pt in zip(param_names, m.ty.params)
            )
            detail = f"({params}) -> {ty_str(m.ty.ret)}"
        out.append(Completion(label=mname, kind="function", detail=detail))
    return out
