"""capa/lsp_server.py, Language Server Protocol implementation.

A minimal Capa language server. v1 ships:

- ``textDocument/publishDiagnostics`` on every ``didOpen`` /
  ``didChange`` / ``didSave``, computed by re-running the full
  lexer + parser + analyzer pipeline on the buffer.
- ``textDocument/hover`` for identifiers: shows the symbol's
  signature and inferred type, rendered as Markdown.
- ``textDocument/definition`` for identifiers: jumps to the
  position where the symbol was declared. Built-in symbols
  (``Stdio``, ``Net``, ``Result``, etc.) cleanly return no
  location because they have no source origin.
- ``textDocument/references`` for identifiers: lists every use
  of the same symbol in the file, optionally including the
  declaration itself (controlled by the LSP request's
  ``includeDeclaration`` flag).
- ``textDocument/documentSymbol``: hierarchical outline of the
  module: constants, types (structs and sum types) with their
  fields and variants nested, traits and capabilities with their
  method signatures nested, top-level functions, and impl blocks
  with their methods nested. Powers the editor's outline view,
  breadcrumbs, and symbol search.
- ``textDocument/codeAction``: Quick Fixes that apply
  ``did you mean 'X'?`` suggestions emitted by the analyzer.
  For every diagnostic whose message ends in
  ``; did you mean 'SUGGESTION'?``, the server returns a Quick
  Fix that replaces the typo with the suggested name. The fix
  range is computed from the source line (the diagnostic's
  position is approximate for some error families, like
  method/field typos, so we search the line for the misspelled
  token).
- ``textDocument/rename`` (and ``prepareRename``): renames the
  symbol under the cursor by editing every reference and the
  declaration. Builds directly on ``compute_references``. The
  new name is validated as a Capa identifier (must match the
  lexer's IDENT pattern and not be a reserved keyword). Refuses
  to rename built-in symbols (``Stdio``, ``Net``, ``Result``,
  ...) cleanly.
- ``textDocument/completion``: keyword + identifier completion
  at the cursor. v1 offers Capa keywords, built-in type and
  capability names, common variant constructors (`Some`,
  `None`, `Ok`, `Err`), and every name declared at module
  level. Mid-edit buffers that fail to parse fall back to just
  keywords and built-ins (so the suggestion list never goes
  dark on a half-typed line). After a ``.`` the list narrows
  to methods of the receiver's type (with full signatures).
- ``textDocument/semanticTokens/full``: type-aware highlighting
  beyond what the TextMate grammar can do. Functions,
  parameters, variables, capabilities (with a ``defaultLibrary``
  modifier on the built-ins like ``Stdio``), types, sum-type
  variants, and constants are coloured distinctly. Both
  reference and declaration sites are tagged.

Runtime entry points:

``serve()``
    Block on stdio, reading LSP requests from stdin and writing
    responses to stdout. Used by ``python -m capa lsp``.

The ``pygls`` package is imported lazily so the rest of the
compiler never has to depend on it; ``--check`` and friends
continue to work in a stock-Python environment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from . import __version__ as _CAPA_VERSION
from . import capa_ast as A
from .analyzer import AnalysisResult, Symbol, SymbolKind, analyze
from .errors import LexerError
from .lexer import Lexer
from .parser import Parser, ParserError
from .tokens import KEYWORDS, Pos
from .typesys import Ty, TyFun, TyName, ty_str

if TYPE_CHECKING:  # only for type hints; runtime import is lazy
    from lsprotocol import types as lsp


_SERVER_NAME = "capa-lsp"


# ---------------------------------------------------------------
# Position translation
# ---------------------------------------------------------------
# Capa positions are 1-based (line and column). LSP positions are
# 0-based and use UTF-16 code units for the column. Because v1
# Capa is mostly ASCII source, treating the column as a UTF-8
# byte offset and then subtracting 1 is faithful enough; non-ASCII
# strings inside source still position correctly because the
# parser tracks columns by character.


def _to_lsp_position(pos: Pos) -> "lsp.Position":
    from lsprotocol import types as lsp
    return lsp.Position(line=max(pos.line - 1, 0), character=max(pos.col - 1, 0))


def _to_lsp_range(pos: Pos, end_pos: Pos | None = None) -> "lsp.Range":
    """Build a one-character-wide range when only ``pos`` is
    available, or a precise start-to-end range when both are.

    The Capa errors carry only a single position today; the
    one-character range is enough for editors to underline the
    starting token, which matches what the CLI's caret does.
    """
    from lsprotocol import types as lsp
    start = _to_lsp_position(pos)
    if end_pos is None:
        end = lsp.Position(line=start.line, character=start.character + 1)
    else:
        end = _to_lsp_position(end_pos)
    return lsp.Range(start=start, end=end)


# ---------------------------------------------------------------
# Diagnostic computation
# ---------------------------------------------------------------


def compute_diagnostics(source: str, filename: str) -> "list[lsp.Diagnostic]":
    """Run the full pipeline and return one LSP diagnostic per
    error found. A clean buffer returns an empty list.

    Errors from the lexer and parser are eager (they short-circuit
    the pipeline); analyzer errors are collected and returned
    together.
    """
    from lsprotocol import types as lsp

    diagnostics: list[lsp.Diagnostic] = []

    # Lexer.
    try:
        tokens = Lexer(source, filename=filename).lex()
    except LexerError as e:
        diagnostics.append(
            lsp.Diagnostic(
                range=_to_lsp_range(e.pos) if e.pos else _to_lsp_range(
                    Pos(line=1, col=1, offset=0)
                ),
                severity=lsp.DiagnosticSeverity.Error,
                source=_SERVER_NAME,
                message=e.message,
            )
        )
        return diagnostics

    # Parser.
    try:
        module = Parser(tokens, source=source, filename=filename).parse_module()
    except ParserError as e:
        diagnostics.append(
            lsp.Diagnostic(
                range=_to_lsp_range(e.pos) if e.pos else _to_lsp_range(
                    Pos(line=1, col=1, offset=0)
                ),
                severity=lsp.DiagnosticSeverity.Error,
                source=_SERVER_NAME,
                message=e.message,
            )
        )
        return diagnostics

    # Analyzer.
    result = analyze(module, source=source, filename=filename)
    for err in result.errors:
        diagnostics.append(
            lsp.Diagnostic(
                range=_to_lsp_range(err.pos),
                severity=lsp.DiagnosticSeverity.Error,
                source=_SERVER_NAME,
                message=err.message,
            )
        )
    return diagnostics


# ---------------------------------------------------------------
# Hover support
# ---------------------------------------------------------------
# Hover answers ``what is this symbol?`` for the identifier under
# the cursor. We compute it by:
#
#   1. Re-running the pipeline (cheap; analyse is sub-100ms on
#      every example file in the repo).
#   2. Walking the parsed Module to collect ``Ident`` nodes with
#      their source span (line + col_start..col_end).
#   3. Picking the one whose span covers the cursor position.
#   4. Looking up that Ident in ``AnalysisResult.bindings`` to
#      reach the Symbol, then formatting the Symbol's kind and
#      type as Markdown.
#
# Coverage is intentionally limited to ``Ident`` nodes in v1; the
# parser does not record end positions for non-leaf expressions,
# so hovering on, say, the middle of a struct literal would need
# more bookkeeping than the value justifies right now.


def _walk(node) -> "list":
    """Yield every AST node reachable from ``node`` via dataclass
    fields. Order is deterministic; not breadth-first vs
    depth-first matters less than reaching everything."""
    if isinstance(node, A.Node):
        yield node
        for f in node.__dataclass_fields__.values():
            yield from _walk(getattr(node, f.name))
    elif isinstance(node, (list, tuple)):
        for x in node:
            yield from _walk(x)
    # Strings, ints, None, etc. are leaves and not interesting.


def collect_idents(module: A.Module) -> list[A.Ident]:
    """All ``Ident`` nodes in the module, in walk order."""
    return [n for n in _walk(module) if isinstance(n, A.Ident)]


# Declaration-site enumeration: the parser now records the
# IDENT-token position for each declared name (``name_pos`` field).
# We wrap each declaration as a synthetic ``A.Ident`` so the same
# find-by-position / Symbol-lookup pipeline works on declarations.
#
# Each entry carries a ``decl_kind`` tag the caller uses to find
# the symbol: ``global`` for items registered in the module's
# global scope (functions, types, traits, capabilities, constants),
# ``param`` for function parameters (resolved against the function's
# local scope, but we can locate the symbol generically from the
# bindings map by matching name+pos), ``variant`` for sum-type
# variants, ``field`` for struct fields (which are not separate
# symbols but project into the struct's ``struct_fields`` dict),
# ``method_sig`` for trait/capability method signatures.


@dataclass
class _DeclSite:
    """Synthetic identifier at a declaration site."""
    ident: A.Ident                  # name + name_pos as an Ident
    decl_kind: str                  # "global", "param", "variant", "field", "method_sig"
    container_name: Optional[str] = None  # struct for fields, sum for variants, trait for methods


def collect_decl_sites(module: A.Module) -> list[_DeclSite]:
    """Walk the module and yield a ``_DeclSite`` for every named
    declaration whose name position the parser has recorded.

    Older AST nodes (or synthetic AST built in tests) may have
    ``name_pos = None``; those are skipped silently so the LSP
    machinery degrades gracefully rather than crashing.
    """
    sites: list[_DeclSite] = []

    def maybe(name: str, pos: Optional[Pos], kind: str, container: Optional[str] = None) -> None:
        if pos is None:
            return
        sites.append(
            _DeclSite(
                ident=A.Ident(pos=pos, name=name),
                decl_kind=kind,
                container_name=container,
            )
        )

    for item in module.items:
        if isinstance(item, A.ConstDecl):
            maybe(item.name, item.name_pos, "global")
        elif isinstance(item, A.TypeStruct):
            maybe(item.name, item.name_pos, "global")
            for f in item.fields:
                maybe(f.name, f.name_pos, "field", container=item.name)
        elif isinstance(item, A.TypeSum):
            maybe(item.name, item.name_pos, "global")
            for v in item.variants:
                maybe(v.name, v.name_pos, "variant")
        elif isinstance(item, A.TraitDecl):
            maybe(item.name, item.name_pos, "global")
            for m in item.methods:
                maybe(m.name, m.name_pos, "method_sig", container=item.name)
        elif isinstance(item, A.FunDecl):
            maybe(item.name, item.name_pos, "global")
            for p in item.params:
                if p.name != "self":
                    maybe(p.name, p.name_pos, "param", container=item.name)
        elif isinstance(item, A.ImplBlock):
            for m in item.methods:
                maybe(m.name, m.name_pos, "global", container=item.type_name)
                for p in m.params:
                    if p.name != "self":
                        maybe(p.name, p.name_pos, "param", container=m.name)

    return sites


def find_decl_site_at(
    sites: list[_DeclSite], line: int, col: int,
) -> Optional[_DeclSite]:
    """Like ``find_ident_at`` but for the declaration list."""
    for s in sites:
        if s.ident.pos.line != line:
            continue
        col_start = s.ident.pos.col
        col_end = col_start + len(s.ident.name)
        if col_start <= col < col_end:
            return s
    return None


def find_ident_at(
    idents: list[A.Ident], line: int, col: int,
) -> Optional[A.Ident]:
    """Return the ``Ident`` whose source span covers the (1-based)
    cursor position, if any. ``line`` and ``col`` are 1-based to
    match Capa's internal Pos convention; the LSP server converts
    the 0-based wire values before calling this function.

    Identifiers cannot overlap, so on a match the first hit is
    the right answer.
    """
    for ident in idents:
        if ident.pos.line != line:
            continue
        col_start = ident.pos.col
        col_end = col_start + len(ident.name)
        if col_start <= col < col_end:
            return ident
    return None


def _format_symbol_for_hover(
    sym: Symbol, ident_ty: Optional[Ty],
) -> str:
    """Render a Capa Symbol as the Markdown body of a hover
    response. Falls back to a generic ``name: T`` shape when the
    Symbol kind has no specialised rendering.

    ``ident_ty`` is the inferred type recorded for the Ident
    itself (from ``AnalysisResult.types``); it can be more
    specific than ``sym.ty`` when type inference filled in a
    generic. When available, prefer it for the display.
    """
    name = sym.name
    if sym.kind == SymbolKind.FUNCTION and isinstance(sym.ty, TyFun):
        # Render as a Capa-style signature, parameter names when
        # known, types from the TyFun.
        param_names = sym.param_names or [
            f"arg{i + 1}" for i in range(len(sym.ty.params))
        ]
        params = ", ".join(
            f"{pn}: {ty_str(pt)}"
            for pn, pt in zip(param_names, sym.ty.params)
        )
        return f"```capa\nfun {name}({params}) -> {ty_str(sym.ty.ret)}\n```"
    if sym.kind == SymbolKind.PARAM:
        ty = ident_ty if ident_ty is not None else sym.ty
        if ty is not None:
            return (
                f"```capa\n{name}: {ty_str(ty)}\n```"
                f"\n\n*parameter*"
            )
        return f"`{name}` (parameter)"
    if sym.kind in (SymbolKind.LOCAL_VAR, SymbolKind.LOCAL):
        ty = ident_ty if ident_ty is not None else sym.ty
        kind_label = (
            "mutable variable" if sym.kind == SymbolKind.LOCAL_VAR
            else "binding"
        )
        if ty is not None:
            return (
                f"```capa\n{name}: {ty_str(ty)}\n```"
                f"\n\n*{kind_label}*"
            )
        return f"`{name}` ({kind_label})"
    if sym.kind == SymbolKind.CONSTANT:
        ty = sym.ty
        head = "const " + name
        if ty is not None:
            head += f": {ty_str(ty)}"
        return f"```capa\n{head}\n```\n\n*constant*"
    if sym.kind == SymbolKind.VARIANT:
        owner = sym.variant_owner.name if sym.variant_owner else "?"
        head = name
        if sym.variant_payload_ty is not None:
            head += f"({ty_str(sym.variant_payload_ty)})"
        return (
            f"```capa\n{head}\n```"
            f"\n\n*variant of `{owner}`*"
        )
    if sym.kind == SymbolKind.CAPABILITY:
        return (
            f"```capa\ncapability {name}\n```"
            f"\n\n*user-defined capability*"
        )
    if sym.kind in (SymbolKind.TYPE_STRUCT, SymbolKind.TYPE_SUM):
        kind = "struct" if sym.kind == SymbolKind.TYPE_STRUCT else "sum type"
        return f"```capa\ntype {name}\n```\n\n*{kind}*"
    # Fallback.
    if sym.ty is not None:
        return f"```capa\n{name}: {ty_str(sym.ty)}\n```"
    return f"`{name}`"


def _resolve_decl_symbol(
    site: _DeclSite, result: AnalysisResult, module: A.Module,
) -> Optional[Symbol]:
    """Find the Symbol for a declaration site.

    Global declarations (functions, types, traits, capabilities,
    constants, impl-method names) live in
    ``result.global_symbols``. Variants live nested inside their
    owning sum type's ``sum_variants``. Method signatures inside
    a trait/capability sit on the parent's ``methods`` dict.
    Parameters and struct fields do not have first-class Symbols
    in the analyzer's current model; they resolve to the first
    parameter or field with a matching name on the containing
    declaration, surfaced as a synthetic Symbol so the caller's
    rendering code keeps working.
    """
    if site.decl_kind == "global":
        # Top-level item or impl method.
        if site.container_name is None:
            return result.global_symbols.get(site.ident.name)
        # Impl method: look it up on the target type's methods.
        owner = result.global_symbols.get(site.container_name)
        if owner is None:
            return None
        return owner.methods.get(site.ident.name)
    if site.decl_kind == "variant":
        for s in result.global_symbols.values():
            if s.kind == SymbolKind.TYPE_SUM:
                v = s.sum_variants.get(site.ident.name)
                if v is not None:
                    return v
        return None
    if site.decl_kind == "method_sig":
        # Trait method signature. The trait/capability has the
        # signature in trait_method_sigs (a TyFun), but not as a
        # Symbol. We synthesise one carrying the TyFun.
        if site.container_name is None:
            return None
        owner = result.global_symbols.get(site.container_name)
        if owner is None:
            return None
        ty = owner.trait_method_sigs.get(site.ident.name)
        if ty is None:
            return None
        return Symbol(
            name=site.ident.name,
            kind=SymbolKind.FUNCTION,
            pos=site.ident.pos,
            ty=ty,
        )
    if site.decl_kind == "field":
        if site.container_name is None:
            return None
        owner = result.global_symbols.get(site.container_name)
        if owner is None:
            return None
        fty = owner.struct_fields.get(site.ident.name)
        if fty is None:
            return None
        # Fields are not first-class Symbols in the analyzer; we
        # wrap them as a synthetic Symbol with kind=LOCAL so the
        # hover renderer prints ``name: T`` plus a kind label.
        return Symbol(
            name=site.ident.name,
            kind=SymbolKind.LOCAL,
            pos=site.ident.pos,
            ty=fty,
        )
    if site.decl_kind == "param":
        # Find any binding inside the containing function's body
        # that resolves to a param with this name. We scan
        # bindings.values() because params are scoped locally and
        # the analyzer does not expose function-local scopes on
        # the result.
        if site.container_name is None:
            return None
        # Locate the function so we can scan only its body.
        target_fn = _find_fundecl(module, site.container_name)
        if target_fn is None:
            return None
        body_idents = [
            n for n in _walk(target_fn.body) if isinstance(n, A.Ident)
        ]
        for ident in body_idents:
            sym = result.bindings.get(id(ident))
            if (
                sym is not None
                and sym.kind == SymbolKind.PARAM
                and sym.name == site.ident.name
            ):
                return sym
        # Param exists in the parameter list but is unused inside
        # the body. Synthesise a stand-in so hover still works.
        for p in target_fn.params:
            if p.name == site.ident.name and p.type_expr is not None:
                return Symbol(
                    name=p.name,
                    kind=SymbolKind.PARAM,
                    pos=site.ident.pos,
                )
        return None
    return None


def _find_fundecl(
    module: A.Module, name: str,
) -> Optional[A.FunDecl]:
    """Locate a FunDecl by name across top-level items and impl
    blocks. Returns the first match; method names are not unique
    across impls but the LSP use cases only care about which
    function-scope to search."""
    for item in module.items:
        if isinstance(item, A.FunDecl) and item.name == name:
            return item
        if isinstance(item, A.ImplBlock):
            for m in item.methods:
                if m.name == name:
                    return m
    return None


def compute_hover(
    source: str, filename: str, line: int, col: int,
) -> Optional[tuple[str, A.Ident]]:
    """Compute the hover content (Markdown) and the source range
    to highlight when the cursor sits at the 1-based
    ``(line, col)`` position. Returns ``None`` when the position
    is not inside a recognised identifier or the analyzer has no
    binding to report (the file may have parse errors).

    The returned tuple is ``(markdown, ident)``: the ident is
    surfaced so the caller can build an LSP range from its span.
    """
    try:
        tokens = Lexer(source, filename=filename).lex()
        module = Parser(tokens, source=source, filename=filename).parse_module()
    except (LexerError, ParserError):
        return None

    result = analyze(module, source=source, filename=filename)
    # 1) Try a reference Ident at the cursor.
    ident = find_ident_at(collect_idents(module), line, col)
    if ident is not None:
        sym = result.bindings.get(id(ident))
        if sym is not None:
            ident_ty = result.types.get(id(ident))
            return _format_symbol_for_hover(sym, ident_ty), ident
    # 2) Fall back to a declaration site.
    site = find_decl_site_at(collect_decl_sites(module), line, col)
    if site is not None:
        sym = _resolve_decl_symbol(site, result, module)
        if sym is not None:
            return _format_symbol_for_hover(sym, None), site.ident
    return None


def compute_definition(
    source: str, filename: str, line: int, col: int,
) -> Optional[Pos]:
    """Resolve the identifier at ``(line, col)`` to the source
    position where its symbol is declared.

    Returns ``None`` when:
    - the cursor is not on a recognised identifier;
    - the buffer has parse errors that block analysis;
    - the symbol has no resolved binding (e.g. typo at the
      cursor);
    - the symbol is a built-in (its declared position is the
      ``Pos(0, 0, 0)`` sentinel, which would jump the editor to
      the top of a non-existent file).

    Positions returned use Capa's 1-based convention; the caller
    converts to LSP's 0-based form.
    """
    try:
        tokens = Lexer(source, filename=filename).lex()
        module = Parser(tokens, source=source, filename=filename).parse_module()
    except (LexerError, ParserError):
        return None

    result = analyze(module, source=source, filename=filename)
    ident = find_ident_at(collect_idents(module), line, col)
    sym: Optional[Symbol] = None
    if ident is not None:
        sym = result.bindings.get(id(ident))
    if sym is None:
        site = find_decl_site_at(collect_decl_sites(module), line, col)
        if site is not None:
            sym = _resolve_decl_symbol(site, result, module)
            if sym is not None:
                # On a declaration site, "go to definition" is a
                # no-op: jump to the name itself. Use the site
                # position so the editor lands exactly on the
                # token even if Symbol.pos points at the start of
                # the enclosing construct (e.g. ``fun``).
                return site.ident.pos
    if sym is None:
        return None
    # Filter out built-in symbols (declared with line=0, col=0).
    if sym.pos.line == 0 and sym.pos.col == 0:
        return None
    return sym.pos


def compute_references(
    source: str, filename: str, line: int, col: int,
    *,
    include_declaration: bool = True,
) -> Optional[list[A.Ident]]:
    """Resolve the identifier at ``(line, col)`` and return every
    other identifier in the module that resolves to the same
    symbol.

    The result is a list of ``Ident`` AST nodes whose ``pos`` and
    ``name`` the caller uses to build LSP ranges. The list is
    ordered by source position (line, then column).

    ``include_declaration`` controls whether a synthetic
    declaration "reference" is added. When ``True``, and the
    declaring symbol has a real source position (not a built-in
    sentinel), the declaration line is included at the symbol's
    pos. The parser does not record name spans on declaration
    nodes, so the synthetic entry uses the symbol's name length
    (a close-enough approximation for editors that highlight or
    jump to the entry).

    Returns ``None`` when the cursor is not on an identifier or
    has no resolved binding.
    """
    try:
        tokens = Lexer(source, filename=filename).lex()
        module = Parser(tokens, source=source, filename=filename).parse_module()
    except (LexerError, ParserError):
        return None

    result = analyze(module, source=source, filename=filename)
    idents = collect_idents(module)
    decl_sites = collect_decl_sites(module)

    # The pivot can be either a reference Ident or a declaration
    # site. Either way we end up with a Symbol and the position
    # of the matching declaration's name.
    target_sym: Optional[Symbol] = None
    decl_name_pos: Optional[Pos] = None
    decl_name: Optional[str] = None

    pivot = find_ident_at(idents, line, col)
    if pivot is not None:
        target_sym = result.bindings.get(id(pivot))
        if target_sym is not None:
            # Find the matching decl_site (if any) so we can emit
            # the declaration entry at the precise name position.
            for s in decl_sites:
                cand = _resolve_decl_symbol(s, result, module)
                if cand is target_sym:
                    decl_name_pos = s.ident.pos
                    decl_name = s.ident.name
                    break

    if target_sym is None:
        site = find_decl_site_at(decl_sites, line, col)
        if site is not None:
            target_sym = _resolve_decl_symbol(site, result, module)
            if target_sym is not None:
                decl_name_pos = site.ident.pos
                decl_name = site.ident.name

    if target_sym is None:
        return None

    # Every Ident whose binding points at the same Symbol object.
    refs: list[A.Ident] = [
        ident for ident in idents
        if result.bindings.get(id(ident)) is target_sym
    ]

    if include_declaration and not (
        target_sym.pos.line == 0 and target_sym.pos.col == 0
    ):
        # Prefer the precise name_pos when we found one; fall back
        # to the symbol's recorded position otherwise.
        if decl_name_pos is not None and decl_name is not None:
            dpos = decl_name_pos
            dname = decl_name
        else:
            dpos = target_sym.pos
            dname = target_sym.name
        already_there = any(
            r.pos.line == dpos.line and r.pos.col == dpos.col
            for r in refs
        )
        if not already_there:
            refs.append(A.Ident(pos=dpos, name=dname))

    refs.sort(key=lambda i: (i.pos.line, i.pos.col))
    return refs


# ---------------------------------------------------------------
# Document symbols (outline)
# ---------------------------------------------------------------
# The LSP DocumentSymbol shape is a tree of (name, kind, range,
# children). We carry our own lightweight ``DocSymbol`` here so
# that the pure-function core can be tested without ``pygls`` or
# ``lsprotocol`` installed; the server handler converts each
# DocSymbol into an ``lsp.DocumentSymbol`` at the boundary.


# The ``kind`` field uses string tags that the handler maps to
# LSP's ``SymbolKind`` enum. The tag set is deliberately small
# and close to Capa's vocabulary, rather than overloading the
# enum names.
_LSP_KIND_TAGS = {
    "constant", "function", "struct", "sum", "field", "variant",
    "trait", "capability", "method", "impl",
}


@dataclass
class DocSymbol:
    name: str
    detail: str
    kind: str      # one of _LSP_KIND_TAGS
    pos: Pos
    children: list["DocSymbol"] = field(default_factory=list)


def _fun_detail(fn: A.FunDecl) -> str:
    """Render a Capa function signature for the outline detail
    column, omitting ``self`` from impl methods. Type annotations
    use the source text as captured by ``_ty_text`` where
    available, falling back to a simple node name."""
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
    """Best-effort, structural renderer of a TypeExpr to a single
    line. Used only for the outline ``detail`` field, so a faithful
    representation matters less than a readable one."""
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


def compute_document_symbols(
    source: str, filename: str,
) -> Optional[list[DocSymbol]]:
    """Walk a parsed module and return the outline as a list of
    ``DocSymbol`` trees, one per top-level item.

    Returns ``None`` only on lexer or parser failure (so the
    editor can render a sensible empty outline rather than a
    stale or guessed one). Items appear in source order.
    """
    try:
        tokens = Lexer(source, filename=filename).lex()
        module = Parser(tokens, source=source, filename=filename).parse_module()
    except (LexerError, ParserError):
        return None

    out: list[DocSymbol] = []
    for item in module.items:
        sym = _item_to_doc_symbol(item)
        if sym is not None:
            out.append(sym)
    return out


def _item_to_doc_symbol(item: A.Item) -> Optional[DocSymbol]:
    if isinstance(item, A.ConstDecl):
        detail = _type_expr_to_text(item.type_expr)
        return DocSymbol(
            name=item.name, detail=detail, kind="constant", pos=item.pos,
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
            name=item.name, detail="struct", kind="struct", pos=item.pos,
            children=children,
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
            name=item.name, detail="sum", kind="sum", pos=item.pos,
            children=children,
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
                    name=m.name,
                    detail=f"({params}){ret}",
                    kind="method", pos=m.pos,
                )
            )
        return DocSymbol(
            name=item.name, detail=kind, kind=kind, pos=item.pos,
            children=children,
        )
    if isinstance(item, A.FunDecl):
        return DocSymbol(
            name=item.name, detail=_fun_detail(item),
            kind="function", pos=item.pos,
        )
    if isinstance(item, A.ImplBlock):
        # The displayed name encodes the trait/cap and target,
        # mirroring how the source reads: ``impl SendEmail for SmtpMailer``.
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
            name=display_name, detail="", kind="impl", pos=item.pos,
            children=children,
        )
    # Imports etc. are not surfaced in the outline (single-file
    # projects today). Returning None drops them silently.
    return None


# ---------------------------------------------------------------
# Code actions: Quick Fix for "did you mean 'X'?" hints
# ---------------------------------------------------------------
# Five analyzer error families append `; did you mean 'X'?` to
# their message: undefined name, undefined type, no method on
# type, no field on struct, unknown variant. For each such
# diagnostic we want to offer a one-click Quick Fix that
# replaces the misspelled token with the suggestion.
#
# The diagnostic's position is the start of the *construct* the
# error belongs to (the receiver for a method call, the struct
# literal head for a field, ...), not necessarily the start of
# the misspelled token. We therefore extract the typo from the
# message itself (it is always the quoted string immediately
# preceding `; did you mean`) and search the source line for it.


# Pattern matches both the typo and the suggestion in one go.
# We use the last quoted string before `;` to find the typo,
# anchored on the literal `did you mean` suffix.
_DID_YOU_MEAN_RE = re.compile(
    r"'([^']+)'\s*;\s*did you mean '([^']+)'\?"
)


@dataclass
class CodeActionEdit:
    """A single text replacement, in 1-based Capa coordinates.
    The LSP handler converts to ``lsp.TextEdit`` at the
    boundary."""
    line: int
    col_start: int
    col_end: int
    new_text: str


@dataclass
class CodeAction:
    """A Quick Fix the server can offer for a diagnostic."""
    title: str
    edit: CodeActionEdit


def _find_token_column(line_text: str, token: str) -> Optional[int]:
    """Find the 1-based column where ``token`` appears on the
    given source line, matching it as a whole word so a typo
    like ``in`` does not pick up the ``in`` inside ``println``.

    Returns ``None`` when the token cannot be located, which
    happens when the source has been edited in the time between
    the diagnostic being computed and the code action being
    requested.
    """
    pattern = re.compile(r"\b" + re.escape(token) + r"\b")
    match = pattern.search(line_text)
    if match is None:
        return None
    return match.start() + 1  # convert to 1-based


def compute_code_actions(
    source: str, diagnostic_message: str, diagnostic_line: int,
) -> list[CodeAction]:
    """Return the Quick Fixes available for a single diagnostic.

    The diagnostic is identified only by its message and the line
    number it points at; we do not depend on the diagnostic's
    column being the start of the typo, since the analyzer
    sometimes emits errors against the enclosing construct
    instead of the offending token.

    Returns an empty list when the message has no
    ``did you mean 'X'?`` suffix or the typo cannot be located
    on the line.
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


# ---------------------------------------------------------------
# Rename
# ---------------------------------------------------------------
# Rename rewrites every reference + the declaration of the symbol
# under the cursor. The hard part is collecting the positions
# (already solved by compute_references with include_declaration);
# the rest is validating the new name and packing each position
# as a TextEdit covering the OLD name's span.
#
# The new name must satisfy the Capa identifier shape (matching
# the lexer: start with letter or underscore, continue with
# alphanumeric or underscore) and must not collide with a
# reserved keyword. Built-in symbols (Stdio, Net, Result, ...)
# refuse rename cleanly since their declarations live outside
# the source.


@dataclass
class RenameEdit:
    """A single position to rewrite. Line/col are 1-based; the
    LSP handler converts to 0-based before emitting the TextEdit."""
    line: int
    col_start: int
    col_end: int


@dataclass
class RenameResult:
    """Outcome of a rename request."""
    edits: list[RenameEdit] = field(default_factory=list)
    error: Optional[str] = None


def _is_valid_capa_identifier(name: str) -> bool:
    """Return True iff ``name`` matches the lexer's IDENT pattern
    and is not a reserved keyword. The lexer accepts identifiers
    that start with a letter or underscore and continue with
    alphanumerics or underscores, which ``str.isidentifier``
    captures faithfully for ASCII; Capa source is ASCII for
    identifiers in v1.
    """
    if not name:
        return False
    if not name.isidentifier():
        return False
    if name in KEYWORDS:
        return False
    return True


def compute_prepare_rename(
    source: str, filename: str, line: int, col: int,
) -> Optional[tuple[Pos, str]]:
    """Pre-flight check used by ``textDocument/prepareRename``:
    is the cursor on a renameable symbol?

    Returns ``(name_pos, name)`` describing the highlighted range
    when rename is possible. Returns ``None`` to signal "not
    renameable" (built-in, no symbol, parse error, ...).
    """
    try:
        tokens = Lexer(source, filename=filename).lex()
        module = Parser(tokens, source=source, filename=filename).parse_module()
    except (LexerError, ParserError):
        return None
    result = analyze(module, source=source, filename=filename)

    # Try a reference first.
    ident = find_ident_at(collect_idents(module), line, col)
    if ident is not None:
        sym = result.bindings.get(id(ident))
        if sym is not None and not (sym.pos.line == 0 and sym.pos.col == 0):
            return ident.pos, ident.name

    # Then a declaration site.
    site = find_decl_site_at(collect_decl_sites(module), line, col)
    if site is not None:
        sym = _resolve_decl_symbol(site, result, module)
        if sym is not None and not (sym.pos.line == 0 and sym.pos.col == 0):
            return site.ident.pos, site.ident.name

    return None


def compute_rename(
    source: str, filename: str, line: int, col: int, new_name: str,
) -> RenameResult:
    """Compute the set of edits needed to rename the symbol under
    the cursor to ``new_name``.

    Returns a ``RenameResult`` with either ``edits`` populated
    (success) or ``error`` set to a human-readable explanation
    (failure). The handler can render the error as an LSP
    ResponseError or surface it through the editor's notification
    channel; we keep the message readable rather than terse.
    """
    if not _is_valid_capa_identifier(new_name):
        return RenameResult(
            error=(
                f"{new_name!r} is not a valid Capa identifier; "
                f"identifiers start with a letter or underscore "
                f"and must not be a reserved keyword"
            ),
        )

    refs = compute_references(
        source, filename, line, col, include_declaration=True,
    )
    if refs is None:
        return RenameResult(
            error="no renameable symbol at the cursor position",
        )

    edits = [
        RenameEdit(
            line=r.pos.line,
            col_start=r.pos.col,
            col_end=r.pos.col + len(r.name),
        )
        for r in refs
    ]
    return RenameResult(edits=edits)


# ---------------------------------------------------------------
# Completion
# ---------------------------------------------------------------
# v1 completion is intentionally minimal: keywords + a curated
# set of built-in names + module-level identifiers when the
# buffer parses. The motivating constraint is that the user is
# typically mid-edit when completion fires, so the buffer rarely
# parses. We therefore split the answer into two layers:
#
#   1. A floor that always works (keywords + builtins), computed
#      without invoking lexer/parser/analyzer at all.
#   2. A "best effort" extension when the buffer parses cleanly
#      (top-level names from the analyzed module).
#
# Type-aware completion (method names after ``.``, field
# completion inside struct literals, variant completion in match
# arms) requires deeper integration with the analyzer's scope
# model and is a v2 deliverable. v1 still adds receiver-typed
# suggestions where the receiver is a simple in-scope identifier
# of a known type, because that case is cheap and covers the
# most common "stdio." / "list." invocations.


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
    LSP CompletionItemKind in the handler. ``detail`` is a
    short type or signature line shown next to the item."""
    label: str
    kind: str       # "keyword" | "type" | "capability" | "variant" | "function" | "constant" | "value"
    detail: str = ""
    insert_text: Optional[str] = None  # falls back to label


def _floor_completions() -> list[Completion]:
    """The keyword + built-in floor. Returned even when the
    buffer fails to parse, so users completing mid-edit always
    see something useful."""
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
    """Top-level names from the analyzed module: functions, types,
    traits, capabilities, constants, plus variants of any sum
    types declared in the file."""
    out: list[Completion] = []
    for name, sym in result.global_symbols.items():
        if name in {n.label for n in _floor_completions()}:
            continue  # avoid duplicating built-ins
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
            # Also surface each variant, since users often type the
            # variant name directly (e.g. ``Red`` rather than
            # ``Color::Red``).
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
    """Parameters and let/var bindings visible at ``(line, col)``.

    We use a syntactic approximation: a binding is "in scope"
    when its declaration's line precedes the cursor's line in the
    same function body. This is a deliberate simplification (no
    intra-block dead-zone analysis) that errs on the side of
    offering too much rather than too little; LSP clients fuzzy-
    rank by prefix anyway.
    """
    out: list[Completion] = []
    seen: set[str] = set()

    def collect_from(fn: A.FunDecl) -> None:
        # Only collect from the function that contains the cursor.
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
                detail = _type_expr_to_text(p.type_expr)
            out.append(Completion(label=p.name, kind="value", detail=detail))
        for n in _walk(fn.body):
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
    """Heuristic: the cursor is inside this function if the
    function's start position is at or before the line and the
    next top-level item starts after it. Without end positions
    on FunDecl, we approximate by checking the line range of the
    body's statements."""
    if fn.pos.line > line:
        return False
    # Inspect the body's last statement line, when available.
    last_line = fn.pos.line
    for stmt in fn.body.stmts:
        if stmt.pos.line > last_line:
            last_line = stmt.pos.line
    # Allow a generous slack (10 lines past the last seen stmt)
    # so cursors on freshly-opened blank lines still feel "inside".
    return line <= last_line + 10


def _scan_dot_context(
    source: str, line: int, col: int,
) -> Optional[tuple[int, int]]:
    """If the cursor sits in a ``<receiver>.<partial><cursor>``
    shape, return the (1-based) source position of the ``.``.
    Returns ``None`` otherwise. The receiver itself can be any
    expression (an identifier, a string literal, a parenthesised
    sub-expression, ...): the AST resolves it later.
    """
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
    return line, idx  # 1-based: ``text[idx - 1]`` is the dot


_PLACEHOLDER = "__CAPA_COMPL__"


def _parse_with_method_placeholder(
    source: str, filename: str, line: int, col: int,
) -> Optional[tuple[A.Module, AnalysisResult]]:
    """Try parsing the buffer twice: as-is first, and on failure
    with a synthetic identifier inserted at the cursor so a
    trailing ``stdio.`` still produces a FieldAccess in the AST.

    Returns the parsed module and analysis result on success, or
    ``None`` if both attempts fail (we then give up on smart
    completion and fall back to the keyword + built-in floor).
    """
    # Attempt 1: the buffer as-is.
    try:
        tokens = Lexer(source, filename=filename).lex()
        module = Parser(tokens, source=source, filename=filename).parse_module()
        result = analyze(module, source=source, filename=filename)
        return module, result
    except (LexerError, ParserError):
        pass

    # Attempt 2: inject the placeholder. The new buffer should
    # parse iff the only failure was the trailing ``.<eof>``-shape
    # at the cursor.
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
    the FieldAccess / MethodCall whose dot sits at
    ``(dot_line, dot_col)`` (both 1-based).

    The placeholder-parse pass should have produced an AST node
    that covers this dot. We walk the module looking for a
    FieldAccess or MethodCall whose receiver is the expression
    immediately preceding ``(dot_line, dot_col)``. The receiver's
    type comes from ``result.types``; the resulting TyName looks
    up the type Symbol in ``global_symbols``.
    """
    best: Optional[A.Expr] = None  # the receiver

    def consider(node: A.Expr, receiver: A.Expr) -> None:
        nonlocal best
        # The dot in ``recv.name`` sits AFTER the receiver. The
        # node's pos points at the receiver's start; we want the
        # one whose receiver end aligns with dot_col on dot_line.
        # We do not track end positions, so an approximation:
        # pick the FieldAccess/MethodCall whose pos is at or
        # before the dot AND on the same line. The deepest match
        # (latest in walk order) wins.
        if node.pos.line != dot_line:
            return
        if node.pos.col > dot_col:
            return
        best_local = receiver
        nonlocal best
        best = best_local

    for n in _walk(module):
        if isinstance(n, A.FieldAccess):
            consider(n, n.receiver)
        elif isinstance(n, A.MethodCall):
            consider(n, n.receiver)

    if best is None:
        return None
    ty = result.types.get(id(best))
    if isinstance(ty, TyName):
        sym = result.global_symbols.get(ty.name)
        if sym is not None and sym.methods:
            return sym
    return None


def _method_completions(method_sym: Symbol) -> list[Completion]:
    """Render a type's registered methods as Completion entries.
    The detail column carries the method's TyFun signature so
    editors show ``length() -> Int`` next to the name."""
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


def compute_completions(
    source: str, filename: str, line: int, col: int,
) -> list[Completion]:
    """Return the completion list at the cursor position.

    Two paths:

    * **Method context** (``receiver.<cursor>``): we resolve the
      receiver's type and return only its methods, with no floor
      noise. Mid-edit buffers are handled by re-parsing with a
      synthetic placeholder injected at the cursor.
    * **General context** (anywhere else): keywords + built-ins,
      plus, when the buffer parses cleanly, top-level names and
      approximate locals.
    """
    # Detect method-context first; if we hit a dot, we never want
    # to mix in keyword/builtin noise.
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
    try:
        tokens = Lexer(source, filename=filename).lex()
        module = Parser(tokens, source=source, filename=filename).parse_module()
    except (LexerError, ParserError):
        return completions
    result = analyze(module, source=source, filename=filename)
    completions.extend(_module_completions(module, result))
    completions.extend(_local_completions(module, result, line, col))

    # De-duplicate by label (later entries with richer detail win
    # over earlier floor entries when names collide, e.g. a
    # built-in shadowed by a user binding of the same name).
    by_label: dict[str, Completion] = {}
    for c in completions:
        by_label[c.label] = c
    return list(by_label.values())


# ---------------------------------------------------------------
# Semantic tokens
# ---------------------------------------------------------------
# LSP semantic tokens deliver type-aware highlighting on top of
# what a static TextMate grammar can do. The protocol uses a
# server-defined legend (an ordered list of token types and
# modifiers) and a single flat array of five-integer tuples per
# token, with deltas relative to the previous token's position.
#
# Our legend is small and Capa-flavoured: we want capabilities
# coloured distinctly from regular types (the whole point of the
# language is that capabilities are special), and we want
# built-in capabilities marked so editor themes can render them
# with a different intensity than user-defined ones.


_SEM_TOKEN_TYPES: list[str] = [
    "function",     # 0
    "parameter",    # 1
    "variable",     # 2
    "interface",    # 3  (LSP-standard name we use for "capability")
    "type",         # 4  (structs, sums, traits)
    "enumMember",   # 5  (sum-type variants)
    "property",     # 6  (struct fields)
]

_SEM_TOKEN_MODIFIERS: list[str] = [
    "defaultLibrary",   # bit 0: built-ins (Stdio, Some, ...)
    "declaration",      # bit 1: this token is the declaration site
    "readonly",         # bit 2: let bindings, constants
]


def _sem_modifiers_bitmask(modifiers: set[str]) -> int:
    """Encode a set of modifier names as a bitmask using
    ``_SEM_TOKEN_MODIFIERS`` indices."""
    out = 0
    for m in modifiers:
        if m in _SEM_TOKEN_MODIFIERS:
            out |= 1 << _SEM_TOKEN_MODIFIERS.index(m)
    return out


@dataclass(frozen=True)
class _SemToken:
    """One semantic-token entry in 1-based absolute coordinates.
    The handler converts to the LSP 0-based relative encoding
    before sending."""
    line: int
    col: int
    length: int
    type_index: int
    modifiers_mask: int


def _symbol_to_sem_token_type(sym: Symbol) -> Optional[tuple[int, set[str]]]:
    """Map a Capa Symbol to a semantic-tokens (type_index,
    modifier_set) pair. Returns ``None`` when the symbol does not
    map to a known token type (built-in keyword-flavoured names
    end up here)."""
    is_builtin = sym.pos.line == 0 and sym.pos.col == 0
    mods: set[str] = set()
    if is_builtin:
        mods.add("defaultLibrary")
    if sym.kind == SymbolKind.FUNCTION:
        return _SEM_TOKEN_TYPES.index("function"), mods
    if sym.kind == SymbolKind.PARAM:
        return _SEM_TOKEN_TYPES.index("parameter"), mods
    if sym.kind == SymbolKind.LOCAL:
        mods.add("readonly")
        return _SEM_TOKEN_TYPES.index("variable"), mods
    if sym.kind == SymbolKind.LOCAL_VAR:
        return _SEM_TOKEN_TYPES.index("variable"), mods
    if sym.kind == SymbolKind.CONSTANT:
        mods.add("readonly")
        return _SEM_TOKEN_TYPES.index("variable"), mods
    if sym.kind == SymbolKind.CAPABILITY:
        return _SEM_TOKEN_TYPES.index("interface"), mods
    if sym.kind in (SymbolKind.TYPE_STRUCT, SymbolKind.TYPE_SUM,
                    SymbolKind.TRAIT):
        return _SEM_TOKEN_TYPES.index("type"), mods
    if sym.kind == SymbolKind.VARIANT:
        return _SEM_TOKEN_TYPES.index("enumMember"), mods
    return None


def _decl_site_to_sem_token_type(
    site: _DeclSite, result: AnalysisResult, module: A.Module,
) -> Optional[tuple[int, set[str]]]:
    """Tag a declaration site. Fields get the ``property`` type
    (no Symbol for them); the rest defer to
    ``_symbol_to_sem_token_type`` with a ``declaration`` modifier
    layered on top."""
    mods = {"declaration"}
    if site.decl_kind == "field":
        return _SEM_TOKEN_TYPES.index("property"), mods
    sym = _resolve_decl_symbol(site, result, module)
    if sym is None:
        return None
    pair = _symbol_to_sem_token_type(sym)
    if pair is None:
        return None
    type_index, sym_mods = pair
    return type_index, sym_mods | mods


def compute_semantic_tokens(
    source: str, filename: str,
) -> tuple[list[str], list[str], list[int]]:
    """Compute the LSP semantic-tokens response for the buffer.

    Returns a triple ``(token_types, token_modifiers, data)``:

    * ``token_types`` is the legend's type list, in the order the
      server will reference them by index;
    * ``token_modifiers`` is the legend's modifier list;
    * ``data`` is the flat relative-encoded array
      (groups of five ints: deltaLine, deltaStart, length,
      tokenType, tokenModifiers). LSP positions are 0-based.

    A buffer that fails to lex/parse returns an empty ``data``
    array. The legend is always the same so the client can
    register it once at server initialisation.
    """
    try:
        tokens = Lexer(source, filename=filename).lex()
        module = Parser(tokens, source=source, filename=filename).parse_module()
    except (LexerError, ParserError):
        return _SEM_TOKEN_TYPES, _SEM_TOKEN_MODIFIERS, []
    result = analyze(module, source=source, filename=filename)

    sem_tokens: list[_SemToken] = []

    # Reference idents.
    for ident in collect_idents(module):
        sym = result.bindings.get(id(ident))
        if sym is None:
            continue
        pair = _symbol_to_sem_token_type(sym)
        if pair is None:
            continue
        type_index, mods = pair
        sem_tokens.append(
            _SemToken(
                line=ident.pos.line,
                col=ident.pos.col,
                length=len(ident.name),
                type_index=type_index,
                modifiers_mask=_sem_modifiers_bitmask(mods),
            )
        )

    # Declaration sites.
    for site in collect_decl_sites(module):
        pair = _decl_site_to_sem_token_type(site, result, module)
        if pair is None:
            continue
        type_index, mods = pair
        sem_tokens.append(
            _SemToken(
                line=site.ident.pos.line,
                col=site.ident.pos.col,
                length=len(site.ident.name),
                type_index=type_index,
                modifiers_mask=_sem_modifiers_bitmask(mods),
            )
        )

    # TypeName references inside type annotations (parameter
    # types, return types, struct field types, ...). These are
    # not Ident nodes, so the analyzer does not file them in
    # ``bindings``; we resolve them by name in ``global_symbols``.
    for n in _walk(module):
        if not isinstance(n, A.TypeName):
            continue
        sym = result.global_symbols.get(n.name)
        if sym is None:
            continue
        pair = _symbol_to_sem_token_type(sym)
        if pair is None:
            continue
        type_index, mods = pair
        sem_tokens.append(
            _SemToken(
                line=n.pos.line,
                col=n.pos.col,
                length=len(n.name),
                type_index=type_index,
                modifiers_mask=_sem_modifiers_bitmask(mods),
            )
        )

    # let / var bindings inside function bodies. ``let`` is a
    # readonly variable, ``var`` is mutable. Only the simple
    # ``let name = ...`` shape produces a tagged identifier here
    # (destructuring patterns each get their own IdentPat which
    # we pick up by walking the pattern subtree).
    var_idx = _SEM_TOKEN_TYPES.index("variable")
    for n in _walk(module):
        if isinstance(n, A.LetStmt):
            for pat in _walk(n.pattern):
                if isinstance(pat, A.IdentPat):
                    sem_tokens.append(
                        _SemToken(
                            line=pat.pos.line,
                            col=pat.pos.col,
                            length=len(pat.name),
                            type_index=var_idx,
                            modifiers_mask=_sem_modifiers_bitmask(
                                {"readonly", "declaration"}
                            ),
                        )
                    )
        elif isinstance(n, A.VarStmt) and n.name_pos is not None:
            sem_tokens.append(
                _SemToken(
                    line=n.name_pos.line,
                    col=n.name_pos.col,
                    length=len(n.name),
                    type_index=var_idx,
                    modifiers_mask=_sem_modifiers_bitmask(
                        {"declaration"}
                    ),
                )
            )

    # Sort by (line, col) for the relative encoding. Tokens at
    # the same position can in principle appear twice (a
    # reference Ident and a decl site with overlapping coverage);
    # drop duplicates keeping the first occurrence.
    sem_tokens.sort(key=lambda t: (t.line, t.col))
    seen: set[tuple[int, int]] = set()
    deduped: list[_SemToken] = []
    for t in sem_tokens:
        if (t.line, t.col) in seen:
            continue
        seen.add((t.line, t.col))
        deduped.append(t)

    data: list[int] = []
    prev_line_0 = 0
    prev_col_0 = 0
    for t in deduped:
        line_0 = t.line - 1
        col_0 = t.col - 1
        if line_0 == prev_line_0:
            delta_line = 0
            delta_start = col_0 - prev_col_0
        else:
            delta_line = line_0 - prev_line_0
            delta_start = col_0
        data.extend([
            delta_line, delta_start, t.length,
            t.type_index, t.modifiers_mask,
        ])
        prev_line_0 = line_0
        prev_col_0 = col_0
    return _SEM_TOKEN_TYPES, _SEM_TOKEN_MODIFIERS, data


# ---------------------------------------------------------------
# Server wiring
# ---------------------------------------------------------------


def _build_server():
    """Construct a configured ``LanguageServer``. Kept lazy so
    importing this module never requires ``pygls`` to be
    installed; only ``serve()`` and tests that touch the server
    do."""
    from pygls.lsp.server import LanguageServer
    from lsprotocol import types as lsp

    server = LanguageServer(
        name=_SERVER_NAME,
        version=_CAPA_VERSION,
    )

    def _refresh(ls, uri: str, source: str) -> None:
        # The LSP filename should be a friendly path; strip the
        # ``file://`` scheme when possible so analyzer errors print
        # ``foo.capa:3:5`` rather than ``file:///.../foo.capa:3:5``.
        filename = uri
        if uri.startswith("file://"):
            from urllib.parse import unquote
            filename = unquote(uri[len("file://"):])
            # On Windows, paths come through as ``/c:/...``.
            if filename.startswith("/") and len(filename) > 2 and filename[2] == ":":
                filename = filename[1:]
        diags = compute_diagnostics(source, filename)
        ls.text_document_publish_diagnostics(
            lsp.PublishDiagnosticsParams(uri=uri, diagnostics=diags)
        )

    @server.feature(lsp.TEXT_DOCUMENT_DID_OPEN)
    def did_open(ls, params: "lsp.DidOpenTextDocumentParams") -> None:
        _refresh(ls, params.text_document.uri, params.text_document.text)

    @server.feature(lsp.TEXT_DOCUMENT_DID_CHANGE)
    def did_change(ls, params: "lsp.DidChangeTextDocumentParams") -> None:
        # With TextDocumentSyncKind.Incremental (the pygls default)
        # the document content is reconstructed for us; pull it
        # from the workspace.
        doc = ls.workspace.get_text_document(params.text_document.uri)
        _refresh(ls, params.text_document.uri, doc.source)

    @server.feature(lsp.TEXT_DOCUMENT_DID_SAVE)
    def did_save(ls, params: "lsp.DidSaveTextDocumentParams") -> None:
        doc = ls.workspace.get_text_document(params.text_document.uri)
        _refresh(ls, params.text_document.uri, doc.source)

    @server.feature(lsp.TEXT_DOCUMENT_DID_CLOSE)
    def did_close(ls, params: "lsp.DidCloseTextDocumentParams") -> None:
        # On close, clear diagnostics for the URI so they do not
        # linger in the editor's problems view.
        ls.text_document_publish_diagnostics(
            lsp.PublishDiagnosticsParams(
                uri=params.text_document.uri, diagnostics=[],
            )
        )

    @server.feature(lsp.TEXT_DOCUMENT_HOVER)
    def hover(
        ls, params: "lsp.HoverParams",
    ) -> "Optional[lsp.Hover]":
        doc = ls.workspace.get_text_document(params.text_document.uri)
        # LSP positions are 0-based; Capa positions are 1-based.
        line = params.position.line + 1
        col = params.position.character + 1
        result = compute_hover(doc.source, params.text_document.uri, line, col)
        if result is None:
            return None
        markdown, ident = result
        start = lsp.Position(
            line=ident.pos.line - 1, character=ident.pos.col - 1,
        )
        end = lsp.Position(
            line=ident.pos.line - 1,
            character=ident.pos.col - 1 + len(ident.name),
        )
        return lsp.Hover(
            contents=lsp.MarkupContent(
                kind=lsp.MarkupKind.Markdown, value=markdown,
            ),
            range=lsp.Range(start=start, end=end),
        )

    @server.feature(lsp.TEXT_DOCUMENT_DEFINITION)
    def definition(
        ls, params: "lsp.DefinitionParams",
    ) -> "Optional[lsp.Location]":
        doc = ls.workspace.get_text_document(params.text_document.uri)
        line = params.position.line + 1
        col = params.position.character + 1
        target = compute_definition(
            doc.source, params.text_document.uri, line, col,
        )
        if target is None:
            return None
        # Capa positions are 1-based, LSP is 0-based. The
        # declaration position points at the start of the name;
        # we report a zero-width range there because the parser
        # does not record name lengths on declaration nodes. Most
        # clients (VSCode, Helix, Neovim) jump to the start and
        # ignore the end for navigation purposes.
        start = lsp.Position(
            line=target.line - 1, character=target.col - 1,
        )
        return lsp.Location(
            uri=params.text_document.uri,
            range=lsp.Range(start=start, end=start),
        )

    # Mapping from our string ``kind`` tags to LSP SymbolKind.
    # Names not in LSP's enum collapse to a near neighbour: a
    # Capa ``sum`` type maps to LSP ``Enum``, a ``capability`` to
    # LSP ``Interface``, etc.
    _to_lsp_kind = {
        "constant":   lsp.SymbolKind.Constant,
        "function":   lsp.SymbolKind.Function,
        "struct":     lsp.SymbolKind.Struct,
        "sum":        lsp.SymbolKind.Enum,
        "field":      lsp.SymbolKind.Field,
        "variant":    lsp.SymbolKind.EnumMember,
        "trait":      lsp.SymbolKind.Interface,
        "capability": lsp.SymbolKind.Interface,
        "method":     lsp.SymbolKind.Method,
        "impl":       lsp.SymbolKind.Class,
    }

    def _doc_to_lsp(sym) -> "lsp.DocumentSymbol":
        # A zero-width range at the declaration position. Most
        # editors are happy with this; a future parser change
        # that records full spans would let us return a proper
        # range here.
        pos = lsp.Position(
            line=sym.pos.line - 1, character=sym.pos.col - 1,
        )
        rng = lsp.Range(start=pos, end=pos)
        return lsp.DocumentSymbol(
            name=sym.name,
            detail=sym.detail or None,
            kind=_to_lsp_kind.get(sym.kind, lsp.SymbolKind.Variable),
            range=rng,
            selection_range=rng,
            children=[_doc_to_lsp(c) for c in sym.children] or None,
        )

    @server.feature(lsp.TEXT_DOCUMENT_DOCUMENT_SYMBOL)
    def document_symbol(
        ls, params: "lsp.DocumentSymbolParams",
    ) -> "Optional[list[lsp.DocumentSymbol]]":
        doc = ls.workspace.get_text_document(params.text_document.uri)
        syms = compute_document_symbols(doc.source, params.text_document.uri)
        if syms is None:
            return None
        return [_doc_to_lsp(s) for s in syms]

    @server.feature(lsp.TEXT_DOCUMENT_CODE_ACTION)
    def code_action(
        ls, params: "lsp.CodeActionParams",
    ) -> "Optional[list[lsp.CodeAction]]":
        doc = ls.workspace.get_text_document(params.text_document.uri)
        actions: list[lsp.CodeAction] = []
        for diag in (params.context.diagnostics or []):
            if not diag.message:
                continue
            # Diagnostic ranges are 0-based; our compute_code_actions
            # speaks 1-based Capa coordinates.
            diag_line_1 = diag.range.start.line + 1
            for ca in compute_code_actions(doc.source, diag.message, diag_line_1):
                edit = ca.edit
                text_edit = lsp.TextEdit(
                    range=lsp.Range(
                        start=lsp.Position(
                            line=edit.line - 1,
                            character=edit.col_start - 1,
                        ),
                        end=lsp.Position(
                            line=edit.line - 1,
                            character=edit.col_end - 1,
                        ),
                    ),
                    new_text=edit.new_text,
                )
                actions.append(
                    lsp.CodeAction(
                        title=ca.title,
                        kind=lsp.CodeActionKind.QuickFix,
                        diagnostics=[diag],
                        edit=lsp.WorkspaceEdit(
                            changes={params.text_document.uri: [text_edit]},
                        ),
                        is_preferred=True,
                    )
                )
        return actions or None

    # Register the semantic-tokens legend at server construction
    # time so the client can record it on initialise.
    _sem_legend = lsp.SemanticTokensLegend(
        token_types=_SEM_TOKEN_TYPES,
        token_modifiers=_SEM_TOKEN_MODIFIERS,
    )

    @server.feature(
        lsp.TEXT_DOCUMENT_SEMANTIC_TOKENS_FULL,
        lsp.SemanticTokensRegistrationOptions(
            legend=_sem_legend, full=True, range=False,
        ),
    )
    def semantic_tokens_full(
        ls, params: "lsp.SemanticTokensParams",
    ) -> "Optional[lsp.SemanticTokens]":
        doc = ls.workspace.get_text_document(params.text_document.uri)
        _types, _mods, data = compute_semantic_tokens(
            doc.source, params.text_document.uri,
        )
        return lsp.SemanticTokens(data=data)

    _to_completion_kind = {
        "keyword":    lsp.CompletionItemKind.Keyword,
        "type":       lsp.CompletionItemKind.Class,
        "capability": lsp.CompletionItemKind.Interface,
        "variant":    lsp.CompletionItemKind.EnumMember,
        "function":   lsp.CompletionItemKind.Function,
        "constant":   lsp.CompletionItemKind.Constant,
        "value":      lsp.CompletionItemKind.Variable,
    }

    @server.feature(lsp.TEXT_DOCUMENT_COMPLETION)
    def completion(
        ls, params: "lsp.CompletionParams",
    ) -> "Optional[list[lsp.CompletionItem]]":
        doc = ls.workspace.get_text_document(params.text_document.uri)
        line = params.position.line + 1
        col = params.position.character + 1
        items = compute_completions(
            doc.source, params.text_document.uri, line, col,
        )
        return [
            lsp.CompletionItem(
                label=c.label,
                kind=_to_completion_kind.get(
                    c.kind, lsp.CompletionItemKind.Text,
                ),
                detail=c.detail or None,
                insert_text=c.insert_text,
            )
            for c in items
        ]

    @server.feature(lsp.TEXT_DOCUMENT_PREPARE_RENAME)
    def prepare_rename(
        ls, params: "lsp.PrepareRenameParams",
    ) -> "Optional[lsp.Range]":
        doc = ls.workspace.get_text_document(params.text_document.uri)
        line = params.position.line + 1
        col = params.position.character + 1
        pre = compute_prepare_rename(
            doc.source, params.text_document.uri, line, col,
        )
        if pre is None:
            return None
        pos, name = pre
        start = lsp.Position(line=pos.line - 1, character=pos.col - 1)
        end = lsp.Position(
            line=pos.line - 1, character=pos.col - 1 + len(name),
        )
        return lsp.Range(start=start, end=end)

    @server.feature(lsp.TEXT_DOCUMENT_RENAME)
    def rename(
        ls, params: "lsp.RenameParams",
    ) -> "Optional[lsp.WorkspaceEdit]":
        doc = ls.workspace.get_text_document(params.text_document.uri)
        line = params.position.line + 1
        col = params.position.character + 1
        result = compute_rename(
            doc.source, params.text_document.uri, line, col,
            params.new_name,
        )
        if result.error is not None:
            # Surface the error to the editor as a no-op rename.
            # The LSP spec lets servers return null here; clients
            # typically show a notification "rename failed".
            ls.show_message(
                result.error, lsp.MessageType.Warning,
            )
            return None
        text_edits = [
            lsp.TextEdit(
                range=lsp.Range(
                    start=lsp.Position(
                        line=e.line - 1, character=e.col_start - 1,
                    ),
                    end=lsp.Position(
                        line=e.line - 1, character=e.col_end - 1,
                    ),
                ),
                new_text=params.new_name,
            )
            for e in result.edits
        ]
        return lsp.WorkspaceEdit(
            changes={params.text_document.uri: text_edits},
        )

    @server.feature(lsp.TEXT_DOCUMENT_REFERENCES)
    def references(
        ls, params: "lsp.ReferenceParams",
    ) -> "Optional[list[lsp.Location]]":
        doc = ls.workspace.get_text_document(params.text_document.uri)
        line = params.position.line + 1
        col = params.position.character + 1
        include_decl = (
            params.context.include_declaration
            if params.context is not None else True
        )
        idents = compute_references(
            doc.source, params.text_document.uri, line, col,
            include_declaration=include_decl,
        )
        if idents is None:
            return None
        locations: list[lsp.Location] = []
        for ident in idents:
            start = lsp.Position(
                line=ident.pos.line - 1, character=ident.pos.col - 1,
            )
            end = lsp.Position(
                line=ident.pos.line - 1,
                character=ident.pos.col - 1 + len(ident.name),
            )
            locations.append(
                lsp.Location(
                    uri=params.text_document.uri,
                    range=lsp.Range(start=start, end=end),
                )
            )
        return locations

    return server


def serve() -> int:
    """Run the LSP server over stdio. Blocks until the client
    disconnects. Returns the process exit code: 0 on clean
    shutdown, 2 if ``pygls`` is not installed.
    """
    try:
        server = _build_server()
    except ImportError:
        import sys
        print(
            "capa lsp: pygls is required to run the language server.\n"
            "Install it with: pip install 'pygls>=2.0'",
            file=sys.stderr,
        )
        return 2
    server.start_io()
    return 0
