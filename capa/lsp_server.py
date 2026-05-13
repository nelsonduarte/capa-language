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

Completion, semantic tokens, and rename remain on the roadmap.

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
from .tokens import Pos
from .typesys import Ty, TyFun, ty_str

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
    ident = find_ident_at(collect_idents(module), line, col)
    if ident is None:
        return None
    sym = result.bindings.get(id(ident))
    if sym is None:
        return None
    ident_ty = result.types.get(id(ident))
    return _format_symbol_for_hover(sym, ident_ty), ident


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
    if ident is None:
        return None
    sym = result.bindings.get(id(ident))
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
    pivot = find_ident_at(idents, line, col)
    if pivot is None:
        return None
    target_sym = result.bindings.get(id(pivot))
    if target_sym is None:
        return None

    # Every Ident whose binding points at the same Symbol object.
    # Symbol identity (Python ``is``) is the natural notion: the
    # analyzer creates a single Symbol per declaration and reuses
    # it for every reference, so an identity check matches all
    # uses (including the pivot itself, which we keep so editors
    # can render the active reference highlighted).
    refs: list[A.Ident] = [
        ident for ident in idents
        if result.bindings.get(id(ident)) is target_sym
    ]

    if include_declaration and not (
        target_sym.pos.line == 0 and target_sym.pos.col == 0
    ):
        # Synthesise an Ident-shaped entry at the declaration
        # position so the caller can render a Location for it.
        # We do not add it if a reference at that exact position
        # already exists (which happens when the parser
        # represented the declaration name as an Ident, rare in
        # v1 but worth defending against).
        already_there = any(
            r.pos.line == target_sym.pos.line
            and r.pos.col == target_sym.pos.col
            for r in refs
        )
        if not already_there:
            refs.append(
                A.Ident(pos=target_sym.pos, name=target_sym.name)
            )

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
