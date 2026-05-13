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

Completion, semantic tokens, and code actions remain on the
roadmap.

Runtime entry points:

``serve()``
    Block on stdio, reading LSP requests from stdin and writing
    responses to stdout. Used by ``python -m capa lsp``.

The ``pygls`` package is imported lazily so the rest of the
compiler never has to depend on it; ``--check`` and friends
continue to work in a stock-Python environment.
"""

from __future__ import annotations

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
