"""capa/lsp_server.py, Language Server Protocol implementation.

A minimal Capa language server (LSP), v1: **diagnostics only**.
On every ``didOpen`` / ``didChange`` / ``didSave``, the server
re-runs the full lexer + parser + analyzer pipeline on the
buffer's current contents and publishes the resulting errors as
``textDocument/publishDiagnostics`` events. Each diagnostic
carries the same source-aligned position the CLI prints, so
editors can underline the offending range and surface the
message in their UI.

Hover, go-to-definition, completion, semantic tokens, and other
LSP capabilities are deliberately deferred: the goal of v1 is to
give users of any LSP-capable editor (VSCode, Neovim, Helix,
Emacs, JetBrains) the same diagnostics they would see by running
``capa --check``, with no roundtrip to the terminal.

Runtime entry points:

``serve()``
    Block on stdio, reading LSP requests from stdin and writing
    responses to stdout. Used by ``python -m capa lsp``.

The ``pygls`` package is imported lazily so the rest of the
compiler never has to depend on it; ``--check`` and friends
continue to work in a stock-Python environment.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from . import __version__ as _CAPA_VERSION
from .analyzer import analyze
from .errors import LexerError
from .lexer import Lexer
from .parser import Parser, ParserError
from .tokens import Pos

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
