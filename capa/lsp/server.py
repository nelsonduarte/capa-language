"""LSP server wiring.

Everything else in the package is pure Python that takes Capa
source as input and returns Capa-native types. This module is
the one that talks to ``pygls`` / ``lsprotocol``: it builds the
``LanguageServer``, registers handlers for each LSP feature,
and translates between Capa-native and LSP-wire types.

``serve()`` is the entry point used by ``python -m capa lsp``.
``pygls`` is imported lazily so the package stays usable without
the optional ``[lsp]`` extra installed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .. import __version__ as _CAPA_VERSION
from ..tokens import Pos
from .code_actions import compute_code_actions
from .completion import compute_completions
from .definition import compute_definition
from .diagnostics import compute_diagnostics
from .document_symbols import compute_document_symbols
from .hover import compute_hover
from .references import compute_references
from .rename import compute_prepare_rename, compute_rename
from .semantic_tokens import (
    TOKEN_MODIFIERS as SEM_TOKEN_MODIFIERS,
    TOKEN_TYPES as SEM_TOKEN_TYPES,
    compute_semantic_tokens,
)


SERVER_NAME = "capa-lsp"


if TYPE_CHECKING:
    from lsprotocol import types as lsp


def _uri_to_filename(uri: str) -> str:
    """Translate a ``file://`` URI to a friendly path for error
    messages. ``foo.capa:3:5`` reads better than
    ``file:///c:/.../foo.capa:3:5`` in editor problem panes."""
    if not uri.startswith("file://"):
        return uri
    from urllib.parse import unquote
    filename = unquote(uri[len("file://"):])
    if filename.startswith("/") and len(filename) > 2 and filename[2] == ":":
        # ``/c:/...`` on Windows -> ``c:/...``.
        filename = filename[1:]
    return filename


def _to_lsp_position(pos: Pos):
    from lsprotocol import types as lsp
    return lsp.Position(
        line=max(pos.line - 1, 0),
        character=max(pos.col - 1, 0),
    )


def _to_lsp_range(pos: Pos, end_pos: "Pos | None" = None):
    """One-character range when only ``pos`` is available;
    precise start-to-end when both. The one-character form is
    enough for editors to underline the starting token."""
    from lsprotocol import types as lsp
    start = _to_lsp_position(pos)
    if end_pos is None:
        end = lsp.Position(line=start.line, character=start.character + 1)
    else:
        end = _to_lsp_position(end_pos)
    return lsp.Range(start=start, end=end)


def _build_server():
    """Construct and configure the LanguageServer.

    Kept lazy so importing this module never requires ``pygls``;
    only ``serve()`` and tests that touch the server do.
    """
    from pygls.lsp.server import LanguageServer
    from lsprotocol import types as lsp

    server = LanguageServer(name=SERVER_NAME, version=_CAPA_VERSION)

    # -----------------------------------------------------------
    # Diagnostics: pushed proactively on every did_open / change
    # / save and cleared on close.
    # -----------------------------------------------------------

    def _refresh(ls, uri: str, source: str) -> None:
        filename = _uri_to_filename(uri)
        diagnostics = []
        for d in compute_diagnostics(source, filename):
            diagnostics.append(
                lsp.Diagnostic(
                    range=_to_lsp_range(d.pos),
                    severity=lsp.DiagnosticSeverity.Error,
                    source=d.source,
                    message=d.message,
                )
            )
        ls.text_document_publish_diagnostics(
            lsp.PublishDiagnosticsParams(uri=uri, diagnostics=diagnostics)
        )

    @server.feature(lsp.TEXT_DOCUMENT_DID_OPEN)
    def did_open(ls, params: "lsp.DidOpenTextDocumentParams") -> None:
        _refresh(ls, params.text_document.uri, params.text_document.text)

    @server.feature(lsp.TEXT_DOCUMENT_DID_CHANGE)
    def did_change(ls, params: "lsp.DidChangeTextDocumentParams") -> None:
        doc = ls.workspace.get_text_document(params.text_document.uri)
        _refresh(ls, params.text_document.uri, doc.source)

    @server.feature(lsp.TEXT_DOCUMENT_DID_SAVE)
    def did_save(ls, params: "lsp.DidSaveTextDocumentParams") -> None:
        doc = ls.workspace.get_text_document(params.text_document.uri)
        _refresh(ls, params.text_document.uri, doc.source)

    @server.feature(lsp.TEXT_DOCUMENT_DID_CLOSE)
    def did_close(ls, params: "lsp.DidCloseTextDocumentParams") -> None:
        ls.text_document_publish_diagnostics(
            lsp.PublishDiagnosticsParams(
                uri=params.text_document.uri, diagnostics=[],
            )
        )

    # -----------------------------------------------------------
    # Hover.
    # -----------------------------------------------------------

    @server.feature(lsp.TEXT_DOCUMENT_HOVER)
    def hover(ls, params: "lsp.HoverParams"):
        doc = ls.workspace.get_text_document(params.text_document.uri)
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

    # -----------------------------------------------------------
    # Definition.
    # -----------------------------------------------------------

    @server.feature(lsp.TEXT_DOCUMENT_DEFINITION)
    def definition(ls, params: "lsp.DefinitionParams"):
        doc = ls.workspace.get_text_document(params.text_document.uri)
        line = params.position.line + 1
        col = params.position.character + 1
        target = compute_definition(
            doc.source, params.text_document.uri, line, col,
        )
        if target is None:
            return None
        start = lsp.Position(
            line=target.line - 1, character=target.col - 1,
        )
        return lsp.Location(
            uri=params.text_document.uri,
            range=lsp.Range(start=start, end=start),
        )

    # -----------------------------------------------------------
    # References.
    # -----------------------------------------------------------

    @server.feature(lsp.TEXT_DOCUMENT_REFERENCES)
    def references(ls, params: "lsp.ReferenceParams"):
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
        return [
            lsp.Location(
                uri=params.text_document.uri,
                range=lsp.Range(
                    start=lsp.Position(
                        line=i.pos.line - 1, character=i.pos.col - 1,
                    ),
                    end=lsp.Position(
                        line=i.pos.line - 1,
                        character=i.pos.col - 1 + len(i.name),
                    ),
                ),
            )
            for i in idents
        ]

    # -----------------------------------------------------------
    # Document symbols (outline).
    # -----------------------------------------------------------

    _docsym_kind = {
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

    def _docsym_to_lsp(sym):
        pos = lsp.Position(
            line=sym.pos.line - 1, character=sym.pos.col - 1,
        )
        rng = lsp.Range(start=pos, end=pos)
        return lsp.DocumentSymbol(
            name=sym.name,
            detail=sym.detail or None,
            kind=_docsym_kind.get(sym.kind, lsp.SymbolKind.Variable),
            range=rng,
            selection_range=rng,
            children=[_docsym_to_lsp(c) for c in sym.children] or None,
        )

    @server.feature(lsp.TEXT_DOCUMENT_DOCUMENT_SYMBOL)
    def document_symbol(ls, params: "lsp.DocumentSymbolParams"):
        doc = ls.workspace.get_text_document(params.text_document.uri)
        syms = compute_document_symbols(doc.source, params.text_document.uri)
        if syms is None:
            return None
        return [_docsym_to_lsp(s) for s in syms]

    # -----------------------------------------------------------
    # Code actions.
    # -----------------------------------------------------------

    @server.feature(lsp.TEXT_DOCUMENT_CODE_ACTION)
    def code_action(ls, params: "lsp.CodeActionParams"):
        doc = ls.workspace.get_text_document(params.text_document.uri)
        actions = []
        for diag in (params.context.diagnostics or []):
            if not diag.message:
                continue
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

    # -----------------------------------------------------------
    # Semantic tokens.
    # -----------------------------------------------------------

    _sem_legend = lsp.SemanticTokensLegend(
        token_types=SEM_TOKEN_TYPES,
        token_modifiers=SEM_TOKEN_MODIFIERS,
    )

    @server.feature(
        lsp.TEXT_DOCUMENT_SEMANTIC_TOKENS_FULL,
        lsp.SemanticTokensRegistrationOptions(
            legend=_sem_legend, full=True, range=False,
        ),
    )
    def semantic_tokens_full(ls, params: "lsp.SemanticTokensParams"):
        doc = ls.workspace.get_text_document(params.text_document.uri)
        _types, _mods, data = compute_semantic_tokens(
            doc.source, params.text_document.uri,
        )
        return lsp.SemanticTokens(data=data)

    # -----------------------------------------------------------
    # Completion.
    # -----------------------------------------------------------

    _completion_kind = {
        "keyword":    lsp.CompletionItemKind.Keyword,
        "type":       lsp.CompletionItemKind.Class,
        "capability": lsp.CompletionItemKind.Interface,
        "variant":    lsp.CompletionItemKind.EnumMember,
        "function":   lsp.CompletionItemKind.Function,
        "constant":   lsp.CompletionItemKind.Constant,
        "value":      lsp.CompletionItemKind.Variable,
    }

    @server.feature(lsp.TEXT_DOCUMENT_COMPLETION)
    def completion(ls, params: "lsp.CompletionParams"):
        doc = ls.workspace.get_text_document(params.text_document.uri)
        line = params.position.line + 1
        col = params.position.character + 1
        items = compute_completions(
            doc.source, params.text_document.uri, line, col,
        )
        return [
            lsp.CompletionItem(
                label=c.label,
                kind=_completion_kind.get(
                    c.kind, lsp.CompletionItemKind.Text,
                ),
                detail=c.detail or None,
                insert_text=c.insert_text,
            )
            for c in items
        ]

    # -----------------------------------------------------------
    # Rename (+ prepareRename).
    # -----------------------------------------------------------

    @server.feature(lsp.TEXT_DOCUMENT_PREPARE_RENAME)
    def prepare_rename(ls, params: "lsp.PrepareRenameParams"):
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
    def rename(ls, params: "lsp.RenameParams"):
        doc = ls.workspace.get_text_document(params.text_document.uri)
        line = params.position.line + 1
        col = params.position.character + 1
        result = compute_rename(
            doc.source, params.text_document.uri, line, col,
            params.new_name,
        )
        if result.error is not None:
            ls.show_message(result.error, lsp.MessageType.Warning)
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
