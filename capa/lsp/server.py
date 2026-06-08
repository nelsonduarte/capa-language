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
from .document_highlight import compute_document_highlights
from .document_symbols import compute_document_symbols
from .folding import compute_folding_ranges
from .formatting import compute_formatting, compute_range_formatting
from .hover import compute_hover
from .inlay_hint import compute_inlay_hints
from .references import compute_references
from .rename import compute_prepare_rename, compute_rename
from .semantic_tokens import (
    TOKEN_MODIFIERS as SEM_TOKEN_MODIFIERS,
    TOKEN_TYPES as SEM_TOKEN_TYPES,
    compute_semantic_tokens,
)
from .signature_help import compute_signature_help
from .workspace_symbols import compute_workspace_symbols


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


# ---------------------------------------------------------------
# Position-encoding boundary.
#
# Internally every compute_* helper works in *codepoint* columns
# (matching the lexer's offsets). The LSP wire protocol, however,
# uses UTF-16 code units for ``character`` columns (pygls defaults
# to the ``Utf16`` PositionCodec). For ASCII these coincide, but a
# line containing an astral (supplementary-plane) char shifts every
# subsequent column. So we convert at the server boundary only:
#
# * INBOUND  (client -> server): ``_inbound_line_col`` turns a
#   client ``lsp.Position`` into 1-based codepoint (line, col).
# * OUTBOUND (server -> client): build the ``lsp.Range`` /
#   ``lsp.Position`` in codepoint space first, then run it through
#   ``_to_client_range`` / ``_to_client_position`` before emitting.
#
# The document carries its own ``position_codec``; we reuse it when
# reachable and fall back to a module-level codec otherwise (e.g. a
# mocked doc in tests).
# ---------------------------------------------------------------


def _codec(doc=None):
    """Return the PositionCodec to use. Prefer the document's own
    codec (constructed with the negotiated encoding); fall back to a
    fresh default ``Utf16`` codec when none is reachable."""
    from pygls.workspace import PositionCodec
    if doc is not None:
        cand = getattr(doc, "position_codec", None)
        if isinstance(cand, PositionCodec):
            return cand
    return PositionCodec()


def _doc_lines(doc) -> "list[str]":
    """Document text split for the codec (keepends so column maths
    stay per-line). Tolerates a mocked ``.source``."""
    source = getattr(doc, "source", "") or ""
    if not isinstance(source, str):
        source = ""
    return source.splitlines(keepends=True)


def _inbound_line_col(doc, position) -> "tuple[int, int]":
    """Convert a client ``lsp.Position`` (0-based, UTF-16 column)
    into the 1-based codepoint (line, col) the compute_* helpers
    expect."""
    server_pos = _codec(doc).position_from_client_units(
        _doc_lines(doc), position,
    )
    return server_pos.line + 1, server_pos.character + 1


def _to_client_position(doc, position):
    """Convert a codepoint-space ``lsp.Position`` to client UTF-16
    units."""
    return _codec(doc).position_to_client_units(_doc_lines(doc), position)


def _to_client_range(doc, rng):
    """Convert a codepoint-space ``lsp.Range`` to client UTF-16
    units."""
    return _codec(doc).range_to_client_units(_doc_lines(doc), rng)


def _to_lsp_position(pos: Pos):
    from lsprotocol import types as lsp
    return lsp.Position(
        line=max(pos.line - 1, 0),
        character=max(pos.col - 1, 0),
    )


def _to_lsp_range(pos: Pos, end_pos: "Pos | None" = None):
    """One-character range when only ``pos`` is available;
    precise start-to-end when both. The one-character form is
    enough for editors to underline the starting token.

    Returns a range in *codepoint* space; callers convert to client
    UTF-16 units at the emit boundary."""
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
        # Convert outbound ranges against the *analysed* source (the
        # arg), which on did_open precedes the workspace doc being
        # populated. Reuse the doc's codec when reachable.
        doc = ls.workspace.get_text_document(uri)
        codec = _codec(doc)
        lines = source.splitlines(keepends=True)
        diagnostics = []
        for d in compute_diagnostics(source, filename):
            diagnostics.append(
                lsp.Diagnostic(
                    range=codec.range_to_client_units(
                        lines, _to_lsp_range(d.pos),
                    ),
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
        line, col = _inbound_line_col(doc, params.position)
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
            range=_to_client_range(doc, lsp.Range(start=start, end=end)),
        )

    # -----------------------------------------------------------
    # Definition.
    # -----------------------------------------------------------

    @server.feature(lsp.TEXT_DOCUMENT_DEFINITION)
    def definition(ls, params: "lsp.DefinitionParams"):
        doc = ls.workspace.get_text_document(params.text_document.uri)
        line, col = _inbound_line_col(doc, params.position)
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
            range=_to_client_range(doc, lsp.Range(start=start, end=start)),
        )

    # -----------------------------------------------------------
    # References.
    # -----------------------------------------------------------

    @server.feature(lsp.TEXT_DOCUMENT_REFERENCES)
    def references(ls, params: "lsp.ReferenceParams"):
        doc = ls.workspace.get_text_document(params.text_document.uri)
        line, col = _inbound_line_col(doc, params.position)
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
                range=_to_client_range(doc, lsp.Range(
                    start=lsp.Position(
                        line=i.pos.line - 1, character=i.pos.col - 1,
                    ),
                    end=lsp.Position(
                        line=i.pos.line - 1,
                        character=i.pos.col - 1 + len(i.name),
                    ),
                )),
            )
            for i in idents
        ]

    # -----------------------------------------------------------
    # Document highlight (textDocument/documentHighlight). When
    # the cursor sits on an identifier, highlight every occurrence
    # of the same binding in this document. Distinct from
    # textDocument/references which spans the workspace.
    # -----------------------------------------------------------

    _highlight_kind = {
        "text":  lsp.DocumentHighlightKind.Text,
        "read":  lsp.DocumentHighlightKind.Read,
        "write": lsp.DocumentHighlightKind.Write,
    }

    @server.feature(lsp.TEXT_DOCUMENT_DOCUMENT_HIGHLIGHT)
    def document_highlight(ls, params: "lsp.DocumentHighlightParams"):
        doc = ls.workspace.get_text_document(params.text_document.uri)
        line, col = _inbound_line_col(doc, params.position)
        hits = compute_document_highlights(
            doc.source, params.text_document.uri, line, col,
        )
        if hits is None:
            return None
        return [
            lsp.DocumentHighlight(
                range=_to_client_range(doc, lsp.Range(
                    start=lsp.Position(line=h.line - 1, character=h.col - 1),
                    end=lsp.Position(
                        line=h.line - 1,
                        character=h.col - 1 + len(h.name),
                    ),
                )),
                kind=_highlight_kind.get(h.kind, lsp.DocumentHighlightKind.Text),
            )
            for h in hits
        ]

    # -----------------------------------------------------------
    # Folding ranges (textDocument/foldingRange). Gutter +/-
    # regions for collapsible blocks. Backed by an AST walk that
    # returns empty on parse failure so a mid-edit file does not
    # confuse the editor.
    # -----------------------------------------------------------

    @server.feature(lsp.TEXT_DOCUMENT_FOLDING_RANGE)
    def folding_range(ls, params: "lsp.FoldingRangeParams"):
        doc = ls.workspace.get_text_document(params.text_document.uri)
        ranges = compute_folding_ranges(doc.source)
        if not ranges:
            return None
        return [
            lsp.FoldingRange(
                start_line=r.start_line - 1,
                end_line=r.end_line - 1,
                kind={
                    "region":  lsp.FoldingRangeKind.Region,
                    "comment": lsp.FoldingRangeKind.Comment,
                    "imports": lsp.FoldingRangeKind.Imports,
                }.get(r.kind, lsp.FoldingRangeKind.Region),
            )
            for r in ranges
        ]

    # -----------------------------------------------------------
    # Formatting (textDocument/formatting + rangeFormatting).
    # Backed by capa.formatter.format_source (the v3 AST round-
    # trip pipeline with v1+v2 line-level fallback on parse error).
    # -----------------------------------------------------------

    @server.feature(lsp.TEXT_DOCUMENT_FORMATTING)
    def formatting(ls, params: "lsp.DocumentFormattingParams"):
        doc = ls.workspace.get_text_document(params.text_document.uri)
        edits = compute_formatting(doc.source)
        return [
            lsp.TextEdit(
                range=_to_client_range(doc, lsp.Range(
                    start=lsp.Position(
                        line=e.start_line - 1,
                        character=e.start_col - 1,
                    ),
                    end=lsp.Position(
                        line=e.end_line - 1,
                        character=e.end_col - 1,
                    ),
                )),
                new_text=e.new_text,
            )
            for e in edits
        ] or None

    @server.feature(lsp.TEXT_DOCUMENT_RANGE_FORMATTING)
    def range_formatting(ls, params: "lsp.DocumentRangeFormattingParams"):
        doc = ls.workspace.get_text_document(params.text_document.uri)
        start_line, start_col = _inbound_line_col(doc, params.range.start)
        end_line, end_col = _inbound_line_col(doc, params.range.end)
        edits = compute_range_formatting(
            doc.source,
            start_line, start_col,
            end_line, end_col,
        )
        return [
            lsp.TextEdit(
                range=_to_client_range(doc, lsp.Range(
                    start=lsp.Position(
                        line=e.start_line - 1,
                        character=e.start_col - 1,
                    ),
                    end=lsp.Position(
                        line=e.end_line - 1,
                        character=e.end_col - 1,
                    ),
                )),
                new_text=e.new_text,
            )
            for e in edits
        ] or None

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

    def _docsym_to_lsp(doc, sym):
        pos = lsp.Position(
            line=sym.pos.line - 1, character=sym.pos.col - 1,
        )
        rng = _to_client_range(doc, lsp.Range(start=pos, end=pos))
        return lsp.DocumentSymbol(
            name=sym.name,
            detail=sym.detail or None,
            kind=_docsym_kind.get(sym.kind, lsp.SymbolKind.Variable),
            range=rng,
            selection_range=rng,
            children=[_docsym_to_lsp(doc, c) for c in sym.children] or None,
        )

    @server.feature(lsp.TEXT_DOCUMENT_DOCUMENT_SYMBOL)
    def document_symbol(ls, params: "lsp.DocumentSymbolParams"):
        doc = ls.workspace.get_text_document(params.text_document.uri)
        syms = compute_document_symbols(doc.source, params.text_document.uri)
        if syms is None:
            return None
        return [_docsym_to_lsp(doc, s) for s in syms]

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
                    range=_to_client_range(doc, lsp.Range(
                        start=lsp.Position(
                            line=edit.line - 1,
                            character=edit.col_start - 1,
                        ),
                        end=lsp.Position(
                            line=edit.line - 1,
                            character=edit.col_end - 1,
                        ),
                    )),
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
        line, col = _inbound_line_col(doc, params.position)
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
        line, col = _inbound_line_col(doc, params.position)
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
        return _to_client_range(doc, lsp.Range(start=start, end=end))

    @server.feature(lsp.TEXT_DOCUMENT_RENAME)
    def rename(ls, params: "lsp.RenameParams"):
        doc = ls.workspace.get_text_document(params.text_document.uri)
        line, col = _inbound_line_col(doc, params.position)
        result = compute_rename(
            doc.source, params.text_document.uri, line, col,
            params.new_name,
        )
        if result.error is not None:
            ls.show_message(result.error, lsp.MessageType.Warning)
            return None
        text_edits = [
            lsp.TextEdit(
                range=_to_client_range(doc, lsp.Range(
                    start=lsp.Position(
                        line=e.line - 1, character=e.col_start - 1,
                    ),
                    end=lsp.Position(
                        line=e.line - 1, character=e.col_end - 1,
                    ),
                )),
                new_text=params.new_name,
            )
            for e in result.edits
        ]
        return lsp.WorkspaceEdit(
            changes={params.text_document.uri: text_edits},
        )

    # -----------------------------------------------------------
    # Signature help (textDocument/signatureHelp). Triggered on
    # ``(`` and ``,`` so the popup tracks the active parameter as
    # the user types arguments. Returns None when the cursor is
    # not inside a resolvable call's argument list.
    # -----------------------------------------------------------

    @server.feature(
        lsp.TEXT_DOCUMENT_SIGNATURE_HELP,
        lsp.SignatureHelpOptions(trigger_characters=["(", ","]),
    )
    def signature_help(ls, params: "lsp.SignatureHelpParams"):
        doc = ls.workspace.get_text_document(params.text_document.uri)
        line, col = _inbound_line_col(doc, params.position)
        info = compute_signature_help(
            doc.source, params.text_document.uri, line, col,
        )
        if info is None:
            return None
        sig = lsp.SignatureInformation(
            label=info.label,
            parameters=[
                lsp.ParameterInformation(label=p)
                for p in info.parameters
            ],
            active_parameter=info.active_parameter,
        )
        return lsp.SignatureHelp(
            signatures=[sig],
            active_signature=0,
            active_parameter=info.active_parameter,
        )

    # -----------------------------------------------------------
    # Inlay hints (textDocument/inlayHint). Inline ``: T`` type
    # hints for un-annotated let / var bindings within the
    # requested range. The hint text is the analyzer's inferred
    # type, so it agrees with hover.
    # -----------------------------------------------------------

    @server.feature(
        lsp.TEXT_DOCUMENT_INLAY_HINT,
        lsp.InlayHintOptions(resolve_provider=False),
    )
    def inlay_hint(ls, params: "lsp.InlayHintParams"):
        doc = ls.workspace.get_text_document(params.text_document.uri)
        start_line, _start_col = _inbound_line_col(doc, params.range.start)
        end_line, _end_col = _inbound_line_col(doc, params.range.end)
        hints = compute_inlay_hints(
            doc.source, params.text_document.uri, start_line, end_line,
        )
        if not hints:
            return None
        return [
            lsp.InlayHint(
                position=_to_client_position(doc, lsp.Position(
                    line=h.line - 1, character=h.col - 1,
                )),
                label=h.label,
                kind=lsp.InlayHintKind.Type,
                padding_left=False,
                padding_right=False,
            )
            for h in hints
        ]

    # -----------------------------------------------------------
    # Workspace symbols (workspace/symbol). Project-wide search
    # across every .capa file under the workspace folders;
    # unparseable files are skipped. Positions come back in
    # codepoint space and are not codec-converted (the symbol box
    # tolerates a one-char selection range and we have no doc to
    # convert against for files that are not open).
    # -----------------------------------------------------------

    _wssym_kind = {
        "constant":   lsp.SymbolKind.Constant,
        "function":   lsp.SymbolKind.Function,
        "struct":     lsp.SymbolKind.Struct,
        "sum":        lsp.SymbolKind.Enum,
        "trait":      lsp.SymbolKind.Interface,
        "capability": lsp.SymbolKind.Interface,
    }

    @server.feature(lsp.WORKSPACE_SYMBOL)
    def workspace_symbol(ls, params: "lsp.WorkspaceSymbolParams"):
        files = _enumerate_workspace_capa_files(ls)
        syms = compute_workspace_symbols(params.query, files)
        out = []
        for s in syms:
            pos = lsp.Position(
                line=max(s.pos.line - 1, 0),
                character=max(s.pos.col - 1, 0),
            )
            end = lsp.Position(
                line=pos.line, character=pos.character + len(s.name),
            )
            out.append(
                lsp.WorkspaceSymbol(
                    name=s.name,
                    kind=_wssym_kind.get(s.kind, lsp.SymbolKind.Variable),
                    location=lsp.Location(
                        uri=_filename_to_uri(s.filename),
                        range=lsp.Range(start=pos, end=end),
                    ),
                )
            )
        return out

    return server


def _filename_to_uri(filename: str) -> str:
    """Translate a local path back into a ``file://`` URI for
    workspace-symbol locations."""
    from pathlib import Path
    from urllib.parse import quote
    p = str(Path(filename).resolve()).replace("\\", "/")
    if not p.startswith("/"):
        p = "/" + p  # Windows ``c:/...`` -> ``/c:/...``
    return "file://" + quote(p)


def _enumerate_workspace_capa_files(ls) -> "list[tuple[str, str]]":
    """Collect ``(filename, source)`` for every ``.capa`` file
    under the client's workspace folders. Open documents use their
    in-memory source (so unsaved edits are searchable); files only
    on disk are read fresh. Unreadable files are skipped."""
    from pathlib import Path

    roots: list[Path] = []
    try:
        folders = ls.workspace.folders or {}
    except Exception:
        folders = {}
    for folder in folders.values():
        uri = getattr(folder, "uri", None)
        if not uri:
            continue
        root = _uri_to_filename(uri)
        try:
            p = Path(root)
            if p.is_dir():
                roots.append(p)
        except OSError:
            continue

    # Map of resolved-path -> in-memory source for open docs, so an
    # unsaved edit is reflected in search results.
    open_sources: dict[str, str] = {}
    try:
        for uri, doc in (ls.workspace.text_documents or {}).items():
            src = getattr(doc, "source", None)
            if not isinstance(src, str):
                continue
            try:
                key = str(Path(_uri_to_filename(uri)).resolve())
            except OSError:
                continue
            open_sources[key] = src
    except Exception:
        pass

    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for root in roots:
        try:
            paths = sorted(root.rglob("*.capa"))
        except OSError:
            continue
        for path in paths:
            try:
                key = str(path.resolve())
            except OSError:
                key = str(path)
            if key in seen:
                continue
            seen.add(key)
            if key in open_sources:
                out.append((str(path), open_sources[key]))
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            out.append((str(path), source))
    return out


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
