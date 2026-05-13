"""capa/lsp_server.py, back-compat shim.

The Language Server Protocol implementation used to live in this
single ~2 100-line file. It now lives split across
:mod:`capa.lsp`, one module per LSP feature. This module
re-exports the public surface so existing imports
(``from capa.lsp_server import compute_hover``) keep working.

The one wrinkle is :func:`compute_diagnostics`: the new
implementation returns Capa-native :class:`capa.lsp.Diagnostic`
dataclasses, but tests and any callers built before the split
expect the LSP wire shape (``lsp.Diagnostic`` from
``lsprotocol``). We adapt at this layer to avoid breaking them.
"""

from __future__ import annotations

from typing import Optional

from .lsp import (
    # context
    DeclSite as _DeclSite,
    LspContext,
    collect_decl_sites,
    collect_idents,
    find_decl_site_at,
    find_ident_at,
    walk as _walk,
    # symbol_resolve
    resolve_decl_symbol as _resolve_decl_symbol,
    # hover / definition / references / rename / completion /
    # document symbols / code actions / semantic tokens
    CodeAction,
    CodeActionEdit,
    Completion,
    DocSymbol,
    RenameEdit,
    RenameResult,
    SEMANTIC_TOKEN_MODIFIERS as _SEM_TOKEN_MODIFIERS,
    SEMANTIC_TOKEN_TYPES as _SEM_TOKEN_TYPES,
    compute_code_actions,
    compute_completions,
    compute_definition,
    compute_document_symbols,
    compute_hover,
    compute_prepare_rename,
    compute_references,
    compute_rename,
    compute_semantic_tokens,
    is_valid_capa_identifier as _is_valid_capa_identifier,
    # server entry point
    serve,
)
from .lsp.diagnostics import compute_diagnostics as _compute_diagnostics_native


def compute_diagnostics(source: str, filename: str):
    """Back-compat wrapper: returns ``list[lsp.Diagnostic]``
    rather than the Capa-native shape produced by
    :func:`capa.lsp.compute_diagnostics`. New code should import
    the native form from :mod:`capa.lsp` directly."""
    from lsprotocol import types as lsp

    out: list = []
    for d in _compute_diagnostics_native(source, filename):
        start = lsp.Position(
            line=max(d.pos.line - 1, 0),
            character=max(d.pos.col - 1, 0),
        )
        end = lsp.Position(
            line=start.line, character=start.character + 1,
        )
        out.append(
            lsp.Diagnostic(
                range=lsp.Range(start=start, end=end),
                severity=lsp.DiagnosticSeverity.Error,
                source=d.source,
                message=d.message,
            )
        )
    return out


__all__ = [
    "CodeAction",
    "CodeActionEdit",
    "Completion",
    "DocSymbol",
    "LspContext",
    "RenameEdit",
    "RenameResult",
    "collect_decl_sites",
    "collect_idents",
    "compute_code_actions",
    "compute_completions",
    "compute_definition",
    "compute_diagnostics",
    "compute_document_symbols",
    "compute_hover",
    "compute_prepare_rename",
    "compute_references",
    "compute_rename",
    "compute_semantic_tokens",
    "find_decl_site_at",
    "find_ident_at",
    "serve",
]
