"""Capa Language Server Protocol implementation.

This package replaces the former single-file ``capa.lsp_server``
module. Each LSP feature lives in its own submodule with a pure
``compute_*`` function that takes Capa source as input and
returns Capa-native types; :mod:`capa.lsp.server` is the one
module that talks to ``pygls`` / ``lsprotocol`` and wires those
pure functions to the actual LSP wire protocol.

Layout:

    capa/lsp/
    ├── context.py           LspContext, AST walkers, position finders
    ├── symbol_resolve.py    decl-site Symbol resolution
    ├── diagnostics.py       compute_diagnostics + Diagnostic
    ├── hover.py             compute_hover
    ├── definition.py        compute_definition
    ├── references.py        compute_references
    ├── rename.py            compute_rename + prepareRename + validation
    ├── document_symbols.py  compute_document_symbols + DocSymbol
    ├── completion.py        compute_completions + Completion + dot-context
    ├── code_actions.py      compute_code_actions + CodeAction
    ├── semantic_tokens.py   compute_semantic_tokens + legend
    └── server.py            _build_server, serve()

The public surface is re-exported here for convenience and for
back-compat with the prior ``capa.lsp_server`` module (a shim of
that name still lives in the package root and just re-exports
from here).
"""

from __future__ import annotations

from .code_actions import CodeAction, CodeActionEdit, compute_code_actions
from .completion import Completion, compute_completions
from .context import (
    DeclSite, LspContext, collect_decl_sites, collect_idents,
    find_decl_site_at, find_ident_at, walk,
)
from .definition import compute_definition
from .diagnostics import Diagnostic, compute_diagnostics
from .document_symbols import DocSymbol, compute_document_symbols
from .hover import compute_hover
from .references import compute_references
from .rename import (
    RenameEdit, RenameResult,
    compute_prepare_rename, compute_rename,
    is_valid_capa_identifier,
)
from .semantic_tokens import (
    TOKEN_MODIFIERS as SEMANTIC_TOKEN_MODIFIERS,
    TOKEN_TYPES as SEMANTIC_TOKEN_TYPES,
    compute_semantic_tokens,
)
from .server import SERVER_NAME, serve
from .symbol_resolve import find_fundecl, resolve_decl_symbol


__all__ = [
    # context
    "DeclSite",
    "LspContext",
    "collect_decl_sites",
    "collect_idents",
    "find_decl_site_at",
    "find_ident_at",
    "walk",
    # symbol_resolve
    "find_fundecl",
    "resolve_decl_symbol",
    # diagnostics
    "Diagnostic",
    "compute_diagnostics",
    # hover
    "compute_hover",
    # definition
    "compute_definition",
    # references
    "compute_references",
    # rename
    "RenameEdit",
    "RenameResult",
    "compute_prepare_rename",
    "compute_rename",
    "is_valid_capa_identifier",
    # document_symbols
    "DocSymbol",
    "compute_document_symbols",
    # completion
    "Completion",
    "compute_completions",
    # code_actions
    "CodeAction",
    "CodeActionEdit",
    "compute_code_actions",
    # semantic_tokens
    "SEMANTIC_TOKEN_MODIFIERS",
    "SEMANTIC_TOKEN_TYPES",
    "compute_semantic_tokens",
    # server
    "SERVER_NAME",
    "serve",
]
