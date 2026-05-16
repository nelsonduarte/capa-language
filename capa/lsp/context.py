"""Shared parse + analyse context for LSP features.

Every LSP feature (hover, definition, references, rename,
completion, document symbols, semantic tokens) starts with the
same recipe: lex the buffer, parse it, analyse it, walk for
Idents and declaration sites, look something up. Without a
helper, that recipe gets copy-pasted a dozen times. ``LspContext``
centralises it and exposes lazy caches for the structures the
features actually want.

Only ``compute_diagnostics`` skips this class because it cares
about preserving the lex / parse error itself; bailing out the
moment a buffer doesn't parse would lose the diagnostic the user
came to read.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .. import capa_ast as A
from ..analyzer import AnalysisResult, analyze
from ..errors import LexerError
from ..lexer import Lexer
from ..loader import LinkedModule, LoaderError, ModuleLoader
from ..parser import Parser, ParserError
from ..tokens import Pos


def _capa_search_paths() -> list[Path]:
    """Same parse of ``CAPA_PATH`` as the CLI uses, duplicated here
    so the LSP resolves imports the way the user's compile would.
    """
    import os
    raw = os.environ.get("CAPA_PATH", "")
    if not raw:
        return []
    out: list[Path] = []
    for entry in raw.split(os.pathsep):
        entry = entry.strip()
        if not entry:
            continue
        p = Path(entry).expanduser()
        if p.is_dir():
            out.append(p)
    return out


@dataclass
class LspContext:
    """Bundle of artefacts produced by parsing + analysing the
    buffer once. Construct via :meth:`parse`, which returns
    ``None`` on lexer or parser failure.

    When the buffer contains ``import`` statements and the loader
    can resolve them, ``module`` is the merged linked AST and
    ``linked`` carries the loader's auxiliary maps. Otherwise the
    fields are populated from the buffer alone, matching the
    pre-loader behaviour.
    """

    source: str
    filename: str
    module: A.Module
    result: AnalysisResult
    linked: Optional[LinkedModule] = None
    _idents: Optional[list[A.Ident]] = None
    _decl_sites: Optional[list] = None  # list[DeclSite]; forward-defined

    @classmethod
    def parse(
        cls, source: str, filename: str,
    ) -> "Optional[LspContext]":
        try:
            tokens = Lexer(source, filename=filename).lex()
            module = Parser(
                tokens, source=source, filename=filename,
            ).parse_module()
        except (LexerError, ParserError):
            return None

        # If the buffer imports anything *and* it points at a real
        # path on disk, run the loader so analysis sees the imported
        # items and the false "undefined name" diagnostics on
        # imported references go away. Lexer / parser errors in
        # imported files, cycles, and missing imports fall back to
        # single-file analysis silently: the editor surface should
        # never crash because a transitively-imported file is
        # mid-edit.
        linked: Optional[LinkedModule] = None
        module_for_analysis = module
        sources_map: Optional[dict[str, str]] = None
        privates_map: Optional[dict[str, set[str]]] = None
        if _has_imports(module) and _filename_on_disk(filename):
            try:
                loader = ModuleLoader(search_paths=_capa_search_paths())
                linked = loader.load_root(source, filename)
                module_for_analysis = linked.module
                sources_map = linked.sources
                privates_map = linked.module_privates
            except (LexerError, ParserError, LoaderError, OSError):
                linked = None

        result = analyze(
            module_for_analysis,
            source=source, filename=filename,
            sources=sources_map,
            module_privates=privates_map,
        )
        return cls(
            source=source, filename=filename,
            module=module_for_analysis,
            result=result,
            linked=linked,
        )

    @property
    def idents(self) -> list[A.Ident]:
        if self._idents is None:
            all_idents = collect_idents(self.module)
            self._idents = _filter_to_this_file(
                all_idents, self.filename,
                key=lambda x: x.pos.filename,
            ) if self.linked is not None else all_idents
        return self._idents

    @property
    def decl_sites(self) -> list:
        if self._decl_sites is None:
            all_sites = collect_decl_sites(self.module)
            self._decl_sites = _filter_to_this_file(
                all_sites, self.filename,
                key=lambda s: s.ident.pos.filename,
            ) if self.linked is not None else all_sites
        return self._decl_sites


def _has_imports(module: A.Module) -> bool:
    return any(isinstance(it, A.Import) for it in module.items)


def _filename_on_disk(filename: str) -> bool:
    """The loader needs a resolvable on-disk path to follow
    imports. LSP-only buffers (untitled, in-memory test fixtures)
    are skipped so we don't trigger I/O on phantom paths.
    """
    if not filename or filename.startswith("<"):
        return False
    return Path(filename).exists()


def _filter_to_this_file(items, filename, *, key):
    """When the module is the linker output, restrict a list of
    position-carrying items to those originating in ``filename`` so
    cursor lookups in the editor don't collide with line numbers
    from imported modules. Items whose ``pos.filename`` is empty
    fall through (synthetic / parser-side gaps default to the root
    file).
    """
    this = _resolve_or_none(filename)
    if this is None:
        return list(items)
    out = []
    for item in items:
        item_file = key(item)
        if not item_file:
            out.append(item)
            continue
        if _resolve_or_none(item_file) == this:
            out.append(item)
    return out


def _resolve_or_none(filename: str) -> Optional[str]:
    if not filename or filename.startswith("<"):
        return None
    try:
        return str(Path(filename).resolve())
    except OSError:
        return None


# ---------------------------------------------------------------
# AST walkers
# ---------------------------------------------------------------


def walk(node):
    """Yield every AST node reachable from ``node`` via dataclass
    fields. Order is deterministic; not depth-first vs
    breadth-first matters less than reaching everything."""
    if isinstance(node, A.Node):
        yield node
        for f in node.__dataclass_fields__.values():
            yield from walk(getattr(node, f.name))
    elif isinstance(node, (list, tuple)):
        for x in node:
            yield from walk(x)
    # Strings, ints, None are leaves.


def collect_idents(module: A.Module) -> list[A.Ident]:
    """All ``Ident`` nodes in the module, in walk order."""
    return [n for n in walk(module) if isinstance(n, A.Ident)]


# ---------------------------------------------------------------
# Declaration sites
# ---------------------------------------------------------------
# The parser records the ``IDENT``-token position for every
# declared name (``name_pos`` field). We wrap each declaration as
# a synthetic ``A.Ident`` so the find-by-position / Symbol-lookup
# pipeline used for references also works on declarations.


@dataclass
class DeclSite:
    """Synthetic identifier at a declaration site."""
    ident: A.Ident                          # name + name_pos as an Ident
    decl_kind: str                          # see _DECL_KINDS
    container_name: Optional[str] = None    # struct for fields, sum for variants, etc.


# Internal use: the legal ``decl_kind`` tags.
_DECL_KINDS = frozenset({
    "global", "param", "variant", "field", "method_sig",
})


def collect_decl_sites(module: A.Module) -> list[DeclSite]:
    """Walk the module and yield a ``DeclSite`` for every named
    declaration whose name position the parser recorded. Older
    AST nodes with ``name_pos = None`` (synthetic AST in tests,
    typically) are skipped silently."""
    sites: list[DeclSite] = []

    def maybe(name: str, pos: Optional[Pos], kind: str, container: Optional[str] = None) -> None:
        if pos is None:
            return
        sites.append(
            DeclSite(
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


# ---------------------------------------------------------------
# Position lookup
# ---------------------------------------------------------------


def find_ident_at(
    idents: list[A.Ident], line: int, col: int,
) -> Optional[A.Ident]:
    """Return the ``Ident`` whose source span covers the
    (1-based) cursor position, if any."""
    for ident in idents:
        if ident.pos.line != line:
            continue
        col_start = ident.pos.col
        col_end = col_start + len(ident.name)
        if col_start <= col < col_end:
            return ident
    return None


def find_decl_site_at(
    sites: list[DeclSite], line: int, col: int,
) -> Optional[DeclSite]:
    """Like :func:`find_ident_at` but for declaration sites."""
    for s in sites:
        if s.ident.pos.line != line:
            continue
        col_start = s.ident.pos.col
        col_end = col_start + len(s.ident.name)
        if col_start <= col < col_end:
            return s
    return None
