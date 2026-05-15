"""Capa module loader and linker.

Resolves ``import foo.bar`` references, parses each imported file,
and merges the imported modules' top-level items into a single
linked AST that the analyzer can type-check as one unit.

This is the **MVP** module system:

- ``import foo.bar`` resolves to ``<importer-dir>/foo/bar.capa``.
- All top-level declarations (``fun``, ``type``, ``trait``,
  ``capability``, ``impl``, ``const``) of the imported module
  become accessible **unqualified** in the importing module.
- The ``as`` alias is parsed but ignored at link time; future
  iterations can use it for qualified access.
- Transitive imports are followed depth-first; each file is
  loaded at most once (cached by resolved path).
- Cyclic imports raise a ``LoaderError`` that names the cycle.
- Name conflicts (two imported items with the same top-level
  name) are detected at link time and reported with both
  source locations.

What this MVP does **not** do:

- Per-module namespacing or qualified access (no ``foo.bar.fn``).
- ``pub`` visibility enforcement (every top-level item is exported).
- Stdlib path resolution (only relative paths from importer dir).
- Cross-file error messages with the imported file's source
  snippet rendered (positions are correct; snippet may be from
  the wrong file). Acceptable for v1, a v2 fix.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import capa_ast as A
from .lexer import Lexer, LexerError
from .parser import Parser
from .tokens import Pos


class LoaderError(Exception):
    """Error from the loader / linker phase. Carries an optional
    position (in the importing file) and the importer's filename
    so the CLI can render a single-line diagnostic in the same
    shape as analyzer / parser errors.
    """

    def __init__(
        self, message: str,
        pos: Optional[Pos] = None,
        filename: str = "",
    ):
        super().__init__(message)
        self.message = message
        self.pos = pos
        self.filename = filename

    def format(self) -> str:
        if self.pos is not None:
            return (
                f"{self.filename}:{self.pos.line}:{self.pos.col}: "
                f"error: {self.message}"
            )
        return f"{self.filename}: error: {self.message}"


@dataclass
class LinkedModule:
    """Result of linking a root Capa module with its transitive
    imports. ``module`` is the merged AST (Import nodes removed,
    all imported items inlined); ``sources`` maps each
    contributing file's absolute path to its source text, used by
    the CLI's error formatter to render snippets from the right
    file when an error originates in an imported module.
    """
    module: A.Module
    sources: dict[str, str] = field(default_factory=dict)


class ModuleLoader:
    """Resolves and parses Capa modules transitively.

    The loader is stateful: it caches parsed modules by their
    canonical (resolved) absolute path, so re-importing the same
    file from two places does the I/O + parsing exactly once.
    """

    def __init__(self) -> None:
        self._cache: dict[Path, A.Module] = {}
        self._sources: dict[Path, str] = {}
        self._loading: list[Path] = []  # stack for cycle detection

    # -------- public entry points --------

    def load_root(
        self,
        source: str,
        filename: str,
    ) -> LinkedModule:
        """Parse the already-read root source, then recursively load
        every imported module. Returns a flat LinkedModule with the
        merged item list and a source map for diagnostics.
        """
        root_path = Path(filename).resolve()
        root_dir = (
            root_path.parent if root_path.is_absolute() or root_path.exists()
            else Path.cwd()
        )
        try:
            tokens = Lexer(source, filename=filename).lex()
        except LexerError:
            raise  # caller (CLI) handles lex errors uniformly
        root_module = Parser(
            tokens, source=source, filename=filename,
        ).parse_module()
        self._cache[root_path] = root_module
        self._sources[root_path] = source

        # Recursively load imports and collect them into a flat
        # item list. Deduplicate by resolved path; preserve a
        # deterministic order (depth-first, root last).
        flat_items: list[A.Item] = []
        seen_paths: set[Path] = set()
        # Track name -> (Pos, source_file) for conflict detection.
        decl_origin: dict[str, tuple[Pos, str]] = {}

        self._link(
            root_module, root_path, root_dir,
            flat_items, seen_paths, decl_origin,
        )

        merged = A.Module(pos=root_module.pos, items=flat_items)
        sources = {str(p): src for p, src in self._sources.items()}
        return LinkedModule(module=merged, sources=sources)

    # -------- internals --------

    def _resolve(self, path_parts: list[str], from_dir: Path) -> Path:
        """Resolve ``import foo.bar`` to ``<from_dir>/foo/bar.capa``."""
        rel = Path(*path_parts).with_suffix(".capa")
        return (from_dir / rel).resolve()

    def _link(
        self,
        module: A.Module,
        module_path: Path,
        module_dir: Path,
        out_items: list[A.Item],
        seen_paths: set[Path],
        decl_origin: dict[str, tuple[Pos, str]],
    ) -> None:
        """Append ``module``'s items (and those of its transitive
        imports) to ``out_items``. Resolves imports relative to
        ``module_dir``.
        """
        # First pass: pull in items from this module's imports
        # (depth-first, so dependencies are loaded before their
        # dependents). Skip the Import nodes themselves; the
        # imported items are merged in their stead.
        for item in module.items:
            if isinstance(item, A.Import):
                self._handle_import(
                    item, module_dir, module_path,
                    out_items, seen_paths, decl_origin,
                )

        # Second pass: emit this module's own items, checking for
        # name conflicts with what's already been linked.
        for item in module.items:
            if isinstance(item, A.Import):
                continue  # already handled
            name = _item_name(item)
            if name is None:
                # No top-level name (e.g. an impl block).
                # Impls are matched by their target type at
                # analyze time, so we emit them as-is and let
                # the analyzer's existing checks handle them.
                out_items.append(item)
                continue
            if name in decl_origin:
                prev_pos, prev_file = decl_origin[name]
                raise LoaderError(
                    f"name conflict: '{name}' declared in "
                    f"{prev_file} (line {prev_pos.line}) and "
                    f"{module_path} (line {item.pos.line}). "
                    f"Either rename one or pick the import "
                    f"explicitly.",
                    pos=item.pos,
                    filename=str(module_path),
                )
            decl_origin[name] = (item.pos, str(module_path))
            out_items.append(item)

    def _handle_import(
        self,
        imp: A.Import,
        module_dir: Path,
        module_path: Path,
        out_items: list[A.Item],
        seen_paths: set[Path],
        decl_origin: dict[str, tuple[Pos, str]],
    ) -> None:
        target = self._resolve(imp.path, module_dir)

        if target in seen_paths:
            # Already linked: this is the multi-import deduplication
            # path. No work to do.
            return
        if target in self._loading:
            # Cycle detected. Render the cycle for the error.
            cycle = " -> ".join(str(p) for p in self._loading) + f" -> {target}"
            raise LoaderError(
                f"cyclic import: {cycle}",
                pos=imp.pos,
                filename=str(module_path),
            )

        if not target.exists():
            joined = ".".join(imp.path)
            raise LoaderError(
                f"cannot resolve 'import {joined}': "
                f"expected file at {target}",
                pos=imp.pos,
                filename=str(module_path),
            )

        try:
            source = target.read_text(encoding="utf-8")
        except OSError as e:
            raise LoaderError(
                f"cannot read {target}: {e}",
                pos=imp.pos,
                filename=str(module_path),
            )

        try:
            tokens = Lexer(source, filename=str(target)).lex()
            imported = Parser(
                tokens, source=source, filename=str(target),
            ).parse_module()
        except LexerError as e:
            # Re-raise so the CLI's existing lexer-error formatter
            # handles it. The filename on the error is already the
            # imported file's path.
            raise

        self._loading.append(target)
        self._cache[target] = imported
        self._sources[target] = source
        try:
            self._link(
                imported, target, target.parent,
                out_items, seen_paths, decl_origin,
            )
        finally:
            self._loading.pop()
        seen_paths.add(target)


def _item_name(item: A.Item) -> Optional[str]:
    """The top-level name of an item (for conflict detection).

    Returns ``None`` for items that do not introduce a top-level
    name (currently: impl blocks). ``Import`` is handled outside
    this function.
    """
    if isinstance(item, A.FunDecl):
        return item.name
    if isinstance(item, A.ConstDecl):
        return item.name
    if isinstance(item, A.TypeStruct):
        return item.name
    if isinstance(item, A.TypeSum):
        return item.name
    if isinstance(item, A.TraitDecl):
        # Capability declarations share the TraitDecl class with
        # ``is_capability=True``; the name is taken the same way.
        return item.name
    return None
