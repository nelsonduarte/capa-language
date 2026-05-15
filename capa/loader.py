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

- ``pub`` visibility enforcement (every top-level item is exported).
- Cross-file error messages with the imported file's source
  snippet rendered (positions are correct; snippet may be from
  the wrong file). Acceptable for v1, a v2 fix.

Resolution order for ``import foo.bar``:

1. ``<importer-dir>/foo/bar.capa`` (proximity wins, same as the
   first MVP).
2. ``<root>/foo/bar.capa`` for each ``root`` in the configured
   ``search_paths`` (typically passed by the CLI after reading the
   ``CAPA_PATH`` environment variable).

The first existing candidate is returned. If none match, the
LoaderError lists every path that was tried.
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
    # Per-import-alias map: alias name -> set of top-level names it
    # contributes. Populated by the linker as each Import is
    # processed. Used by the post-link rewrite pass that turns
    # ``mod.fn(args)`` into ``fn(args)`` when ``mod`` is a known
    # import alias.
    module_exports: dict[str, set[str]] = field(default_factory=dict)


class ModuleLoader:
    """Resolves and parses Capa modules transitively.

    The loader is stateful: it caches parsed modules by their
    canonical (resolved) absolute path, so re-importing the same
    file from two places does the I/O + parsing exactly once.
    """

    def __init__(
        self,
        search_paths: Optional[list[Path]] = None,
    ) -> None:
        self._cache: dict[Path, A.Module] = {}
        self._sources: dict[Path, str] = {}
        self._loading: list[Path] = []  # stack for cycle detection
        # alias -> set of top-level names declared in that import's
        # target file. Populated as each Import is processed.
        # Powers the post-link "qualified call" rewrite (foo.fn()
        # -> fn() when foo is a registered alias).
        self._module_exports: dict[str, set[str]] = {}
        # Additional directories searched (in order) after the
        # importer-relative path fails to resolve. Typically the
        # CLI populates this from the ``CAPA_PATH`` env var so
        # stdlib-style modules can live outside the project tree.
        self._search_paths: list[Path] = list(search_paths or [])

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
        # Post-link rewrite: `mod.fn(args)` becomes `fn(args)`
        # when `mod` is a known import alias and `fn` is one of
        # that module's directly-declared names. The merged AST
        # already has every function at top level (unqualified);
        # we are only removing the intermediate receiver lookup
        # so the analyzer + transpiler see a plain function call.
        if self._module_exports:
            _rewrite_qualified_calls(merged, self._module_exports)
        sources = {str(p): src for p, src in self._sources.items()}
        return LinkedModule(
            module=merged,
            sources=sources,
            module_exports=dict(self._module_exports),
        )

    # -------- internals --------

    def _candidate_paths(
        self, path_parts: list[str], from_dir: Path,
    ) -> list[Path]:
        """Every path the loader will try to resolve ``import
        foo.bar`` to, in priority order. Importer-relative comes
        first so a project-local module always shadows one of the
        same name on the search path.
        """
        rel = Path(*path_parts).with_suffix(".capa")
        return [from_dir / rel] + [root / rel for root in self._search_paths]

    def _resolve(self, path_parts: list[str], from_dir: Path) -> Optional[Path]:
        """Return the first existing candidate path, or ``None``."""
        for c in self._candidate_paths(path_parts, from_dir):
            if c.exists():
                return c.resolve()
        return None

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

        if target is None:
            # No candidate matched. Report every path that was
            # tried so the user can tell whether they need to
            # adjust CAPA_PATH or the import statement itself.
            joined = ".".join(imp.path)
            tried = self._candidate_paths(imp.path, module_dir)
            tried_msg = "; ".join(str(p) for p in tried)
            raise LoaderError(
                f"cannot resolve 'import {joined}': tried {tried_msg}",
                pos=imp.pos,
                filename=str(module_path),
            )

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

        # Record the import's alias + the set of names it
        # directly contributes (not transitive). Default alias is
        # the last segment of the dotted path; ``as`` overrides.
        alias = imp.alias or imp.path[-1]
        direct_names: set[str] = set()
        for it in imported.items:
            if isinstance(it, A.Import):
                continue
            name = _item_name(it)
            if name is not None:
                direct_names.add(name)
        # Two imports with the same alias would clash on the
        # rewrite side; the user wrote two `import foo` (or
        # `import a as F` and `import b as F`). Detect early and
        # report instead of silently overwriting.
        if alias in self._module_exports and self._module_exports[alias] != direct_names:
            raise LoaderError(
                f"two imports share the alias '{alias}'; "
                f"use 'import ... as <name>' to disambiguate",
                pos=imp.pos,
                filename=str(module_path),
            )
        self._module_exports[alias] = direct_names


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


def _rewrite_qualified_calls(
    module: "A.Module",
    module_exports: dict[str, set[str]],
) -> None:
    """Walk ``module`` in place and rewrite every ``MethodCall``
    whose receiver is ``Ident(alias)`` (where ``alias`` is a
    registered import) and whose method is one of the directly-
    declared names of that import. The rewrite replaces the
    MethodCall node's contents with a ``Call`` to ``Ident(method)``,
    keeping the same arguments.

    Why this approach: the loader already merges imported items
    at the top of the linked module, so every imported function
    is in the global scope under its bare name. Rewriting the
    receiver away means the analyzer and transpiler do not need
    to know about modules at all; they just see a regular
    function call.

    Implementation: we cannot replace AST nodes wholesale because
    parent nodes hold strong references. Instead we mutate the
    existing ``MethodCall`` into a shape that the existing
    pipeline already handles, by changing it to a ``Call`` of an
    ``Ident``. Since the class has different fields we substitute
    the parent's slot.
    """
    rewriter = _Rewriter(module_exports)
    rewriter.visit_module(module)


class _Rewriter:
    """Single-purpose AST mutator: replace
    ``MethodCall(Ident(alias), method, args)`` with
    ``Call(Ident(method), args)`` when ``alias`` is a registered
    import. The walker is exhaustive across statement and
    expression node types Capa currently has; new node types
    added later need a clause here to keep the rewrite working
    inside them.
    """

    def __init__(self, module_exports: dict[str, set[str]]) -> None:
        self.module_exports = module_exports

    def visit_module(self, m: A.Module) -> None:
        for item in m.items:
            self.visit_item(item)

    def visit_item(self, item: A.Item) -> None:
        if isinstance(item, A.FunDecl):
            if item.body is not None:
                self.visit_block(item.body)
        elif isinstance(item, A.ConstDecl):
            item.value = self.visit_expr(item.value)
        elif isinstance(item, A.ImplBlock):
            for method in item.methods:
                if method.body is not None:
                    self.visit_block(method.body)
        # Other items (TypeStruct, TypeSum, TraitDecl, Import) have
        # no expression-bearing slots to walk for this rewrite.

    def visit_block(self, b: A.Block) -> None:
        for stmt in b.stmts:
            self.visit_stmt(stmt)

    def visit_stmt(self, s: A.Stmt) -> None:
        if isinstance(s, A.LetStmt):
            s.value = self.visit_expr(s.value)
        elif isinstance(s, A.VarStmt):
            s.value = self.visit_expr(s.value)
        elif isinstance(s, A.AssignStmt):
            s.value = self.visit_expr(s.value)
            s.target = self.visit_expr(s.target)
        elif isinstance(s, A.ReturnStmt):
            if s.value is not None:
                s.value = self.visit_expr(s.value)
        elif isinstance(s, A.ExprStmt):
            s.expr = self.visit_expr(s.expr)
        elif isinstance(s, A.IfStmt):
            s.cond = self.visit_expr(s.cond)
            self.visit_block(s.then_block)
            for i, (cond, block) in enumerate(s.elif_arms):
                new_cond = self.visit_expr(cond)
                self.visit_block(block)
                s.elif_arms[i] = (new_cond, block)
            if s.else_block is not None:
                self.visit_block(s.else_block)
        elif isinstance(s, A.WhileStmt):
            s.cond = self.visit_expr(s.cond)
            self.visit_block(s.body)
        elif isinstance(s, A.ForStmt):
            s.iter = self.visit_expr(s.iter)
            self.visit_block(s.body)
        # BreakStmt / ContinueStmt have no expression slots.

    def visit_expr(self, e: A.Expr) -> A.Expr:
        # MethodCall is the one shape we actively rewrite. Every
        # other expression shape is walked recursively (so a
        # MethodCall nested inside another expression also gets
        # picked up) and returned unchanged.
        if isinstance(e, A.MethodCall):
            # Recurse first into receiver and arguments to handle
            # nested rewrites (e.g. ``foo.fn(bar.gn())``).
            e.receiver = self.visit_expr(e.receiver)
            e.args = [self.visit_expr(a) for a in e.args]
            recv = e.receiver
            if isinstance(recv, A.Ident):
                exports = self.module_exports.get(recv.name)
                if exports is not None and e.method in exports:
                    # Rewrite in place: replace the MethodCall's
                    # callee/args structure with a plain Call.
                    return A.Call(
                        pos=e.pos,
                        callee=A.Ident(pos=recv.pos, name=e.method),
                        type_args=e.type_args,
                        args=e.args,
                        arg_names=e.arg_names,
                    )
            return e
        if isinstance(e, A.Call):
            e.callee = self.visit_expr(e.callee)
            e.args = [self.visit_expr(a) for a in e.args]
            return e
        if isinstance(e, A.BinOp):
            e.left = self.visit_expr(e.left)
            e.right = self.visit_expr(e.right)
            return e
        if isinstance(e, A.UnaryOp):
            e.operand = self.visit_expr(e.operand)
            return e
        if isinstance(e, A.FieldAccess):
            e.receiver = self.visit_expr(e.receiver)
            return e
        if isinstance(e, A.Index):
            e.receiver = self.visit_expr(e.receiver)
            e.index = self.visit_expr(e.index)
            return e
        if isinstance(e, A.Try):
            e.expr = self.visit_expr(e.expr)
            return e
        if isinstance(e, A.StructLit):
            # fields are list[tuple[str, Expr]]; replace in place
            for i, (fname, fexpr) in enumerate(e.fields):
                e.fields[i] = (fname, self.visit_expr(fexpr))
            return e
        if isinstance(e, A.ListLit):
            e.elements = [self.visit_expr(x) for x in e.elements]
            return e
        if isinstance(e, A.TupleLit):
            e.elements = [self.visit_expr(x) for x in e.elements]
            return e
        if isinstance(e, A.InterpolatedString):
            new_parts: list = []
            for p in e.parts:
                if isinstance(p, A.Expr):
                    new_parts.append(self.visit_expr(p))
                else:
                    new_parts.append(p)
            e.parts = new_parts
            return e
        if isinstance(e, A.LambdaExpr):
            if isinstance(e.body, A.Block):
                self.visit_block(e.body)
            else:
                e.body = self.visit_expr(e.body)
            return e
        if isinstance(e, A.MatchExpr):
            e.scrutinee = self.visit_expr(e.scrutinee)
            for arm in e.arms:
                if arm.guard is not None:
                    arm.guard = self.visit_expr(arm.guard)
                if isinstance(arm.body, A.Block):
                    self.visit_block(arm.body)
                else:
                    arm.body = self.visit_expr(arm.body)
            return e
        if isinstance(e, A.IfExpr):
            e.cond = self.visit_expr(e.cond)
            e.then_expr = self.visit_expr(e.then_expr)
            e.else_expr = self.visit_expr(e.else_expr)
            return e
        if isinstance(e, A.RangeExpr):
            e.start = self.visit_expr(e.start)
            e.end = self.visit_expr(e.end)
            return e
        # Leaf nodes (Ident, literals): return as-is.
        return e
