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

- Cross-file error messages with the imported file's source
  snippet rendered (positions are correct; snippet may be from
  the wrong file). Acceptable for v1, a v2 fix.

Visibility (``pub``) is enforced by per-module name mangling
during link. For each non-root imported module the loader picks
a fresh prefix and renames every private item's declaration to
``<prefix>__<name>``; references to those names inside the same
module (Ident, TypeName, ImplBlock.trait_name / type_name,
StructLit.type_name) are rewritten to match. Public items keep
their original names. The importer's call to a private function
hits a regular "undefined name" diagnostic because the original
name is no longer in the merged scope.

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
    # import alias. Only ``pub`` items appear here.
    module_exports: dict[str, set[str]] = field(default_factory=dict)
    # Per-import-alias map of *private* names (original, unmangled).
    # Consulted by the analyzer when an "undefined name" lookup
    # would otherwise produce only a typo hint: a name that matches
    # an entry here yields a "private to module 'X'; mark it 'pub'
    # to expose" diagnostic instead.
    module_privates: dict[str, set[str]] = field(default_factory=dict)


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
        # Monotonic counter that produces a unique mangle prefix
        # for each non-root imported module. Used by
        # ``_mangle_private_items`` to keep private items from
        # two different modules out of one another's way.
        self._mangle_counter: int = 0
        # alias -> set of *private* top-level names (original,
        # unmangled). Used by the analyzer for the specialised
        # "private to module X" diagnostic; never consulted by
        # the qualified-call rewriter (privates must not rewrite).
        self._module_privates: dict[str, set[str]] = {}

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
            module_privates=dict(self._module_privates),
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

        # Enforce ``pub`` visibility on this imported module: rename
        # every private top-level item, and rewrite references to
        # those names that occur inside this module's own items. The
        # root module is never mangled (callers in the root see one
        # another regardless of ``pub``); only imported modules are.
        # The rename map's keys are the original (unmangled) private
        # names; we hold on to them so the analyzer can produce the
        # "private to module" diagnostic.
        self._mangle_counter += 1
        prefix = f"_capa_m{self._mangle_counter}"
        private_rename = _mangle_private_items(imported, prefix)

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
        # Only ``pub`` items are recorded: the qualified-call
        # rewriter uses this map to decide whether ``alias.fn()``
        # should be rewritten to a direct ``fn()`` call, and
        # private items must not be reachable via qualified
        # access either.
        alias = imp.alias or imp.path[-1]
        direct_names: set[str] = set()
        for it in imported.items:
            if isinstance(it, A.Import):
                continue
            if not getattr(it, "is_pub", False):
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
        # Track which names this import contributed *privately*, so
        # the analyzer can specialise "undefined name" diagnostics
        # when the user reached for a private item.
        existing_privates = self._module_privates.get(alias, set())
        self._module_privates[alias] = existing_privates | set(private_rename.keys())


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


def _mangle_private_items(
    module: "A.Module",
    prefix: str,
) -> dict[str, str]:
    """In place: rename every private top-level item in ``module``
    to ``<prefix>__<name>`` and rewrite every internal reference
    (Ident, TypeName, ImplBlock.trait_name / type_name,
    StructLit.type_name) to the new name. Returns the rename map
    so callers can inspect or report on what changed.

    Why this approach: the merged AST stays flat (the analyzer
    sees a single global scope), but the importer's references to
    a private name no longer find a matching declaration because
    the declaration carries a mangled name now. The analyzer's
    existing "undefined name" diagnostic fires, which is the
    enforcement we want. Public items are not mangled, so
    importers continue to call them by their declared names.

    Items without an ``is_pub`` slot (impl blocks) are skipped at
    the rename step; their inner contents are still walked so any
    references they make to names that *did* get mangled get
    rewritten too.
    """
    rename: dict[str, str] = {}
    for item in module.items:
        if isinstance(item, A.Import):
            continue
        if not hasattr(item, "is_pub"):
            continue  # ImplBlock has no is_pub
        if item.is_pub:
            continue
        name = _item_name(item)
        if name is None:
            continue
        new_name = f"{prefix}__{name}"
        rename[name] = new_name
        # All five item types that carry ``is_pub`` also expose a
        # ``name`` attribute. Updating it in place is the only
        # change at the declaration site.
        item.name = new_name
    if rename:
        _PrivateRenameWalker(rename).visit_module(module)
    return rename


class _PrivateRenameWalker:
    """AST walker that rewrites every reference whose name is a
    key in ``rename`` to the mapped name.

    Scope of the rewrite is deliberately limited to names that
    refer to *top-level items*:

    - ``Ident.name`` (function / constant references; also the
      receiver position of a method call before qualified rewrite).
    - ``TypeName.name`` (named types in annotations).
    - ``ImplBlock.trait_name`` / ``ImplBlock.type_name``.
    - ``StructLit.type_name``.

    Pattern bindings, parameter names, local variables, struct
    field names, sum-type variant names, attribute names, and
    method names on traits are *not* rewritten because they do
    not denote top-level items.
    """

    def __init__(self, rename: dict[str, str]) -> None:
        self.rename = rename

    def _r(self, name: str) -> str:
        return self.rename.get(name, name)

    # ---- module / item ----

    def visit_module(self, m: "A.Module") -> None:
        for item in m.items:
            self.visit_item(item)

    def visit_item(self, item) -> None:
        if isinstance(item, A.FunDecl):
            self._visit_fun(item)
        elif isinstance(item, A.ConstDecl):
            self.visit_type(item.type_expr)
            self.visit_expr(item.value)
        elif isinstance(item, A.TypeStruct):
            for f in item.fields:
                self.visit_type(f.type_expr)
        elif isinstance(item, A.TypeSum):
            for v in item.variants:
                if v.payload is not None:
                    self.visit_type(v.payload)
        elif isinstance(item, A.TraitDecl):
            for ms in item.methods:
                for p in ms.params:
                    if p.type_expr is not None:
                        self.visit_type(p.type_expr)
                if ms.return_type is not None:
                    self.visit_type(ms.return_type)
        elif isinstance(item, A.ImplBlock):
            if item.trait_name is not None:
                item.trait_name = self._r(item.trait_name)
            item.type_name = self._r(item.type_name)
            for ta in item.type_args:
                self.visit_type(ta)
            for m in item.methods:
                self._visit_fun(m)

    def _visit_fun(self, fn: "A.FunDecl") -> None:
        for p in fn.params:
            if p.type_expr is not None:
                self.visit_type(p.type_expr)
        if fn.return_type is not None:
            self.visit_type(fn.return_type)
        if fn.body is not None:
            self.visit_block(fn.body)

    # ---- type expressions ----

    def visit_type(self, t) -> None:
        if isinstance(t, A.TypeName):
            t.name = self._r(t.name)
            for arg in t.args:
                self.visit_type(arg)
        elif isinstance(t, A.FunType):
            for p in t.param_types:
                self.visit_type(p)
            self.visit_type(t.return_type)
        elif isinstance(t, A.TupleType):
            for e in t.elements:
                self.visit_type(e)
        # UnitType: nothing.

    # ---- statements ----

    def visit_block(self, b: "A.Block") -> None:
        for s in b.stmts:
            self.visit_stmt(s)

    def visit_stmt(self, s) -> None:
        if isinstance(s, A.LetStmt):
            if s.type_expr is not None:
                self.visit_type(s.type_expr)
            self.visit_expr(s.value)
        elif isinstance(s, A.VarStmt):
            if s.type_expr is not None:
                self.visit_type(s.type_expr)
            self.visit_expr(s.value)
        elif isinstance(s, A.AssignStmt):
            self.visit_expr(s.value)
            self.visit_expr(s.target)
        elif isinstance(s, A.ReturnStmt):
            if s.value is not None:
                self.visit_expr(s.value)
        elif isinstance(s, A.ExprStmt):
            self.visit_expr(s.expr)
        elif isinstance(s, A.IfStmt):
            self.visit_expr(s.cond)
            self.visit_block(s.then_block)
            for cond, blk in s.elif_arms:
                self.visit_expr(cond)
                self.visit_block(blk)
            if s.else_block is not None:
                self.visit_block(s.else_block)
        elif isinstance(s, A.WhileStmt):
            self.visit_expr(s.cond)
            self.visit_block(s.body)
        elif isinstance(s, A.ForStmt):
            self.visit_expr(s.iter)
            self.visit_block(s.body)
        # BreakStmt / ContinueStmt: nothing.

    # ---- expressions ----

    def visit_expr(self, e) -> None:
        if isinstance(e, A.Ident):
            e.name = self._r(e.name)
            return
        if isinstance(e, A.Call):
            self.visit_expr(e.callee)
            for ta in e.type_args:
                self.visit_type(ta)
            for a in e.args:
                self.visit_expr(a)
            return
        if isinstance(e, A.MethodCall):
            self.visit_expr(e.receiver)
            for ta in e.type_args:
                self.visit_type(ta)
            for a in e.args:
                self.visit_expr(a)
            return
        if isinstance(e, A.BinOp):
            self.visit_expr(e.left)
            self.visit_expr(e.right)
            return
        if isinstance(e, A.UnaryOp):
            self.visit_expr(e.operand)
            return
        if isinstance(e, A.FieldAccess):
            self.visit_expr(e.receiver)
            return
        if isinstance(e, A.Index):
            self.visit_expr(e.receiver)
            self.visit_expr(e.index)
            return
        if isinstance(e, A.Try):
            self.visit_expr(e.expr)
            return
        if isinstance(e, A.StructLit):
            e.type_name = self._r(e.type_name)
            for ta in e.type_args:
                self.visit_type(ta)
            for _, fexpr in e.fields:
                self.visit_expr(fexpr)
            return
        if isinstance(e, A.ListLit):
            for x in e.elements:
                self.visit_expr(x)
            return
        if isinstance(e, A.TupleLit):
            for x in e.elements:
                self.visit_expr(x)
            return
        if isinstance(e, A.InterpolatedString):
            for p in e.parts:
                if isinstance(p, A.Expr):
                    self.visit_expr(p)
            return
        if isinstance(e, A.LambdaExpr):
            for p in e.params:
                if p.type_expr is not None:
                    self.visit_type(p.type_expr)
            if e.return_type is not None:
                self.visit_type(e.return_type)
            if isinstance(e.body, A.Block):
                self.visit_block(e.body)
            else:
                self.visit_expr(e.body)
            return
        if isinstance(e, A.MatchExpr):
            self.visit_expr(e.scrutinee)
            for arm in e.arms:
                if arm.guard is not None:
                    self.visit_expr(arm.guard)
                if isinstance(arm.body, A.Block):
                    self.visit_block(arm.body)
                else:
                    self.visit_expr(arm.body)
            return
        if isinstance(e, A.IfExpr):
            self.visit_expr(e.cond)
            self.visit_expr(e.then_expr)
            self.visit_expr(e.else_expr)
            return
        if isinstance(e, A.RangeExpr):
            self.visit_expr(e.start)
            self.visit_expr(e.end)
            return
        # Leaf nodes (literals, BoolLit, etc.): nothing.
