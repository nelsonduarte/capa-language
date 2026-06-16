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
        # Resolved path -> the (alias, selectors) signature of the
        # FIRST import that linked it. A later import of the same path
        # is normally deduplicated to a no-op; but if its selection
        # diverges (whole-module after a selective view, or two
        # different selective views), the dedup would silently drop the
        # second import and only the first view would survive. We keep
        # the first signature so the dedup path can detect a divergent
        # re-import and error instead of hiding symbols. See
        # ``_import_signature``.
        self._import_sig: dict[Path, tuple] = {}

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
        # Make the root file's directory a fallback search path so a
        # nested submodule (e.g. ``sinks/csv_sink.capa``) can do
        # ``import domain`` and find the sibling of the root
        # (``./domain.capa``) without forcing the project to flatten
        # its layout. Appended at lowest priority so it does not
        # shadow CAPA_PATH or ./libraries; de-duped.
        if root_dir not in self._search_paths:
            self._search_paths.append(root_dir)
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

    def _package_modules(self, pkg_name: str, from_dir: Path) -> list[str]:
        """If ``pkg_name`` names a directory of modules under the
        importer dir or any search root, return its importable
        ``<pkg>.<stem>`` names, sorted and de-duped across roots.
        Returns ``[]`` when no such package directory exists or it
        holds no top-level ``.capa`` files. Subdirectories are not
        recursed; only direct ``*.capa`` children are modules.
        """
        stems: set[str] = set()
        found_dir = False
        for root in [from_dir, *self._search_paths]:
            pkg_dir = root / pkg_name
            if not pkg_dir.is_dir():
                continue
            found_dir = True
            for f in pkg_dir.glob("*.capa"):
                if f.is_file():
                    stems.add(f.stem)
        if not found_dir or not stems:
            return []
        return sorted(f"{pkg_name}.{s}" for s in stems)

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
            joined = ".".join(imp.path)
            # A bare ``import pkg`` that names a package *directory*
            # (not a module file) is a common slip. Point at the
            # modules it actually offers instead of the raw paths.
            if len(imp.path) == 1:
                modules = self._package_modules(imp.path[0], module_dir)
                if modules:
                    raise LoaderError(
                        f"cannot resolve 'import {joined}': "
                        f"'{joined}' is a package directory, not a "
                        f"module. Import one of its modules: "
                        f"{', '.join(modules)}",
                        pos=imp.pos,
                        filename=str(module_path),
                    )
            # No candidate matched. Report every path that was
            # tried so the user can tell whether they need to
            # adjust CAPA_PATH or the import statement itself.
            tried = self._candidate_paths(imp.path, module_dir)
            tried_msg = "; ".join(str(p) for p in tried)
            raise LoaderError(
                f"cannot resolve 'import {joined}': tried {tried_msg}",
                pos=imp.pos,
                filename=str(module_path),
            )

        if target in seen_paths:
            # Already linked: this is the multi-import deduplication
            # path. A second import of the SAME path is a benign no-op
            # *only* when it asks for the same view as the first. A
            # divergent re-import (e.g. ``import lib (foo)`` then a
            # whole ``import lib``, or two different selective lists)
            # would be silently dropped here, leaving only the first
            # view's symbols available with no diagnostic. The reverse
            # order happens to expose more, so the visible surface
            # would depend on import order. Refuse the divergence
            # outright.
            prior_sig = self._import_sig.get(target)
            this_sig = _import_signature(imp)
            if prior_sig is not None and prior_sig != this_sig:
                joined = ".".join(imp.path)
                raise LoaderError(
                    f"module '{joined}' imported twice with different "
                    f"selection: the first import and this one ask for "
                    f"different symbols, so which symbols end up visible "
                    f"would depend on import order. Make the two imports "
                    f"identical, or merge them into one import that "
                    f"selects every symbol you need.",
                    pos=imp.pos,
                    filename=str(module_path),
                )
            return
        if target in self._loading:
            # Cycle detected. Render the cycle for the error.
            cycle = " -> ".join(str(p) for p in self._loading) + f" -> {target}"
            raise LoaderError(
                f"cyclic import: {cycle}",
                pos=imp.pos,
                filename=str(module_path),
            )

        # First import of this path: remember its selection signature
        # so a later divergent re-import (handled in the dedup branch
        # above) can be refused rather than silently dropped.
        self._import_sig[target] = _import_signature(imp)

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

        # Selective import (``import foo (a, b as c)``): hide every
        # pub item the importer did not ask for, and apply per-symbol
        # ``as`` renames. Runs after private mangling so the two
        # rename maps key on disjoint (original) names. Validation
        # (unknown / non-pub symbol) happens here against the just-
        # parsed module, before any references are rewritten.
        selective_rename: dict[str, str] = {}
        if imp.selectors is not None:
            selective_rename = _apply_selective_import(
                imp, imported, prefix, module_path,
            )

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
        if imp.selectors is not None:
            # Selective import: only the selected symbols are visible,
            # under their final (aliased-or-original) names. The
            # unselected pub items were mangled out of scope above, so
            # ``foo.unselected()`` correctly fails to resolve.
            direct_names = set(selective_rename.values())
        else:
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


def _import_signature(imp: "A.Import") -> tuple:
    """A hashable, order-independent fingerprint of what an import
    brings into scope: its alias and its selector set. Two imports of
    the same path with equal signatures are the same view (a benign
    no-op on the second); unequal signatures diverge (whole vs
    selective, or two different selective lists) and must not be
    silently deduplicated. Selectors are normalised to a frozenset so
    ``(a, b)`` and ``(b, a)`` compare equal."""
    selectors = (
        None if imp.selectors is None
        else frozenset(imp.selectors)
    )
    return (imp.alias, selectors)


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


def _names_bound_by_pattern(p: A.Pattern, out: set[str]) -> None:
    """Add every name introduced by ``p`` (recursively) to ``out``.
    Used by :func:`_collect_bound_names` to assemble the shadow
    set the qualified-call rewriter consults."""
    if isinstance(p, A.IdentPat):
        out.add(p.name)
    elif isinstance(p, A.VariantPat):
        for sub in p.payloads:
            _names_bound_by_pattern(sub, out)
    elif isinstance(p, A.TuplePat):
        for sub in p.elements:
            _names_bound_by_pattern(sub, out)
    elif isinstance(p, A.StructPat):
        # ``Foo { x }`` (shorthand for ``x: x``) binds ``x``.
        # ``Foo { x: pat }`` recurses into ``pat``.
        for (fname, sub) in p.fields:
            if sub is None:
                out.add(fname)
            else:
                _names_bound_by_pattern(sub, out)
    # WildcardPat / LiteralPat / OrPat (v0: no bindings inside
    # alternatives) introduce no names.


def _collect_bound_names(fn: A.FunDecl) -> set[str]:
    """Return every name that becomes a local binding inside
    ``fn``: parameters, ``let`` / ``var`` / ``for`` patterns,
    ``match`` arm pattern binders, and ``LambdaExpr`` params.

    Scope is function-level, not block-level: a ``let foo = ...``
    on line 10 marks ``foo`` as shadowed for every line of the
    function, not just lines 10+. That is over-conservative
    (a use on line 5 that pre-dates the local binding would be
    treated as shadowed too) but SOUND: we never silently drop a
    method call's receiver and rewrite it as a free-function
    call when the receiver could refer to a local. The user
    workaround if they want the pre-line-10 use to be the module
    call is to either rename the local or call the module
    function bare; both are obvious from the error site."""
    names: set[str] = set()
    for p in fn.params:
        names.add(p.name)
    if fn.body is not None:
        _walk_block_for_binders(fn.body, names)
    return names


def _walk_block_for_binders(b: A.Block, names: set[str]) -> None:
    for stmt in b.stmts:
        _walk_stmt_for_binders(stmt, names)


def _walk_stmt_for_binders(s: A.Stmt, names: set[str]) -> None:
    if isinstance(s, A.LetStmt):
        _names_bound_by_pattern(s.pattern, names)
        _walk_expr_for_binders(s.value, names)
    elif isinstance(s, A.VarStmt):
        names.add(s.name)
        _walk_expr_for_binders(s.value, names)
    elif isinstance(s, A.AssignStmt):
        _walk_expr_for_binders(s.target, names)
        _walk_expr_for_binders(s.value, names)
    elif isinstance(s, A.ReturnStmt):
        if s.value is not None:
            _walk_expr_for_binders(s.value, names)
    elif isinstance(s, A.ExprStmt):
        _walk_expr_for_binders(s.expr, names)
    elif isinstance(s, A.IfStmt):
        _walk_expr_for_binders(s.cond, names)
        _walk_block_for_binders(s.then_block, names)
        for (cond, blk) in s.elif_arms:
            _walk_expr_for_binders(cond, names)
            _walk_block_for_binders(blk, names)
        if s.else_block is not None:
            _walk_block_for_binders(s.else_block, names)
    elif isinstance(s, A.WhileStmt):
        _walk_expr_for_binders(s.cond, names)
        _walk_block_for_binders(s.body, names)
    elif isinstance(s, A.ForStmt):
        _names_bound_by_pattern(s.pattern, names)
        _walk_expr_for_binders(s.iter, names)
        _walk_block_for_binders(s.body, names)
    # BreakStmt / ContinueStmt: nothing to walk.


def _walk_expr_for_binders(e: A.Expr, names: set[str]) -> None:
    if isinstance(e, A.LambdaExpr):
        for p in e.params:
            names.add(p.name)
        if isinstance(e.body, A.Block):
            _walk_block_for_binders(e.body, names)
        else:
            _walk_expr_for_binders(e.body, names)
    elif isinstance(e, A.MatchExpr):
        _walk_expr_for_binders(e.scrutinee, names)
        for arm in e.arms:
            _names_bound_by_pattern(arm.pattern, names)
            if arm.guard is not None:
                _walk_expr_for_binders(arm.guard, names)
            if isinstance(arm.body, A.Block):
                _walk_block_for_binders(arm.body, names)
            else:
                _walk_expr_for_binders(arm.body, names)
    elif isinstance(e, A.IfExpr):
        _walk_expr_for_binders(e.cond, names)
        _walk_expr_for_binders(e.then_expr, names)
        _walk_expr_for_binders(e.else_expr, names)
    elif isinstance(e, A.Call):
        _walk_expr_for_binders(e.callee, names)
        for a in e.args:
            _walk_expr_for_binders(a, names)
    elif isinstance(e, A.MethodCall):
        _walk_expr_for_binders(e.receiver, names)
        for a in e.args:
            _walk_expr_for_binders(a, names)
    elif isinstance(e, A.BinOp):
        _walk_expr_for_binders(e.left, names)
        _walk_expr_for_binders(e.right, names)
    elif isinstance(e, A.UnaryOp):
        _walk_expr_for_binders(e.operand, names)
    elif isinstance(e, A.FieldAccess):
        _walk_expr_for_binders(e.receiver, names)
    elif isinstance(e, A.Index):
        _walk_expr_for_binders(e.receiver, names)
        _walk_expr_for_binders(e.index, names)
    elif isinstance(e, A.Try):
        _walk_expr_for_binders(e.expr, names)
    elif isinstance(e, A.StructLit):
        for (_, fexpr) in e.fields:
            _walk_expr_for_binders(fexpr, names)
    elif isinstance(e, (A.ListLit, A.TupleLit)):
        for x in e.elements:
            _walk_expr_for_binders(x, names)
    elif isinstance(e, A.InterpolatedString):
        for p in e.parts:
            if isinstance(p, A.Expr):
                _walk_expr_for_binders(p, names)
    elif isinstance(e, A.RangeExpr):
        _walk_expr_for_binders(e.start, names)
        _walk_expr_for_binders(e.end, names)
    # Leaf exprs (Ident, *Lit, ...) introduce nothing.


class _Rewriter:
    """Single-purpose AST mutator: replace
    ``MethodCall(Ident(alias), method, args)`` with
    ``Call(Ident(method), args)`` when ``alias`` is a registered
    import. The walker is exhaustive across statement and
    expression node types Capa currently has; new node types
    added later need a clause here to keep the rewrite working
    inside them.

    Scope-aware: before each function/method body is walked, the
    set of names introduced as local bindings (parameters, let /
    var / for / match-pattern / lambda-param) is collected via
    :func:`_collect_bound_names` and stashed on ``_locals``. The
    MethodCall rewrite then skips when the receiver's name is in
    that set, since the local binding shadows whatever module
    alias the same name might otherwise refer to. This prevents
    e.g. ``fun foo(http: GetOnlyHttp) ... http.get(url)`` from
    being silently downgraded into ``get(url)`` when an upstream
    ``import capa_http.http`` registered ``http`` as a module
    alias and capa_http.http exports ``get``.
    """

    def __init__(self, module_exports: dict[str, set[str]]) -> None:
        self.module_exports = module_exports
        # Names that are bound locally in the function/method
        # body currently being walked. Refreshed per-function.
        self._locals: set[str] = set()

    def visit_module(self, m: A.Module) -> None:
        for item in m.items:
            self.visit_item(item)

    def visit_item(self, item: A.Item) -> None:
        if isinstance(item, A.FunDecl):
            if item.body is not None:
                saved = self._locals
                self._locals = _collect_bound_names(item)
                try:
                    self.visit_block(item.body)
                finally:
                    self._locals = saved
        elif isinstance(item, A.ConstDecl):
            item.value = self.visit_expr(item.value)
        elif isinstance(item, A.ImplBlock):
            for method in item.methods:
                if method.body is not None:
                    saved = self._locals
                    self._locals = _collect_bound_names(method)
                    try:
                        self.visit_block(method.body)
                    finally:
                        self._locals = saved
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
            if isinstance(recv, A.Ident) and recv.name not in self._locals:
                exports = self.module_exports.get(recv.name)
                if exports is not None and e.method in exports:
                    # Rewrite in place: replace the MethodCall's
                    # callee/args structure with a plain Call.
                    return A.Call(
                        pos=e.pos,
                        callee=A.Ident(pos=recv.pos, name=e.method),
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


def _apply_selective_import(
    imp: "A.Import",
    module: "A.Module",
    prefix: str,
    importer_path: Path,
) -> dict[str, str]:
    """Restrict a selective ``import foo (a, b as c)`` to its listed
    symbols, renaming where ``as`` was used.

    Two rewrites are folded into one walker pass over ``module``:

    - every ``pub`` top-level item the importer did *not* select is
      renamed to ``<prefix>__sel__<name>`` so it disappears from the
      merged global scope (the same trick :func:`_mangle_private_items`
      uses for private items); and
    - each selected item that carried an ``as`` alias is renamed to
      that alias.

    Returns ``{original_selected_name: visible_name}`` (the visible
    name is the ``as`` alias when present, else the original). The
    caller uses it to populate ``module_exports`` so qualified access
    (``foo.visible_name()``) keeps working.

    Validation happens before any rename: a selector that names a
    symbol the target module does not declare, or declares without
    ``pub``, raises a :class:`LoaderError` anchored at the importing
    file. Sum-type *variants* are intentionally not selectable here.
    A *selected* sum type (no ``as``) keeps its variants' original
    names so its constructors and ``match`` patterns stay usable. A
    *non-selected* (hidden) sum type has its variants hidden too:
    each variant is mangled alongside the type declaration and every
    reference to it inside the module (constructor or ``match``
    pattern) is rewritten, so the variants do not leak into the
    importer's scope and cannot collide with the importer's own
    declarations or with another hidden dependency's variants.

    Renaming a sum type via ``as`` is rejected with a clear error:
    rewriting its variants to track the alias is deferred (see module
    docstring / CHANGELOG), and a half-applied rename would leave the
    variants dangling. Import the type without ``as`` to bring its
    variants.

    The central case this unblocks -- two libraries that both export a
    ``pub fun parse`` -- needs only function/type/const/capability
    renaming, which this covers.
    """
    assert imp.selectors is not None
    # Index the target module's *original* top-level names by their
    # ``pub`` status, so we can validate selectors and decide which
    # pub items to hide. Privates were already mangled by the caller;
    # we index the (post-private-mangle) items: a private item no
    # longer carries its original name, so a selector that named a
    # private will simply be "unknown" -- which is the right error
    # shape ("no public symbol"), since the user cannot select a
    # private regardless.
    pub_names: set[str] = set()
    all_pub_items: list[A.Item] = []
    _item_by_name: dict[str, A.Item] = {}
    for it in module.items:
        if isinstance(it, A.Import):
            continue
        if not getattr(it, "is_pub", False):
            continue
        name = _item_name(it)
        if name is not None:
            pub_names.add(name)
            all_pub_items.append(it)
            _item_by_name[name] = it

    selected_originals: set[str] = set()
    visible: dict[str, str] = {}
    rename: dict[str, str] = {}
    seen_selectors: set[str] = set()
    for (orig, sel_alias) in imp.selectors:
        if orig in seen_selectors:
            raise LoaderError(
                f"symbol '{orig}' is selected more than once in "
                f"'import {'.'.join(imp.path)} (...)'",
                pos=imp.pos,
                filename=str(importer_path),
            )
        seen_selectors.add(orig)
        if orig not in pub_names:
            joined = ".".join(imp.path)
            raise LoaderError(
                f"module '{joined}' has no public symbol '{orig}'. "
                f"Selective imports can only bring 'pub' items; check "
                f"the spelling and that '{orig}' is declared 'pub'.",
                pos=imp.pos,
                filename=str(importer_path),
            )
        if sel_alias is not None and isinstance(
            _item_by_name.get(orig), A.TypeSum
        ):
            # Renaming a sum type would orphan its variants: the type
            # declaration takes the alias but the variant constructors
            # (and ``match`` patterns) still carry the original names,
            # which no longer resolve to the renamed type. Tracking the
            # alias through every variant is deferred, so reject this
            # rather than emit a half-broken import.
            joined = ".".join(imp.path)
            raise LoaderError(
                f"renaming a sum type ('{orig} as {sel_alias}') in a "
                f"selective import is not yet supported; import it "
                f"without 'as' to bring its variants. "
                f"(module '{joined}')",
                pos=imp.pos,
                filename=str(importer_path),
            )
        selected_originals.add(orig)
        target_name = sel_alias if sel_alias is not None else orig
        visible[orig] = target_name
        if sel_alias is not None:
            rename[orig] = sel_alias

    # Hide every pub item that was not selected by mangling its name.
    # For a hidden sum type, hide its variants too: each variant is
    # mangled alongside the type so its constructors and ``match``
    # patterns no longer resolve in the importer's scope (and cannot
    # collide with the importer's own or another dependency's variants).
    for it in all_pub_items:
        name = _item_name(it)
        if name is None or name in selected_originals:
            continue
        rename[name] = f"{prefix}__sel__{name}"
        if isinstance(it, A.TypeSum):
            for v in it.variants:
                rename[v.name] = f"{prefix}__sel__{v.name}"

    if rename:
        # Rename declarations in place, then rewrite references.
        for it in all_pub_items:
            name = _item_name(it)
            if name is not None and name in rename:
                it.name = rename[name]
            # A hidden sum type's variant declarations are renamed
            # too, so the analyzer registers the variants under their
            # mangled names and the originals leave the global scope.
            if isinstance(it, A.TypeSum):
                for v in it.variants:
                    if v.name in rename:
                        v.name = rename[v.name]
        _PrivateRenameWalker(rename).visit_module(module)
    return visible


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
      receiver position of a method call before qualified rewrite,
      and a no-payload variant constructor).
    - ``TypeName.name`` (named types in annotations).
    - ``ImplBlock.trait_name`` / ``ImplBlock.type_name``.
    - ``StructLit.type_name``.
    - ``VariantPat.name`` / ``StructPat.type_name`` in ``match``
      patterns (a variant constructor used as a pattern).

    Variant names are rewritten only when they appear in ``rename``,
    which happens for a *hidden* sum type (its variants are mangled
    alongside the type so they do not leak into the importer). A
    variant whose name is not in ``rename`` is left untouched, so the
    variants of a visible or selected sum type keep their names.

    Parameter names, local variables, struct field names, attribute
    names, and method names on traits are *not* rewritten because
    they do not denote top-level items. Identifier pattern bindings
    are local and likewise never rewritten.
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
                for pt in v.payloads:
                    self.visit_type(pt)
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
            for a in e.args:
                self.visit_expr(a)
            return
        if isinstance(e, A.MethodCall):
            self.visit_expr(e.receiver)
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
                self.visit_pattern(arm.pattern)
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

    # ---- patterns ----

    def visit_pattern(self, p) -> None:
        # Only ``VariantPat.name`` denotes a top-level item (a sum-type
        # constructor) and is rewritten when that variant was hidden.
        # ``StructPat.type_name`` is also a top-level reference; struct
        # types are not variant-hidden, but rewriting it keeps the pass
        # consistent if a struct type was itself renamed. Identifier and
        # wildcard bindings are local and never rewritten.
        if isinstance(p, A.VariantPat):
            p.name = self._r(p.name)
            for sub in p.payloads:
                self.visit_pattern(sub)
        elif isinstance(p, A.StructPat):
            p.type_name = self._r(p.type_name)
            for _, sub in p.fields:
                if sub is not None:
                    self.visit_pattern(sub)
        elif isinstance(p, A.TuplePat):
            for sub in p.elements:
                self.visit_pattern(sub)
        elif isinstance(p, A.OrPat):
            for alt in p.alternatives:
                self.visit_pattern(alt)
        # WildcardPat / IdentPat / LiteralPat: nothing to rewrite.
