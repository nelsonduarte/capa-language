"""Frozen-struct types mixin.

A conservative, type-level analysis that closes the H2 finding
of the 2026-05 backend security audit: mutating a struct that
appears as a key in a ``Set`` or ``Map`` breaks the data
structure's invariant on both backends (the Python ``CapaSet``
dict corrupts its hash bucket; the Wasm linear-scan ``set_add``
silently misses entries that were already there).

The rule, applied at analysis time:

    If a struct type ``T`` is reachable (directly or transitively
    via fields, collection-element types, or sum-variant payloads)
    from any ``Set<...T...>`` or ``Map<...T..., V>`` position in
    the program, then field assignments ``p.field = value`` on
    any value of type ``T`` are rejected.

Only struct **keys** are frozen: ``Map`` values are not part of
the hash and may still be mutated. Built-in types (``Int``,
``String``, ``List``, ``Option``, etc.) are never candidates.

The mixin exposes one entry point, ``_compute_frozen_types``,
that is called once per module from ``Analyzer.analyze`` after
``_collect_globals`` and before statement checking. The result
populates ``self._frozen_types``, which ``_check_assign``
consults via :meth:`_is_frozen` when its target is a
``FieldAccess``.

The mixin assumes ``self`` has the analyzer state set up by
``Analyzer.__init__`` (in particular ``global_scope``, which is
queried to distinguish user-defined structs from builtins and
to walk struct fields during the transitive closure).
"""

from __future__ import annotations

from .. import capa_ast as A
from ..typesys import CAPABILITY_NAMES, PRIMITIVE_NAMES


# Built-in generic and nominal type names that the analyzer
# already knows about. None of these are user-defined structs,
# so they are never candidates for freezing even when they
# appear inside a ``Set`` or ``Map`` key position. Kept as a
# module-level frozenset so the membership test is cheap and
# the list is easy to audit.
_BUILTIN_TYPE_NAMES: frozenset[str] = frozenset({
    "List", "Map", "Set", "Option", "Result", "Range",
    "JsonValue", "Task", "Self", "Unit",
}) | PRIMITIVE_NAMES | CAPABILITY_NAMES


class _FrozenTypesMixin:
    def _compute_frozen_types(self, module: A.Module) -> set[str]:
        """Return the set of user-struct type names that must
        not be field-mutated anywhere in the program.

        Two phases:

        1. Seed: scan every ``TypeExpr`` occurrence in the
           module and collect the user-struct base names that
           appear in a ``Set<X>`` argument or ``Map<K, V>`` key
           position.
        2. Transitive closure: if struct ``A`` is frozen and
           has a field of struct type ``B``, ``B`` becomes
           frozen too. Iterate to fixpoint over the global
           scope's already-resolved struct field types
           (populated by ``_collect_globals``).
        """
        from . import SymbolKind

        frozen = self._find_collection_keys_in_module(module)

        # Transitive closure via struct fields. The
        # ``_collect_globals`` pre-pass that runs before this
        # method already resolved every struct field to a
        # concrete ``Ty``, so the worklist walk just consults
        # ``sym.struct_fields`` directly.
        worklist = list(frozen)
        while worklist:
            name = worklist.pop()
            sym = self.global_scope.lookup(name)
            if sym is None or sym.kind != SymbolKind.TYPE_STRUCT:
                continue
            for field_ty in sym.struct_fields.values():
                for base in self._extract_struct_bases_from_ty(field_ty):
                    if base not in frozen:
                        frozen.add(base)
                        worklist.append(base)
        return frozen

    def _find_collection_keys_in_module(
        self, module: A.Module,
    ) -> set[str]:
        """Seed set: every user-struct name that appears in a
        ``Set<X>`` or ``Map<K, V>`` key position somewhere in
        the module. Walks the AST mechanically and records each
        Set / Map argument; the recursion in
        :meth:`_extract_struct_bases` ensures nested
        occurrences (``Set<List<Point>>``,
        ``Map<(Point, Int), Bool>``) are caught too.
        """
        keys: set[str] = set()

        def visit_type(te: A.TypeExpr) -> None:
            if isinstance(te, A.TypeName):
                if te.name == "Set" and len(te.args) >= 1:
                    keys.update(self._extract_struct_bases(te.args[0]))
                elif te.name == "Map" and len(te.args) >= 1:
                    keys.update(self._extract_struct_bases(te.args[0]))
                for a in te.args:
                    visit_type(a)
            elif isinstance(te, A.TupleType):
                for e in te.elements:
                    visit_type(e)
            elif isinstance(te, A.FunType):
                for p in te.param_types:
                    visit_type(p)
                visit_type(te.return_type)

        def visit_block(blk: A.Block) -> None:
            for stmt in blk.stmts:
                visit_stmt(stmt)

        def visit_stmt(stmt: A.Stmt) -> None:
            if isinstance(stmt, A.LetStmt):
                if stmt.type_expr is not None:
                    visit_type(stmt.type_expr)
            elif isinstance(stmt, A.VarStmt):
                if stmt.type_expr is not None:
                    visit_type(stmt.type_expr)
            elif isinstance(stmt, A.IfStmt):
                visit_block(stmt.then_block)
                for _cond, blk in stmt.elif_arms:
                    visit_block(blk)
                if stmt.else_block is not None:
                    visit_block(stmt.else_block)
            elif isinstance(stmt, A.WhileStmt):
                visit_block(stmt.body)
            elif isinstance(stmt, A.ForStmt):
                visit_block(stmt.body)

        def visit_fun(fn: A.FunDecl) -> None:
            for p in fn.params:
                if p.type_expr is not None:
                    visit_type(p.type_expr)
            if fn.return_type is not None:
                visit_type(fn.return_type)
            visit_block(fn.body)

        for item in module.items:
            if isinstance(item, A.TypeStruct):
                for fld in item.fields:
                    visit_type(fld.type_expr)
            elif isinstance(item, A.TypeSum):
                for v in item.variants:
                    for payload in v.payloads:
                        visit_type(payload)
            elif isinstance(item, A.ConstDecl):
                visit_type(item.type_expr)
            elif isinstance(item, A.FunDecl):
                visit_fun(item)
            elif isinstance(item, A.TraitDecl):
                for method in item.methods:
                    for p in method.params:
                        if p.type_expr is not None:
                            visit_type(p.type_expr)
                    if method.return_type is not None:
                        visit_type(method.return_type)
            elif isinstance(item, A.ImplBlock):
                for ta in item.type_args:
                    visit_type(ta)
                for method in item.methods:
                    visit_fun(method)
        return keys

    def _extract_struct_bases(self, te: A.TypeExpr) -> set[str]:
        """Recursively pull user-struct type names out of a
        type expression. ``Set<List<Point>>`` -> ``{"Point"}``;
        ``Map<(Point, Int), Bool>`` -> ``{"Point"}``;
        ``Set<Int>`` -> ``set()``.

        A name counts as a user struct iff it is not in
        ``_BUILTIN_TYPE_NAMES`` and resolves to a
        ``TYPE_STRUCT`` symbol in the global scope. Sum types,
        traits, capabilities, and type parameters are excluded
        - the freeze rule only applies to structs because only
        struct field-writes (``p.x = ...``) are the targets the
        rule needs to reject.
        """
        from . import SymbolKind

        bases: set[str] = set()
        if isinstance(te, A.TypeName):
            if te.name not in _BUILTIN_TYPE_NAMES:
                sym = self.global_scope.lookup(te.name)
                if sym is not None and sym.kind == SymbolKind.TYPE_STRUCT:
                    bases.add(te.name)
            for a in te.args:
                bases.update(self._extract_struct_bases(a))
        elif isinstance(te, A.TupleType):
            for e in te.elements:
                bases.update(self._extract_struct_bases(e))
        elif isinstance(te, A.FunType):
            for p in te.param_types:
                bases.update(self._extract_struct_bases(p))
            bases.update(self._extract_struct_bases(te.return_type))
        return bases

    def _extract_struct_bases_from_ty(self, ty) -> set[str]:
        """Like :meth:`_extract_struct_bases` but operates on a
        resolved ``Ty`` (used during the transitive closure,
        which walks struct field types from
        ``sym.struct_fields``). Kept separate from the AST
        walker so the two phases don't share a fragile
        polymorphic helper.
        """
        from . import SymbolKind
        from ..typesys import TyName, TyTuple, TyFun

        bases: set[str] = set()
        if isinstance(ty, TyName):
            if ty.name not in _BUILTIN_TYPE_NAMES:
                sym = self.global_scope.lookup(ty.name)
                if sym is not None and sym.kind == SymbolKind.TYPE_STRUCT:
                    bases.add(ty.name)
            for a in ty.args:
                bases.update(self._extract_struct_bases_from_ty(a))
        elif isinstance(ty, TyTuple):
            for e in ty.elements:
                bases.update(self._extract_struct_bases_from_ty(e))
        elif isinstance(ty, TyFun):
            for p in ty.params:
                bases.update(self._extract_struct_bases_from_ty(p))
            bases.update(self._extract_struct_bases_from_ty(ty.ret))
        return bases

    def _is_frozen(self, ty) -> bool:
        """True iff ``ty`` is a ``TyName`` whose base name is
        in ``self._frozen_types``. Used by ``_check_assign``
        to gate the field-mutation rejection on the receiver
        type of a ``FieldAccess`` target.
        """
        from ..typesys import TyName

        if isinstance(ty, TyName):
            return ty.name in self._frozen_types
        return False
