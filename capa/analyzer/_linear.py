"""Linear (must-consume) type discipline -- roadmap S1.

A ``linear type Foo { ... }`` value must be *consumed* before it
leaves scope: passed to a ``consume`` parameter (including a
``consume self`` method on the type, e.g. ``close``), or returned
(which transfers the obligation to the caller). Letting one drop --
bound to a ``let`` and never used, or live at the end of the function
-- is an error. This closes the resource-leak bug class (an open file
never closed, a transaction never committed/aborted) at compile time.

This is the DUAL of the capability ``consume`` discipline already in
the analyzer:

  * ``_consumed`` (capabilities): errors on *use after consume*.
    Branch merge is a conservative UNION (consumed if any path
    consumes).
  * ``_live_linear`` (this mixin): errors on *never consumed*.
    Branch merge is an INTERSECTION over non-diverging arms -- a
    value is still an outstanding obligation only if it survives
    unconsumed on a reachable path; consuming it on some-but-not-all
    paths is itself an error (one path would leak), surfaced at the
    merge point.

The state (``self._linear_types``, ``self._live_linear``) lives on the
Analyzer (see ``__init__``). This mixin holds the operations; the
statement/expression/items mixins call the hooks at the right points.
"""

from __future__ import annotations

from typing import Optional

from .._owned_obligation import carries_linear, owned_obligation
from ..tokens import Pos
from ..typesys import Ty, TyName, TyTuple


class _LinearMixin:
    # A linear/typestate value cannot contain itself by value and a
    # container nesting collapses (an index has no static path), so the
    # depth of a move path is naturally bounded. This is a defensive
    # backstop only: a chain deeper than K linear fields collapses to the
    # whole-value place so the analysis stays finite on a pathological type.
    _LINEAR_PATH_MAX_DEPTH = 8

    # ---- type predicate ------------------------------------------

    def _ty_is_linear(self, ty: Optional[Ty]) -> bool:
        """True if ``ty`` names a ``linear type`` struct or a typestate."""
        return isinstance(ty, TyName) and ty.name in self._linear_types

    def _owned_obligation(self, ty: Optional[Ty]) -> bool:
        """True iff a value of type ``ty`` carries a must-consume
        obligation: it is itself linear/typestate, OR a CARRIER struct that
        transitively owns a linear/typestate field. THE single predicate the
        obligation seams gate on (``_linear_bind``, the consume-param /
        borrowed-param seeding, the anonymous-drop and reassign-drop checks);
        the manifest builder gates its ``is_linear`` / ``consumes`` /
        ``produces_linear`` on the exact same shared helper."""
        root = ty.name if isinstance(ty, TyName) else None
        return owned_obligation(root, self._linear_types, self._symbol_field_roots)

    # ---- place / move-path helpers -------------------------------

    def _struct_fields_of(self, ty: Optional[Ty]) -> Optional[dict]:
        """The declared field map of a struct / typestate ``TyName``
        (``field name -> Ty``), or ``None`` for any other type. A
        typestate is a state-indexed struct, so its fields live in the
        same ``struct_fields`` map as a plain struct's."""
        if not isinstance(ty, TyName):
            return None
        sym = self.global_scope.lookup(ty.name)
        if sym is None:
            return None
        from . import SymbolKind
        if sym.kind != SymbolKind.TYPE_STRUCT:
            return None
        return sym.struct_fields

    def _type_carries_linear(self, ty: Optional[Ty]) -> bool:
        """True iff ``ty`` transitively reaches a linear/typestate type
        through struct fields (never through a container element or a
        ``Fun`` signature). Delegates to the shared ``carries_linear`` walk
        (the same one the manifest uses) so the carrier classification lives
        in exactly one place; the analyzer supplies its Symbol-based
        field-root lookup. Used by the HOLE-2 alias-move rule: a NON-linear
        struct that owns a linear/typestate field is still move-on-alias."""
        root = ty.name if isinstance(ty, TyName) else None
        return carries_linear(root, self._linear_types, self._symbol_field_roots)

    # ---- container-of-linear invariant (mirror of the cap discipline) ----

    def _reaches_linear(self, ty: Optional[Ty], _depth: int = 0) -> bool:
        """Recursive leaf test: True iff a linear/typestate type is reachable
        anywhere in ``ty`` -- as ``ty`` itself, through a struct field
        (``_type_carries_linear``), or below a container / tuple layer at any
        nesting depth. Structural twin of ``_contains_any_capability``, so the
        container-of-linear invariant mirrors the capability one exactly.

        Like ``_cap_in_container`` it does NOT descend a ``TyFun``: a linear
        value captured inside a closure is a signature, not container storage,
        and consuming a captured value is already barred by the capture-consume
        check in ``_mark_consumed_args``."""
        if ty is None:
            return False
        if self._owned_obligation(ty):
            return True
        if _depth >= self._LINEAR_PATH_MAX_DEPTH:
            return False
        if isinstance(ty, TyName):
            return any(self._reaches_linear(a, _depth + 1) for a in ty.args)
        if isinstance(ty, TyTuple):
            return any(
                self._reaches_linear(e, _depth + 1) for e in ty.elements
            )
        return False

    def _container_carries_linear(self, ty: Optional[Ty]) -> bool:
        """True iff a linear/typestate type is reachable STRICTLY BELOW a
        container head in ``ty``: a List / Set element, a Map key OR value, a
        tuple element, or any generic argument, at any nesting depth. Twin of
        ``_cap_in_container``.

        A BARE linear/typestate value (or a bare linear-carrying struct) at the
        TOP level is deliberately NOT flagged: that is the whole point of the
        linear discipline, a single-owner value flows BY NAME (a direct
        parameter / return / binding / field). Only the below-a-container form
        is barred. The type is resolved against ``_ty_subs`` first, so a
        container whose element was pinned only by inference is judged on its
        real element type."""
        ty = self._resolve_ty(ty)
        if isinstance(ty, TyName):
            return any(self._reaches_linear(a) for a in ty.args)
        if isinstance(ty, TyTuple):
            return any(self._reaches_linear(e) for e in ty.elements)
        return False

    def _linear_container_use_gate(self, e: "A.Expr", ty: Optional[Ty]) -> None:
        """Per-expression use-gate (twin of the cap ``_cap_in_container`` gate
        in ``_check_expr``): reject a sub-expression whose resolved type packs
        a linear/typestate value inside a list / set / map / tuple, so a
        container / tuple literal, a producing higher-order ``map`` /
        ``flat_map``, a container-typed binding / param / return on use, and
        any nesting are all closed at a single site. Deduped per node. Also
        invoked from the annotated-list-literal binding path, which bypasses
        ``_check_expr`` to thread the expected element type."""
        if not self._container_carries_linear(ty):
            return
        if id(e) in self._linear_container_reported:
            return
        self._linear_container_reported.add(id(e))
        self._err(
            "a linear/typestate value cannot be used here: this value is a "
            "container of single-owner values, and a linear/typestate value "
            "may only flow as a bare, top-level value (a direct parameter / "
            "return / binding), never packed inside a list, set, map, or "
            "tuple",
            e.pos,
        )

    # ---- conditional/match alias bar (Finding 1) ------------------

    def _arm_is_linear_place(self, arm: "A.Expr") -> bool:
        """True iff ``arm`` yields an EXISTING linear/typestate place: a bare
        ``Ident`` or an Ident-rooted ``FieldAccess`` whose leaf type is
        linear/typestate. A nested ``IfExpr`` / ``MatchExpr`` wrapper is
        recursively unwrapped (``if a then s else (if b then s else s)``), so a
        place selected at any nesting depth counts. A call / literal /
        ``become`` / struct-literal produces a FRESH value that cannot alias an
        existing obligation, so it is not a place and is not barred.

        A ``FieldAccess`` is judged through ``_linear_place`` (the same
        Ident-rooted, linear-leaf recognition the move seams use), so a
        projection of a non-linear carrier down to a linear field
        (``s.conn``) counts while a non-linear field (``s.name``) does not."""
        from .. import capa_ast as _A
        if isinstance(arm, _A.IfExpr):
            return (
                self._arm_is_linear_place(arm.then_expr)
                or self._arm_is_linear_place(arm.else_expr)
            )
        if isinstance(arm, _A.MatchExpr):
            return any(
                isinstance(a.body, _A.Expr)
                and self._arm_is_linear_place(a.body)
                for a in arm.arms
            )
        if isinstance(arm, _A.Ident):
            sym = self.scope.lookup(arm.name)
            return self._ty_is_linear(sym.ty if sym is not None else None)
        if isinstance(arm, _A.FieldAccess):
            return self._linear_place(arm) is not None
        return False

    def _conditional_selects_linear_place(self, e: "A.Expr") -> bool:
        """True iff the conditional/match wrapper ``e`` yields an EXISTING
        linear/typestate place in at least one arm (recursing through nested
        wrappers). The arm bodies are ``IfExpr.then_expr`` / ``else_expr`` and
        each ``MatchExpr`` arm body that is an ``Expr`` (a multi-line ``Block``
        arm body is Unit-typed, so it can never host a place)."""
        from .. import capa_ast as _A
        if isinstance(e, _A.IfExpr):
            return (
                self._arm_is_linear_place(e.then_expr)
                or self._arm_is_linear_place(e.else_expr)
            )
        if isinstance(e, _A.MatchExpr):
            return any(
                isinstance(a.body, _A.Expr)
                and self._arm_is_linear_place(a.body)
                for a in e.arms
            )
        return False

    def _check_linear_conditional_alias(
        self, e: "A.Expr", ty: Optional[Ty],
    ) -> None:
        """Per-expression bar (Finding 1): reject an ``if`` / ``match``
        expression that selects an EXISTING linear/typestate place in a branch.

        A conditional whose value is a linear place aliases an obligation the
        analysis already tracks under its own name: the move / consume / return
        / receiver seams recognise only a bare ``Ident`` / ``FieldAccess``, not
        an ``if`` / ``match`` wrapper, so binding, consuming, or returning the
        wrapper opens a SECOND obligation on the same runtime value (a double-
        free). Because every producing context (a ``let`` / ``var`` RHS, a
        consume argument, a ``consume self`` receiver, a ``return`` value, a
        ``become`` value, a struct-literal element) evaluates the wrapper
        through ``_check_expr``, this ONE gate closes every site.

        Barred syntactically on the arm nodes plus a type lookup, so it does
        not depend on the live-set at the check moment. Only an ``Ident`` /
        ``FieldAccess`` arm of linear type can alias an existing obligation; a
        call / literal / ``become`` arm yields a FRESH value, so the legitimate
        conditional factory (``let t = if c then open(1) else open(2)``) is not
        barred. Deduped per node. A NON-linear conditional (yielding a String /
        Int / Option / plain struct) is filtered out first by ``ty``."""
        from .. import capa_ast as _A
        if not isinstance(e, (_A.IfExpr, _A.MatchExpr)):
            return
        if not self._owned_obligation(ty):
            return
        if id(e) in self._linear_conditional_reported:
            return
        if not self._conditional_selects_linear_place(e):
            return
        self._linear_conditional_reported.add(id(e))
        self._err(
            "a linear/typestate value cannot be selected through a "
            "conditional / match expression; bind it directly (e.g. "
            "`let x = ...` in each branch) or open a fresh value per branch, "
            "so each resource has a single owner",
            e.pos,
        )

    def _check_no_linear_container(
        self, ty: Optional[Ty], pos: Pos, context: str,
    ) -> None:
        """Entry-gate wrapper (twin of ``_check_no_cap_container``): reject a
        type that packs a linear/typestate value inside a container in
        ``context`` -- a parameter / return / field / const / variant payload
        typed ``List<Conn>`` / ``(Conn, Int)`` / ``Map<K, Conn>`` -- for a
        precise diagnostic at the declaration even when the body never uses it.
        Uses the CONTAINER-scoped predicate (a bare linear value stays legal),
        never an ``any linear`` one, because a bare linear parameter / return /
        field is how single-owner values flow."""
        if not self._container_carries_linear(ty):
            return
        self._err(
            f"a linear/typestate value cannot appear in {context}; a "
            f"single-owner value may only flow as a bare, top-level value "
            f"(a direct parameter / return / binding), never packed inside a "
            f"list, set, map, or tuple",
            pos,
        )

    def _reject_linear_leak_via_substitution(
        self,
        pre_ty: Optional[Ty],
        post_ty: Optional[Ty],
        callee_label: str,
        pos: Pos,
        *,
        slot: str,
    ) -> None:
        """Twin of ``_reject_cap_leak_via_substitution``: fire when generic
        substitution puts a linear/typestate value BELOW A CONTAINER where the
        unsubstituted form had none. ``stash<T>(xs: List<T>, v: T)`` called at
        ``T = Conn`` turns ``List<T>`` (no container-of-linear) into
        ``List<Conn>`` (a container-of-linear), so the call is rejected at the
        substitution site even when the caller never uses the container.

        Container-scoped, NOT ``any linear``: a BARE linear value flowing
        through a generic (``id<T>(v: T) -> T`` at ``T = Conn``) stays legal,
        because linear values flow by name including through generics. Only the
        container-of-linear form is barred."""
        if not self._container_carries_linear(post_ty):
            return
        if self._container_carries_linear(pre_ty):
            return
        self._err(
            f"call to {callee_label}: {slot} substitutes a linear/typestate "
            f"value into a generic container type; a single-owner value may "
            f"only flow as a bare, top-level value (a direct parameter / "
            f"return / binding), never packed inside a list, set, map, or "
            f"tuple",
            pos,
        )

    def _linear_field_paths(
        self, place: str, ty: Optional[Ty], _depth: int = 0,
    ) -> list[str]:
        """The finite set of ``place.f...`` sub-paths whose leaf type is
        linear/typestate, enumerated from ``ty``'s struct fields (bounded
        by ``_LINEAR_PATH_MAX_DEPTH``). A linear field is a leaf (consuming
        it whole satisfies it, so we do not descend into it); a non-linear
        struct field is descended to find any deeper linear leaf. Walks
        struct fields only -- never a container element or a ``Fun``
        signature -- so authority reached only through a container / closure
        is not enumerated here (it is barred from containers separately)."""
        if _depth >= self._LINEAR_PATH_MAX_DEPTH:
            return []
        fields = self._struct_fields_of(ty)
        if fields is None:
            return []
        out: list[str] = []
        for fname, fty in fields.items():
            sub = f"{place}.{fname}"
            if self._ty_is_linear(fty):
                out.append(sub)
            else:
                out.extend(self._linear_field_paths(sub, fty, _depth + 1))
        return out

    def _linear_place(self, expr: "A.Expr") -> Optional[str]:
        """The canonical dotted place for an Ident-rooted ``expr`` whose
        LEAF type is linear/typestate, or ``None``. This is ``_path_of``
        restricted to the linear/typestate places the discipline tracks,
        with the ``_LINEAR_PATH_MAX_DEPTH`` collapse: a chain deeper than K
        fields collapses to its base name so a pathological type stays
        finite. An index (``xs[i]``) or any non-static component yields
        ``None`` via ``_path_of`` -- the Model-B container collapse for
        free (no per-element move path)."""
        path = self._path_of(expr)
        if path is None:
            return None
        from .. import capa_ast as _A
        if isinstance(expr, _A.Ident):
            sym = self.scope.lookup(expr.name)
            leaf_ty = sym.ty if sym is not None else None
        else:
            leaf_ty = self.types.get(id(expr))
        if not self._ty_is_linear(leaf_ty):
            return None
        if path.count(".") > self._LINEAR_PATH_MAX_DEPTH:
            return path.split(".", 1)[0]
        return path

    @staticmethod
    def _has_component_prefix(place: str, names: set[str]) -> bool:
        """True iff ``place`` or a ``.``-split prefix of it is in ``names``.
        Component-wise, never a raw ``startswith``: the prefixes of
        ``s.conn.fd`` are exactly ``s``, ``s.conn``, ``s.conn.fd``, so an
        entry ``s`` covers ``s.conn`` but an entry ``session`` never covers
        ``s``. The one prefix walk behind ``_prefix_consumed`` /
        ``_prefix_borrowed`` / ``_field_discharged``."""
        parts = place.split(".")
        for i in range(1, len(parts) + 1):
            if ".".join(parts[:i]) in names:
                return True
        return False

    def _prefix_consumed(self, place: str) -> bool:
        """True iff ``place`` or a ``.``-split prefix of it is in
        ``_consumed`` (the UNION-merged use-after-consume set)."""
        return self._has_component_prefix(place, self._consumed)

    def _prefix_borrowed(self, place: str) -> bool:
        """True iff ``place`` or a ``.``-split prefix of it is in
        ``_borrowed_linear``."""
        return self._has_component_prefix(place, self._borrowed_linear)

    def _field_discharged(self, place: str) -> bool:
        """True iff the linear FIELD ``place`` (or a prefix of it) was moved
        out on the current merged path -- i.e. it is in the
        INTERSECTION-merged ``_linear_field_moved``. This is what the
        scope-exit per-field accounting reads, NOT ``_prefix_consumed``: a
        field consumed on only SOME branches is in ``_consumed`` (union) but
        must NOT count as discharged at scope exit, or a conditional-field-
        consume would leak silently."""
        return self._has_component_prefix(place, self._linear_field_moved)

    def _subpath_consumed(self, base: str) -> Optional[str]:
        """The first consumed path that has ``base`` as a strict ``.``-split
        prefix (``base.<field>...``), or ``None``. The trailing dot forces a
        component boundary, so ``base='s'`` matches ``s.conn`` but never
        ``session``."""
        prefix = base + "."
        for p in self._consumed:
            if p.startswith(prefix):
                return p
        return None

    # ---- obligation bookkeeping ----------------------------------

    def _linear_bind(self, name: str, ty: Optional[Ty], pos: Pos) -> None:
        """Record a new outstanding must-consume obligation for ``name``
        when ``ty`` carries one -- a bare ``linear type`` / typestate value
        OR a CARRIER struct that transitively owns a linear/typestate field
        (E1, the load-bearing seam: this arms a carrier from a FACTORY CALL
        ``let b = make_box()`` at the binding, not only at the pack site).
        Called when a ``let`` / ``var`` binds the result of an expression.

        Re-binding a name clears any earlier use-after-consume poison on
        it (``_consumed`` / ``_linear_names``): a fresh ``let h = ...``
        introduces a brand-new value under that name, so a prior consume
        of the old value must not flag uses of the new one. Typestate
        chains re-bind the same name (``let s = become(s, ...)``) and
        rely on this.

        B-F1: if ``_linear_transfer_if_alias`` just marked ``name`` borrowed
        (the RHS aliased a borrowed value), do NOT open a fresh owned
        obligation -- the single obligation stays with the caller and the
        new name is borrowed too."""
        if name in self._borrowed_linear:
            return
        if self._owned_obligation(ty):
            self._live_linear[name] = (pos, ty)
            self._consumed.discard(name)
            self._linear_names.discard(name)

    def _linear_discharge(self, name: str, pos: Optional[Pos] = None) -> None:
        """Clear the obligation for ``name`` (it was consumed /
        transferred) and POISON the name against later use.

        A linear value is consumed *exactly once*: once it has been
        passed to a ``consume`` parameter / ``consume self`` method,
        transitioned by ``become``, or returned, the binding must not be
        used again. We record the name in ``_consumed`` (the same flow
        set the capability discipline keys its use-after-consume check
        on) and in ``_linear_names`` (so the use-site picks the
        ``linear value`` wording instead of ``capability``). Poisoning a
        name that carried no live obligation is harmless -- a later
        ``_linear_bind`` of the same name lifts the poison.

        B-F1: a name in ``_borrowed_linear`` is a non-consume linear /
        typestate parameter the caller still owns; it cannot be consumed
        or transferred here. Every discharge path (consume-arg, return,
        ``consume self``, ``become``) funnels through this guard, so
        rejecting the borrowed name here covers them all. ``pos`` locates
        the offending site for the diagnostic; the guard returns without
        discharging (a borrowed name never carries a live obligation of
        its own)."""
        if name in self._borrowed_linear:
            if pos is not None:
                self._err(
                    f"cannot consume or transfer borrowed linear/typestate "
                    f"value {name!r}; the caller retains ownership -- "
                    f"declare the parameter `consume` to take ownership",
                    pos,
                )
            return
        # HOLE-1 (iii): consuming the WHOLE ``name`` after one of its
        # linear fields was already moved out is a partial-move double-free
        # (the field's value would be freed twice). Scan ``_consumed``
        # component-wise for any ``name.<field>...`` before discharging.
        sub = self._subpath_consumed(name)
        if sub is not None:
            if pos is not None:
                self._err(
                    f"cannot consume {name!r}: its field {sub!r} was already "
                    f"consumed, so consuming the whole value would double-free "
                    f"that field -- consume the remaining fields individually "
                    f"instead",
                    pos,
                )
            self._live_linear.pop(name, None)
            return
        had = name in self._live_linear
        self._live_linear.pop(name, None)
        if had:
            self._consumed.add(name)
            self._linear_names.add(name)

    def _reject_husk_reconsume(self, name: str, pos: Pos) -> bool:
        """Carrier-class completion: a carrier whose linear field(s) were ALL
        moved out is a spent HUSK -- ``_linear_move_field`` popped it from
        ``_live_linear`` (its obligation was discharged PER FIELD), so it is
        no longer a live obligation, but consuming / returning / re-packing
        the WHOLE husk again would re-transfer an already-moved field, a
        double-free (``close(b.h); sink(b)`` ran ``close`` twice at runtime).

        Reuses the SAME HOLE-1(iii) ``_subpath_consumed`` scan the still-live
        partial-move path uses: if any ``name.<field>...`` was moved out, the
        whole husk cannot be re-consumed. Returns True (and reports) iff
        ``name`` is such a husk. Fires ONLY for a name NOT in ``_live_linear``
        (a live carrier's whole-consume is caught in ``_linear_discharge``);
        the husk root is deliberately NOT marked wholesale-consumed, so
        READING its other (non-linear) fields and DROPPING it stay legal --
        the per-field-discharge semantic that keeps a field moved out in one
        arm and the husk dropped (capa_claimdesk) compiling."""
        if name in self._live_linear:
            return False
        sub = self._subpath_consumed(name)
        if sub is None:
            return False
        self._err(
            f"cannot consume {name!r}: its field {sub!r} was already "
            f"consumed, so consuming the whole value would double-free that "
            f"field -- its linear fields were already moved out",
            pos,
        )
        return True

    def _moved_subpath_sets(self) -> tuple:
        """THE single source of the sub-path-keyed structures the move seam
        (``_linear_move_field``) records a moved-out linear field place in.
        ``_linear_move_field`` writes a place THROUGH this tuple, and both
        ``_carry_moved_subpaths`` (re-key a moved sub-path across an alias) and
        ``_clear_moved_subpaths`` (drop a stale moved sub-path on a fresh
        re-arm) iterate it, so the producer and the two re-keyers cannot
        diverge: adding a fourth structure here propagates to all three at
        once, and a carry / clear can never silently under-cover a structure
        the move seam populates. Read FRESH each call because a branch merge
        (``_check_if`` / ``_check_match_expr``) rebinds these sets.

        The prefix scans that walk this tuple are ``.``-component scoped
        (``name + "."``), so they touch only the DOTTED sub-paths a field move
        produces, never a whole-root consume entry that shares the name."""
        return (self._consumed, self._linear_names, self._linear_field_moved)

    def _linear_move_field(self, place: str, pos: Pos) -> None:
        """HOLE-1 (ii): consume / move a linear FIELD ``place`` (``s.conn``)
        -- via ``close(s.conn)``, ``become(s.conn, ..)``, a ``consume self``
        method on it, or a projection ``let c = s.conn``. Poison the path in
        ``_consumed`` so the whole-value consume scan and the scope-exit
        per-field enumeration both see it, and so a later read of the same
        field is rejected as use-after-move by the ordinary FieldAccess
        use-site check.

        A double move of the same field (``place`` or a prefix already in
        ``_consumed``) is left to that use-site check, which fires when the
        field expression is re-evaluated at the second consume; this method
        simply does not re-poison, so the diagnostic is reported once.

        WARNING-4: consuming / moving a place whose base (or any ``.``-split
        prefix) is a BORROWED linear/typestate value transfers ownership the
        caller still holds -- a double-free. The component-wise prefix test
        gates consume / move only, never a read."""
        if self._prefix_borrowed(place):
            self._err(
                f"cannot consume or move linear/typestate field {place!r}; "
                f"it belongs to a borrowed value the caller still owns -- "
                f"declare the parameter `consume` to take ownership",
                pos,
            )
            return
        if self._prefix_consumed(place):
            return
        # Record the moved-out place in every sub-path-keyed structure through
        # the single ``_moved_subpath_sets`` source, so the carry / clear
        # re-keyers cannot drift from what a move poisons. This is the one
        # place a moved field is recorded, including the Connection C per-field
        # discharge record (``_linear_field_moved``), which is INTERSECTION-
        # merged at branch points (see ``_check_if`` / ``_check_match_expr``),
        # unlike the union-merged use-after-consume set, so a field consumed on
        # only some branches is NOT counted as discharged at scope exit.
        for moved_set in self._moved_subpath_sets():
            moved_set.add(place)
        # Moving out a carrier's LAST outstanding linear field discharges the
        # whole carrier obligation (the blessed per-field-discharge
        # semantic): drop it from the live set so it is not re-reported at
        # scope exit and does not linger past the arm / block it was bound
        # in (where a later branch-merge intersection would wrongly wipe this
        # move). A bare linear leaf has no linear sub-fields, so it is never
        # auto-discharged here -- it stays live until consumed as a whole.
        root = place.split(".", 1)[0]
        live = self._live_linear.get(root)
        if live is not None:
            subs = self._linear_field_paths(root, live[1])
            if subs and all(self._field_discharged(s) for s in subs):
                self._live_linear.pop(root, None)

    def _linear_rearm_field(self, place: str, pos: Pos) -> None:
        """The INVERSE of ``_linear_move_field``: re-arm a linear FIELD
        ``place`` (``s.conn``) that a fresh store wrote into AFTER a prior
        consume / move of the same field (``close(s.conn); s.conn = ...``).

        Two symmetric effects, each undoing one the move seam applied:

        - Clear the exact leaf ``place`` and every ``place.`` sub-path from
          EVERY moved-subpath structure through the single
          ``_moved_subpath_sets()`` source (the same tuple the move seam
          records THROUGH), so the re-arm can never under-cover a structure
          the move poisoned. Skipping ``_linear_field_moved`` here was the
          root of Face C, so iterating the one source -- never a hard-coded
          2-of-3 list -- is the fail-closed guard.
        - Re-open the carrier ROOT's must-consume obligation in
          ``_live_linear`` when its declared type carries one, so the newly
          stored value is accounted at scope exit (no missed leak) instead of
          lingering popped as a spent husk.

        Deliberately does NOT touch ``_drop_exempt_linear``: a re-armed
        ``consume`` parameter carrier stays drop-exempt (that exemption is
        checked FIRST in ``_linear_check_dropped``)."""
        prefix = place + "."
        for moved_set in self._moved_subpath_sets():
            moved_set.discard(place)
            for p in [q for q in moved_set if q.startswith(prefix)]:
                moved_set.discard(p)
        root = place.split(".", 1)[0]
        sym = self.scope.lookup(root)
        root_ty = sym.ty if sym is not None else None
        if self._owned_obligation(root_ty):
            self._live_linear[root] = (pos, root_ty)

    def _carry_moved_subpaths(self, src: str, dst: str) -> None:
        """Re-key every moved-out linear sub-path of ``src`` onto ``dst`` when
        ``dst`` aliases ``src`` (``let d = c``, ``var d = c``, ``d = c``). A
        carrier whose field was moved out is a spent HUSK; the move seam
        poisons the SOURCE sub-path but the alias arms a FRESH obligation on
        the target, so without carrying the moved-out sub-path across, the
        target forgets the field was already freed and the whole husk can be
        re-consumed through the alias -- a double-free, and the same route a
        chain of aliases (``let c = b; let d = c``) extends.

        Re-keys within EACH structure the move seam populates
        (``_moved_subpath_sets``), so the husk-reconsume / discharge /
        field-use scans fire on the alias with no new state and no mirror
        table, and each set's own membership is preserved (a sub-path in the
        union-merged consume set but not the intersection-merged field-move set
        carries into only the former). Only the moved SUB-PATH travels, never
        the whole root, so a non-linear read of the aliased husk stays legal
        (that is why root-marking was dropped). A ``src`` with no moved-out
        sub-path (a still-whole carrier, a bare linear, a chain root) carries
        nothing, so the whole-carrier alias is untouched."""
        prefix = src + "."
        for moved_set in self._moved_subpath_sets():
            for p in [q for q in moved_set if q.startswith(prefix)]:
                moved_set.add(dst + p[len(src):])

    def _clear_moved_subpaths(self, name: str) -> None:
        """Drop the WHOLE ``name.*`` moved sub-tree from every moved-subpath
        structure (``_moved_subpath_sets``) when a re-assignment re-arms the
        TARGET ``name``. The move seam records a moved field as a sub-path
        (``c.h``), but a re-arm's bind clears only the exact ROOT ``c``, so a
        stale ``c.*`` from a spent-husk target would otherwise persist across
        the reassignment and both (i) reject a legitimate whole-consume of the
        fresh value as a double-free and (ii) mask the fresh value's own leak
        at scope exit.

        Strict ``name + "."`` prefix: only sub-paths are cleared, never the
        root ``name`` itself and never a sibling like ``name2``. Called by the
        re-assign re-arm path (``_check_assign``) BEFORE
        ``_linear_transfer_if_alias`` re-carries the SOURCE's sub-paths onto
        the target, so it clears the target's OWN stale sub-tree without
        wiping the ones the alias transfer then re-carries -- the order is
        why an alias whose source is itself a spent husk stays rejected."""
        prefix = name + "."
        for moved_set in self._moved_subpath_sets():
            for p in [q for q in moved_set if q.startswith(prefix)]:
                moved_set.discard(p)

    def _linear_transfer_if_alias(self, value: "A.Expr", target: str) -> None:
        """When a ``let``/``var`` RHS is a bare identifier naming a still-
        live linear obligation (``let h2 = h``), MOVE the obligation off
        the source name rather than letting ``_linear_bind`` open a second
        independent obligation under the new name. A linear value has a
        single owner: ``h`` and ``h2`` denote the SAME value, so each must
        not be separately consumable -- without the move, ``close(h)`` and
        ``close(h2)`` would both type-check and double-consume.

        The source is poisoned (``_consumed`` / ``_linear_names``) exactly
        as a real consume / anonymous drop is, so a later use of the source
        name (``close(h)`` after ``let h2 = h``) is rejected as use-after-
        consume. The new name's fresh obligation is armed by the caller's
        ``_linear_bind`` immediately after, so the single obligation now
        lives under the new name (``let h2 = h; close(h2)`` stays valid).

        B-F1: re-binding ``target`` to a new value first clears any
        borrowed marker it held (the invariant that a name is in at most
        one of ``_live_linear`` / ``_borrowed_linear``). Aliasing a
        BORROWED source (``let b = h`` where ``h`` is a non-consume linear
        param) then propagates the borrowed marker onto ``target`` and does
        NOT move an obligation -- there is none to move, the caller still
        owns it -- so the alias is borrowed too and ``_linear_bind`` skips
        opening a fresh owned obligation under it.

        No-op (beyond clearing the target marker) unless the RHS is a bare
        ``Ident`` naming a borrowed value or one that currently holds a live
        obligation -- a non-identifier RHS (a call, ``become``, ...)
        produces a fresh value, and an already-consumed source is gone from
        ``_live_linear`` and handled by the ordinary use-after-consume
        check on the RHS itself."""
        from .. import capa_ast as _A
        self._borrowed_linear.discard(target)
        if isinstance(value, _A.FieldAccess):
            # HOLE-1 (ii): a projection ``let c = s.conn`` MOVES the linear
            # field out of its carrier -- poison ``s.conn`` so the carrier
            # can no longer consume it, and let ``_linear_bind`` arm ``c``
            # as the fresh owner.
            place = self._linear_place(value)
            if place is None:
                return
            # WARNING-5: projecting a field of a BORROWED value binds the
            # new name BORROWED too (the caller still owns it), so
            # ``_linear_bind`` skips arming an owned obligation and a later
            # consume of the name routes into the borrowed guard.
            if self._prefix_borrowed(place):
                self._borrowed_linear.add(target)
                return
            self._linear_move_field(place, value.pos)
            return
        if not isinstance(value, _A.Ident):
            return
        if value.name in self._borrowed_linear:
            self._borrowed_linear.add(target)
            return
        if value.name in self._live_linear:
            # Carry any partially-moved sub-path onto the alias BEFORE the
            # whole obligation transfers, so the tail of an alias chain (whose
            # husk head re-armed it live) inherits the moved-out field and a
            # re-consume through it is rejected.
            self._carry_moved_subpaths(value.name, target)
            self._linear_discharge(value.name)
            return
        # HOLE-2 (option a): aliasing a value whose type TRANSITIVELY
        # carries a linear/typestate field -- a struct that may be
        # NON-linear itself (``Session``, ``Settlement``) -- MOVES the base:
        # poison it so any later consume / move / read of the moved-out
        # original rejects as use-after-move, while ``target`` becomes the
        # sole accessor. Without this, ``let t = s; close(s.conn);
        # close(t.conn)`` would double-free the shared field. A projection
        # (``let settled = result.claim``) is a field access, handled above,
        # so a carrier that is only projected from is never moved here.
        val_ty = self.types.get(id(value))
        if val_ty is None:
            sym = self.scope.lookup(value.name)
            val_ty = sym.ty if sym is not None else None
        if self._type_carries_linear(val_ty):
            self._consumed.add(value.name)
            self._linear_names.add(value.name)
            # The source may be a spent HUSK (its linear field already moved
            # out, popped from the live set). Carry that moved-out sub-path
            # onto the alias so consuming / returning / re-packing the whole
            # husk through ``target`` (or the next link of a chain) is rejected
            # exactly as it is on the source.
            self._carry_moved_subpaths(value.name, target)

    def _linear_reassign(self, name: str, ty: Optional[Ty], pos: Pos) -> None:
        """Handle ``h = <expr>`` re-assignment to an existing name.

        Re-binding a name whose current value is a still-live linear
        obligation DROPS that value (it is overwritten and can never be
        consumed again), so report it like any other drop. Then the new
        value is registered: if it is itself linear, ``_linear_bind``
        parks the fresh obligation under the name (and lifts any consume
        poison); if it is not, the name simply stops carrying a linear
        obligation.

        Valid: re-assigning to a name whose previous value was already
        consumed (``close(h); h = open()``) -- the old value is gone
        from ``_live_linear``, so nothing is reported, and the fresh
        value re-arms the obligation.

        B-F1: the target's borrowed marker is cleared by
        ``_linear_transfer_if_alias`` (its no-op top always runs before this
        re-arm on the non-self-assign path, so a fresh reassign of a
        previously-borrowed name still drops the stale borrow), which is why
        it is NOT cleared here: a borrowed source aliased in
        (``t = h``) must keep ``t`` borrowed so the re-arm below skips arming
        a fresh OWNED obligation and a later consume routes into the borrowed
        guard. Clearing it here would launder the caller's value."""
        # LIN-1: a ``consume`` parameter's value is drop exempt, so
        # overwriting it by re-assignment is a legal drop of the terminal
        # owner, not a leak of the old value. Clear the exemption: the value
        # assigned below is freshly produced and carries a real must-consume
        # obligation of its own (``_linear_bind`` arms it non-exempt).
        was_drop_exempt = name in self._drop_exempt_linear
        self._drop_exempt_linear.discard(name)
        old = self._live_linear.get(name)
        if old is not None:
            if not was_drop_exempt:
                self._err(
                    f"linear value {name!r} is dropped without being "
                    f"consumed; re-assigning to it overwrites the old value, "
                    f"which a `linear type` / typestate value cannot be -- "
                    f"consume the current value (e.g. a `consume self` method "
                    f"like `close`, or `become`) before re-assigning",
                    pos,
                )
            del self._live_linear[name]
        self._linear_bind(name, ty, pos)

    # ---- anonymous drop (``let _ = ...`` / bare expr stmt) -------

    def _linear_check_anonymous_drop(
        self, expr: "A.Expr", ty: Optional[Ty], pos: Pos,
    ) -> None:
        """Error when a linear / typestate value is dropped into a slot
        that holds no obligation: a wildcard binding ``let _ = open()``
        or a bare expression statement ``open()`` / ``become(c, S)``.

        A named binding parks the obligation under its name and the
        scope-exit check catches a later leak; an anonymous one has no
        name to track, so the value would silently vanish unconsumed.
        We flag it at the drop site with the same intent as the named
        case. ``ty`` is the value's type as computed by ``_check_expr``.

        If the dropped expression is a bare identifier naming a still
        live linear binding (``let _ = h``), discharge that binding too:
        the value has moved into the anonymous slot and is reported once
        here, not again at function exit.

        Gated on ``_owned_obligation`` (D), so dropping a CARRIER-returning
        call as a bare statement / ``let _ = make_box()`` -- which leaks the
        struct's linear field -- is caught, not just a bare linear value."""
        if not self._owned_obligation(ty):
            return
        from .. import capa_ast as _A
        if isinstance(expr, _A.Ident):
            self._live_linear.pop(expr.name, None)
        self._err(
            "linear value is dropped without being consumed; a "
            "`linear type` / typestate value must be passed to a "
            "consuming function (e.g. a `consume self` method like "
            "`close`), transitioned with `become`, or returned -- it "
            "cannot be discarded into `_` or a bare expression statement",
            pos,
        )

    # ---- borrowed-value aggregate escape (B-F1) ------------------

    def _linear_check_borrowed_escape(self, expr: "A.Expr", pos: Pos) -> None:
        """B-F1: reject a bare BORROWED linear / typestate identifier
        packed into an aggregate literal (a struct field, or a list /
        tuple element).

        Packing a borrowed value into an aggregate lets it escape the
        callee -- returned, stored, or later consumed by whoever holds
        the aggregate -- while the caller still owns it, so it would
        double-consume / double-free. This is the one escape path that is
        NOT funnelled through ``_linear_discharge`` (an aggregate literal
        is neither a consume position nor a bare-identifier return), so it
        gets an explicit check here, mirroring the owned-value leak-at-exit
        protection the analyzer already applies to an OWNED value packed
        the same way."""
        from .. import capa_ast as _A
        if isinstance(expr, _A.Ident) and expr.name in self._borrowed_linear:
            self._err(
                f"cannot pack borrowed linear/typestate value "
                f"{expr.name!r} into an aggregate; the caller retains "
                f"ownership -- declare the parameter `consume` to take "
                f"ownership",
                pos,
            )

    # ---- enforcement at scope / function exit --------------------

    def _linear_check_dropped(self, names: set[str]) -> None:
        """Error for every ``name`` in ``names`` that still holds a
        live linear obligation (i.e. was never consumed before its
        binding went out of scope). Removes them from the live set so
        the same value is not reported twice up the scope chain.

        HOLE-1 (iv) per-field accounting. A live obligation may have had
        SOME of its linear fields moved out (``close(s.conn)`` /
        ``let c = s.conn``) while the rest were never consumed. For each
        live ``name`` we enumerate its linear/typestate sub-fields and
        split on what is still outstanding:

        - no linear sub-fields, or none of them consumed: the WHOLE value
          was never (partially) moved, so it leaks -- the whole-value
          message.
        - some but not all consumed (a partial move): each UNCONSUMED
          sub-field leaks and is reported BY PATH (``s.b``), so the
          diagnostic names the field the user forgot, not the opaque
          whole.
        - all consumed (fully moved out): satisfied, no report."""
        for name in names:
            live = self._live_linear.get(name)
            if live is None:
                continue
            pos, ty = live
            # LIN-1: a ``consume`` parameter is DROP EXEMPT. It was seeded
            # into ``_live_linear`` only to poison a re-consume / use-after-
            # consume (caught by the single use-after-consume check above);
            # dropping it without re-consuming is the terminal-owner
            # semantics (``discard`` / ``adopt``), not a leak. A CARRIER
            # ``consume`` param is exempt transitively (adopting the whole
            # carrier + its contents is legal). Clear it so it is not
            # re-checked up the scope chain.
            if name in self._drop_exempt_linear:
                del self._live_linear[name]
                continue
            subs = self._linear_field_paths(name, ty)
            # Discharge is read from the INTERSECTION-merged field-move set,
            # not ``_consumed``: a field moved on only some branches is NOT
            # discharged at scope exit (Connection C).
            consumed = [s for s in subs if self._field_discharged(s)]
            if not consumed:
                self._err(
                    f"linear value {name!r} is dropped without being "
                    f"consumed; a `linear type` value must be passed to a "
                    f"consuming function (e.g. a `consume self` method like "
                    f"`close`) or returned before it goes out of scope",
                    pos,
                )
            elif len(consumed) < len(subs):
                for s in subs:
                    if self._field_discharged(s):
                        continue
                    self._err(
                        f"linear field {s!r} is dropped without being "
                        f"consumed; consume it (e.g. a `consume self` method "
                        f"like `close`) or move it out before the value goes "
                        f"out of scope",
                        pos,
                    )
            del self._live_linear[name]
