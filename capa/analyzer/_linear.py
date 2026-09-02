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

from .._owned_obligation import (
    carries_linear,
    linear_leaf_paths,
    owned_obligation,
)
from ..tokens import Pos
from ..typesys import Ty, TyName, TyTuple


class _LinearMixin:
    # A move PLACE is a syntactic dotted path (``s.conn.fd``); a chain
    # deeper than K field components collapses to the whole-value base so
    # the tracked place stays a bounded string. This is a sound
    # finite-syntactic bound, NOT a carrier-termination guard: the
    # obligation predicate / enumerator terminate by cycle detection (see
    # ``capa/_owned_obligation.py``), decoupled from this collapse.
    _LINEAR_PLACE_MAX_DEPTH = 8

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

    def _reaches_linear(self, ty: Optional[Ty]) -> bool:
        """Recursive leaf test: True iff a linear/typestate type is reachable
        anywhere in ``ty`` -- as ``ty`` itself, through a struct field
        (``_type_carries_linear``), or below a container / tuple layer at any
        nesting depth. Structural twin of ``_contains_any_capability``, so the
        container-of-linear invariant mirrors the capability one exactly.

        No depth cap: ``ty`` is a resolved type tree whose generic-arg /
        tuple-element nesting is finite (it cannot cycle), and it delegates
        struct-field descent to the now-cycle-safe ``_owned_obligation``
        predicate, so the walk terminates without a fail-open bound (a deep
        ``List<...<Conn>>`` is correctly rejected at any nesting).

        Like ``_cap_in_container`` it does NOT descend a ``TyFun``: a linear
        value captured inside a closure is a signature, not container storage,
        and consuming a captured value is already barred by the capture-consume
        check in ``_mark_consumed_args``."""
        if ty is None:
            return False
        if self._owned_obligation(ty):
            return True
        if isinstance(ty, TyName):
            return any(self._reaches_linear(a) for a in ty.args)
        if isinstance(ty, TyTuple):
            return any(self._reaches_linear(e) for e in ty.elements)
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

    def _linear_field_paths(self, place: str, ty: Optional[Ty]) -> list[str]:
        """The finite set of ``place.f...`` sub-paths whose leaf type is
        linear/typestate, enumerated from ``ty``'s struct fields. Delegates
        to the shared :func:`linear_leaf_paths` seam (the same field-root
        lookup the obligation predicate walks), so the carrier leaf
        enumeration lives in exactly one place; the analyzer supplies its
        Symbol-based field-root lookup. The enumeration is path-scoped (a
        diamond yields both branches) and fail-CLOSED budgeted (a crafted
        exponential-diamond type collapses to a whole-value obligation),
        never depth-capped."""
        root = ty.name if isinstance(ty, TyName) else None
        return linear_leaf_paths(
            place, root, self._linear_types, self._symbol_field_roots,
        )

    def _linear_place(self, expr: "A.Expr") -> Optional[str]:
        """The canonical dotted place for an Ident-rooted ``expr`` whose
        LEAF type is linear/typestate, or ``None``. This is ``_path_of``
        restricted to the linear/typestate places the discipline tracks,
        with the ``_LINEAR_PLACE_MAX_DEPTH`` collapse: a chain deeper than K
        fields collapses to its base name so the tracked place stays a
        bounded string (a sound finite-syntactic bound, independent of
        carrier termination). An index (``xs[i]``) or any non-static
        component yields ``None`` via ``_path_of`` -- the Model-B container
        collapse for free (no per-element move path)."""
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
        if path.count(".") > self._LINEAR_PLACE_MAX_DEPTH:
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

    def _field_linear_leaves(self, target: "A.Expr") -> list[str]:
        """THE single source of the linear/typestate LEAF places a field
        projection owns -- a store TARGET field or a move OPERAND alike --
        driving the RHS move, the per-leaf re-arm / overwrite-leak, AND every
        field-projection move (``_move_field_leaves``), so the bare-leaf and
        carrier-field paths share one mechanism (the bare leaf is the degenerate
        one-element instance).

        - a bare ``linear type`` / typestate leaf yields its one place (keeping
          the ``_linear_place`` depth-collapse), and
        - a non-linear field yields none.

        A CARRIER-typed target field yields its subtree of linear leaves via
        ``_linear_field_paths`` (the single subtree enumerator, cycle-safe and
        fail-closed budgeted), so the store into a carrier field is driven by
        the SAME per-leaf loop as the bare leaf with no parallel mechanism."""
        place = self._path_of(target)
        if place is None:
            return []
        return self._linear_leaves_of(place, self.types.get(id(target)))

    def _linear_leaves_of(self, place: str, field_ty) -> list[str]:
        """The place-driven core of ``_field_linear_leaves``: which linear /
        typestate leaves the value at ``place`` (of type ``field_ty``) owns.
        Split out so an operand that resolves to a place WITHOUT being spelled
        as a field-access node -- a ``match`` arm binder that VIEWS a carrier
        field -- enumerates its leaves through the SAME single source. Keeps
        the ``_LINEAR_PLACE_MAX_DEPTH`` collapse the node-driven form applied
        through ``_linear_place``."""
        if self._ty_is_linear(field_ty):
            if place.count(".") > self._LINEAR_PLACE_MAX_DEPTH:
                place = place.split(".", 1)[0]
            return [place]
        if self._owned_obligation(field_ty):
            return self._linear_field_paths(place, field_ty)
        return []

    def _move_field_leaves(self, fa: "A.Expr", pos: Pos) -> bool:
        """THE single source of "move a field-PROJECTION operand's linear
        subtree out", used at every move position (consume-arg / struct +
        typestate pack / return / bind / field-store RHS / ``consume self``
        receiver). Composes the two existing single sources -- ``_field_linear_
        leaves`` (which leaves the field owns) and ``_linear_move_field`` (move
        one leaf, including its borrowed reject and moved-set recording) -- and
        returns whether the field owned any linear leaf. A bare leaf (a
        one-element leaf set) and a whole carrier subtree move identically, so
        no move position re-implements the loop.

        Correction: moving only the leaves does NOT catch RE-consuming an
        already-moved CARRIER field. ``_linear_move_field`` short-circuits on an
        already-moved leaf, and the FieldAccess use-site check keys on the field
        / root path, not the deeper leaf, so ``close2(b.two); close2(b.two)`` /
        ``... ; return b.two`` would slip through. Reject it here FIRST -- the
        husk-reconsume analogue for a FieldAccess operand -- CARRIER-only (a
        bare leaf is left to its own use-site check, so its double-consume stays
        exactly one diagnostic)."""
        path = self._path_of(fa)
        if path is None:
            return False
        return self._move_leaves_of(path, self.types.get(id(fa)), pos)

    def _move_leaves_of(self, path: str, field_ty, pos: Pos) -> bool:
        """The place-driven core of ``_move_field_leaves`` (same contract, same
        order of checks), so a field projection and a pattern-binding VIEW of
        the same field move through ONE body."""
        leaves = self._linear_leaves_of(path, field_ty)
        if not leaves:
            return False
        if path is not None and not self._ty_is_linear(field_ty):
            sub = self._subpath_consumed(path)
            if sub is not None:
                self._err(
                    f"cannot consume or move carrier field {path!r}: its "
                    f"linear field {sub!r} was already consumed, so consuming "
                    f"it again would double-free that field -- its linear "
                    f"fields were already moved out",
                    pos,
                )
                return True
        for leaf in leaves:
            self._linear_move_field(leaf, pos)
        return True

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

    def _transfer_borrowed_marker(self, value: "A.Expr", target: str) -> bool:
        """THE one place the BORROWED marker's propagation onto a ``let`` /
        ``var`` / assign target is decided. True iff ``target`` inherited it,
        in which case the caller must not move or arm anything: a borrowed
        source has no obligation to move (the caller still owns it) and
        ``_linear_bind`` skips opening a fresh owned one under the alias.

        Decided on the RESOLVED place, through the same ``_path_of`` every
        other position-driven rule uses, so a conditional / match SELECTION
        and a pattern-binding VIEW reach it exactly as a bare identifier
        does. Spelled syntactically -- ``isinstance(value, Ident)`` reading
        ``value.name``, plus a second copy on the field-projection path --
        both alias forms slipped past every copy: the move seam is a NO-OP on
        a borrowed source, so the bind that follows armed the target as a
        FRESH OWNER and laundered the caller's still-owned value into a
        second obligation. The escape rule at the aggregate-pack sites then
        saw a name that was no longer borrowed, so laundering here defeated
        it one statement later as well.

        PREFIX membership, not whole-place: projecting a field of a borrowed
        value (``let c = h.conn``) binds the new name borrowed too, which is
        what the field-projection path decided for itself before this seam
        existed. That is the opposite choice from
        ``_linear_check_borrowed_escape``, deliberately: the escape rule
        tests the whole place because a borrowed FIELD packed into an
        aggregate is already rejected inside the move seam, so a prefix test
        there would report one mistake twice. Here nothing else reports, and
        a prefix IS the borrow."""
        place = self._path_of(value)
        if place is None or not self._prefix_borrowed(place):
            return False
        self._borrowed_linear.add(target)
        return True

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
        opening a fresh owned obligation under it. That propagation is
        decided ONCE, on the RESOLVED place, by
        ``_transfer_borrowed_marker`` below -- not per RHS shape.

        No-op (beyond clearing the target marker) unless the RHS is a bare
        ``Ident`` naming a borrowed value or one that currently holds a live
        obligation -- a non-identifier RHS (a call, ``become``, ...)
        produces a fresh value, and an already-consumed source is gone from
        ``_live_linear`` and handled by the ordinary use-after-consume
        check on the RHS itself."""
        from .. import capa_ast as _A
        self._borrowed_linear.discard(target)
        if self._transfer_borrowed_marker(value, target):
            return
        if isinstance(value, (_A.IfExpr, _A.MatchExpr)) or (
            self._selection_root_of(value) is not None
        ):
            # A conditional / match SELECTION RHS (bare, or projected off
            # one): the ONE move seam owns the resolve-or-fail-closed verdict,
            # so the bind below arms the target as the single owner.
            self._move_linear_operand(value)
            return
        if isinstance(value, _A.FieldAccess):
            # HOLE-1 (ii): a projection ``let c = s.conn`` / ``let t = b.two``
            # MOVES the field's linear subtree out of its carrier -- poison the
            # leaves so the carrier can no longer consume them, and let
            # ``_linear_bind`` arm ``target`` as the fresh owner. Driven by the
            # leaf-set enumerator so a bare leaf and a whole carrier field move
            # identically (covers ``let`` + ``var`` + name-reassign at once).
            if not self._field_linear_leaves(value):
                return
            self._move_field_leaves(value, value.pos)
            return
        if isinstance(value, (_A.Call, _A.MethodCall)):
            # E3: a ``let``/``var``/assign RHS that is a generic identity /
            # passthrough call (``let h2 = id(h)``) MOVES the argument its
            # result aliases off the source, through the ONE move seam, so the
            # caller's ``_linear_bind`` arms the NEW name as the single owner
            # (the source is poisoned, a later ``close(h)`` rejects). A fresh
            # factory call moves nothing and the new obligation is genuinely
            # fresh.
            self._move_linear_operand(value)
            return
        if not isinstance(value, _A.Ident):
            return
        place = self._path_of(value)
        if place != value.name:
            # The RHS is a pattern-binding VIEW of another place (a ``match``
            # arm binder): the obligation lives at the place it views, so move
            # THAT through the one seam rather than opening a second one here.
            self._move_linear_operand(value)
            return
        # Past this point the RESOLVED place and the spelled name are the same
        # string, proven by the test above, so keying on either is keying on
        # the resolved place -- ``place`` is used to say so.
        if place in self._live_linear:
            # Carry any partially-moved sub-path onto the alias BEFORE the
            # whole obligation transfers, so the tail of an alias chain (whose
            # husk head re-armed it live) inherits the moved-out field and a
            # re-consume through it is rejected.
            self._carry_moved_subpaths(place, target)
            self._linear_discharge(place)
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
        val_ty = self._operand_leaf_ty(value)
        if self._type_carries_linear(val_ty):
            self._consumed.add(place)
            self._linear_names.add(place)
            # The source may be a spent HUSK (its linear field already moved
            # out, popped from the live set). Carry that moved-out sub-path
            # onto the alias so consuming / returning / re-packing the whole
            # husk through ``target`` (or the next link of a chain) is rejected
            # exactly as it is on the source.
            self._carry_moved_subpaths(place, target)

    # ---- the ONE transfer-operand rule ---------------------------

    def _move_transfer_operand(self, value: "A.Expr", pos: Pos) -> bool:
        """Move a TRANSFER operand -- a ``return`` value, a ``become`` value, a
        ``consume self`` receiver, a ``consume`` argument -- through the ONE
        move seam, and apply the ONE borrowed-transfer reject the four
        positions share.

        The seam deliberately returns False for a BORROWED bare value (its
        contract: the caller supplies the wording, because the aggregate-pack
        position words it differently). That reject used to be spelled out at
        each transfer position as ``isinstance(value, Ident) and value.name in
        _borrowed_linear``, which is a SYNTACTIC test: a borrowed value reached
        through a pattern-binding view or a conditional selection matched none
        of the four copies and was silently transferred. Deciding it on the
        RESOLVED place instead, in one place, closes all four at once."""
        if self._move_linear_operand(value, pos=pos):
            return True
        place = self._path_of(value)
        if place is None or place not in self._borrowed_linear:
            return False
        if self._reject_linear_capture(place, pos):
            return True
        self._linear_discharge(place, pos)
        return True

    # ---- the ONE pattern-binding seam ----------------------------

    def _linear_bind_pattern_own(
        self, p: "A.Pattern", value: "A.Expr", ty: Optional[Ty], pos: Pos,
    ) -> None:
        """Record the linear consequence of an OWNING binding -- a ``let``,
        whose bound names outlive the statement, so the obligation TRANSFERS
        onto them.

        A bare ``IdentPat`` is the shape ``let h = open()`` / ``let h2 = h``
        already used: move any aliased source, then arm the name. A
        DESTRUCTURING ``let Box { c: inner } = b`` binds each field name to
        the corresponding field PLACE, so it is exactly the projection
        ``let inner = b.c`` per field and moves the field out of its carrier
        -- the shape that previously bound nothing at all and left the
        carrier consumable a second time through its original name. The
        field's type is read back from the symbol the pattern binder just
        defined, so this seam never re-derives a field type."""
        from .. import capa_ast as _A
        if isinstance(p, _A.IdentPat):
            self._linear_transfer_if_alias(value, p.name)
            self._linear_bind(p.name, ty, pos)
            return
        if isinstance(p, _A.WildcardPat):
            self._linear_check_anonymous_drop(value, ty, pos)
            return
        if not self._owned_obligation(ty):
            return
        if isinstance(p, _A.StructPat):
            for fname, fpat in p.fields:
                if fpat is None:
                    bound = fname
                elif isinstance(fpat, _A.IdentPat):
                    bound = fpat.name
                elif isinstance(fpat, _A.WildcardPat):
                    continue
                else:
                    self._reject_unresolvable_binding(p.pos)
                    return
                sym = self.scope.lookup_local(bound)
                sub_ty = sym.ty if sym is not None else None
                proj = _A.FieldAccess(
                    pos=p.pos, receiver=value, field_name=fname,
                )
                self.types[id(proj)] = sub_ty
                self._linear_transfer_if_alias(proj, bound)
                self._linear_bind(bound, sub_ty, pos)
            return
        if self._pattern_has_binding(p):
            self._reject_unresolvable_binding(p.pos)

    def _linear_bind_pattern_view(
        self, p: "A.Pattern", source: "A.Expr", ty: Optional[Ty], pos: Pos,
    ) -> None:
        """Record the linear consequence of a VIEWING binding -- a ``match``
        arm binder, whose names live only inside the arm while the scrutinee
        keeps the obligation.

        This is the seam the whole match-arm class turns on. The binder is NOT
        a second obligation: it is registered in ``_linear_alias`` as a view of
        the scrutinee's place, so consuming it, projecting a field off it,
        returning it, packing it, or re-reading it after a consume all resolve
        -- through the single ``_path_of`` -- to the scrutinee. When the
        scrutinee is a genuinely FRESH value instead (``match mkbox() { v ->
        ... }``) the binder is the only owner, so it is armed as one. When the
        scrutinee resolves to neither (an unsummarisable call, arms that
        disagree) the binding FAILS CLOSED, because a binder whose owner the
        compiler cannot name could be consumed once through the binder and
        again through the original."""
        if not self._owned_obligation(ty):
            return
        bound = set(self.scope.symbols)
        if not bound:
            # A literal / wildcard arm binds nothing: the obligation simply
            # stays under the scrutinee's own name, as it does today.
            return
        cls = self._classify_selection_value(source)
        if cls[0] == "place":
            views = self._pattern_view_places(p, cls[1])
            if views is not None and set(views) == bound:
                self._linear_alias.update(views)
                return
        elif cls[0] == "fresh":
            from .. import capa_ast as _A
            if isinstance(p, _A.IdentPat):
                self._linear_bind(p.name, ty, pos)
                return
        self._reject_unresolvable_binding(pos)

    def _pattern_view_places(self, p: "A.Pattern", place: str):
        """Map each name ``p`` binds to the PLACE it views, given the
        scrutinee's place. ``None`` when a shape cannot be mapped, which the
        caller turns into the fail-closed reject."""
        from .. import capa_ast as _A
        if isinstance(p, _A.IdentPat):
            return {p.name: place}
        if isinstance(p, _A.WildcardPat):
            return {}
        if isinstance(p, _A.StructPat):
            out: dict = {}
            for fname, fpat in p.fields:
                sub = f"{place}.{fname}"
                if fpat is None:
                    out[fname] = sub
                    continue
                nested = self._pattern_view_places(fpat, sub)
                if nested is None:
                    return None
                out.update(nested)
            return out
        if isinstance(p, _A.LiteralPat):
            return {}
        return None

    def _reject_unresolvable_binding(self, pos: Pos) -> None:
        """The fail-closed verdict for a binding over a must-consume value
        whose single owner cannot be named. Rejecting is the conservative
        side: accepting would let the value be consumed through the binder AND
        through whatever else still names it."""
        self._err(
            "a linear/typestate value cannot be bound by this pattern: the "
            "compiler cannot tell which single owner each bound name denotes, "
            "so consuming through the binding could free the value twice -- "
            "bind the whole value to one name (e.g. `v -> ...`) and project "
            "its fields from that name",
            pos,
        )

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

        If the dropped expression denotes a still live linear PLACE
        (``let _ = h``), discharge that binding too: the value has moved
        into the anonymous slot and is reported once here, not again at
        function exit. The place is taken from ``_path_of``, the one
        resolver, so an alias spelling of the same drop -- a conditional
        selection or a pattern-binding view -- pops the SAME binding. Popped
        by ``expr.name`` instead, an alias spelling left the binding live
        and the value was reported a second time at scope exit: one mistake,
        two diagnostics.

        Gated on ``_owned_obligation`` (D), so dropping a CARRIER-returning
        call as a bare statement / ``let _ = make_box()`` -- which leaks the
        struct's linear field -- is caught, not just a bare linear value."""
        if not self._owned_obligation(ty):
            return
        place = self._path_of(expr)
        if place is not None:
            self._live_linear.pop(place, None)
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
        the same way.

        Decides on the RESOLVED place, through the same ``_path_of`` every
        other position-driven rule uses, so a pattern-binding view and a
        conditional selection reach it exactly as a bare identifier does.
        Spelled syntactically it was laundered by both alias forms, at every
        pack site, while the identical direct spelling was rejected.

        WHOLE-place only, deliberately: a borrowed FIELD (``p.conn``) packed
        here is already rejected inside the move seam by
        ``_linear_move_field``'s own borrowed guard, so testing a prefix here
        would report one mistake twice. The division of labour between this
        rule and the move seam is unchanged; only the resolution is."""
        place = self._path_of(expr)
        if place is not None and place in self._borrowed_linear:
            self._err(
                f"cannot pack borrowed linear/typestate value "
                f"{place!r} into an aggregate; the caller retains "
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
