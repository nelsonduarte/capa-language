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

from ..tokens import Pos
from ..typesys import Ty, TyName


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

    def _prefix_consumed(self, place: str) -> bool:
        """True iff ``place`` or a ``.``-split prefix of it is in
        ``_consumed``. Component-wise, never a raw ``startswith``: the
        prefixes of ``s.conn.fd`` are exactly ``s``, ``s.conn``,
        ``s.conn.fd``, so a consumed ``s`` covers ``s.conn`` but a consumed
        ``session`` never covers ``s``."""
        parts = place.split(".")
        for i in range(1, len(parts) + 1):
            if ".".join(parts[:i]) in self._consumed:
                return True
        return False

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
        """Record a new outstanding linear obligation for ``name`` when
        ``ty`` is linear. Called when a ``let`` / ``var`` binds the
        result of an expression that produces a linear value.

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
        if self._ty_is_linear(ty):
            self._live_linear[name] = pos
            self._live_linear_ty[name] = ty
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
            self._live_linear_ty.pop(name, None)
            return
        had = name in self._live_linear
        self._live_linear.pop(name, None)
        self._live_linear_ty.pop(name, None)
        if had:
            self._consumed.add(name)
            self._linear_names.add(name)

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
        if not isinstance(value, _A.Ident):
            return
        if value.name in self._borrowed_linear:
            self._borrowed_linear.add(target)
            return
        if value.name not in self._live_linear:
            return
        self._linear_discharge(value.name)

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
        value re-arms the obligation."""
        # B-F1: re-assigning a non-borrowed value to the name clears any
        # borrowed marker it held, so ``_linear_bind`` below can arm a
        # fresh owned obligation from the new value.
        self._borrowed_linear.discard(name)
        old_pos = self._live_linear.get(name)
        if old_pos is not None:
            self._err(
                f"linear value {name!r} is dropped without being "
                f"consumed; re-assigning to it overwrites the old value, "
                f"which a `linear type` / typestate value cannot be -- "
                f"consume the current value (e.g. a `consume self` method "
                f"like `close`, or `become`) before re-assigning",
                pos,
            )
            del self._live_linear[name]
            self._live_linear_ty.pop(name, None)
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
        here, not again at function exit."""
        if not self._ty_is_linear(ty):
            return
        from .. import capa_ast as _A
        if isinstance(expr, _A.Ident):
            self._live_linear.pop(expr.name, None)
            self._live_linear_ty.pop(expr.name, None)
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
            pos = self._live_linear.get(name)
            if pos is None:
                continue
            subs = self._linear_field_paths(name, self._live_linear_ty.get(name))
            consumed = [s for s in subs if self._prefix_consumed(s)]
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
                    if self._prefix_consumed(s):
                        continue
                    self._err(
                        f"linear field {s!r} is dropped without being "
                        f"consumed; consume it (e.g. a `consume self` method "
                        f"like `close`) or move it out before the value goes "
                        f"out of scope",
                        pos,
                    )
            del self._live_linear[name]
            self._live_linear_ty.pop(name, None)
