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
    # ---- type predicate ------------------------------------------

    def _ty_is_linear(self, ty: Optional[Ty]) -> bool:
        """True if ``ty`` names a ``linear type`` struct."""
        return isinstance(ty, TyName) and ty.name in self._linear_types

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
        rely on this."""
        if self._ty_is_linear(ty):
            self._live_linear[name] = pos
            self._consumed.discard(name)
            self._linear_names.discard(name)

    def _linear_discharge(self, name: str) -> None:
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
        ``_linear_bind`` of the same name lifts the poison."""
        had = name in self._live_linear
        self._live_linear.pop(name, None)
        if had:
            self._consumed.add(name)
            self._linear_names.add(name)

    def _linear_transfer_if_alias(self, value: "A.Expr") -> None:
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

        No-op unless the RHS is a bare ``Ident`` that currently holds a
        live obligation -- a non-identifier RHS (a call, ``become``, ...)
        produces a fresh value, and an already-consumed source is gone from
        ``_live_linear`` and handled by the ordinary use-after-consume
        check on the RHS itself."""
        from .. import capa_ast as _A
        if not isinstance(value, _A.Ident):
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
        self._err(
            "linear value is dropped without being consumed; a "
            "`linear type` / typestate value must be passed to a "
            "consuming function (e.g. a `consume self` method like "
            "`close`), transitioned with `become`, or returned -- it "
            "cannot be discarded into `_` or a bare expression statement",
            pos,
        )

    # ---- enforcement at scope / function exit --------------------

    def _linear_check_dropped(self, names: set[str]) -> None:
        """Error for every ``name`` in ``names`` that still holds a
        live linear obligation (i.e. was never consumed before its
        binding went out of scope). Removes them from the live set so
        the same value is not reported twice up the scope chain."""
        for name in names:
            pos = self._live_linear.get(name)
            if pos is None:
                continue
            self._err(
                f"linear value {name!r} is dropped without being "
                f"consumed; a `linear type` value must be passed to a "
                f"consuming function (e.g. a `consume self` method like "
                f"`close`) or returned before it goes out of scope",
                pos,
            )
            del self._live_linear[name]
