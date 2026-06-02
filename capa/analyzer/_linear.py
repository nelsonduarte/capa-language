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
        result of an expression that produces a linear value."""
        if self._ty_is_linear(ty):
            self._live_linear[name] = pos

    def _linear_discharge(self, name: str) -> None:
        """Clear the obligation for ``name`` (it was consumed /
        transferred). No-op if ``name`` carried none."""
        self._live_linear.pop(name, None)

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
