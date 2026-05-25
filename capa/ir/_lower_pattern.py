"""Pattern-side AST -> CIR lowering.

Three concerns:

- ``_refine_pattern_binds`` -- after a match-arm pattern lands,
  refine the type info attached to every binder so downstream
  emitters see the right Capa type.
- ``_variant_payload_tys`` -- look up a variant constructor's
  payload types so the binder types can be propagated.
- ``_lower_pattern`` / ``_lower_literal_pattern`` -- translate
  an AST pattern into a CIR ``Pattern``.

Audit P1 refactor: split per AST family.
"""

from __future__ import annotations

from .. import capa_ast as A
from ._lower_helpers import _split_tuple_elem_types, _split_top_level_comma
from ._nodes import (
    PatIdent, PatLiteral, PatTuple, PatVariant, PatWildcard, Pattern, Value,
)


class _LowerPatternMixin:
    def _refine_pattern_binds(self, p: A.Pattern, scrut_ty: str) -> None:
        """Best-effort: thread the scrutinee's type into pattern-bound
        identifier locals so downstream method dispatch sees the
        right receiver type. Without this, ``Some(m) -> m.get(k)``
        sees ``m: Unknown`` and skips the type-aware Map/List/String
        rewrite. We handle Option, Result, and user-defined sum
        types where the lowerer has the variant decl's payload types
        in scope. Tuple patterns recurse element-by-element using
        the per-position types parsed out of the scrutinee's tuple
        type string. A top-level IdentPat catch-all binds the whole
        scrutinee, so the binder takes the scrutinee's type directly;
        without this the Wasm backend declared the local as the
        Unknown-default ``i64`` and the assignment from an i32
        scrutinee (Bool, tuple pointer) tripped the validator."""
        if isinstance(p, A.IdentPat):
            self._bind_local(p.name, scrut_ty)
            return
        if isinstance(p, A.TuplePat):
            elem_tys = _split_tuple_elem_types(scrut_ty)
            for idx, sub in enumerate(p.elements):
                ety = elem_tys[idx] if idx < len(elem_tys) else "Unknown"
                if isinstance(sub, A.IdentPat):
                    self._bind_local(sub.name, ety)
                else:
                    self._refine_pattern_binds(sub, ety)
            return
        if not isinstance(p, A.VariantPat) or not p.payloads:
            return
        payload_tys = self._variant_payload_tys(p.name, scrut_ty)
        if payload_tys is None or len(payload_tys) != len(p.payloads):
            return
        for sub, ty in zip(p.payloads, payload_tys):
            if isinstance(sub, A.IdentPat):
                self._bind_local(sub.name, ty)
            else:
                # Nested patterns share the same refinement rule.
                self._refine_pattern_binds(sub, ty)

    def _variant_payload_tys(
        self, variant_name: str, scrut_ty: str,
    ) -> Optional[list[str]]:
        """Return the payload type(s) bound by ``Variant(...)`` when
        the scrutinee has type ``scrut_ty``. Handles the built-in
        ``Option<T>`` / ``Result<T, E>`` shapes via string parsing,
        and user-defined sums via the pre-collected ``_user_variants``
        table populated by ``lower_module``."""
        if scrut_ty.startswith("Option<") and scrut_ty.endswith(">"):
            inner = scrut_ty[7:-1]
            if variant_name == "Some":
                return [inner]
            if variant_name == "None":
                return []
        if scrut_ty.startswith("Result<") and scrut_ty.endswith(">"):
            inner = scrut_ty[7:-1]
            t, e = _split_top_level_comma(inner)
            if variant_name == "Ok":
                return [t]
            if variant_name == "Err":
                return [e]
        if variant_name in self._user_variants:
            return list(self._user_variants[variant_name])
        return None

    def _lower_pattern(self, p: A.Pattern) -> Pattern:
        """Translate an AST pattern to its IR shape. Phase 2D supports
        Wildcard, Ident, Literal (Int / String / Bool / Unit), and
        Variant (with payloads). Other shapes (Struct, Tuple, Or)
        raise UnsupportedInIR until a later phase handles them."""
        if isinstance(p, A.WildcardPat):
            return PatWildcard()
        if isinstance(p, A.IdentPat):
            # Track the binding name as a local in the arm scope so
            # that the arm body can reference it. ``_bind_local``
            # preserves any refinement that ``_refine_pattern_binds``
            # may have written before us (same-frame rebinding keeps
            # the more specific type); when the name shadows an outer
            # binding it gets a fresh alpha-renamed identifier so the
            # two Wasm locals don't collide on incompatible shapes.
            bound = self._bind_local(p.name, "Unknown")
            return PatIdent(name=bound)
        if isinstance(p, A.LiteralPat):
            return self._lower_literal_pattern(p)
        if isinstance(p, A.VariantPat):
            payloads = [self._lower_pattern(sub) for sub in p.payloads]
            return PatVariant(name=p.name, payloads=payloads)
        if isinstance(p, A.TuplePat):
            elements = [self._lower_pattern(sub) for sub in p.elements]
            return PatTuple(elements=elements)
        raise UnsupportedInIR(f"match pattern {type(p).__name__}")

    def _lower_literal_pattern(self, p: A.LiteralPat) -> Pattern:
        v = p.value
        if isinstance(v, A.IntLit):
            return PatLiteral(kind="int", value=v.value)
        if isinstance(v, A.StringLit):
            return PatLiteral(kind="str", value=v.value)
        if isinstance(v, A.BoolLit):
            return PatLiteral(kind="bool", value=v.value)
        if isinstance(v, A.UnitLit):
            return PatLiteral(kind="unit", value=None)
        raise UnsupportedInIR(
            f"literal pattern of kind {type(v).__name__}"
        )

    # ------------------------------------------------------------
    # Expressions: each returns a Value.
    # ------------------------------------------------------------

