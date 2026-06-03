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

from dataclasses import dataclass
from typing import Optional

from .. import capa_ast as A
from ._lower_helpers import (
    _split_tuple_elem_types, _split_top_level_comma, UnsupportedInIR,
)
from ._nodes import (
    PatIdent, PatLiteral, PatTuple, PatVariant, PatWildcard, Pattern, Value,
)


# Two CIR pattern shapes that the core ``_nodes`` set does not carry
# yet (the Python IR emitter only understands the original five). They
# live here rather than in ``_nodes`` because only the Wasm match
# emitter consumes them; the Wasm emitter imports them from this module
# (no import cycle: lowering never imports the emitter). If a later
# phase teaches the Python IR emitter about them they should graduate
# into ``_nodes``.
@dataclass
class PatOr(Pattern):
    """``A | B | ... -> body``. Matches if ANY alternative matches;
    the body runs once. Only the binding-free case is lowered (the
    lowerer rejects alternatives that bind names); the emitter ORs
    the per-alternative predicates together."""
    alternatives: list


@dataclass
class PatStruct(Pattern):
    """``Type { field: subpat, field2, ... } -> body``. Matches a
    struct scrutinee by destructuring fields. ``fields`` is an
    ordered list of ``(field_name, sub_pattern)`` pairs; shorthand
    ``{ x }`` lowers to ``("x", PatIdent("x"))``. The emitter loads
    each field from the struct's heap record (via the struct layout
    offsets) and recursively matches the sub-pattern."""
    type_name: str
    fields: list  # list[tuple[str, Pattern]]


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
        if isinstance(p, A.OrPat):
            return self._lower_or_pattern(p)
        if isinstance(p, A.StructPat):
            return self._lower_struct_pattern(p)
        raise UnsupportedInIR(f"match pattern {type(p).__name__}")

    def _lower_or_pattern(self, p: A.OrPat) -> Pattern:
        """Lower an or-pattern. Each alternative is lowered
        independently; the emitter ORs their predicates and runs the
        shared body once. We accept only binding-free alternatives
        (variant-without-payload, literal, wildcard) -- supporting
        bindings would require every alternative to bind the same
        names with the same types (Rust's rule), which the Wasm
        emitter does not implement. A binding-bearing alternative
        raises so a program never silently miscompiles."""
        alts: list[Pattern] = []
        for sub in p.alternatives:
            if isinstance(sub, A.IdentPat):
                raise UnsupportedInIR(
                    "or-pattern with bindings not supported on the "
                    "Wasm backend yet (alternatives must be "
                    "binding-free: literal / wildcard / "
                    "payload-less variant)"
                )
            if isinstance(sub, A.VariantPat) and sub.payloads:
                raise UnsupportedInIR(
                    "or-pattern with bindings not supported on the "
                    "Wasm backend yet (a variant alternative may not "
                    "carry payload binders)"
                )
            lowered = self._lower_pattern(sub)
            alts.append(lowered)
        return PatOr(alternatives=alts)

    def _lower_struct_pattern(self, p: A.StructPat) -> Pattern:
        """Lower a struct-destructuring pattern. Shorthand fields
        (``{ x }``) carry a ``None`` sub-pattern in the AST, which we
        expand to ``IdentPat(x)`` (bind the field to a local named
        after it). Each sub-pattern is lowered recursively and its
        binders are tracked as arm-scope locals."""
        fields: list = []
        for fname, sub in p.fields:
            if sub is None:
                sub = A.IdentPat(pos=p.pos, name=fname)
            fields.append((fname, self._lower_pattern(sub)))
        return PatStruct(type_name=p.type_name, fields=fields)

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
        if isinstance(v, A.CharLit):
            # A Char is a single-codepoint String at the value level
            # (see ``_lower_expr.py``'s CharLit -> ``lit_str`` rule).
            # Lower the pattern as a one-char String literal so the
            # existing String-scrutinee match path compares it via
            # ``$str_eq`` (kind="str"); on the Wasm path the scrutinee
            # type is normalized ``Char`` -> ``String`` before emit, so
            # ``match c { 'a' -> ... }`` routes to ``_emit_string_match``
            # and ``PatLiteral.kind == "str"`` is what that path reads.
            # The Python emitter also renders a "str"-kind PatLiteral
            # as the one-char string literal, matching the value rule.
            return PatLiteral(kind="str", value=v.value)
        if isinstance(v, A.FloatLit):
            return PatLiteral(kind="float", value=v.value)
        raise UnsupportedInIR(
            f"literal pattern of kind {type(v).__name__}"
        )

    # ------------------------------------------------------------
    # Expressions: each returns a Value.
    # ------------------------------------------------------------

