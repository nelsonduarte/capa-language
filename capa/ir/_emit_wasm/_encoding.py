"""Low-level value-encoding helpers shared across emission mixins.

The Wasm backend's uniform i64 payload slot for variant data
needs two encoding tricks:

- **Strings** cross the slot as a packed ``(ptr | (len << 32))``
  i64. Storing requires the 9-instruction pack sequence; reading
  back into separate ``${name}_ptr`` / ``${name}_len`` i32 locals
  requires the 8-instruction unpack sequence.

- **Pointer-shaped values** (struct, sum, list, map, set, tuple)
  cross the slot as their raw i32 pointer, extended to i64. The
  predicate that classifies a Capa type as pointer-shaped lives
  here because the slot-emission code in five different mixins
  needs the same answer.

Each helper appeared inline 5-7 times across the emitter before
this extraction (audit 2026-05-25 item #7 phase 2). Centralising
them eliminates the drift risk where one site fixes a bug and
the others silently keep the old shape.
"""

from __future__ import annotations

from .._nodes import Value


class _EncodingMixin:
    """Provides string-pack / unpack / pointer-shape predicates to
    every other emitter mixin. Assumes the host class supplies
    ``self._write`` (line emission), ``self._push_string_value_as_ptr_len``
    (defined by ``_StringEmissionMixin``), and the layout tables
    ``self._struct_layouts`` / ``self._sum_layouts``."""

    def _emit_pack_string_value_to_i64(self, v: Value) -> None:
        """Push the String ``v`` onto the operand stack as a packed
        i64 (low 32 bits = ptr, high 32 bits = len). Uses
        ``$_alloc_tmp_i64`` as scratch; callers must declare it as
        a function-local. After this returns the stack has one
        additional i64."""
        self._push_string_value_as_ptr_len(v)
        self._write("i64.extend_i32_u")  # len -> i64
        self._write("i64.const 32")
        self._write("i64.shl")            # (len << 32)
        self._write("local.tee $_alloc_tmp_i64")
        self._write("drop")
        self._write("i64.extend_i32_u")  # ptr -> i64
        self._write("local.get $_alloc_tmp_i64")
        self._write("i64.or")            # ptr | (len << 32)

    def _emit_unpack_i64_to_string(self, ptr_local: str, len_local: str) -> None:
        """Consume an i64 from the top of the operand stack and
        split it into ``${ptr_local}`` (low 32 bits) and
        ``${len_local}`` (high 32 bits). Uses ``$_alloc_tmp_i64``
        as scratch; callers must declare it as a function-local
        and must declare both ``${ptr_local}`` and ``${len_local}``
        as i32 locals."""
        self._write("local.tee $_alloc_tmp_i64")
        self._write("i32.wrap_i64")
        self._write(f"local.set ${ptr_local}")
        self._write("local.get $_alloc_tmp_i64")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")
        self._write(f"local.set ${len_local}")

    def _is_pointer_shape_ty(self, ty: str) -> bool:
        """True iff ``ty`` lowers to an i32 heap pointer in the
        Wasm backend's value representation. Struct, sum, list /
        map / set, non-unit tuple, and user-defined TRAIT types all
        hand their data round through a heap record; their pointer
        needs i32 -> i64 extension when stored in a uniform i64
        payload slot.

        A trait-typed value lowers to a single i32 pointer (a
        concrete struct or sum) tagged with a dynamic type-id, so
        it is pointer-shaped exactly like the concrete types it
        stands in for. Recognising it here repairs the store side
        (Option/Result payload, Map value, List element, tuple
        component, struct field) and the read-back side (match-arm
        payload unwrap) symmetrically through this one predicate.

        Variant-construction call sites OR in their own checks on
        top of this predicate (``arg.kind == "variant_ctor"`` and
        ``arg.ty in self._variant_to_sum``), because the Value's
        declared type is the variant name rather than the sum
        name at the construction boundary.
        """
        head = ty.split("<", 1)[0]
        return (
            head in self._struct_layouts
            or head in self._sum_layouts
            or head in getattr(self, "_trait_value_types", ())
            or ty.startswith(("List", "Map", "Set"))
            or (ty.startswith("(") and ty.endswith(")") and ty != "()")
        )
