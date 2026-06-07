"""Value-level emission and Capa<->Wasm type mapping.

Owns the helpers every other emitter calls when it needs to
push a ``Value`` onto the operand stack or translate a Capa
type name to its Wasm representation:

- ``_size_of`` -- byte size of a Capa scalar.
- ``_lookup_local_or_param_ty`` -- map a local name to its
  declared Capa type.
- ``_is_string_local`` / ``_param_is_string`` -- predicates the
  String-pack helpers use to decide whether a local is a
  (ptr, len) pair.
- ``_dst_capa_ty`` / ``_effective_value_ty`` -- canonical Capa
  type for a Value's declared / inferred ty field.
- ``_push_value`` -- emit the WAT to put ``v`` on the stack in
  the right Wasm type, picking integer / float / pointer-shape
  paths.
- ``_wasm_type`` -- map a Capa type name to ``i32`` / ``i64`` /
  ``f64`` (or empty for Unit).

Audit P1 split: this cluster is consulted by every
instruction emitter; extracting it keeps WasmEmitter's body
focused on top-level orchestration.
"""

from __future__ import annotations

from typing import Optional

from .._nodes import Value
from ._layout import (
    WasmEmissionError, _TYPE_SIZE,
    _size_of, _store_op_for_size, _load_op_for_size,
    _strip_type_qualifiers,
)


# Capa scalar types this phase knows how to lower. Any other type
# raises NotImplementedError when encountered; the caller (test or
# tooling) is expected to know what subset of the IR Phase 6A
# accepts.
_CAPA_TO_WASM = {
    "Int": "i64",
    "Bool": "i32",
    "Float": "f64",
    "Unit": "",  # no result clause
}


class _ValueEmissionMixin:
    def _size_of(self, capa_ty: str) -> int:
        """Wrapper around the module-level ``_size_of`` that
        consults the emitter's known struct/sum layouts."""
        return _size_of(capa_ty, self._sum_layouts, self._struct_layouts)

    def _lookup_local_or_param_ty(self, name: str) -> Optional[str]:
        """Find ``name`` in the current function's locals or
        params and return its Capa type string, or None if not
        present. Used by ``_emit_user_call`` to detect closure
        callees (callee_name is a local of Fun(...) type) before
        falling back to the ``call $name`` path for top-level
        functions."""
        if self._current_fn is None:
            return None
        ty = self._current_fn.locals.get(name)
        if ty is not None:
            return ty
        for p in self._current_fn.params:
            if p.name == name:
                return p.ty
        return None

    def _is_string_local(self, name: str) -> bool:
        ty = self._current_fn.locals.get(name) if self._current_fn else None
        return ty == "String"

    def _param_is_string(self, name: str) -> bool:
        if self._current_fn is None:
            return False
        for p in self._current_fn.params:
            if p.name == name:
                return p.ty == "String"
        return False

    def _dst_capa_ty(self, name: str) -> str:
        if self._current_fn is None:
            return ""
        return self._current_fn.locals.get(name, "")

    def _effective_value_ty(self, v: Value) -> str:
        """Resolve a Value's effective Capa type. The IR sometimes
        carries Unknown on Values captured at lowering time before
        the analyzer's type info reached them (impl-method ``self``,
        pattern binders for builtin sum-type variants). When the
        Value is a local or param, consult fn.locals for a
        refined entry, fall back to the param list, and only then
        accept the raw v.ty.

        Returns the empty string when nothing concrete is
        recoverable; callers should treat that as Unknown."""
        ty = v.ty or ""
        if ty and ty not in ("Unknown", "?") and not ty.startswith("?"):
            return ty
        if v.kind in ("local", "param") and self._current_fn is not None:
            from_locals = self._current_fn.locals.get(v.name, "")
            if from_locals and from_locals not in ("Unknown", "?"):
                return from_locals
            for p in self._current_fn.params:
                if p.name == v.name and p.ty and p.ty not in ("Unknown", "?"):
                    return p.ty
        return ty

    # ----- value pushing ----------------------------------------

    def _push_value(self, v: Value) -> None:
        """Emit the instruction(s) that push a Value onto the Wasm
        operand stack. Wasm has no concept of "Value" the way the
        IR does; every operation reads from the stack.

        Inside a lifted lambda body, captured locals load from the
        env record at their layout offset instead of a Wasm local.
        Non-String types use the standard size-dispatched load;
        String captures route through ``_push_string_value_as_ptr_len``
        which has its own env-aware path."""
        if v.kind in ("local", "param") and v.name in self._current_captures:
            offset, capa_ty = self._current_captures[v.name]
            if capa_ty != "String":
                self._write("local.get $env")
                # Float captures round-trip as f64 (the closure-pack
                # site uses ``f64.store`` for Float since
                # ``i64.store`` would type-mismatch the f64 operand).
                # Load must match. ``_load_op_for_size(8)`` returns
                # ``i64.load`` which would mismatch the consumer's
                # f64 local.
                if capa_ty == "Float":
                    self._write(f"f64.load offset={offset}")
                else:
                    size = self._size_of(capa_ty)
                    self._write(f"{_load_op_for_size(size)} offset={offset}")
                return
        if v.kind == "global" and v.name in self._const_values:
            # Module-level constant: inline the RHS literal at the
            # use site in the SAME calling shape a local / param of
            # that type would use. A String const must be pushed as
            # two i32s (ptr, len) -- the standard String value shape
            # every consumer (capability-method arg push, user-call
            # arg push, concat, ==) expects. Recursing through the
            # generic path here would land in the ``lit_str`` branch
            # below, which emits a PACKED i64 (ptr | len<<32) meant
            # only for uniform 8-byte slots (tuple / Map / variant
            # payload); fed where (i32, i32) is expected it type-
            # mismatches and crashes the module. Delegate String
            # consts to the (ptr, len) helper (which has its own
            # const branch) and keep the recursion for the scalar
            # consts (Int -> i64, Bool -> i32, Float -> f64, Unit ->
            # nothing), whose single-value shapes the lit_* branches
            # already produce correctly.
            const_v = self._const_values[v.name]
            if const_v.kind == "lit_str":
                self._push_string_value_as_ptr_len(v)
                return
            self._push_value(const_v)
            return
        if (v.kind == "global" and v.ty
                and v.ty.startswith("Fun")):
            # Top-level function reference used as a ``Fun(...)``
            # value (e.g. ``xs.map(double_int)``). The thunk pass
            # in ``_register_fn_ref_thunks`` already registered a
            # closure-ABI wrapper for this (fn_name, sig_key); look
            # it up to get the table slot and pack the closure
            # value as ``(fn_idx << 32) | 0`` (env_ptr is 0 for
            # zero-capture thunks). Mirrors the layout
            # ``_emit_make_lambda`` writes for a captureless
            # lifted lambda.
            sig_key = self._fun_type_to_sig_key(v.ty)
            key = (v.name, sig_key)
            thunk = self._fn_ref_thunks.get(key)
            if thunk is None:
                raise WasmEmissionError(
                    f"top-level function {v.name!r} used as "
                    f"Fun(...) value, but no thunk was registered "
                    f"for sig {sig_key!r}. The pre-emit thunk "
                    f"discovery pass may have missed this site or "
                    f"the function's signature contains a type "
                    f"the closure ABI cannot encode."
                )
            fn_idx = thunk["fn_idx"]
            self._write(f"i64.const {fn_idx << 32}")
            return
        if v.kind in ("local", "param"):
            self._write(f"local.get ${v.name}")
            return
        if v.kind == "lit_int":
            self._write(f"i64.const {v.literal}")
            return
        if v.kind == "lit_float":
            # WAT accepts standard float literal syntax. We rely on
            # Python's repr() to produce a parseable form for any
            # finite value the source contained.
            self._write(f"f64.const {v.literal!r}")
            return
        if v.kind == "lit_bool":
            self._write(f"i32.const {1 if v.literal else 0}")
            return
        if v.kind == "lit_unit":
            # Unit has no Wasm representation; pushing a unit value
            # is a no-op. The instruction that asked for the push
            # should not have done so for a Unit-typed sink.
            return
        if v.kind == "lit_str":
            # String literal pushed as a packed i64 (ptr |
            # (len << 32)). Callers that need (ptr, len) as two
            # i32s should use _push_string_value_as_ptr_len
            # explicitly; the packed form here is what every
            # uniform 8-byte slot expects (tuple slot, Map value
            # slot, variant payload slot).
            offset, length = self._intern_string(v.literal)
            self._write(f"i64.const {offset | (length << 32)}")
            return
        if v.kind == "variant_ctor":
            # Payload-less variant used as a value (``return Neither``,
            # ``let x = Excellent``, ...). Emit alloc + tag store
            # inline, leaving the pointer on the stack. A function-
            # level ``$_alloc_tmp`` local stores the pointer so we
            # can re-push it after ``i32.store`` consumed the first
            # copy along with the tag value.
            sum_name = self._variant_to_sum.get(v.name)
            if sum_name is None:
                raise WasmEmissionError(
                    f"variant {v.name!r} has no sum-type layout; was "
                    f"the parent ``type`` declared in module.types?"
                )
            sum_layout = self._sum_layouts[sum_name]
            tag, _payloads = sum_layout["variants"][v.name]
            size = sum_layout["size"]
            self._write(f"i32.const {size}")
            self._write("call $alloc")
            self._write("local.tee $_alloc_tmp")
            self._write(f"i32.const {tag}")
            self._write("i32.store")
            self._write("local.get $_alloc_tmp")
            return
        raise WasmEmissionError(
            f"value kind {v.kind!r} not supported "
            f"(no Wasm encoding yet for {v!r})"
        )

    # ----- helpers ----------------------------------------------

    def _wasm_type(self, capa_ty: str) -> str:
        # Reduce to the bare type name (drops generic args and a
        # typestate state index, e.g. ``Door[Closed]`` -> ``Door``, so
        # a state-indexed type resolves to its zero-field-struct layout).
        head = _strip_type_qualifiers(capa_ty)
        if head in _CAPA_TO_WASM:
            return _CAPA_TO_WASM[head]
        # Slice 25.2 - 25.6 (2026-05-30): Fs, Net, Db, Proc, Env,
        # Clock are un-erased as i32 handles into the host's per-
        # instance cap table so a restricted cap survives crossing
        # function boundaries (audit slice 25 F1; Net also closes F2
        # by routing through ``urlparse(url).hostname`` rather than
        # ``$str_contains``). Random / Unsafe / Stdio stay erased
        # (no attenuation surface to wire).
        if head in ("Fs", "Net", "Db", "Proc", "Env", "Clock"):
            return "i32"
        # ``()`` is Capa's empty-tuple / Unit alias from the type
        # printer; treat it the same as Unit (no Wasm result).
        if capa_ty == "()":
            return ""
        # Struct and sum types are stored on the heap and passed by
        # i32 pointer. Locals/params/return values of these types
        # are i32 at the Wasm level.
        if head in self._struct_layouts or head in self._sum_layouts:
            return "i32"
        # Collection types: List / Map / Set are also heap pointers.
        # Their stdlib methods will resolve dispatch on the receiver
        # type string later, but at the value-shape level they are
        # i32 pointers identical to structs.
        if head in ("List", "Map", "Set"):
            return "i32"
        # ``Range<Int>`` is a 24-byte heap record allocated by
        # MakeRange; the value-shape is an i32 pointer identical to
        # other collection types. The for-iter fast-path reads
        # start / end / inclusive out of the record directly.
        if head == "Range":
            return "i32"
        # Closures are packed i64: (fn_idx << 32) | env_ptr.
        if capa_ty.startswith("Fun"):
            return "i64"
        # User-defined trait / capability with a unique impl:
        # values are i32 pointers to the impl's struct.
        if head in self._trait_to_impl:
            return "i32"
        # User-defined trait / capability with more than one impl:
        # a value of this type is a single i32 pointer to a
        # participating struct (whose offset-0 word carries the
        # concrete type-id). No packing at boundaries; dynamic
        # dispatch loads the tag at the call site and dispatches via
        # an if-chain (see ``_emit_multi_impl_dispatch``).
        if head in getattr(self, "_multi_impl_traits", ()):
            return "i32"
        # Tuples render as ``(T1, T2, ...)``. Stored on the heap
        # as 16-byte records (one uniform 8-byte slot per element
        # for up to 2 elements; arities other than 2 are deferred).
        if capa_ty.startswith("(") and capa_ty.endswith(")"):
            return "i32"
        # Payloadless variant values (e.g. ``Low`` for a Severity
        # sum) carry the variant name as their .ty rather than the
        # parent sum name. Resolve via _variant_to_sum.
        if head in self._variant_to_sum:
            return "i32"
        # Unresolved tyvars (``?`` or analyzer's ``?lst_N``) default
        # to i64 so the Wasm verifier accepts the local declaration;
        # callers that use the local with a wrong type will surface
        # the issue at instruction emission time.
        if capa_ty.startswith("?") or capa_ty in ("Unknown", ""):
            return "i64"
        raise WasmEmissionError(
            f"Capa type {capa_ty!r} has no Wasm encoding yet"
        )

