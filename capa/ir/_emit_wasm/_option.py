"""Option<T> + Result<T, E> method-dispatch mixin.

Owns the Wasm lowering for the built-in Option / Result method
surface. Both types share the 16-byte sum layout (tag@0, payload@8)
so a single emitter handles both; the only difference is the tag
naming (Some/None vs Ok/Err) which is captured in
``_TAG_CHECK_METHODS``.

Methods supported (slice 6, 2026-05):

- ``is_some`` / ``is_none`` / ``is_ok`` / ``is_err``: tag at offset
  0 against 0 / 1. Returns Bool.
- ``unwrap_or(default)``: when the discriminant indicates the
  value-bearing variant (Some / Ok), load the payload at offset 8
  with a type-appropriate opcode and bind to dst; otherwise emit
  the default value.
- ``map(f)`` on Option<T> / Result<T, E>: invokes the closure on
  the value-bearing payload and rebuilds with the closure's return
  (new Option<U> / Result<U, E>). Fallback branch passes the
  receiver pointer through (Err / None encoding doesn't depend on
  T).
- ``and_then(f)``: like ``map`` but the closure returns an
  Option<U> / Result<U, E> directly; the value-bearing branch
  becomes that pointer.
- ``or_else(f)``: the dual of ``and_then``. Value-bearing arm
  passes receiver through; fallback arm invokes the closure
  (Option's variant: ``Fun() -> Option<T>``; Result's: ``Fun(E)
  -> Result<T, F>``).
- ``filter(p: T -> Bool)`` on Option<T>: ``Some(v) if p(v) else
  None``. Pointer pass-through on the success arm.
- ``ok_or(err)`` on Option<T>: ``Some(v) -> Ok(v)``;
  ``None -> Err(err)``. Always allocates fresh sum records
  (changing sum type).
- ``ok()`` / ``err()`` on Result<T, E>: project to Option<T> /
  Option<E>. ``Ok(v).ok() -> Some(v)`` etc.

Per-payload-type encoding inside the 8-byte payload slot is
consistent with variant construction:

- ``Int``: i64 directly
- ``Bool``: i64-extended (read back via ``i32.wrap_i64``)
- ``Float``: f64 in the slot (bit pattern preserved)
- ``String``: packed ``ptr | (len << 32)`` as i64
- pointer-shape (struct / sum / tuple / List / Map / Set):
  i64-extended i32 pointer

The closure ABI matches ``_emit_list_map``: push env_ptr (low 32
of the closure i64), push the payload (per-type wire shape), then
push fn_idx (high 32 of the closure i64) and ``call_indirect``
against the matching ``(type $sig_N)``. The sig must already be
in ``self._closure_sig_keys``; lambda-lifting populates it.
"""

from __future__ import annotations

from .._capa_types import BUILTIN_CAPS  # noqa: F401  (re-exported by sibling mixins)
from .._nodes import MethodCall, Value
from ._layout import WasmEmissionError, _OPTION_LAYOUT


# Methods that are pure tag checks returning Bool. Each entry maps
# (sum_name, method) -> expected_tag. ``is_some`` / ``is_ok`` test
# for tag 0 (the value-bearing variant); ``is_none`` / ``is_err``
# test for tag 1.
_TAG_CHECK_METHODS: dict[tuple[str, str], int] = {
    ("Option", "is_some"): 0,
    ("Option", "is_none"): 1,
    ("Result", "is_ok"):   0,
    ("Result", "is_err"):  1,
}

# Methods that take a closure argument. Listed so the locals
# walker can declare ``$_lam_fn_tmp`` even when the function uses
# only Option/Result HOFs and no List HOFs.
OPTRES_HOF_METHODS: frozenset[str] = frozenset({
    "map", "and_then", "filter", "or_else", "map_err",
})

# Fixed panic messages for ``unwrap()`` on the value-less variant.
# Interned verbatim into linear memory so a ``None.unwrap()`` /
# ``Err.unwrap()`` trap writes the same ``panic: <message>`` line the
# Python runtime writes (capa/runtime/_result.py uses the identical
# strings). ``Result.unwrap()`` deliberately omits the Err value:
# formatting an arbitrary E identically on both backends is not
# guaranteed, and byte-for-byte parity is the central promise.
_UNWRAP_NONE_MSG = "called unwrap() on a None value"
_UNWRAP_ERR_MSG = "called unwrap() on an Err value"

# Option / Result methods that can panic (and so reach the
# ``capa:host/panic`` import) on the value-less variant. Used by the
# discovery / WIT walkers to gate the import emission the same way a
# direct ``panic(...)`` call does.
_PANICKING_OPTRES_METHODS: frozenset[str] = frozenset({"unwrap", "expect"})


def methodcall_may_panic(instr) -> bool:
    """True when ``instr`` is an Option / Result ``unwrap`` / ``expect``
    MethodCall, i.e. one whose value-less arm reaches ``$panic``. The
    Wasm discovery + WIT walkers use this (alongside the direct
    ``panic(...)`` call check) to decide whether the module imports
    ``capa:host/panic``."""
    from .._nodes import MethodCall
    if not isinstance(instr, MethodCall):
        return False
    if instr.method not in _PANICKING_OPTRES_METHODS:
        return False
    recv_ty = (instr.receiver.ty or "") if instr.receiver is not None else ""
    return recv_ty.split("<", 1)[0] in ("Option", "Result")


class _OptionEmissionMixin:
    def _emit_option_method_call(self, instr: MethodCall) -> None:
        """Dispatch a method on an ``Option<T>`` or ``Result<T, E>``
        receiver. Walks a small switch over method names; any
        method not in the supported set raises so the caller
        surfaces a precise coverage gap."""
        recv = instr.receiver
        method = instr.method
        recv_ty = recv.ty or ""
        sum_name = recv_ty.split("<", 1)[0]
        if sum_name not in ("Option", "Result"):
            raise WasmEmissionError(
                f"Option/Result dispatch invoked on receiver of type "
                f"{recv_ty!r}; this is a bug in the MethodCall router"
            )
        tag = _TAG_CHECK_METHODS.get((sum_name, method))
        if tag is not None:
            self._emit_optres_tag_check(recv, instr.dst, tag)
            return
        if method == "unwrap_or":
            if not instr.args:
                raise WasmEmissionError(
                    f"{sum_name}.unwrap_or expects 1 argument"
                )
            self._emit_optres_unwrap_or(recv, instr.args[0], instr.dst)
            return
        if method in ("unwrap", "expect"):
            # ``unwrap`` / ``expect`` emit ``call $panic`` on the
            # value-less arm. ``$panic`` is the host import; a user
            # function literally named ``panic`` is emitted as ``$panic``
            # too, so the two would collide and the module would be
            # invalid. The Python backend is immune (the runtime calls
            # its own ``panic`` directly), so rather than miscompile we
            # surface the conflict precisely. Shadowing ``panic`` while
            # also calling ``.unwrap()`` is pathological; this keeps the
            # backend honest instead of silently diverging.
            if "panic" in self._user_fn_names:
                raise WasmEmissionError(
                    f"{sum_name}.{method} cannot be lowered while a "
                    f"user function named 'panic' shadows the builtin "
                    f"(the panic host import collides with it); rename "
                    f"the function or use a match instead"
                )
            if method == "unwrap":
                self._emit_optres_unwrap(sum_name, recv, instr.dst)
                return
            if not instr.args:
                raise WasmEmissionError(
                    f"{sum_name}.expect expects 1 argument"
                )
            self._emit_optres_expect(recv, instr.args[0], instr.dst)
            return
        if method == "map":
            self._emit_optres_map(sum_name, instr)
            return
        if method == "and_then":
            self._emit_optres_and_then(sum_name, instr)
            return
        if method == "or_else":
            self._emit_optres_or_else(sum_name, instr)
            return
        if sum_name == "Option" and method == "filter":
            self._emit_option_filter(instr)
            return
        if sum_name == "Option" and method == "ok_or":
            self._emit_option_ok_or(instr)
            return
        if sum_name == "Result" and method == "map_err":
            self._emit_result_map_err(instr)
            return
        if sum_name == "Result" and method == "ok":
            self._emit_result_ok(instr)
            return
        if sum_name == "Result" and method == "err":
            self._emit_result_err(instr)
            return
        raise WasmEmissionError(
            f"{sum_name} method {method!r} is not implemented on the "
            f"Wasm backend"
        )

    # ------------------------------------------------------------------
    # tag check + unwrap_or (pre-slice-6 surface, kept as-is)
    # ------------------------------------------------------------------

    def _emit_optres_tag_check(
        self, recv: Value, dst, expected_tag: int,
    ) -> None:
        """``opt.is_some() / .is_none() / res.is_ok() / .is_err()``.
        Pushes a Bool (i32 0/1) and binds to dst."""
        self._push_value(recv)
        self._write("i32.load")
        self._write(f"i32.const {expected_tag}")
        self._write("i32.eq")
        self._store_or_drop_result(dst, "Bool")

    def _emit_optres_unwrap_or(
        self, recv: Value, default: Value, dst,
    ) -> None:
        """``opt.unwrap_or(default) / res.unwrap_or(default)``: if
        the tag is 0 (Some / Ok), extract the payload at offset 8
        into dst; otherwise bind default into dst."""
        if dst is None:
            return
        dst_ty = self._dst_capa_ty(dst) or ""
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._write("local.get $_m_scrut")
        self._write("i32.load")
        self._write("i32.const 0")
        self._write("i32.eq")
        if dst_ty == "String":
            self._write("if")
            self._indent += 1
            self._write("local.get $_m_scrut")
            self._write("i64.load offset=8")
            self._emit_unpack_i64_to_string(f"{dst}_ptr", f"{dst}_len")
            self._indent -= 1
            self._write("else")
            self._indent += 1
            self._emit_string_assign(dst, default)
            self._indent -= 1
            self._write("end")
            return
        wasm_ty = self._wasm_type(dst_ty or "Int")
        self._write(f"if (result {wasm_ty})")
        self._indent += 1
        self._write("local.get $_m_scrut")
        self._emit_load_optres_payload(dst_ty, base_local="_m_scrut")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._push_value(default)
        self._indent -= 1
        self._write("end")
        self._write(f"local.set ${dst}")

    def _emit_optres_unwrap(self, sum_name: str, recv: Value, dst) -> None:
        """``opt.unwrap() / res.unwrap()``: if the tag is 0 (Some / Ok)
        extract the payload at offset 8 into dst; otherwise panic with
        a fixed message and trap (``call $panic`` + ``unreachable``).
        The panic message is byte-identical to the Python runtime's."""
        msg = (
            _UNWRAP_NONE_MSG if sum_name == "Option" else _UNWRAP_ERR_MSG
        )
        offset, length = self._intern_string(msg)
        self._emit_optres_value_or_panic(recv, dst, msg_ptr=offset, msg_len=length)

    def _emit_optres_expect(self, recv: Value, msg: Value, dst) -> None:
        """``opt.expect(msg) / res.expect(msg)``: like ``unwrap`` but
        panics with the caller-supplied message on the value-less
        variant."""
        self._emit_optres_value_or_panic(recv, dst, msg_value=msg)

    def _emit_optres_value_or_panic(
        self, recv: Value, dst, *,
        msg_ptr: int | None = None, msg_len: int | None = None,
        msg_value: Value | None = None,
    ) -> None:
        """Shared body for ``unwrap`` / ``expect``. Branch on the tag:
        the value arm extracts the offset-8 payload into dst; the
        fallback arm pushes the panic message (an interned fixed string
        when ``msg_ptr``/``msg_len`` are given, or a runtime String
        Value for ``expect``), calls ``$panic`` and traps. The
        ``unreachable`` makes the fallback arm valid regardless of the
        value arm's result type."""
        if dst is None:
            return
        dst_ty = self._dst_capa_ty(dst) or ""

        def emit_panic() -> None:
            if msg_value is not None:
                self._push_string_value_as_ptr_len(msg_value)
            else:
                self._write(f"i32.const {msg_ptr}")
                self._write(f"i32.const {msg_len}")
            self._write("call $panic")
            self._write("unreachable")

        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._write("local.get $_m_scrut")
        self._write("i32.load")
        self._write("i32.const 0")
        self._write("i32.eq")
        if dst_ty == "String":
            self._write("if")
            self._indent += 1
            self._write("local.get $_m_scrut")
            self._write("i64.load offset=8")
            self._emit_unpack_i64_to_string(f"{dst}_ptr", f"{dst}_len")
            self._indent -= 1
            self._write("else")
            self._indent += 1
            emit_panic()
            self._indent -= 1
            self._write("end")
            return
        wasm_ty = self._wasm_type(dst_ty or "Int")
        self._write(f"if (result {wasm_ty})")
        self._indent += 1
        self._write("local.get $_m_scrut")
        self._emit_load_optres_payload(dst_ty, base_local="_m_scrut")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        emit_panic()
        self._indent -= 1
        self._write("end")
        self._write(f"local.set ${dst}")

    # ------------------------------------------------------------------
    # slice-6 HOFs
    # ------------------------------------------------------------------

    def _emit_optres_map(self, sum_name: str, instr: MethodCall) -> None:
        """``opt.map(f) / res.map(f)``: invoke ``f`` on the value-
        bearing payload; rebuild a new sum record with the closure
        result. The fallback variant (None / Err) keeps the same
        16-byte shape with E unchanged, so we pass the receiver
        pointer through rather than re-allocating.

        For Result.map, the output type is ``Result<U, E>``; the
        Err encoding doesn't depend on T so receiver pass-through
        is safe (the bytes at offset 8 are the unchanged E
        payload)."""
        self._emit_optres_value_branch_hof(
            sum_name, instr,
            value_kind="rebuild",          # rebuild Some(f(v)) / Ok(f(v))
            fallback_kind="pass_through",  # receiver pointer is already None / Err(e)
        )

    def _emit_optres_and_then(
        self, sum_name: str, instr: MethodCall,
    ) -> None:
        """``opt.and_then(f) / res.and_then(f)``: invoke ``f`` on
        the value-bearing payload; ``f`` already returns an
        Option<U> / Result<U, E> pointer, so the value branch is
        that pointer directly. Fallback branch passes the
        receiver through (None / Err(e) encoding unchanged)."""
        self._emit_optres_value_branch_hof(
            sum_name, instr,
            value_kind="raw",              # closure already returns Option<U> / Result<U,E>
            fallback_kind="pass_through",
        )

    def _emit_optres_or_else(
        self, sum_name: str, instr: MethodCall,
    ) -> None:
        """``opt.or_else(f) / res.or_else(f)``. The dual of
        ``and_then``: fallback branch invokes the closure (Option's
        variant has the closure take zero user args; Result's takes
        the Err's payload). Value-bearing branch passes the
        receiver through (Some(v) / Ok(v) encoding unchanged in
        the new sum type)."""
        self._emit_optres_fallback_branch_hof(
            sum_name, instr,
            value_kind="pass_through",
            fallback_kind="raw",
        )

    def _emit_option_filter(self, instr: MethodCall) -> None:
        """``opt.filter(p: T -> Bool) -> Option<T>``. ``Some(v)`` if
        ``p(v)`` is true; ``None`` otherwise. The success arm is a
        pointer pass-through (Some shape unchanged). The reject arm
        builds a fresh None record (the input could have been Some,
        so we can't pass through there)."""
        recv = instr.receiver
        f_arg = instr.args[0]
        dst = instr.dst
        if dst is None:
            return
        recv_ty = recv.ty or "Option"
        payload_ty = self._optres_payload_ty(recv_ty, variant_index=0)
        # Stash receiver and closure.
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._push_value(f_arg)
        self._write("local.set $_lam_fn_tmp")
        # Branch on tag (0 = Some).
        self._write("local.get $_m_scrut")
        self._write("i32.load")
        self._write("i32.const 0")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        # Some(v): call p(v); if true, dst = self; else dst = None.
        self._emit_closure_call_from_optres_payload(
            payload_ty, ret_ty="Bool",
        )
        self._write("if")
        self._indent += 1
        # Predicate true: pointer pass-through.
        self._write("local.get $_m_scrut")
        self._write(f"local.set ${dst}")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # Predicate false: fresh None.
        self._emit_alloc_optres_none()
        self._write(f"local.set ${dst}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # None: pointer pass-through (already None).
        self._write("local.get $_m_scrut")
        self._write(f"local.set ${dst}")
        self._indent -= 1
        self._write("end")

    def _emit_option_ok_or(self, instr: MethodCall) -> None:
        """``opt.ok_or(err) -> Result<T, E>``. ``Some(v) -> Ok(v)``;
        ``None -> Err(err)``. Always allocates fresh sum records
        since the sum type changes (Option -> Result).

        Payload encoding for Ok(v) reuses the same 8-byte slot
        layout as the receiver's Some(v), so the bytes can be
        copied verbatim with a single ``i64.load offset=8`` +
        ``i64.store offset=8``."""
        recv = instr.receiver
        err_arg = instr.args[0]
        dst = instr.dst
        if dst is None:
            return
        # Stash receiver.
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._write("local.get $_m_scrut")
        self._write("i32.load")
        self._write("i32.const 0")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        # Some(v) -> Ok(v): alloc + tag=0 + copy 8-byte payload.
        self._emit_alloc_optres_record(tag=0)
        self._write("local.get $_alloc_tmp_result")
        self._write("local.get $_m_scrut")
        self._write("i64.load offset=8")
        self._write("i64.store offset=8")
        self._write("local.get $_alloc_tmp_result")
        self._write(f"local.set ${dst}")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # None -> Err(err): alloc + tag=1 + store err payload.
        err_ty = err_arg.ty or "Unknown"
        self._emit_alloc_optres_record(tag=1)
        self._emit_store_payload_into_optres(err_arg, err_ty)
        self._write("local.get $_alloc_tmp_result")
        self._write(f"local.set ${dst}")
        self._indent -= 1
        self._write("end")

    def _emit_result_map_err(self, instr: MethodCall) -> None:
        """``res.map_err(f: E -> F) -> Result<T, F>``. Ok arm:
        pointer pass-through (T unchanged). Err arm: invoke f on
        the err payload, rebuild Err with the returned value."""
        recv = instr.receiver
        f_arg = instr.args[0]
        dst = instr.dst
        if dst is None:
            return
        recv_ty = recv.ty or "Result"
        # Variant index 1 = Err; its payload is E.
        err_ty = self._optres_payload_ty(recv_ty, variant_index=1)
        # The closure's return type F lives in the dst's
        # Result<T, F>; parse it off.
        dst_ty = self._dst_capa_ty(dst) or "Result"
        out_err_ty = self._result_err_type(dst_ty) or "Unknown"
        # Stash receiver and closure.
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._push_value(f_arg)
        self._write("local.set $_lam_fn_tmp")
        self._write("local.get $_m_scrut")
        self._write("i32.load")
        self._write("i32.const 0")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        # Ok arm: pointer pass-through.
        self._write("local.get $_m_scrut")
        self._write(f"local.set ${dst}")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # Err arm: alloc fresh Err with f(e).
        self._emit_closure_call_from_optres_payload(
            err_ty, ret_ty=out_err_ty,
        )
        # Stash the closure's return value(s) into scratch so we
        # can sandwich them inside the alloc + tag store. For
        # scalar / pointer results the value is on the stack as a
        # single slot; for String it's two i32s.
        if out_err_ty == "String":
            self._write("local.set $_str_a_len")
            self._write("local.set $_str_a_ptr")
        elif out_err_ty == "Float":
            self._write("local.set $_alloc_tmp_f64")
        else:
            self._write("local.set $_alloc_tmp_i64")
        self._emit_alloc_optres_record(tag=1)
        # Push the dst record's payload slot address, then push the
        # stashed value, then store with the right opcode.
        self._emit_store_stashed_payload_into_optres(out_err_ty)
        self._write("local.get $_alloc_tmp_result")
        self._write(f"local.set ${dst}")
        self._indent -= 1
        self._write("end")

    def _emit_result_ok(self, instr: MethodCall) -> None:
        """``res.ok() -> Option<T>``. ``Ok(v) -> Some(v)`` (alloc
        new Option, copy payload); ``Err(_) -> None`` (alloc fresh
        None record)."""
        recv = instr.receiver
        dst = instr.dst
        if dst is None:
            return
        self._emit_result_projection_to_option(
            recv, dst, value_when_tag=0,
        )

    def _emit_result_err(self, instr: MethodCall) -> None:
        """``res.err() -> Option<E>``. ``Err(e) -> Some(e)`` (alloc
        new Option, copy payload); ``Ok(_) -> None`` (alloc fresh
        None record)."""
        recv = instr.receiver
        dst = instr.dst
        if dst is None:
            return
        self._emit_result_projection_to_option(
            recv, dst, value_when_tag=1,
        )

    # ------------------------------------------------------------------
    # shared HOF skeletons
    # ------------------------------------------------------------------

    def _emit_optres_value_branch_hof(
        self, sum_name: str, instr: MethodCall, *,
        value_kind: str, fallback_kind: str,
    ) -> None:
        """Shared shape for ``map`` / ``and_then``: closure runs on
        the value-bearing payload. ``value_kind`` controls what the
        value arm produces:

        - ``"rebuild"``: closure returns U; allocate a fresh sum
          record with tag=0 and U stored at offset 8.
        - ``"raw"``: closure already returns the full sum<U> /
          sum<U, E> pointer; bind directly.

        ``fallback_kind`` is currently always ``"pass_through"``
        for this shape; included for symmetry with the dual
        helper so future additions can override it."""
        recv = instr.receiver
        f_arg = instr.args[0]
        dst = instr.dst
        if dst is None:
            return
        recv_ty = recv.ty or sum_name
        payload_ty = self._optres_payload_ty(recv_ty, variant_index=0)
        # For value_kind="rebuild" we need the closure's return
        # type to pick the right store-into-slot encoding. Read it
        # off the dst's sum type.
        dst_ty = self._dst_capa_ty(dst) or sum_name
        out_value_ty = self._optres_payload_ty(dst_ty, variant_index=0)
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._push_value(f_arg)
        self._write("local.set $_lam_fn_tmp")
        self._write("local.get $_m_scrut")
        self._write("i32.load")
        self._write("i32.const 0")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        if value_kind == "rebuild":
            # Closure returns U; rebuild Some(U) / Ok(U).
            self._emit_closure_call_from_optres_payload(
                payload_ty, ret_ty=out_value_ty,
            )
            self._stash_closure_return(out_value_ty)
            self._emit_alloc_optres_record(tag=0)
            self._emit_store_stashed_payload_into_optres(out_value_ty)
            self._write("local.get $_alloc_tmp_result")
        elif value_kind == "raw":
            # Closure returns full Option<U> / Result<U, E>; that's
            # the result. Output is always a pointer (i32).
            self._emit_closure_call_from_optres_payload(
                payload_ty, ret_ty=dst_ty,
            )
        else:
            raise WasmEmissionError(
                f"unknown value_kind {value_kind!r} in optres HOF"
            )
        self._write(f"local.set ${dst}")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        if fallback_kind == "pass_through":
            self._write("local.get $_m_scrut")
            self._write(f"local.set ${dst}")
        else:
            raise WasmEmissionError(
                f"unknown fallback_kind {fallback_kind!r} in optres HOF"
            )
        self._indent -= 1
        self._write("end")

    def _emit_optres_fallback_branch_hof(
        self, sum_name: str, instr: MethodCall, *,
        value_kind: str, fallback_kind: str,
    ) -> None:
        """Shared shape for ``or_else``: closure runs on the
        fallback payload (or with no args for Option.or_else).
        Value-bearing arm is pointer pass-through.

        For Option.or_else, the closure signature is ``Fun() ->
        Option<T>`` (zero user args). For Result.or_else it's
        ``Fun(E) -> Result<T, F>`` (one user arg, the err
        payload)."""
        recv = instr.receiver
        f_arg = instr.args[0]
        dst = instr.dst
        if dst is None:
            return
        recv_ty = recv.ty or sum_name
        dst_ty = self._dst_capa_ty(dst) or sum_name
        # For Result.or_else, the closure takes the Err payload.
        # For Option.or_else, no user args.
        fallback_payload_ty = (
            None if sum_name == "Option"
            else self._optres_payload_ty(recv_ty, variant_index=1)
        )
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._push_value(f_arg)
        self._write("local.set $_lam_fn_tmp")
        self._write("local.get $_m_scrut")
        self._write("i32.load")
        self._write("i32.const 0")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        # Value arm: pointer pass-through.
        self._write("local.get $_m_scrut")
        self._write(f"local.set ${dst}")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # Fallback: invoke f. Both Option and Result variants
        # already return the full output sum pointer, so bind it.
        if fallback_payload_ty is None:
            self._emit_closure_call_no_payload(ret_ty=dst_ty)
        else:
            self._emit_closure_call_from_optres_payload(
                fallback_payload_ty, ret_ty=dst_ty,
            )
        self._write(f"local.set ${dst}")
        self._indent -= 1
        self._write("end")

    def _emit_result_projection_to_option(
        self, recv: Value, dst, value_when_tag: int,
    ) -> None:
        """Shared body for ``Result.ok()`` and ``Result.err()``.
        ``value_when_tag`` is 0 for ``.ok()`` (project Ok payload
        to Some) and 1 for ``.err()`` (project Err payload to
        Some)."""
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._write("local.get $_m_scrut")
        self._write("i32.load")
        self._write(f"i32.const {value_when_tag}")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        # value arm: alloc Some, copy 8-byte payload verbatim.
        self._emit_alloc_optres_record(tag=0)
        self._write("local.get $_alloc_tmp_result")
        self._write("local.get $_m_scrut")
        self._write("i64.load offset=8")
        self._write("i64.store offset=8")
        self._write("local.get $_alloc_tmp_result")
        self._write(f"local.set ${dst}")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # fallback arm: alloc fresh None.
        self._emit_alloc_optres_none()
        self._write(f"local.set ${dst}")
        self._indent -= 1
        self._write("end")

    # ------------------------------------------------------------------
    # low-level helpers: alloc / payload load+store / closure call
    # ------------------------------------------------------------------

    def _emit_alloc_optres_record(self, tag: int) -> None:
        """Allocate a 16-byte sum record, store the discriminant
        tag at offset 0. Leaves the pointer in
        ``$_alloc_tmp_result``; payload write is the caller's
        responsibility."""
        self._write(f"i32.const {_OPTION_LAYOUT['size']}")
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp_result")
        self._write("local.get $_alloc_tmp_result")
        self._write(f"i32.const {tag}")
        self._write("i32.store")

    def _emit_alloc_optres_none(self) -> None:
        """Allocate a fresh None record (tag=1, no payload). Leaves
        the pointer on the operand stack so the caller can
        ``local.set $dst`` directly."""
        self._emit_alloc_optres_record(tag=1)
        self._write("local.get $_alloc_tmp_result")

    def _emit_load_optres_payload(
        self, payload_ty: str, *, base_local: str,
    ) -> None:
        """Address of the sum record is on the operand stack (or
        will be re-pushed here from ``$base_local``). Emit the
        type-appropriate load against offset 8 to leave the payload
        value(s) on the stack. For String, leaves two i32s (ptr,
        len)."""
        # Caller is responsible for pushing the base address before
        # this call (we don't push it here because some call sites
        # need it on a fresh push, others have it already).
        head = payload_ty.split("<", 1)[0]
        if payload_ty == "Float":
            self._write("f64.load offset=8")
            return
        if payload_ty == "Bool":
            self._write("i64.load offset=8")
            self._write("i32.wrap_i64")
            return
        if payload_ty == "String":
            self._write("i64.load offset=8")
            self._emit_unpack_i64_to_string("_str_a_ptr", "_str_a_len")
            self._write("local.get $_str_a_ptr")
            self._write("local.get $_str_a_len")
            return
        if (head in self._struct_layouts
                or head in self._sum_layouts
                or payload_ty.startswith(("List", "Map", "Set", "Range"))
                or payload_ty.startswith("(")):
            # Pointer-shape: i64-extended pointer in the slot.
            self._write("i64.load offset=8")
            self._write("i32.wrap_i64")
            return
        # Int / unknown: i64 directly.
        self._write("i64.load offset=8")

    def _emit_store_payload_into_optres(
        self, value: Value, payload_ty: str,
    ) -> None:
        """Push the value with the right encoding and store at
        offset 8 of the sum record currently in
        ``$_alloc_tmp_result``."""
        self._write("local.get $_alloc_tmp_result")
        if payload_ty == "String":
            self._emit_pack_string_value_to_i64(value)
            self._write("i64.store offset=8")
            return
        if payload_ty == "Float":
            self._push_value(value)
            self._write("f64.store offset=8")
            return
        if payload_ty == "Bool":
            self._push_value(value)
            self._write("i64.extend_i32_u")
            self._write("i64.store offset=8")
            return
        head = payload_ty.split("<", 1)[0]
        if (head in self._struct_layouts
                or head in self._sum_layouts
                or payload_ty.startswith(("List", "Map", "Set", "Range"))
                or payload_ty.startswith("(")):
            self._push_value(value)
            self._write("i64.extend_i32_u")
            self._write("i64.store offset=8")
            return
        # Int / Unknown.
        self._push_value(value)
        self._write("i64.store offset=8")

    def _stash_closure_return(self, ret_ty: str) -> None:
        """Pop the closure's return value(s) off the operand stack
        into hidden scratch locals so the caller can interleave
        them with a fresh alloc + tag write before the final
        store. Mirrors the List-HOF ``_hof_stash_elem`` shape but
        for return values instead of input elements."""
        if ret_ty == "String":
            self._write("local.set $_str_a_len")
            self._write("local.set $_str_a_ptr")
            return
        if ret_ty == "Float":
            self._write("local.set $_alloc_tmp_f64")
            return
        # Int / Bool / pointer-shape: all fit in a single 8-byte
        # slot. Bool is i32 from the closure but gets re-extended
        # by ``_emit_store_stashed_payload_into_optres`` so the
        # stash always uses an i64 slot. Pointer-shape is i32 too;
        # same treatment.
        head = ret_ty.split("<", 1)[0]
        if ret_ty == "Bool":
            self._write("i64.extend_i32_u")
            self._write("local.set $_alloc_tmp_i64")
            return
        if (head in self._struct_layouts
                or head in self._sum_layouts
                or ret_ty.startswith(("List", "Map", "Set", "Range"))
                or ret_ty.startswith("(")):
            self._write("i64.extend_i32_u")
            self._write("local.set $_alloc_tmp_i64")
            return
        self._write("local.set $_alloc_tmp_i64")

    def _emit_store_stashed_payload_into_optres(self, ret_ty: str) -> None:
        """Counterpart to ``_stash_closure_return``: push the
        stashed value back and store at offset 8 of the sum
        record currently in ``$_alloc_tmp_result``."""
        self._write("local.get $_alloc_tmp_result")
        if ret_ty == "String":
            # Re-pack (ptr, len) into i64 and store.
            self._write("local.get $_str_a_len")
            self._write("i64.extend_i32_u")
            self._write("i64.const 32")
            self._write("i64.shl")
            self._write("local.tee $_alloc_tmp_i64")
            self._write("drop")
            self._write("local.get $_str_a_ptr")
            self._write("i64.extend_i32_u")
            self._write("local.get $_alloc_tmp_i64")
            self._write("i64.or")
            self._write("i64.store offset=8")
            return
        if ret_ty == "Float":
            self._write("local.get $_alloc_tmp_f64")
            self._write("f64.store offset=8")
            return
        # Int / Bool / pointer-shape were all stashed as i64; one
        # store covers them.
        self._write("local.get $_alloc_tmp_i64")
        self._write("i64.store offset=8")

    def _emit_closure_call_from_optres_payload(
        self, payload_ty: str, ret_ty: str,
    ) -> None:
        """Invoke the closure in ``$_lam_fn_tmp`` with the
        payload extracted from the receiver in ``$_m_scrut`` at
        offset 8. The closure's return value(s) end up on the
        operand stack."""
        # A Unit-returning closure leaves NOTHING on the operand
        # stack, but every consumer of this helper (map / map_err
        # rebuild, filter, and_then) then stores or binds the
        # result -- a store with an empty stack produces an invalid
        # Wasm module. ``Option<Unit>`` / ``Result<Unit, E>`` is a
        # near-useless type and out of scope for the closure ABI,
        # so fail loud here, mirroring the list-HOF store guard in
        # ``_emit_store_closure_result_into_slot``. (Before the
        # Unit-result sig-key alignment, ``_closure_sig_key_for``
        # itself raised on the Unit result; this keeps the same
        # clean rejection now that the sig key is representable.)
        if ret_ty in ("Unit", "()"):
            raise WasmEmissionError(
                f"Option/Result HOF: cannot store a closure result of "
                f"type '()' (a Unit-returning ``map`` / ``map_err`` "
                f"produces ``Option<Unit>`` / ``Result<Unit, E>``, which "
                f"the Wasm backend cannot encode). Use the Python backend "
                f"(``capa --run``), or return a scalar from the closure."
            )
        sig_key = self._closure_sig_key_for([payload_ty], ret_ty)
        sig_idx = self._closure_sig_keys.get(sig_key)
        if sig_idx is None:
            raise WasmEmissionError(
                f"Option/Result HOF: no lambda registered with sig "
                f"{sig_key!r} (payload={payload_ty!r}, ret={ret_ty!r})"
            )
        # Push env_ptr (low 32 of the closure i64).
        self._write("local.get $_lam_fn_tmp")
        self._write("i32.wrap_i64")
        # Push the payload from the receiver.
        self._write("local.get $_m_scrut")
        self._emit_load_optres_payload(payload_ty, base_local="_m_scrut")
        # Push fn_idx + call_indirect.
        self._write("local.get $_lam_fn_tmp")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")
        self._write(f"call_indirect (type $sig_{sig_idx})")

    def _emit_closure_call_no_payload(self, ret_ty: str) -> None:
        """Invoke the closure in ``$_lam_fn_tmp`` with no user
        args (Option.or_else's ``Fun() -> Option<T>``). The
        env_ptr is the only arg passed to the lifted lambda."""
        sig_key = self._closure_sig_key_for([], ret_ty)
        sig_idx = self._closure_sig_keys.get(sig_key)
        if sig_idx is None:
            raise WasmEmissionError(
                f"Option.or_else: no lambda registered with sig "
                f"{sig_key!r} (ret={ret_ty!r})"
            )
        # Push env_ptr (low 32 of the closure i64).
        self._write("local.get $_lam_fn_tmp")
        self._write("i32.wrap_i64")
        # Push fn_idx + call_indirect.
        self._write("local.get $_lam_fn_tmp")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")
        self._write(f"call_indirect (type $sig_{sig_idx})")

    # ------------------------------------------------------------------
    # type-string parsers
    # ------------------------------------------------------------------

    def _optres_payload_ty(self, sum_ty: str, *, variant_index: int) -> str:
        """Extract the payload type for the value-bearing or
        fallback variant of an Option<T> / Result<T, E> type
        string. ``variant_index=0`` returns T (Some / Ok payload);
        ``variant_index=1`` returns E for Result (Err payload), or
        ``Unit`` for Option (None has no payload).

        Defaults to ``Unknown`` when the type string lacks the
        expected ``<...>`` form."""
        head = sum_ty.split("<", 1)[0]
        if "<" not in sum_ty or not sum_ty.endswith(">"):
            return "Unknown"
        inner = sum_ty[len(head) + 1:-1].strip()
        if head == "Option":
            return inner if variant_index == 0 else "Unit"
        if head == "Result":
            # Result<T, E> -> split on top-level comma.
            parts = self._split_top_level_comma_optres(inner)
            if len(parts) != 2:
                return "Unknown"
            return parts[variant_index]
        return "Unknown"

    def _result_err_type(self, result_ty: str) -> str | None:
        """``Result<T, F>`` -> ``F``. Returns None when the string
        isn't a parseable Result shape."""
        if not result_ty.startswith("Result<") or not result_ty.endswith(">"):
            return None
        inner = result_ty[7:-1].strip()
        parts = self._split_top_level_comma_optres(inner)
        if len(parts) != 2:
            return None
        return parts[1]

    @staticmethod
    def _split_top_level_comma_optres(s: str) -> list[str]:
        """Depth-aware split on the first top-level comma. Used to
        separate ``T, E`` inside ``Result<T, E>`` when T itself is
        a nested type with its own commas (``Map<K, V>`` etc.)."""
        from .._lower_helpers import _split_top_level
        return _split_top_level(s)
