"""Option<T> + Result<T, E> method-dispatch mixin.

Owns the Wasm lowering for the built-in Option / Result method
surface that policy-eval and other downstream demos exercise:

- ``is_some`` / ``is_none`` on Option<T>: tag at offset 0 against
  0 (Some) / 1 (None). Returns Bool.
- ``is_ok`` / ``is_err`` on Result<T, E>: identical shape with
  the same tag convention.
- ``unwrap_or(default)`` on both: when the discriminant indicates
  the payload-bearing variant (Some / Ok), load the payload at
  offset 8 with a type-appropriate opcode and bind to dst;
  otherwise emit the default value. The result type comes from
  the dst local's Capa type.

Phase 6I scope: ``is_some / is_none / is_ok / is_err / unwrap_or``
only. ``map / and_then / or_else / filter / ok_or / map_err`` are
deferred -- they need closure-arg handling which the dispatch
path here does not yet thread.

Both Option and Result share the 16-byte sum layout (tag@0,
payload@8) so a single emitter handles both. The only difference
between them is the tag-name mapping (Some/None vs Ok/Err), and
since both use 0=value, 1=fallback, ``unwrap_or`` doesn't care
which sum it's looking at.
"""

from __future__ import annotations

from .._nodes import MethodCall, Value
from ._layout import WasmEmissionError


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
        raise WasmEmissionError(
            f"Phase 6I: {sum_name} method {method!r} not supported "
            f"(currently: is_some / is_none / is_ok / is_err / "
            f"unwrap_or). map / and_then / or_else land later."
        )

    def _emit_optres_tag_check(
        self, recv: Value, dst, expected_tag: int,
    ) -> None:
        """``opt.is_some() / .is_none() / res.is_ok() / .is_err()``.
        Pushes a Bool (i32 0/1) and binds to dst."""
        self._push_value(recv)
        self._write("i32.load")
        self._write(f"i32.const {expected_tag}")
        self._write("i32.eq")
        if dst is not None:
            self._write(f"local.set ${dst}")

    def _emit_optres_unwrap_or(
        self, recv: Value, default: Value, dst,
    ) -> None:
        """``opt.unwrap_or(default) / res.unwrap_or(default)``: if
        the tag is 0 (Some / Ok), extract the payload at offset 8
        into dst; otherwise bind default into dst.

        The shape of the load depends on dst's Capa type: Int /
        Bool / Float use type-specific loads against the uniform
        8-byte slot; pointer-shaped types unpack via
        ``i32.wrap_i64``; String unpacks the packed (ptr, len)
        into dst's ``_ptr`` / ``_len`` locals."""
        if dst is None:
            return
        dst_ty = self._dst_capa_ty(dst) or ""
        # Stash the receiver in scratch so we can re-read the tag
        # AND (on hit) re-read the payload without re-evaluating.
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._write("local.get $_m_scrut")
        self._write("i32.load")
        self._write("i32.const 0")
        self._write("i32.eq")
        if dst_ty == "String":
            # String result: both arms write into dst_ptr / dst_len.
            # ``if`` with no result clause; each arm performs its own
            # assignment to the dst locals.
            self._write("if")
            self._indent += 1
            # Some(payload): unpack packed i64 into dst pair.
            self._write("local.get $_m_scrut")
            self._write("i64.load offset=8")
            self._emit_unpack_i64_to_string(f"{dst}_ptr", f"{dst}_len")
            self._indent -= 1
            self._write("else")
            self._indent += 1
            # None / Err: write the default String into dst pair.
            self._emit_string_assign(dst, default)
            self._indent -= 1
            self._write("end")
            return
        # Scalar / pointer-shaped result. Use a ``if (result T)``
        # block so each arm leaves the value on the stack; bind via
        # local.set after the if.
        wasm_ty = self._wasm_type(dst_ty or "Int")
        self._write(f"if (result {wasm_ty})")
        self._indent += 1
        # Some(payload).
        self._write("local.get $_m_scrut")
        head = dst_ty.split("<", 1)[0]
        if dst_ty == "Float":
            self._write("f64.load offset=8")
        elif dst_ty == "Bool":
            # Bool is stored i64-extended in the 8-byte slot;
            # narrow back to i32.
            self._write("i64.load offset=8")
            self._write("i32.wrap_i64")
        elif (head in self._struct_layouts
                or head in self._sum_layouts
                or dst_ty.startswith(("List", "Map", "Set"))):
            # Pointer-shaped payload stored i64-extended.
            self._write("i64.load offset=8")
            self._write("i32.wrap_i64")
        else:
            # Int (or unknown defaulting to i64).
            self._write("i64.load offset=8")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._push_value(default)
        self._indent -= 1
        self._write("end")
        self._write(f"local.set ${dst}")
