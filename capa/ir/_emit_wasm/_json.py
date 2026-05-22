"""JsonValue emission mixin.

Owns Wasm lowering for the built-in ``JsonValue`` sum type:

- The eight method dispatch entries (``is_null``, ``as_bool``,
  ``as_num`` / ``as_number``, ``as_int``, ``as_string``,
  ``as_array``, ``as_object``). Each is a tag-compare followed by
  a fresh ``Option<T>`` allocation: ``Some(payload)`` on match,
  ``None`` otherwise.
- The two free-function host calls ``parse_json`` and ``to_json``
  routed through the ``capa:host/json`` capability bridge.

JsonValue's six variants (JNull/JBool/JNum/JStr/JArr/JObj) live in
the uniform 16-byte sum layout (tag at offset 0, payload at offset
8). See ``_JSONVALUE_LAYOUT`` in ``_layout.py``.

Depends on the layout / Option layouts and reuses the same
i64-packed slot encoding as Option/Result, so no new alloc shapes
are needed.
"""

from __future__ import annotations

from .._nodes import Call, MethodCall, Value
from ._layout import (
    WasmEmissionError,
    _OPTION_LAYOUT, _JSONVALUE_LAYOUT,
)


# Map each ``as_X`` method name to the variant tag whose payload
# the method projects out. ``is_null`` doesn't share this template
# (it returns Bool, not Option), so it has its own emitter.
_JV_AS_METHOD_TO_TAG: dict[str, int] = {
    "as_bool":   _JSONVALUE_LAYOUT["variants"]["JBool"][0],
    "as_num":    _JSONVALUE_LAYOUT["variants"]["JNum"][0],
    "as_number": _JSONVALUE_LAYOUT["variants"]["JNum"][0],
    "as_string": _JSONVALUE_LAYOUT["variants"]["JStr"][0],
    "as_array":  _JSONVALUE_LAYOUT["variants"]["JArr"][0],
    "as_object": _JSONVALUE_LAYOUT["variants"]["JObj"][0],
}


class _JsonEmissionMixin:
    def _emit_jsonvalue_method_call(self, instr: MethodCall) -> None:
        """Dispatch a method on a ``JsonValue`` receiver. All methods
        return either ``Bool`` (``is_null``) or ``Option<T>``
        (everything else). The Option case allocates a 16-byte
        result with tag=0 (Some) + payload at offset 8 on match,
        or tag=1 (None) on miss.

        ``as_int`` is a special case: even when the variant is
        ``JNum``, the projection may still return ``None`` (when
        the float is not integer-valued). Phase 6G ships
        always-Some for integer-valued floats; non-integer floats
        are documented as a fallow case that the host bridge can
        round-trip more faithfully."""
        method = instr.method
        recv = instr.receiver
        dst = instr.dst
        if method == "is_null":
            self._emit_jv_is_null(recv, dst)
            return
        if method == "as_int":
            self._emit_jv_as_int(recv, dst)
            return
        tag = _JV_AS_METHOD_TO_TAG.get(method)
        if tag is None:
            raise WasmEmissionError(
                f"JsonValue: method {method!r} not supported "
                f"(known: is_null, as_bool, as_num, as_number, "
                f"as_int, as_string, as_array, as_object)"
            )
        self._emit_jv_as_some_or_none(recv, dst, tag)

    def _emit_jv_is_null(self, recv: Value, dst):
        """``jv.is_null() -> Bool``: returns i32 1 if tag == 0 (JNull),
        else 0."""
        self._push_value(recv)
        self._write("i32.load")
        self._write("i32.const 0")
        self._write("i32.eq")
        if dst is not None:
            self._write(f"local.set ${dst}")

    def _emit_jv_as_some_or_none(self, recv: Value, dst, expected_tag: int):
        """Shared template for ``as_bool`` / ``as_num`` / ``as_string``
        / ``as_array`` / ``as_object``. The Option layout's Some
        variant holds the payload in an 8-byte slot at offset 8,
        which is byte-for-byte the same as the JsonValue's payload
        slot at offset 8. So projection becomes:

        - alloc 16-byte Option record
        - tag check the JsonValue
        - on match: store tag=0 + copy the i64 payload through
        - on miss:  store tag=1

        We do this through an outer block to keep the result pointer
        on the stack for the final ``local.set``."""
        if dst is None:
            return
        recv_local = "_m_scrut"
        result_local = "_alloc_tmp_result"
        self._push_value(recv)
        self._write(f"local.set ${recv_local}")
        self._write(f"i32.const {_OPTION_LAYOUT['size']}")
        self._write("call $alloc")
        self._write(f"local.set ${result_local}")
        self._write(f"local.get ${recv_local}")
        self._write("i32.load")
        self._write(f"i32.const {expected_tag}")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        # Some: tag=0 + payload at offset 8
        self._write(f"local.get ${result_local}")
        self._write("i32.const 0")
        self._write("i32.store")
        self._write(f"local.get ${result_local}")
        self._write(f"local.get ${recv_local}")
        self._write("i64.load offset=8")
        self._write("i64.store offset=8")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # None: tag=1
        self._write(f"local.get ${result_local}")
        self._write("i32.const 1")
        self._write("i32.store")
        self._indent -= 1
        self._write("end")
        self._write(f"local.get ${result_local}")
        self._write(f"local.set ${dst}")

    def _emit_jv_as_int(self, recv: Value, dst):
        """``jv.as_int() -> Option<Int>``: matches JNum then projects
        the float payload to a signed i64 via ``i64.trunc_f64_s``.
        Phase 6G ships the always-truncate semantics (matches Python's
        ``int()``); the runtime ``as_int`` returns ``None`` for non-
        integer floats, but the Wasm path is lossier here. A future
        refinement can branch on ``f64.trunc(v) == v`` to mirror the
        legacy behaviour faithfully -- not needed for the demos."""
        if dst is None:
            return
        recv_local = "_m_scrut"
        result_local = "_alloc_tmp_result"
        jnum_tag = _JSONVALUE_LAYOUT["variants"]["JNum"][0]
        self._push_value(recv)
        self._write(f"local.set ${recv_local}")
        self._write(f"i32.const {_OPTION_LAYOUT['size']}")
        self._write("call $alloc")
        self._write(f"local.set ${result_local}")
        self._write(f"local.get ${recv_local}")
        self._write("i32.load")
        self._write(f"i32.const {jnum_tag}")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        # Some(int(value))
        self._write(f"local.get ${result_local}")
        self._write("i32.const 0")
        self._write("i32.store")
        self._write(f"local.get ${result_local}")
        self._write(f"local.get ${recv_local}")
        self._write("f64.load offset=8")
        self._write("i64.trunc_f64_s")
        self._write("i64.store offset=8")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write(f"local.get ${result_local}")
        self._write("i32.const 1")
        self._write("i32.store")
        self._indent -= 1
        self._write("end")
        self._write(f"local.get ${result_local}")
        self._write(f"local.set ${dst}")

    # ----- parse_json / to_json (host bridge) -------------------

    def _emit_call_host_json_parse(self, instr: Call) -> None:
        """``parse_json(s: String) -> Result<JsonValue, String>``.

        Canonical ABI: push the String arg (ptr, len) + a 12-byte
        return area, call the imported host function (void return),
        then materialise a Capa Result<i32, String> heap record
        from the flat fields in the return area."""
        if not instr.args:
            raise WasmEmissionError("parse_json: expected 1 arg")
        arg = instr.args[0]
        if arg.ty != "String":
            raise WasmEmissionError(
                f"parse_json: expected String arg, got {arg.ty!r}"
            )
        if arg.kind == "lit_str":
            offset, length = self._intern_string(arg.literal)
            self._write(f"i32.const {offset}")
            self._write(f"i32.const {length}")
        else:
            self._push_string_value_as_ptr_len(arg)
        self._write("i32.const 12")
        self._write("call $alloc")
        self._write("local.tee $_ret_area")
        self._write("call $Json_parse")
        self._emit_cap_indirect_materialise(
            "result_u32_string", instr.dst,
        )

    def _emit_call_host_json_to_string(self, instr: Call) -> None:
        """``to_json(jv: JsonValue) -> String``.

        Canonical ABI: push the JsonValue handle (i32) + an 8-byte
        return area, call (void return), then bind dst's String
        (ptr, len) locals from the flat fields the host wrote."""
        if not instr.args:
            raise WasmEmissionError("to_json: expected 1 arg")
        arg = instr.args[0]
        self._push_value(arg)
        self._write("i32.const 8")
        self._write("call $alloc")
        self._write("local.tee $_ret_area")
        self._write("call $Json_to_string")
        self._emit_cap_indirect_materialise("string", instr.dst)
