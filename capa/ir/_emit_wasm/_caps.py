"""Capability-method call emission for the Wasm backend.

Wraps three concerns that belong together:

- ``_cap_method_wasm_sig``: maps a WIT signature pattern (the
  one ``capa.ir._emit_wit._WIT_SIGNATURES`` records) to the
  matching core wasm ``(param ...) -> (result ...)`` shape.
  Hand-coded for the handful of patterns in use; widening this
  table is how new capability methods land.

- ``_emit_cap_method_call``: the per-call-site emitter. Pushes
  the arguments (with the String (ptr, len) expansion), then
  either does a direct call (when the canonical-ABI return is
  one flat value) or the indirect-return dance (allocate ret
  area, push it, call, materialise).

- ``_emit_cap_indirect_materialise``: the post-call code that
  reconstructs a Capa-side value from the flat fields the host
  wrote into the return area. One branch per return shape
  (``list_string``, ``option_string``,
  ``result_string_io_error``, ``result_unit_io_error``,
  ``result_u32_string``, ``string``); each one allocates the
  heap record downstream IR expects.

Extracted from ``__init__.py`` in May 2026 because the file
crossed the project's 700-line modularity threshold and the
canonical-ABI work added a self-contained concern that the rest
of the emitter does not need to inspect.
"""

from __future__ import annotations

from .._nodes import Call, MethodCall  # noqa: F401 (Call used by callers' type hints)
from .._emit_wit import _WIT_SIGNATURES
from ._layout import WasmEmissionError


# Capability methods whose canonical-ABI return type lowers to
# more than one flat value, forcing an indirect return through a
# caller-allocated return area. Each entry is
# ``(cap, method) -> (ret_area_size_bytes, materialiser_kind)``.
# The materialiser kind selects the post-call code in
# ``_emit_cap_indirect_materialise``; kept off the hot path so
# each return shape can evolve independently.
_CANONICAL_INDIRECT_RETURN: dict[tuple[str, str], tuple[int, str]] = {
    # list<string>: (data_ptr i32, len i32) = 8 bytes flat.
    ("Env", "args"): (8, "list_string"),
    # option<string>: (tag i32, ptr i32, len i32) = 12 bytes flat.
    # tag = 0 for Some, 1 for None.
    ("Env", "get"): (12, "option_string"),
    # result<string, io-error>: tag i32 + max(2 i32s for Ok string,
    # 4 i32s for Err io-error) = 4 + 16 = 20 bytes flat.
    ("Fs", "read"): (20, "result_string_io_error"),
    # result<_, io-error>: tag i32 + max(0 i32s for Ok unit,
    # 4 i32s for Err io-error) = 4 + 16 = 20 bytes flat.
    ("Fs", "write"): (20, "result_unit_io_error"),
    # ``Json`` used to live here when parse_json / to_json crossed a
    # host bridge; they now compile to local-export calls into the
    # bundled JSON parser (see ``capa.ir._builtin_json``), so no
    # canonical-ABI indirect return is needed on this side.
}


class _CapDispatchMixin:
    def _cap_method_wasm_sig(
        self, cap: str, method: str,
    ) -> tuple[list[str], str]:
        """Return (param_types, result_type) for the Wasm core
        signature of a capability method. String args expand to two
        i32s (ptr, len). The result_type is empty for void methods.
        Mirrors the WIT signatures in ``_emit_wit._WIT_SIGNATURES``;
        keep the two tables in sync.

        Phase 6F still hand-codes a handful of WIT patterns rather
        than parsing the WIT shape generally; widening this table
        is the natural extension when new capability methods land."""
        wit = _WIT_SIGNATURES.get((cap, method))
        if wit is None:
            raise WasmEmissionError(
                f"no Wasm signature for {cap}.{method}"
            )
        if "func(msg: string)" in wit:
            return (["i32", "i32"], "")
        if "func() -> f64" in wit:
            return ([], "f64")
        if "func() -> s64" in wit or "func() -> i64" in wit:
            return ([], "i64")
        if "func(name: string) -> option<string>" in wit:
            # Canonical ABI: ``option<string>`` lowers to three flat
            # i32s (tag, ptr, len). Indirect return through a
            # caller-allocated 12-byte area; the IR materialiser
            # rebuilds a Capa Option<String> (16-byte record:
            # tag@0, packed (ptr|len<<32) i64 payload@8).
            return (["i32", "i32", "i32"], "")
        if "func(path: string) -> result<string, io-error>" in wit:
            # Canonical ABI indirect return: path (ptr, len) + a
            # caller-allocated 20-byte return area for tag + Ok
            # string (ptr, len) or Err io-error (m_ptr, m_len,
            # c_ptr, c_len). Materialiser rebuilds a Capa
            # Result<String, IoError>.
            return (["i32", "i32", "i32"], "")
        if "func(path: string, content: string) -> result<_, io-error>" in wit:
            # Canonical ABI indirect return: path + content +
            # 20-byte ret area for the result. Same layout as
            # Fs.read's Err branch; Ok carries unit (no flat
            # fields).
            return (["i32", "i32", "i32", "i32", "i32"], "")
        if "func() -> list<string>" in wit:
            # Canonical ABI: ``list<string>`` lowers to two flat i32
            # values (data_ptr, len). Two flats exceeds the default
            # ``MAX_FLAT_RESULTS = 1``, so the lowering is indirect:
            # the caller passes a return-area pointer; the callee
            # writes (data_ptr, len) into it. The IR call-site
            # materialises a Capa List<String> header (16 bytes)
            # from the flat fields after the call.
            return (["i32"], "")
        if "func(prefix: string)" in wit and "->" not in wit:
            # Fs.restrict_to: a string-arg, no-result no-op at the
            # Wasm level. The capability discipline is enforced
            # by the analyzer; at runtime the import is shared.
            return (["i32", "i32"], "")
        if "func(s: string) -> result<u32, string>" in wit:
            # Json.parse, canonical ABI: string arg (ptr, len) +
            # 12-byte ret area. ret layout: tag i32 @ 0; Ok arm
            # carries u32 (the JsonValue handle) @ 4; Err arm
            # carries (msg_ptr, msg_len) @ 4, 8.
            return (["i32", "i32", "i32"], "")
        if "func(jv: u32) -> string" in wit:
            # Json.to_string, canonical ABI: jv u32 handle + 8-byte
            # ret area for (ptr, len). Old direct multi-value path
            # had ``(result i32 i32)``; component lowering forces
            # the indirect convention.
            return (["i32", "i32"], "")
        raise WasmEmissionError(
            f"cap method {cap}.{method} has shape {wit!r} that "
            f"the Wasm emitter does not yet decode"
        )

    def _emit_cap_method_call(self, instr: MethodCall) -> None:
        cap = instr.cap_used
        method = instr.method
        # Canonical ABI lowering for indirect-return methods: the
        # caller allocates a return area, passes its pointer as the
        # trailing argument, then reads the flat fields from the
        # area after the call. The size of the area + the
        # materialisation are method-specific (a List<string>
        # header for ``Env.args``, an Option<String> record for
        # ``Env.get``, ...). The non-indirect path stays unchanged
        # so primitive-return methods (Stdio, Clock) follow the
        # historical multi-value direct-return shape.
        indirect = _CANONICAL_INDIRECT_RETURN.get((cap, method))
        # Push each argument. String args (literals or locals)
        # expand to (ptr, len) i32 pairs; scalar args use the
        # regular push path.
        for arg in instr.args:
            if arg.kind == "lit_str":
                offset, length = self._intern_string(arg.literal)
                self._write(f"i32.const {offset}")
                self._write(f"i32.const {length}")
            elif arg.kind == "local" and self._is_string_local(arg.name):
                self._write(f"local.get ${arg.name}_ptr")
                self._write(f"local.get ${arg.name}_len")
            elif arg.kind == "param" and self._param_is_string(arg.name):
                self._write(f"local.get ${arg.name}_ptr")
                self._write(f"local.get ${arg.name}_len")
            else:
                self._push_value(arg)
        if indirect is not None:
            ret_area_size, ret_kind = indirect
            # Allocate ret_area, stash in $_ret_area, push as the
            # trailing arg, call (void), then materialise the Capa
            # value from the flat fields the host wrote.
            self._write(f"i32.const {ret_area_size}")
            self._write("call $alloc")
            self._write("local.tee $_ret_area")
            self._write(f"call ${cap}_{method}")
            self._emit_cap_indirect_materialise(ret_kind, instr.dst)
            return
        self._write(f"call ${cap}_{method}")
        # Result handling. Void methods (Stdio.print/println) leave
        # nothing on the stack; methods with a return value (e.g.
        # Clock.now_secs -> f64) leave a single primitive that we
        # bind to ``instr.dst``. The dispatch consults the cap's
        # WIT signature to know whether to expect a result.
        _params, result_ty = self._cap_method_wasm_sig(cap, method)
        if result_ty and instr.dst is not None:
            self._write(f"local.set ${instr.dst}")

    def _emit_cap_indirect_materialise(self, ret_kind: str, dst) -> None:
        """Materialise a Capa-side value from the flat fields the
        host wrote into ``$_ret_area``. One branch per return shape;
        each one reads from a fixed canonical-ABI offset and
        allocates the heap record downstream IR expects."""
        if ret_kind == "list_string":
            # ret_area layout: (data_ptr i32) @ 0, (len i32) @ 4.
            # Capa List<String> header: 16 bytes (len, cap, data, pad).
            # cap = len so a subsequent .push triggers grow once a
            # second element lands; same convention MakeList uses.
            self._write("i32.const 16")
            self._write("call $alloc")
            if dst is not None:
                self._write(f"local.tee ${dst}")
            else:
                self._write("local.tee $_alloc_tmp")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=4")
            self._write("i32.store offset=0")
            if dst is not None:
                self._write(f"local.get ${dst}")
            else:
                self._write("local.get $_alloc_tmp")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=4")
            self._write("i32.store offset=4")
            if dst is not None:
                self._write(f"local.get ${dst}")
            else:
                self._write("local.get $_alloc_tmp")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=0")
            self._write("i32.store offset=8")
            return
        if ret_kind == "option_string":
            # ret_area layout: tag i32 @ 0, ptr i32 @ 4, len i32 @ 8.
            # Capa Option<String> layout: tag@0, packed i64 (ptr |
            # len<<32) @ 8. Total record size 16 bytes.
            dst_local = dst if dst is not None else "_alloc_tmp"
            self._write("i32.const 16")
            self._write("call $alloc")
            self._write(f"local.set ${dst_local}")
            # tag
            self._write(f"local.get ${dst_local}")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=0")
            self._write("i32.store offset=0")
            # packed (ptr|len<<32). Build the i64 in pieces, store.
            self._write(f"local.get ${dst_local}")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=8")           # len (high)
            self._write("i64.extend_i32_u")
            self._write("i64.const 32")
            self._write("i64.shl")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=4")           # ptr (low)
            self._write("i64.extend_i32_u")
            self._write("i64.or")
            self._write("i64.store offset=8")
            return
        if ret_kind in ("result_string_io_error", "result_unit_io_error"):
            # ret_area layout (20 bytes):
            #   tag i32 @ 0
            #   Ok arm (string): ptr i32 @ 4, len i32 @ 8 (unused
            #     for result_unit_io_error)
            #   Err arm (io-error): m_ptr i32 @ 4, m_len i32 @ 8,
            #     c_ptr i32 @ 12, c_len i32 @ 16
            # Capa Result<T, IoError>: tag@0, payload@8 (16-byte
            # record). Ok<String> payload is packed-i64 (ptr |
            # len<<32); Ok<Unit> payload is zero; Err payload is
            # i32 pointer to a freshly-allocated IoError struct
            # (4 i32 fields: message.ptr, message.len, cause.ptr,
            # cause.len -- same layout as the existing IO_ERROR
            # struct).
            dst_local = dst if dst is not None else "_alloc_tmp"
            self._write("i32.const 16")
            self._write("call $alloc")
            self._write(f"local.set ${dst_local}")
            # Copy tag.
            self._write(f"local.get ${dst_local}")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=0")
            self._write("i32.store offset=0")
            # Branch on tag.
            self._write("local.get $_ret_area")
            self._write("i32.load offset=0")
            self._write("i32.eqz")
            self._write("if")
            self._indent += 1
            if ret_kind == "result_string_io_error":
                # Ok<String>: pack (ptr, len) -> i64 at dst+8.
                self._write(f"local.get ${dst_local}")
                self._write("local.get $_ret_area")
                self._write("i32.load offset=8")        # len high
                self._write("i64.extend_i32_u")
                self._write("i64.const 32")
                self._write("i64.shl")
                self._write("local.get $_ret_area")
                self._write("i32.load offset=4")        # ptr low
                self._write("i64.extend_i32_u")
                self._write("i64.or")
                self._write("i64.store offset=8")
            else:
                # Ok<Unit>: store an i64 zero placeholder so the
                # payload slot stays deterministically initialised.
                self._write(f"local.get ${dst_local}")
                self._write("i64.const 0")
                self._write("i64.store offset=8")
            self._indent -= 1
            self._write("else")
            self._indent += 1
            # Err<io-error>: alloc 16-byte IoError, copy 4 i32
            # fields, store its pointer (extended to i64) at
            # dst+8.
            self._write("i32.const 16")
            self._write("call $alloc")
            self._write("local.set $_alloc_tmp")
            self._write("local.get $_alloc_tmp")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=4")            # m_ptr
            self._write("i32.store offset=0")
            self._write("local.get $_alloc_tmp")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=8")            # m_len
            self._write("i32.store offset=4")
            self._write("local.get $_alloc_tmp")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=12")           # c_ptr
            self._write("i32.store offset=8")
            self._write("local.get $_alloc_tmp")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=16")           # c_len
            self._write("i32.store offset=12")
            # dst[8] = i64(IoError ptr)
            self._write(f"local.get ${dst_local}")
            self._write("local.get $_alloc_tmp")
            self._write("i64.extend_i32_u")
            self._write("i64.store offset=8")
            self._indent -= 1
            self._write("end")
            return
        if ret_kind == "result_u32_string":
            # ret_area layout (12 bytes):
            #   tag i32 @ 0
            #   Ok arm: u32 @ 4
            #   Err arm: ptr i32 @ 4, len i32 @ 8
            # Capa Result<i32, String> layout: tag@0, payload@8.
            # Ok payload = i64-extended u32; Err payload = packed
            # i64 (ptr | len<<32).
            dst_local = dst if dst is not None else "_alloc_tmp"
            self._write("i32.const 16")
            self._write("call $alloc")
            self._write(f"local.set ${dst_local}")
            # Tag.
            self._write(f"local.get ${dst_local}")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=0")
            self._write("i32.store offset=0")
            # Branch on tag.
            self._write("local.get $_ret_area")
            self._write("i32.load offset=0")
            self._write("i32.eqz")
            self._write("if")
            self._indent += 1
            # Ok<u32>: extend to i64, store at dst+8.
            self._write(f"local.get ${dst_local}")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=4")
            self._write("i64.extend_i32_u")
            self._write("i64.store offset=8")
            self._indent -= 1
            self._write("else")
            self._indent += 1
            # Err<String>: pack (ptr|len<<32) at dst+8.
            self._write(f"local.get ${dst_local}")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=8")            # len high
            self._write("i64.extend_i32_u")
            self._write("i64.const 32")
            self._write("i64.shl")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=4")            # ptr low
            self._write("i64.extend_i32_u")
            self._write("i64.or")
            self._write("i64.store offset=8")
            self._indent -= 1
            self._write("end")
            return
        if ret_kind == "string":
            # ret_area layout: ptr i32 @ 0, len i32 @ 4.
            # Bind dst's String (ptr, len) locals so downstream
            # ${name}_ptr / ${name}_len references resolve.
            if dst is None:
                return
            self._write("local.get $_ret_area")
            self._write("i32.load offset=0")
            self._write(f"local.set ${dst}_ptr")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=4")
            self._write(f"local.set ${dst}_len")
            return
        raise WasmEmissionError(
            f"canonical-ABI materialiser for {ret_kind!r} not implemented"
        )
