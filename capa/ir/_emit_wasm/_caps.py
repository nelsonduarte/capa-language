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
# Capability privileged ops that get an inline attenuation check
# at the Wasm emission level when the receiver carries a tracked
# restrict_to* chain. ``restrict_to`` itself is intentionally
# absent: it is the attenuator, not the privileged op.
# Audit C2 (2026-05-25): Python's Fs.allows / Net.allows / Env.allows
# already gate these in the Python runtime; the Wasm side now
# matches.
_ATTENUATION_PRIVILEGED_OPS: frozenset[tuple[str, str]] = frozenset({
    ("Fs", "read"),
    ("Fs", "write"),
    ("Net", "get"),
    ("Net", "post"),
    ("Env", "get"),
    ("Clock", "now_secs"),
    ("Clock", "now_monotonic"),
})


def _unquote_attenuation_arg(s: str) -> str:
    """``_stringify_expr`` quotes string literals with double quotes
    (``'"/tmp/"'``). The Wasm-side attenuation check only supports
    literal-string arguments; anything else (a runtime variable, a
    format string) is rejected at emit time with a
    ``WasmEmissionError`` so the Python and Wasm backends never
    disagree on what the check enforced.

    Returns the unquoted string for the literal case; raises
    ``WasmEmissionError`` otherwise.
    """
    if len(s) >= 2 and s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    raise WasmEmissionError(
        f"Wasm attenuation check requires a literal-string arg; "
        f"got {s!r}. Add the literal at the source-level "
        f"restrict_to* call, or rely on the Python runtime for "
        f"the dynamic-string case (the analyzer's static "
        f"discipline still applies)."
    )


def _parse_attenuation_key_list(args: list) -> list[str]:
    """``Env.restrict_to_keys(["HOME", "PATH"])`` stringifies its
    single ListLit arg via ``_stringify_expr`` as
    ``'["HOME", "PATH"]'``. Extract the key list back into a Python
    list of unquoted strings. Returns an empty list when the form
    isn't a literal-only list.
    """
    if not args:
        return []
    first = args[0].strip()
    # A single literal key (``restrict_to_keys("HOME")``) is a
    # degenerate but legal shape.
    if first.startswith('"') and first.endswith('"'):
        return [first[1:-1]]
    if not (first.startswith("[") and first.endswith("]")):
        return []
    inner = first[1:-1].strip()
    if not inner:
        return []
    out: list[str] = []
    # Comma-split with quote awareness.
    buf = ""
    in_quotes = False
    for ch in inner:
        if ch == '"':
            in_quotes = not in_quotes
            buf += ch
            continue
        if ch == "," and not in_quotes:
            piece = buf.strip()
            if piece.startswith('"') and piece.endswith('"'):
                out.append(piece[1:-1])
            else:
                # Non-literal key: bail out (fall-back to refusing
                # the whole list so the check stays sound).
                return []
            buf = ""
            continue
        buf += ch
    piece = buf.strip()
    if piece:
        if piece.startswith('"') and piece.endswith('"'):
            out.append(piece[1:-1])
        else:
            return []
    return out


def _atten_err_message(cap: str, method: str) -> str:
    """Diagnostic string shown when an attenuation check denies a
    Wasm-side privileged call. Mirrors the shape of the Python
    runtime's ``Fs._deny`` / ``Net.get`` / ``Env.get`` denial
    messages so a `match ... { Err(io) -> println(io.message) }`
    arm reads a useful sentence either way. The verbose
    cause-list path is not threaded through (cause is left empty
    in the ret area).
    """
    if cap == "Fs":
        return f"Fs capability does not permit {method}"
    if cap == "Net":
        return f"Net capability does not permit {method}"
    if cap == "Env":
        return f"Env capability does not permit access to this name"
    return f"capability does not permit {cap}.{method}"


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
    # Fs.mkdir shares the result_unit_io_error shape with Fs.write.
    ("Fs", "mkdir"): (20, "result_unit_io_error"),
    # Fs.list_dir: result<list<string>, io-error>. tag i32 +
    # max(2 i32s for Ok list-string flat (data_ptr, len),
    # 4 i32s for Err io-error) = 4 + 16 = 20 bytes. Host writes
    # data_ptr+len into the Ok arm; the materialiser allocates a
    # 16-byte List<String> header around the buffer.
    ("Fs", "list_dir"): (20, "result_list_string_io_error"),
    # Stdio.read_line: result<string, io-error>. Same 20-byte shape
    # and materialiser as Fs.read.
    ("Stdio", "read_line"): (20, "result_string_io_error"),
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
        if "func() -> u64" in wit:
            # WIT ``u64`` lowers to Wasm core ``i64``; sign
            # interpretation is the caller's problem. Used by
            # ``capa:host/random/system-seed`` to deliver 8 bytes of
            # OS entropy as a single i64 the guest stashes into
            # ``$rand_state`` for the SplitMix64 PRNG.
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
        if "func() -> result<string, io-error>" in wit:
            # Stdio.read_line: no string arg, just the ret area.
            # Same 20-byte indirect-return shape as Fs.read.
            return (["i32"], "")
        if "func(path: string, content: string) -> result<_, io-error>" in wit:
            # Canonical ABI indirect return: path + content +
            # 20-byte ret area for the result. Same layout as
            # Fs.read's Err branch; Ok carries unit (no flat
            # fields).
            return (["i32", "i32", "i32", "i32", "i32"], "")
        if "func(path: string) -> result<_, io-error>" in wit:
            # Fs.mkdir: single-string arg version of Fs.write's
            # result<_, io-error> shape. Path (ptr, len) + 20-byte
            # ret area.
            return (["i32", "i32", "i32"], "")
        if "func(path: string) -> result<list<string>, io-error>" in wit:
            # Fs.list_dir: same call shape as Fs.read (path + ret
            # area) but the Ok arm carries a list<string> instead
            # of a string. The 20-byte ret area is sized off the
            # Err arm (still the bigger of the two: 4 i32s for
            # io-error vs 2 i32s for the list flat fields).
            return (["i32", "i32", "i32"], "")
        if "func(path: string) -> bool" in wit:
            # Fs.exists / Fs.is_dir: simple string -> i32 (Bool is
            # i32 on the Wasm side). Direct return, no canonical-
            # ABI indirect dance.
            return (["i32", "i32"], "i32")
        if "func() -> bool" in wit:
            # Clock.allows: no-arg query returning a bool. Wasm
            # caps carry no runtime ``not_before`` state so the
            # host always returns 1 (mirrors the unrestricted
            # Python case); static attenuation discipline still
            # applies at the analyzer level.
            return ([], "i32")
        if "func(secs: f64)" in wit and "->" not in wit:
            # Clock.sleep: one f64 arg, no return. Host calls
            # ``time.sleep``; on a denied-by-source Clock the
            # call is a silent no-op (matches Python).
            return (["f64"], "")
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
        if "func(keys: list<string>)" in wit and "->" not in wit:
            # Env.restrict_to_keys: list<string> arg (ptr, len), no
            # result. Mirrors Fs.restrict_to as a host-side no-op;
            # the audit C2 inline check on Env.get is what enforces
            # the discipline. Two i32s for the list header (data
            # ptr, length).
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
        # Attenuator methods (``restrict_to`` / ``restrict_to_keys``
        # / ``restrict_to_after``) are no-ops at the Wasm level:
        # capabilities carry no runtime value at this layer (their
        # methods are imports by name). The audit C2 inline check
        # fires on the *privileged* op (Fs.read, Net.get, Env.get)
        # whose receiver was bound via these attenuators; the
        # attenuator call itself does nothing. Elide the call to
        # avoid having to push arbitrary-typed args (e.g. the
        # List<String> arg of Env.restrict_to_keys).
        if method in ("restrict_to", "restrict_to_keys",
                      "restrict_to_after"):
            return
        # ``allows`` on Fs / Env is inlined at emit time (D4 Option B).
        # For a literal-string argument we collapse the attenuation
        # chain to a static i32 result; for a non-literal argument
        # we raise WasmEmissionError so the user moves to the
        # Python backend or to a literal call. ``Clock.allows`` has
        # no string arg and depends on the live wall clock, so it
        # stays on the host bridge path.
        if method == "allows" and cap in ("Fs", "Env"):
            self._emit_atten_allows(instr, cap)
            return
        # Random method calls route to the guest-side SplitMix64
        # helpers in ``_random.py``. The single host crossing
        # (``system-seed`` for unseeded entropy) is lazy and lives
        # inside ``$rand_state_init_if_needed``; the source-level
        # ``with_seed`` / ``int_range`` / ``float_unit`` never call
        # into the host directly.
        if cap == "Random":
            self._emit_random_method_call(instr)
            return
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
        # Capability attenuation enforcement (audit C2, 2026-05-25):
        # when the lowerer has tagged this MethodCall with an
        # ``attenuations`` list, the receiver was bound via a
        # ``restrict_to`` / ``restrict_to_keys`` / ``restrict_to_after``
        # chain that the Python runtime would honour by failing the
        # operation. The Wasm host bridges historically trusted the
        # guest for attenuation; we now emit an inline runtime check
        # before the host call so the two backends agree.
        # Scope: intra-function only (matches ``_flow._build_atten``
        # which is documented intra-function). Cross-function caps
        # rely on the analyzer's static discipline check.
        attenuations = getattr(instr, "attenuations", None) or []
        # Only privileged ops carry an enforceable check. ``restrict_*``
        # methods themselves are attenuators, not privileged ops;
        # they intentionally pass through unchanged.
        priv_op = (cap, method) in _ATTENUATION_PRIVILEGED_OPS
        if attenuations and priv_op and indirect is not None:
            self._emit_indirect_with_attenuation_check(
                instr, cap, method, indirect, attenuations,
            )
            return
        if attenuations and priv_op and cap == "Clock":
            self._emit_clock_with_attenuation_check(
                instr, cap, method, attenuations,
            )
            return
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

    def _push_string_arg(self, arg) -> None:
        """Push a string Value as (ptr, len). Replicates the inline
        argument-push shape used by ``_emit_cap_method_call`` so the
        attenuation-check path can re-push from stashed locals."""
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

    def _emit_indirect_with_attenuation_check(
        self, instr: MethodCall, cap: str, method: str,
        indirect: tuple[int, str], attenuations: list,
    ) -> None:
        """Emit a Fs / Net / Env privileged op with an inline
        attenuation check. The check fires before the host import;
        on failure we materialise an Err result into the ret area
        and skip the host call. On pass we run the host call as
        normal. Either way ``_emit_cap_indirect_materialise``
        rebuilds the Capa-side value from ``$_ret_area``.

        Layout: alloc ret_area first (so the failure path has a
        valid slot to write into), then evaluate the predicate.
        Each attenuation is enforced individually; the
        intersection (AND) semantics match the Python runtime's
        ``frozenset(... | {prefix})`` shape.

        v1 limitation: only literal-string attenuation arguments are
        enforced at the Wasm level. A ``restrict_to(some_var)`` call
        where ``some_var`` is itself a runtime value triggers
        ``WasmEmissionError`` from this helper -- the analyzer's
        static check still applies, but the runtime check cannot
        prove the prefix matches without crossing the trust
        boundary. The Python runtime handles the dynamic-string
        case via the same ``Fs.allows`` path; the Wasm side
        deliberately refuses rather than fall-through-permit."""
        ret_area_size, ret_kind = indirect

        # Stash all args into scratch locals so we can re-push them
        # for the host call AND read them for the check.
        if cap == "Fs" and method == "read":
            self._push_string_arg(instr.args[0])
            self._write("local.set $_atten_path_len")
            self._write("local.set $_atten_path_ptr")
        elif cap == "Fs" and method == "write":
            self._push_string_arg(instr.args[0])
            self._write("local.set $_atten_path_len")
            self._write("local.set $_atten_path_ptr")
            self._push_string_arg(instr.args[1])
            self._write("local.set $_atten_content_len")
            self._write("local.set $_atten_content_ptr")
        elif cap == "Net" and method in ("get", "post"):
            self._push_string_arg(instr.args[0])
            self._write("local.set $_atten_path_len")
            self._write("local.set $_atten_path_ptr")
        elif cap == "Env" and method == "get":
            self._push_string_arg(instr.args[0])
            self._write("local.set $_atten_path_len")
            self._write("local.set $_atten_path_ptr")
        else:
            raise WasmEmissionError(
                f"attenuation check for {cap}.{method} not "
                f"implemented at the Wasm level"
            )

        # Allocate ret area; stash pointer in $_ret_area for both
        # branches.
        self._write(f"i32.const {ret_area_size}")
        self._write("call $alloc")
        self._write("local.set $_ret_area")

        # Build the predicate: 1 = all attenuations passed, 0 = at
        # least one failed. Stash in $_atten_ok.
        self._write("i32.const 1")
        self._write("local.set $_atten_ok")
        for att in attenuations:
            self._emit_one_attenuation(cap, method, att)

        # Branch on the predicate.
        self._write("local.get $_atten_ok")
        self._write("if")
        self._indent += 1
        # Pass: re-push args, push ret_area, call host.
        if cap == "Fs" and method == "read":
            self._write("local.get $_atten_path_ptr")
            self._write("local.get $_atten_path_len")
        elif cap == "Fs" and method == "write":
            self._write("local.get $_atten_path_ptr")
            self._write("local.get $_atten_path_len")
            self._write("local.get $_atten_content_ptr")
            self._write("local.get $_atten_content_len")
        elif cap == "Net" and method in ("get", "post"):
            self._write("local.get $_atten_path_ptr")
            self._write("local.get $_atten_path_len")
        elif cap == "Env" and method == "get":
            self._write("local.get $_atten_path_ptr")
            self._write("local.get $_atten_path_len")
        self._write("local.get $_ret_area")
        self._write(f"call ${cap}_{method}")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # Fail-closed: write the canonical Err into $_ret_area.
        self._emit_attenuation_err_into_ret_area(cap, method, ret_kind)
        self._indent -= 1
        self._write("end")

        # Bind $_ret_area into local-slot expected by the
        # materialiser (it reads via local.get $_ret_area).
        self._emit_cap_indirect_materialise(ret_kind, instr.dst)

    def _emit_one_attenuation(
        self, cap: str, method: str, att: dict,
    ) -> None:
        """AND one attenuation into ``$_atten_ok``. Each attenuation
        is a record ``{"method": str, "args": [str_form, ...]}`` as
        produced by ``_flatten_restrict_chain``. The arg strings
        come from ``_stringify_expr`` on the AST and are quoted for
        literal forms (``"/tmp/"``) or rendered bare for non-literal
        forms; only the literal form is enforced at the Wasm level.
        """
        att_method = att.get("method")
        args = att.get("args", [])
        if cap == "Fs":
            if att_method != "restrict_to" or not args:
                raise WasmEmissionError(
                    f"unsupported Fs attenuation: {att_method!r} "
                    f"with args {args!r}"
                )
            prefix = _unquote_attenuation_arg(args[0])
            offset, length = self._intern_string(prefix)
            # str_starts_with(path_ptr, path_len, prefix_ptr,
            # prefix_len) -> i32
            self._write("local.get $_atten_path_ptr")
            self._write("local.get $_atten_path_len")
            self._write(f"i32.const {offset}")
            self._write(f"i32.const {length}")
            self._write("call $str_starts_with")
            # ok = ok AND check
            self._write("local.get $_atten_ok")
            self._write("i32.and")
            self._write("local.set $_atten_ok")
            return
        if cap == "Net":
            if att_method != "restrict_to" or not args:
                raise WasmEmissionError(
                    f"unsupported Net attenuation: {att_method!r}"
                )
            host = _unquote_attenuation_arg(args[0])
            offset, length = self._intern_string(host)
            # str_contains(url_ptr, url_len, host_ptr, host_len)
            self._write("local.get $_atten_path_ptr")
            self._write("local.get $_atten_path_len")
            self._write(f"i32.const {offset}")
            self._write(f"i32.const {length}")
            self._write("call $str_contains")
            self._write("local.get $_atten_ok")
            self._write("i32.and")
            self._write("local.set $_atten_ok")
            return
        if cap == "Env":
            if att_method != "restrict_to_keys":
                raise WasmEmissionError(
                    f"unsupported Env attenuation: {att_method!r}"
                )
            # args is a list of stringified keys, normally the
            # single ListLit form (``[\"K1\", \"K2\"]``). Walk
            # the items; OR str_eq against the requested name.
            keys = _parse_attenuation_key_list(args)
            if not keys:
                # Empty allow-list: nothing matches. Force ok=0.
                self._write("i32.const 0")
                self._write("local.set $_atten_ok")
                return
            # Build OR-chain: any_match = (name == K1) | (name == K2) ...
            self._write("i32.const 0")
            self._write("local.set $_atten_match")
            for k in keys:
                koff, klen = self._intern_string(k)
                self._write("local.get $_atten_path_ptr")
                self._write("local.get $_atten_path_len")
                self._write(f"i32.const {koff}")
                self._write(f"i32.const {klen}")
                self._write("call $str_eq")
                self._write("local.get $_atten_match")
                self._write("i32.or")
                self._write("local.set $_atten_match")
            # ok &= any_match
            self._write("local.get $_atten_ok")
            self._write("local.get $_atten_match")
            self._write("i32.and")
            self._write("local.set $_atten_ok")
            return
        raise WasmEmissionError(
            f"attenuation enforcement for cap {cap!r} not implemented"
        )

    def _emit_attenuation_err_into_ret_area(
        self, cap: str, method: str, ret_kind: str,
    ) -> None:
        """Populate ``$_ret_area`` with the canonical Err shape for
        the given ret_kind. Mirrors the runtime ``_deny`` message the
        Python ``Fs._deny`` / ``Net.get`` / ``Env.get`` paths
        produce, so a downstream pattern match on ``Err(io)`` reads
        a sensible diagnostic via ``${io.message}``."""
        message = _atten_err_message(cap, method)
        m_offset, m_length = self._intern_string(message)
        if ret_kind in ("result_string_io_error", "result_unit_io_error"):
            # tag = 1 (Err)
            self._write("local.get $_ret_area")
            self._write("i32.const 1")
            self._write("i32.store offset=0")
            # message ptr / len at offsets 4 / 8.
            self._write("local.get $_ret_area")
            self._write(f"i32.const {m_offset}")
            self._write("i32.store offset=4")
            self._write("local.get $_ret_area")
            self._write(f"i32.const {m_length}")
            self._write("i32.store offset=8")
            # cause ptr / len at offsets 12 / 16: empty.
            self._write("local.get $_ret_area")
            self._write("i32.const 0")
            self._write("i32.store offset=12")
            self._write("local.get $_ret_area")
            self._write("i32.const 0")
            self._write("i32.store offset=16")
            return
        if ret_kind == "option_string":
            # tag = 1 (None); ptr / len at 4 / 8 zero (unused).
            self._write("local.get $_ret_area")
            self._write("i32.const 1")
            self._write("i32.store offset=0")
            self._write("local.get $_ret_area")
            self._write("i32.const 0")
            self._write("i32.store offset=4")
            self._write("local.get $_ret_area")
            self._write("i32.const 0")
            self._write("i32.store offset=8")
            return
        raise WasmEmissionError(
            f"attenuation Err materialisation for {ret_kind!r} "
            f"not implemented"
        )

    def _emit_atten_allows(
        self, instr: MethodCall, cap: str,
    ) -> None:
        """Emit a ``Fs.allows(path)`` / ``Env.allows(name)`` call
        inline (D4 Option B). With no attenuations the call is
        trivially true (matches the Python ``self._allowed is None``
        branch); otherwise we walk the chain at emit time and AND
        each predicate into the result, mirroring the runtime
        check the privileged op (Fs.read / Env.get) already uses
        via ``_emit_indirect_with_attenuation_check``.

        The argument must be a literal string at the Wasm level
        (same constraint as the rest of the inline attenuation
        machinery). A non-literal argument cannot be checked
        statically and raises ``WasmEmissionError`` directing the
        user to either pass a literal or compile to Python.
        """
        attenuations = getattr(instr, "attenuations", None) or []
        # No-arg form would be a bug; both Fs and Env.allows take
        # a single string. Defensive check so a future analyzer
        # change surfaces here rather than producing wrong code.
        if len(instr.args) != 1:
            raise WasmEmissionError(
                f"{cap}.allows expected 1 string arg, got "
                f"{len(instr.args)} -- analyzer should have rejected"
            )
        arg = instr.args[0]
        # Resolve the literal-string form. Locals and params come
        # through with ``arg.kind in {"local", "param"}``; these
        # cannot be checked at emit time because the attenuation
        # chain (also literal) is matched byte-by-byte against the
        # runtime string the local holds. A future slice can lift
        # this restriction by emitting the same inline check the
        # privileged-op path uses; for now we reject loudly.
        if arg.kind != "lit_str":
            raise WasmEmissionError(
                f"{cap}.allows on Wasm requires a literal string "
                f"argument; got a dynamic value. For dynamic paths "
                f"use the privileged op directly (e.g. ``fs.read(p)`` "
                f"and pattern-match on the ``Err`` arm), or compile "
                f"to the Python backend where the runtime carries "
                f"the attenuation set."
            )
        literal: str = arg.literal
        # Compute the static answer. No attenuations -> always true
        # (mirrors ``self._allowed_prefixes is None`` /
        # ``self._allowed_keys is None`` in the Python runtime).
        if not attenuations:
            result = True
        elif cap == "Fs":
            # AND over each restrict_to(prefix): literal must
            # str-start with every prefix in the chain. Anything
            # else (a different attenuation method, a non-literal
            # prefix) is a structural error -- the analyzer should
            # have rejected it on the privileged op already, so
            # we mirror that loudness here.
            result = True
            for att in attenuations:
                if att.get("method") != "restrict_to":
                    raise WasmEmissionError(
                        f"unsupported Fs attenuation on .allows: "
                        f"{att.get('method')!r}"
                    )
                args = att.get("args", [])
                if not args:
                    raise WasmEmissionError(
                        "Fs.restrict_to attenuation with no arg"
                    )
                prefix = _unquote_attenuation_arg(args[0])
                if not literal.startswith(prefix):
                    result = False
                    break
        else:  # cap == "Env"
            # AND over each restrict_to_keys: literal must appear
            # in EVERY key list (intersection semantics, matching
            # the runtime's ``self._allowed_keys is None`` /
            # ``name in self._allowed_keys`` walk through the
            # chain). An empty key list means nothing matches.
            result = True
            for att in attenuations:
                if att.get("method") != "restrict_to_keys":
                    raise WasmEmissionError(
                        f"unsupported Env attenuation on .allows: "
                        f"{att.get('method')!r}"
                    )
                keys = _parse_attenuation_key_list(att.get("args", []))
                if literal not in keys:
                    result = False
                    break
        self._write(f"i32.const {1 if result else 0}")
        if instr.dst is not None:
            self._write(f"local.set ${instr.dst}")

    def _emit_clock_with_attenuation_check(
        self, instr: MethodCall, cap: str, method: str,
        attenuations: list,
    ) -> None:
        """Clock.now_secs / Clock.now_monotonic with
        ``restrict_to_after(t)``. The Python runtime treats the
        ``now_*`` family as pure queries (anyone with a wall clock
        can read it), so no check fires there. The Wasm backend
        preserves that semantic: emit the host call as normal but
        leave a CAPA-RUNTIME-LIMITATION comment so the analyzer
        contract stays visible.

        Clock.sleep on a denied clock is the gated op in the
        Python runtime; it has no Wasm WIT signature yet, so this
        branch is documentation-only until Clock.sleep lands."""
        # Fall through to the standard path; emit a comment marker
        # for grep / audit visibility.
        self._write(
            ";; CAPA-RUNTIME-LIMITATION: Clock.restrict_to_after "
            "is a static-discipline attenuator; now_* are pure "
            "queries, no Wasm-side check fires."
        )
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
        self._write(f"call ${cap}_{method}")
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
        if ret_kind == "result_list_string_io_error":
            # ret_area layout (20 bytes):
            #   tag i32 @ 0
            #   Ok arm (list<string>): data_ptr i32 @ 4, len i32 @ 8
            #   Err arm (io-error): m_ptr i32 @ 4, m_len i32 @ 8,
            #                       c_ptr i32 @ 12, c_len i32 @ 16
            # Capa Result<List<String>, IoError>: tag@0, payload@8
            # (16-byte record). Ok payload is an i32 pointer (i64-
            # extended) to a freshly-allocated 16-byte List<String>
            # header (len@0, cap@4, data_ptr@8, pad@12) wrapping the
            # data buffer the host wrote. Err payload mirrors the
            # ``result_string_io_error`` Err arm.
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
            # Ok<List<String>>: alloc 16-byte header, fill in
            # (len, cap, data_ptr, pad); store the header pointer
            # (i64-extended) into dst+8. cap = len so a subsequent
            # ``.push`` triggers grow on the second insert; matches
            # the convention ``list_string`` materialiser uses.
            self._write("i32.const 16")
            self._write("call $alloc")
            self._write("local.set $_alloc_tmp")
            # header.len = ret_area.len (offset 8)
            self._write("local.get $_alloc_tmp")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=8")
            self._write("i32.store offset=0")
            # header.cap = ret_area.len
            self._write("local.get $_alloc_tmp")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=8")
            self._write("i32.store offset=4")
            # header.data_ptr = ret_area.data_ptr (offset 4)
            self._write("local.get $_alloc_tmp")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=4")
            self._write("i32.store offset=8")
            # dst[8] = i64(header pointer)
            self._write(f"local.get ${dst_local}")
            self._write("local.get $_alloc_tmp")
            self._write("i64.extend_i32_u")
            self._write("i64.store offset=8")
            self._indent -= 1
            self._write("else")
            self._indent += 1
            # Err<io-error>: same as result_string_io_error Err arm.
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
