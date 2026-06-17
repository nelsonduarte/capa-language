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
# Slice 25 (2026-05-30) note: the privileged-op inline-attenuation
# check used to live here, keyed by the ``_ATTENUATION_PRIVILEGED_OPS``
# set. Slices 25.2-25.8 moved every privileged op (Fs / Net / Db /
# Proc / Env / Clock) to the host handle table, which enforces
# ``cap.allows(arg)`` from the receiver's recorded restriction
# before the syscall. The emit-time inline check is no longer
# reachable for any privileged op; slice 25.9 deleted the dead
# machinery (``_emit_indirect_with_attenuation_check``,
# ``_emit_bool_query_with_attenuation_check``,
# ``_emit_clock_with_attenuation_check``,
# ``_emit_attenuation_err_into_ret_area``,
# ``_ATTENUATION_PRIVILEGED_OPS``). The ``.allows(arg)`` query
# methods still inline (``_emit_atten_allows`` collapses the
# literal-arg case to a const at emit time;
# ``_emit_atten_allows_runtime`` handles the dynamic-arg case via
# ``_emit_path_prefix_check`` / ``$proc_allows``), because those
# are guest-side queries with no host syscall to short-circuit.


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
    # Net.get / Net.post: same canonical-ABI shape as Fs.read /
    # Fs.write respectively. The host enforces the receiver Net
    # cap's restriction via the handle table (slice 25.3); Net.post
    # adds a second String arg (the body) and uses the same 20-byte
    # result area as Net.get.
    ("Net", "get"): (20, "result_string_io_error"),
    ("Net", "post"): (20, "result_string_io_error"),
    # Db.exec / Db.query: same canonical-ABI shapes as Fs.write /
    # Fs.read respectively. Both take (path, sql) as two String
    # args. exec returns result<_, io-error> (20 bytes); query
    # returns result<string, io-error> (also 20 bytes).
    ("Db", "exec"):  (20, "result_unit_io_error"),
    ("Db", "query"): (20, "result_string_io_error"),
    # Proc.exec: same shape as Db.query. Two String args (cmd,
    # args_json); returns result<string, io-error> with the
    # captured stdout in the Ok arm. Reuses the existing 20-byte
    # result_string_io_error materialiser.
    ("Proc", "exec"): (20, "result_string_io_error"),
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
        if "func(handle: u32, name: string) -> option<string>" in wit:
            # Slice 25.5 (2026-05-30): Env.get with handle. handle +
            # (ptr, len) + ret_area = 4 i32s.
            return (["i32", "i32", "i32", "i32"], "")
        if ("func(handle: u32, path: string) -> result<string, io-error>" in wit
                or "func(handle: u32, url: string) -> result<string, io-error>" in wit):
            # Slice 25.2 (Fs.read) / 25.3 (Net.get): cap handle (i32)
            # as the FIRST arg so the host can look up the receiver's
            # restriction in its handle table and enforce it before
            # the syscall. handle + (ptr, len) + ret_area = 4 i32s.
            return (["i32", "i32", "i32", "i32"], "")
        if "func() -> result<string, io-error>" in wit:
            # Stdio.read_line: no string arg, just the ret area.
            # Same 20-byte indirect-return shape as Fs.read.
            return (["i32"], "")
        if ("func(handle: u32, path: string, content: string) -> result<_, io-error>" in wit
                or "func(handle: u32, url: string, body: string) -> result<string, io-error>" in wit):
            # Slice 25.2 (Fs.write) / 25.3 (Net.post): handle +
            # two String args + ret_area = 6 i32s. Fs.write returns
            # result<_, io-error> (Ok-Unit) and Net.post returns
            # result<string, io-error>; both lower to a 20-byte
            # caller-allocated ret area so the wire shape is
            # identical at this layer.
            return (["i32", "i32", "i32", "i32", "i32", "i32"], "")
        if "func(path: string, content: string) -> result<_, io-error>" in wit:
            # Canonical ABI indirect return: path + content +
            # 20-byte ret area for the result. Same layout as
            # Fs.read's Err branch; Ok carries unit (no flat
            # fields).
            return (["i32", "i32", "i32", "i32", "i32"], "")
        if ("func(handle: u32, path: string, sql: string) -> result<_, io-error>" in wit):
            # Slice 25.4 (2026-05-30): Db.exec - handle + path + sql
            # + ret_area = 6 i32s. Result<Unit, IoError> return.
            return (["i32", "i32", "i32", "i32", "i32", "i32"], "")
        if ("func(handle: u32, path: string, sql: string) -> result<string, io-error>" in wit):
            # Slice 25.4 (2026-05-30): Db.query - handle + path + sql
            # + ret_area = 6 i32s. Result<String, IoError> return.
            return (["i32", "i32", "i32", "i32", "i32", "i32"], "")
        if ("func(handle: u32, cmd: string, args-json: string) -> result<string, io-error>" in wit):
            # Slice 25.4 (2026-05-30): Proc.exec - handle + cmd +
            # args_json + ret_area = 6 i32s.
            return (["i32", "i32", "i32", "i32", "i32", "i32"], "")
        if "func(path: string, sql: string) -> result<_, io-error>" in wit:
            # Db.exec (pre-slice-25.4 erased shape, kept for
            # backwards lookup tolerance): two-string-arg result-Unit.
            return (["i32", "i32", "i32", "i32", "i32"], "")
        if "func(url: string, body: string) -> result<string, io-error>" in wit:
            # Net.post (pre-slice-25.3 erased shape): two-string-arg
            # result-String. Slice 25.3 promoted this to the handle-
            # bearing pattern above.
            return (["i32", "i32", "i32", "i32", "i32"], "")
        if "func(path: string, sql: string) -> result<string, io-error>" in wit:
            # Db.query (pre-slice-25.4 erased shape).
            return (["i32", "i32", "i32", "i32", "i32"], "")
        if "func(cmd: string, args-json: string) -> result<string, io-error>" in wit:
            # Proc.exec (pre-slice-25.4 erased shape).
            return (["i32", "i32", "i32", "i32", "i32"], "")
        if "func(handle: u32, path: string) -> result<_, io-error>" in wit:
            # Slice 25.2: Fs.mkdir - handle + (ptr, len) + ret_area.
            return (["i32", "i32", "i32", "i32"], "")
        if "func(handle: u32, path: string) -> result<list<string>, io-error>" in wit:
            # Slice 25.2: Fs.list_dir - same call shape as Fs.read
            # but the Ok arm carries a list<string> instead of a
            # string. handle + (ptr, len) + ret_area.
            return (["i32", "i32", "i32", "i32"], "")
        if "func(handle: u32, path: string) -> bool" in wit:
            # Slice 25.2: Fs.exists / Fs.is_dir - handle + (ptr, len)
            # -> i32 (Bool is i32 on the Wasm side). Direct return,
            # no canonical-ABI indirect dance.
            return (["i32", "i32", "i32"], "i32")
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
        if "func(handle: u32) -> f64" in wit:
            # Slice 25.6 (2026-05-30): Clock.now_secs /
            # Clock.now_monotonic - handle (i32) -> f64. The host
            # looks up the receiver Clock to keep the wire shape
            # uniform with the other privileged ops; the now_*
            # family is itself a pure query, so the cap's
            # restrict_to_after deadline doesn't gate them
            # (matches the Python runtime).
            return (["i32"], "f64")
        if "func(handle: u32) -> bool" in wit:
            # Slice 25.6 (2026-05-30): Clock.allows - handle (i32)
            # -> i32 (Bool). The host looks up the receiver Clock
            # and consults its ``allows()`` (which checks
            # ``time.time() >= self._not_before``); pre-slice the
            # host hard-coded ``return 1`` regardless of attenuation
            # so a deny on a narrowed Clock crossing a function
            # boundary was lost.
            return (["i32"], "i32")
        if "func() -> bool" in wit:
            # Clock.allows (pre-slice-25.6 erased shape, kept for
            # backwards lookup tolerance).
            return ([], "i32")
        if "func(handle: u32, secs: f64)" in wit and "->" not in wit:
            # Slice 25.6 (2026-05-30): Clock.sleep with handle +
            # f64 arg, no return. Host looks up the cap and
            # enforces ``clock.allows()`` before calling
            # ``time.sleep``; on a denied cap the call is a silent
            # no-op (matches Python).
            return (["i32", "f64"], "")
        if "func(secs: f64)" in wit and "->" not in wit:
            # Clock.sleep (pre-slice-25.6 erased shape).
            return (["f64"], "")
        if "func(handle: u32) -> list<string>" in wit:
            # Slice 25.5 (2026-05-30): Env.args - handle (i32) +
            # ret_area (i32). Canonical ABI: ``list<string>`` lowers
            # to (data_ptr, len) which the host writes into the
            # caller-allocated ret area.
            return (["i32", "i32"], "")
        if "func() -> list<string>" in wit:
            # Env.args (pre-slice-25.5 erased shape, kept for
            # backwards lookup tolerance).
            return (["i32"], "")
        if ("func(handle: u32, prefix: string) -> u32" in wit
                or "func(handle: u32, host: string) -> u32" in wit):
            # Slices 25.2 / 25.3 / 25.4:
            # Fs.restrict_to / Net.restrict_to / Db.restrict_to /
            # Proc.restrict_to all take the parent handle + the
            # string attenuation arg and return a fresh child
            # handle bound to a narrower restriction. The guest
            # threads the new handle as the receiver of subsequent
            # privileged calls in this branch of the program;
            # passing the cap across a function boundary preserves
            # the restriction (audit slice 25 F1).
            return (["i32", "i32", "i32"], "i32")
        if "func(handle: u32, t: f64) -> u32" in wit:
            # Slice 25.6 (2026-05-30): Clock.restrict_to_after -
            # parent handle (i32) + f64 deadline -> new handle
            # (i32). The host max-merges the new threshold against
            # the parent's deadline (intersection semantics, never
            # widens).
            return (["i32", "f64"], "i32")
        if "func(handle: u32, keys: list<string>) -> u32" in wit:
            # Slice 25.5 (2026-05-30): Env.restrict_to_keys -
            # parent handle + list<string> header (data_ptr, len)
            # -> new handle. The host reads the list out of linear
            # memory, intersects with the parent's allow-list, and
            # returns the child handle.
            return (["i32", "i32", "i32"], "i32")
        if (("func(prefix: string)" in wit
                or "func(host: string)" in wit)
                and "->" not in wit):
            # Pre-slice-25.4 erased shapes for Db / Proc
            # restrict_to; kept for backwards lookup tolerance.
            return (["i32", "i32"], "")
        if "func(keys: list<string>)" in wit and "->" not in wit:
            # Pre-slice-25.5 erased shape for Env.restrict_to_keys;
            # kept for backwards lookup tolerance.
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
        # Slices 25.2 - 25.6 (2026-05-30): the attenuator methods
        # on Fs / Net / Db / Proc / Env / Clock are no longer no-ops
        # at the Wasm level. They cross the host bridge with the
        # receiver's handle + the attenuation arg(s) and return a
        # fresh i32 handle bound to a narrower restriction. The dst
        # local holds the new handle and is threaded as the receiver
        # of downstream privileged calls (including across function
        # boundaries - this is what closes audit slice 25 F1).
        if cap == "Fs" and method == "restrict_to":
            self._emit_fs_restrict_to(instr)
            return
        if cap == "Net" and method == "restrict_to":
            self._emit_net_restrict_to(instr)
            return
        if cap == "Db" and method == "restrict_to":
            self._emit_handle_restrict_to_string(instr, "Db")
            return
        if cap == "Proc" and method == "restrict_to":
            self._emit_handle_restrict_to_string(instr, "Proc")
            return
        if cap == "Env" and method == "restrict_to_keys":
            self._emit_env_restrict_to_keys(instr)
            return
        if cap == "Clock" and method == "restrict_to_after":
            self._emit_clock_restrict_to_after(instr)
            return
        # Attenuator methods on Random / Stdio / Unsafe (the still-
        # erased caps) are no-ops at the Wasm level: their values
        # carry no runtime representation. Random has no
        # restrict_to, but a safety net here keeps the dispatcher
        # tolerant of analyzer additions.
        if method in ("restrict_to", "restrict_to_keys",
                      "restrict_to_after"):
            return
        # ``allows`` on Fs / Env / Db / Proc is inlined at emit time
        # (D4 Option B). For a literal-string argument we collapse the
        # attenuation chain to a static i32 result; for a non-literal
        # argument we emit a runtime check that walks the attenuation
        # chain. ``Clock.allows`` is special-cased (slice 25.6 routes
        # it through a host call that consults the handle's
        # ``not_before`` deadline against the live wall clock) - see
        # the cap == "Clock" + method == "allows" branch below.
        if method == "allows" and cap in ("Fs", "Env", "Db", "Proc", "Net"):
            self._emit_atten_allows(instr, cap)
            return
        # Slice 25.6 (2026-05-30): Clock.allows now takes a handle
        # the host looks up to consult the cap's real not-before
        # deadline. Pre-slice the host hard-coded ``return 1``
        # regardless of attenuation (the inline check fired only
        # on the privileged ops, never on allows itself).
        if cap == "Clock" and method == "allows":
            self._emit_clock_allows_with_handle(instr)
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
        # Slice 25.2 / 25.3 (2026-05-30): Fs / Net no longer need the
        # inline emit-time attenuation check. The host bridge now
        # enforces the receiver cap's restriction via the handle
        # table, which is sound across function boundaries (the bug
        # audit slice 25 F1 documented) AND uses
        # ``urlparse(url).hostname`` for Net (which the inline
        # ``$str_contains`` check failed to do - audit slice 25 F2,
        # substring-attack lookalike URLs were admitted). The handle
        # is pushed as the FIRST arg by the helpers below. The
        # inline machinery stays intact for Db / Proc / Env / Clock
        # (they remain on the old erased-cap path until their own
        # rollout slices).
        if cap == "Fs" and indirect is not None:
            self._emit_fs_method_with_handle(instr, method, indirect)
            return
        if cap == "Fs" and method in ("exists", "is_dir"):
            self._emit_fs_bool_query_with_handle(instr, method)
            return
        if cap == "Net" and indirect is not None:
            self._emit_net_method_with_handle(instr, method, indirect)
            return
        # Slices 25.4 / 25.5 (2026-05-30): Db / Proc / Env
        # indirect-return privileged ops go through the handle-
        # passing helper. The host bridge looks up the receiver cap
        # from the table and enforces ``cap.allows(arg)`` before
        # the syscall, closing audit slice 25 F1 for these caps.
        # The old inline attenuation-check machinery in
        # ``_emit_one_attenuation`` is now dead code for these caps
        # and is kept (commented) for the slice-25.9 cleanup.
        if cap in ("Db", "Proc", "Env") and indirect is not None:
            self._emit_indirect_with_cap_handle(instr, cap, method, indirect)
            return
        # Slice 25.6 (2026-05-30): Clock primitive-return ops
        # (now_secs, now_monotonic, sleep) take ``handle`` as the
        # first arg now too. ``allows`` is handled above. The host
        # enforces attenuation via the handle's ``allows()``, so
        # no inline emit-time check is needed.
        if cap == "Clock" and method in (
            "now_secs", "now_monotonic", "sleep",
        ):
            self._emit_clock_primitive_with_handle(instr, method)
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

    # ---- slice 25.2 Fs handle-passing helpers ------------------

    def _push_fs_handle(self, recv) -> None:
        """Push the receiver Fs cap's i32 handle. The receiver Value
        is always a local or param of type Fs (the analyzer enforces
        this); we emit a ``local.get`` against the matching slot.

        Slice 25.2 (2026-05-30): Fs values became i32 handles into
        the host's per-instance cap table so a restricted cap
        survives crossing function boundaries (audit slice 25 F1).
        """
        if recv.kind not in ("local", "param"):
            raise WasmEmissionError(
                f"Fs method receiver must be a local or param "
                f"(slice 25.2 handle-passing), got {recv.kind!r}"
            )
        # The Fs slot is captured by a lambda the same way other
        # i32 captures are - delegate to ``_push_value`` so the
        # env-aware load path fires when we're inside a lifted
        # lambda body.
        self._push_value(recv)

    def _emit_fs_restrict_to(self, instr: MethodCall) -> None:
        """Emit ``new_fs = fs.restrict_to(prefix)``. Pushes the
        receiver handle + the prefix (ptr, len), calls the host
        import, and binds the i32 result handle to ``instr.dst``.
        The dst's Fs local was declared i32 by the locals walker
        (slice 25.2 un-erased Fs)."""
        if len(instr.args) != 1:
            raise WasmEmissionError(
                f"Fs.restrict_to expected 1 arg, got {len(instr.args)}"
            )
        self._push_fs_handle(instr.receiver)
        self._push_string_arg(instr.args[0])
        self._write("call $Fs_restrict_to")
        if instr.dst is not None:
            self._write(f"local.set ${instr.dst}")

    def _emit_fs_method_with_handle(
        self, instr: MethodCall, method: str,
        indirect: tuple[int, str],
    ) -> None:
        """Emit a Fs privileged op (read / write / mkdir / list_dir)
        with the receiver handle as the FIRST host-call arg. The
        host enforces ``fs.allows(path)`` via the table lookup, so
        no inline emit-time check is needed (the bug fixed by
        slice 25.2). Push order matches the WIT signature: handle,
        then each String arg expanded to (ptr, len), then ret_area.
        """
        ret_area_size, ret_kind = indirect
        # Receiver handle first.
        self._push_fs_handle(instr.receiver)
        # String args expanded the standard way.
        for arg in instr.args:
            self._push_string_arg(arg)
        # Allocate the ret area, stash in $_ret_area, push as the
        # trailing arg, call (void).
        self._write(f"i32.const {ret_area_size}")
        self._write("call $alloc")
        self._write("local.tee $_ret_area")
        self._write(f"call $Fs_{method}")
        self._emit_cap_indirect_materialise(ret_kind, instr.dst)

    def _emit_fs_bool_query_with_handle(
        self, instr: MethodCall, method: str,
    ) -> None:
        """Emit ``fs.exists(path)`` / ``fs.is_dir(path)``. Pushes
        the receiver handle + the path (ptr, len), calls the host
        import, binds the i32 (Bool) result. Host enforces the
        restriction via handle lookup and returns 0 on a denied
        path (fail-closed-as-absent; matches the Python runtime)."""
        if len(instr.args) != 1:
            raise WasmEmissionError(
                f"Fs.{method} expected 1 arg, got {len(instr.args)}"
            )
        self._push_fs_handle(instr.receiver)
        self._push_string_arg(instr.args[0])
        self._write(f"call $Fs_{method}")
        if instr.dst is not None:
            self._write(f"local.set ${instr.dst}")

    # ---- slice 25.3 Net handle-passing helpers -----------------

    def _push_net_handle(self, recv) -> None:
        """Push the receiver Net cap's i32 handle. Mirrors
        ``_push_fs_handle``; the receiver Value is always a local
        or param of type Net (analyzer-enforced) and may live in a
        captured environment when we're inside a lifted lambda
        body (``_push_value`` handles the env-aware load path)."""
        if recv.kind not in ("local", "param"):
            raise WasmEmissionError(
                f"Net method receiver must be a local or param "
                f"(slice 25.3 handle-passing), got {recv.kind!r}"
            )
        self._push_value(recv)

    def _emit_net_restrict_to(self, instr: MethodCall) -> None:
        """Emit ``new_net = net.restrict_to(host)``. Pushes the
        receiver handle + the host (ptr, len), calls the host
        import, binds the i32 result handle to ``instr.dst``. The
        dst's Net local was declared i32 by the locals walker
        (slice 25.3 un-erased Net)."""
        if len(instr.args) != 1:
            raise WasmEmissionError(
                f"Net.restrict_to expected 1 arg, got {len(instr.args)}"
            )
        self._push_net_handle(instr.receiver)
        self._push_string_arg(instr.args[0])
        self._write("call $Net_restrict_to")
        if instr.dst is not None:
            self._write(f"local.set ${instr.dst}")

    def _emit_net_method_with_handle(
        self, instr: MethodCall, method: str,
        indirect: tuple[int, str],
    ) -> None:
        """Emit a Net privileged op (get / post) with the receiver
        handle as the FIRST host-call arg. The host looks up the
        cap and delegates to the Python ``Net.{get,post}`` which
        does ``urlparse(url).hostname`` + ``allows()`` (which is
        what closes audit slice 25 F2; the prior inline
        ``$str_contains(url, host)`` admitted lookalike URLs)."""
        ret_area_size, ret_kind = indirect
        self._push_net_handle(instr.receiver)
        for arg in instr.args:
            self._push_string_arg(arg)
        self._write(f"i32.const {ret_area_size}")
        self._write("call $alloc")
        self._write("local.tee $_ret_area")
        self._write(f"call $Net_{method}")
        self._emit_cap_indirect_materialise(ret_kind, instr.dst)

    # ---- slices 25.4 / 25.5 / 25.6 Db / Proc / Env / Clock helpers ----

    def _push_cap_handle(self, recv, cap: str) -> None:
        """Push the receiver capability's i32 handle. Mirrors
        ``_push_fs_handle`` / ``_push_net_handle``; receiver Value
        must be a local or param of type ``cap`` (analyzer-enforced)
        and may live in a captured environment when emitted inside
        a lifted lambda body (``_push_value`` handles the env-aware
        load path)."""
        if recv.kind not in ("local", "param"):
            raise WasmEmissionError(
                f"{cap} method receiver must be a local or param "
                f"(handle-passing), got {recv.kind!r}"
            )
        self._push_value(recv)

    def _emit_handle_restrict_to_string(
        self, instr: MethodCall, cap: str,
    ) -> None:
        """Emit ``new = cap.restrict_to(arg)`` for caps whose
        attenuation arg is a single String (Db, Proc). Pushes
        receiver handle + arg (ptr, len), calls the host import,
        and binds the i32 result handle to ``instr.dst`` (declared
        i32 by the locals walker now that the cap is un-erased)."""
        if len(instr.args) != 1:
            raise WasmEmissionError(
                f"{cap}.restrict_to expected 1 arg, got "
                f"{len(instr.args)}"
            )
        self._push_cap_handle(instr.receiver, cap)
        self._push_string_arg(instr.args[0])
        self._write(f"call ${cap}_restrict_to")
        if instr.dst is not None:
            self._write(f"local.set ${instr.dst}")

    def _emit_env_restrict_to_keys(self, instr: MethodCall) -> None:
        """Emit ``new = env.restrict_to_keys(keys)``. Pushes
        receiver handle + the list<string> as (data_ptr, len),
        calls the host import, and binds the i32 result handle.
        The keys argument is a Capa List<String>; on the Wasm side
        a List<String> is a 16-byte header (len@0, cap@4,
        data_ptr@8, pad@12) with the data array storing 8-byte
        packed (str_ptr, str_len) pairs - same layout the host
        uses for ``env.args``'s output. We push the data_ptr and
        len directly so the host can walk N=len items out of the
        packed buffer."""
        if len(instr.args) != 1:
            raise WasmEmissionError(
                f"Env.restrict_to_keys expected 1 list arg, got "
                f"{len(instr.args)}"
            )
        # Receiver handle first.
        self._push_cap_handle(instr.receiver, "Env")
        # The list arg is an i32 pointer to the List<String> header;
        # push (data_ptr, len) as the host expects. Push the header
        # value twice and load one field from each copy rather than
        # stashing through a scratch local: the arg is a re-pushable
        # Value (a local or a constant pointer, no side effects), so a
        # second push is cheap and -- unlike ``$_alloc_tmp`` -- needs no
        # cooperation from the locals walker, which only declares that
        # scratch when a list MakeList / list-method gate fires. A list
        # arriving from a call-result fires none of those gates, so the
        # tee/get form referenced an undeclared local. Mirrors the
        # IoError formatter's twice-push in _strings.py.
        arg = instr.args[0]
        self._push_value(arg)
        # data_ptr at offset 8
        self._write("i32.load offset=8")
        # Re-push header to load len.
        self._push_value(arg)
        # len at offset 0
        self._write("i32.load offset=0")
        self._write("call $Env_restrict_to_keys")
        if instr.dst is not None:
            self._write(f"local.set ${instr.dst}")

    def _emit_clock_restrict_to_after(self, instr: MethodCall) -> None:
        """Emit ``new = clock.restrict_to_after(t)``. Pushes
        receiver handle (i32) + threshold (f64), calls the host
        import, binds the i32 result handle. The host max-merges
        the new threshold against the parent's deadline
        (intersection semantics, never widens)."""
        if len(instr.args) != 1:
            raise WasmEmissionError(
                f"Clock.restrict_to_after expected 1 arg, got "
                f"{len(instr.args)}"
            )
        self._push_cap_handle(instr.receiver, "Clock")
        self._push_value(instr.args[0])
        self._write("call $Clock_restrict_to_after")
        if instr.dst is not None:
            self._write(f"local.set ${instr.dst}")

    def _emit_indirect_with_cap_handle(
        self, instr: MethodCall, cap: str, method: str,
        indirect: tuple[int, str],
    ) -> None:
        """Emit a Db / Proc / Env privileged op (Db.exec /
        Db.query / Proc.exec / Env.get / Env.args) with the
        receiver handle as the FIRST host-call arg. The host
        enforces ``cap.allows(...)`` via the table lookup before
        the syscall, closing audit slice 25 F1 for these caps."""
        ret_area_size, ret_kind = indirect
        # Receiver handle first.
        self._push_cap_handle(instr.receiver, cap)
        # String args expanded the standard way; Env.args has no
        # string args so the loop is a no-op for it.
        for arg in instr.args:
            self._push_string_arg(arg)
        self._write(f"i32.const {ret_area_size}")
        self._write("call $alloc")
        self._write("local.tee $_ret_area")
        self._write(f"call ${cap}_{method}")
        self._emit_cap_indirect_materialise(ret_kind, instr.dst)

    def _emit_clock_primitive_with_handle(
        self, instr: MethodCall, method: str,
    ) -> None:
        """Emit a Clock primitive-return op (now_secs, now_monotonic,
        sleep) with the receiver handle as the FIRST host-call arg.
        Returns f64 for now_*; void for sleep."""
        self._push_cap_handle(instr.receiver, "Clock")
        for arg in instr.args:
            self._push_value(arg)
        self._write(f"call $Clock_{method}")
        # now_secs / now_monotonic return f64 -> dst; sleep returns
        # nothing.
        if method in ("now_secs", "now_monotonic") and instr.dst is not None:
            self._write(f"local.set ${instr.dst}")

    def _emit_clock_allows_with_handle(self, instr: MethodCall) -> None:
        """Emit ``clock.allows()`` with the receiver handle. The
        host looks up the cap and consults its real not-before
        deadline against the wall clock (slice 25.6); pre-slice
        the host hard-coded ``return 1`` so a deny on a narrowed
        Clock crossing a function boundary was lost."""
        if instr.args:
            raise WasmEmissionError(
                f"Clock.allows takes no arg, got {len(instr.args)}"
            )
        self._push_cap_handle(instr.receiver, "Clock")
        self._write("call $Clock_allows")
        if instr.dst is not None:
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

    def _emit_one_attenuation(
        self, cap: str, method: str, att: dict,
    ) -> None:
        """AND one attenuation into ``$_atten_ok``. Each attenuation
        is a record ``{"method": str, "args": [str_form, ...]}`` as
        produced by ``_flatten_restrict_chain``.

        Slice 25.9 (2026-05-30): only invoked from the
        ``_emit_atten_allows_runtime`` dynamic-arg path on caps
        Fs / Env / Db / Proc (the literal-arg path collapses to a
        const at emit time without this helper). Net never reaches
        here (``net.allows(...)`` is rejected by the WIT table at
        discovery time) and the privileged-op paths moved to the
        host handle table in slices 25.2-25.8, so the original
        per-cap branch set is reduced to the four caps that still
        host a guest-side ``.allows()`` query."""
        att_method = att.get("method")
        args = att.get("args", [])
        if cap == "Fs":
            if att_method != "restrict_to" or not args:
                raise WasmEmissionError(
                    f"unsupported Fs attenuation: {att_method!r} "
                    f"with args {args!r}"
                )
            prefix = _unquote_attenuation_arg(args[0])
            self._emit_path_prefix_check(prefix)
            return
        if cap == "Db":
            if att_method != "restrict_to" or not args:
                raise WasmEmissionError(
                    f"unsupported Db attenuation: {att_method!r} "
                    f"with args {args!r}"
                )
            prefix = _unquote_attenuation_arg(args[0])
            self._emit_path_prefix_check(prefix)
            return
        if cap == "Net":
            # Net.allows is EXACT host equality: ok &= (host == arg).
            # Net.restrict_to intersects single-host sets, so the AND
            # over the chain reproduces the intersection (two distinct
            # hosts collapse to never-allowed).
            if att_method != "restrict_to" or not args:
                raise WasmEmissionError(
                    f"unsupported Net attenuation: {att_method!r} "
                    f"with args {args!r}"
                )
            host = _unquote_attenuation_arg(args[0])
            offset, length = self._intern_string(host)
            self._write("local.get $_atten_path_ptr")
            self._write("local.get $_atten_path_len")
            self._write(f"i32.const {offset}")
            self._write(f"i32.const {length}")
            self._write("call $str_eq")
            self._write("local.get $_atten_ok")
            self._write("i32.and")
            self._write("local.set $_atten_ok")
            return
        if cap == "Proc":
            # Basename + suffix-boundary check via the
            # ``$proc_allows`` runtime helper (matches Python's
            # ``Proc.allows`` semantics).
            if att_method != "restrict_to" or not args:
                raise WasmEmissionError(
                    f"unsupported Proc attenuation: {att_method!r} "
                    f"with args {args!r}"
                )
            prefix = _unquote_attenuation_arg(args[0])
            offset, length = self._intern_string(prefix)
            self._write("local.get $_atten_path_ptr")
            self._write("local.get $_atten_path_len")
            self._write(f"i32.const {offset}")
            self._write(f"i32.const {length}")
            self._write("call $proc_allows")
            # ok &= predicate
            self._write("local.get $_atten_ok")
            self._write("i32.and")
            self._write("local.set $_atten_ok")
            return
        if cap == "Env":
            # Walk the literal key list and OR-equality the
            # requested name against each key, AND-combine into
            # the running predicate.
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

    def _emit_path_prefix_check(self, prefix: str) -> None:
        """Emit a path-prefix attenuation check that respects path
        component boundaries: ``path == prefix`` OR ``path``
        starts with ``prefix + '/'``. The combined check rejects
        the classic boundary bypass ``Fs.restrict_to("/tmp")``
        admitting ``/tmproot/secret`` that a naive
        ``$str_starts_with(path, "/tmp")`` would accept.

        This is the GUEST-SIDE query check and is a LEXICAL
        APPROXIMATION of the authoritative host-side enforcement.
        The Python ``Fs.allows`` / ``Db.allows`` use
        ``Path.is_relative_to`` after ``os.path.realpath``
        canonicalisation, which resolves ``..`` / ``.`` / symlinks
        and is strictly stronger. The guest Wasm has no filesystem,
        so it cannot realpath at runtime: the component-boundary
        check closes the simple ``/tmproot`` lexical bypass, but a
        path that escapes via a runtime ``..`` (``prefix/../x``) or a
        symlink is NOT caught here on the dynamic-arg path. The
        AUTHORITATIVE answer is the host-side check; this guest query
        is a best-effort lexical hint, so the backends do not fully
        agree on every dynamic traversal query. (Literal-string
        queries are normalised lexically at emit time, which does
        collapse ``..``; only the runtime dynamic-arg path is
        approximate.)

        The prefix is interned once with and once without a
        trailing slash to avoid emitting the canonicalisation
        logic at runtime. ``prefix + '/'`` is the slash-suffixed
        form used for the ``startswith`` arm; ``prefix`` is the
        exact-match arm. Result: ok &&= (eq OR starts_with_slash).
        """
        # exact-match arm: $str_eq(path, prefix)
        offset_eq, length_eq = self._intern_string(prefix)
        self._write("local.get $_atten_path_ptr")
        self._write("local.get $_atten_path_len")
        self._write(f"i32.const {offset_eq}")
        self._write(f"i32.const {length_eq}")
        self._write("call $str_eq")
        # boundary-aware startswith arm: $str_starts_with(path,
        # prefix + '/'). The trailing slash forces the next char
        # of ``path`` (if any) to be a separator, blocking the
        # ``/tmproot`` lookalike.
        prefix_with_slash = prefix if prefix.endswith("/") else prefix + "/"
        offset_sw, length_sw = self._intern_string(prefix_with_slash)
        self._write("local.get $_atten_path_ptr")
        self._write("local.get $_atten_path_len")
        self._write(f"i32.const {offset_sw}")
        self._write(f"i32.const {length_sw}")
        self._write("call $str_starts_with")
        # combine: eq OR starts_with_slash
        self._write("i32.or")
        # ok &= combined
        self._write("local.get $_atten_ok")
        self._write("i32.and")
        self._write("local.set $_atten_ok")

    def _emit_atten_allows(
        self, instr: MethodCall, cap: str,
    ) -> None:
        """Emit a ``Fs.allows(path)`` / ``Env.allows(name)`` call
        inline (D4 Option B). With no attenuations the call is
        trivially true (matches the Python ``self._allowed is None``
        branch); otherwise we walk the chain at emit time and AND
        each predicate into the result. Privileged ops (Fs.read /
        Env.get / ...) enforce the same restriction via the host
        handle table since slice 25 (2026-05-30); this query path
        stays inline because it has no host syscall to short-
        circuit.

        Two argument shapes (slice 14, 2026-05-29):
        - **Literal-string argument**: the answer is fully known at
          emit time. Collapse to a single ``i32.const 0/1`` push;
          zero runtime cost.
        - **Dynamic argument (local / param / computed)**: emit a
          runtime check that mirrors the privileged-op path's
          ``_emit_path_prefix_check`` / key-AND machinery, bound
          to dst as i32.

        Pre-slice-14 the dynamic case raised
        ``WasmEmissionError`` -- programs that passed a non-literal
        path to ``fs.allows(...)`` compiled on Python but crashed
        compile on Wasm. Lifting this restriction removes the
        last cross-backend portability gap from the audit P2
        backlog.
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
        if arg.kind != "lit_str":
            # Dynamic-arg path: emit a runtime check. No
            # attenuations -> always true.
            self._emit_atten_allows_runtime(instr, cap, arg, attenuations)
            return
        literal: str = arg.literal
        # Compute the static answer. No attenuations -> always true
        # (mirrors ``self._allowed_prefixes is None`` /
        # ``self._allowed_keys is None`` in the Python runtime).
        if not attenuations:
            result = True
        elif cap in ("Fs", "Db"):
            # AND over each restrict_to(prefix): literal must
            # match every prefix in the chain at a component
            # boundary (exact match OR followed by '/'). Anything
            # else (a different attenuation method, a non-literal
            # prefix) is a structural error -- the analyzer should
            # have rejected it on the privileged op already, so
            # we mirror that loudness here. Audit 2026-05-29:
            # pre-fix the check used a naive ``startswith`` which
            # admitted ``/tmproot/x`` when restricted to ``/tmp``;
            # the boundary-aware check now matches the Python
            # runtime's ``Path.is_relative_to`` semantics for
            # well-formed lexical paths.
            #
            # Audit 2026-06-17: the Python runtime's ``Fs.allows`` /
            # ``Db.allows`` resolve ``..`` / ``.`` / symlinks through
            # ``os.path.realpath`` before the boundary check, so
            # ``prefix/../escaped.db`` is denied (the ``..`` walks out
            # of the prefix). The pre-fix lexical ``startswith`` here
            # admitted it. We cannot ``realpath`` at emit time (no
            # target FS), but ``os.path.normpath`` collapses the ``..``
            # / ``.`` lexically, which closes the obvious traversal
            # bypass. Symlink-based escapes still require the host's
            # realpath; the guest-side answer is a lexical
            # approximation of the authoritative host check.
            # ``posixpath`` (not ``os.path``) so the normalisation is
            # platform-independent and keeps ``/`` separators on a
            # Windows build host -- the runtime path strings are POSIX.
            import posixpath as _ppath
            literal_norm = _ppath.normpath(literal)
            result = True
            for att in attenuations:
                if att.get("method") != "restrict_to":
                    raise WasmEmissionError(
                        f"unsupported {cap} attenuation on .allows: "
                        f"{att.get('method')!r}"
                    )
                args = att.get("args", [])
                if not args:
                    raise WasmEmissionError(
                        f"{cap}.restrict_to attenuation with no arg"
                    )
                prefix = _ppath.normpath(
                    _unquote_attenuation_arg(args[0])
                )
                sep = prefix if prefix.endswith("/") else prefix + "/"
                if not (literal_norm == prefix
                        or literal_norm.startswith(sep)):
                    result = False
                    break
        elif cap == "Net":
            # AND over each restrict_to(host): the literal host must
            # equal EVERY host in the chain (Net.restrict_to intersects
            # single-host sets, so any two distinct hosts narrow to the
            # empty set -> never allowed). Net.allows is EXACT equality
            # (``host in self._allowed``), not a prefix check, so a host
            # that merely shares a prefix is NOT allowed.
            result = True
            for att in attenuations:
                if att.get("method") != "restrict_to":
                    raise WasmEmissionError(
                        f"unsupported Net attenuation on .allows: "
                        f"{att.get('method')!r}"
                    )
                args = att.get("args", [])
                if not args:
                    raise WasmEmissionError(
                        "Net.restrict_to attenuation with no arg"
                    )
                host = _unquote_attenuation_arg(args[0])
                if literal != host:
                    result = False
                    break
        elif cap == "Proc":
            # AND over each restrict_to(prefix), mirroring the Python
            # runtime's ``Proc.allows`` rule (audit 2026-06-17). That
            # rule is identity-based, NOT basename-based:
            #
            # - a PATH restriction (prefix contains a separator) only
            #   admits a path cmd whose ``normpath`` equals the prefix's
            #   ``normpath``; a bare-name cmd never matches it.
            # - a BARE-NAME restriction (no separator) only admits a
            #   bare-name cmd (``cmd == prefix`` or ``cmd.startswith(
            #   prefix + '-')``); a PATH cmd never matches, so a planted
            #   ``/attacker/git`` cannot impersonate ``restrict_to("git")``.
            #
            # The pre-fix code collapsed the cmd to its basename, which
            # let ``/attacker/git`` slip through ``restrict_to("git")`` --
            # the exact bypass the Python runtime now denies. This whole
            # rule is purely lexical, so the literal collapse mirrors it
            # exactly. ``os.path.normpath`` is computed at emit time on
            # the known literals.
            # ``posixpath`` for the normalisation so a Windows build
            # host keeps ``/`` separators; the runtime treats commands
            # as POSIX path strings. Separator detection still looks at
            # ``/`` only, matching the Python runtime's ``_has_sep``
            # intent on the wire format.
            import posixpath as _ppath

            def _has_sep(s: str) -> bool:
                return "/" in s

            cmd_is_path = _has_sep(literal)
            result = True
            for att in attenuations:
                if att.get("method") != "restrict_to":
                    raise WasmEmissionError(
                        f"unsupported Proc attenuation on .allows: "
                        f"{att.get('method')!r}"
                    )
                args = att.get("args", [])
                if not args:
                    raise WasmEmissionError(
                        "Proc.restrict_to attenuation with no arg"
                    )
                prefix = _unquote_attenuation_arg(args[0])
                if _has_sep(prefix):
                    matched = (
                        cmd_is_path
                        and _ppath.normpath(literal)
                        == _ppath.normpath(prefix)
                    )
                else:
                    matched = (
                        not cmd_is_path
                        and (literal == prefix
                             or literal.startswith(prefix + "-"))
                    )
                if not matched:
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

    def _emit_atten_allows_runtime(
        self, instr, cap: str, arg, attenuations: list,
    ) -> None:
        """Runtime version of ``_emit_atten_allows`` for the
        dynamic-argument case. Stashes the path / name in the
        same ``$_atten_path_*`` scratch the privileged-op
        attenuation check uses, walks the attenuation chain
        emitting per-attenuation checks (AND-combined), then
        binds the i32 accumulator to dst.

        - ``cap in {Fs, Db}``: path-prefix check via
          ``_emit_path_prefix_check`` (the same boundary-aware
          ``eq OR starts-with-slash`` shape the privileged path
          uses).
        - ``cap == Env``: per-attenuation OR-chain of name-equality
          against the keys in that restrict_to_keys list, AND-
          combined across the chain. Empty key list -> ok=0.
        - ``cap == Proc``: per-attenuation call to ``$proc_allows``
          with the prefix literal; basename + suffix-boundary
          match runs at runtime.
        - No attenuations: push 1 (unrestricted, matches
          ``self._allowed_prefixes is None`` /
          ``self._allowed_keys is None``).
        """
        if not attenuations:
            self._write("i32.const 1")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        # Stash the arg in scratch locals (declared by the locals
        # walker on demand whenever a dynamic-arg ``.allows()``
        # call appears in the function).
        self._push_string_arg(arg)
        self._write("local.set $_atten_path_len")
        self._write("local.set $_atten_path_ptr")
        # ok = 1; AND each per-attenuation check into it.
        self._write("i32.const 1")
        self._write("local.set $_atten_ok")
        # Method-name parameter for _emit_one_attenuation is just
        # used in error messages; pass through the source method.
        for att in attenuations:
            self._emit_one_attenuation(cap, instr.method, att)
        self._write("local.get $_atten_ok")
        if instr.dst is not None:
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
            #
            # Tag convention bridge (2026-05): the canonical ABI for
            # ``option<T>`` puts ``none`` first (discriminant 0) and
            # ``some(T)`` second (discriminant 1). Capa's internal
            # Option layout is the inverse (``Some``=0, ``None``=1).
            # When the ret_area was written by the Component Model
            # adapter (a wasm-tools component-wrapped run), the byte
            # follows the WIT convention; when it was written by the
            # core host or by the inline attenuation-deny path, it
            # also follows the WIT convention (changed in this same
            # slice for consistency). Either way: read the WIT
            # discriminant out of the ret_area and XOR-flip to the
            # Capa internal one before storing in the Option record.
            # Without this flip, a component-wrapped Env.get of a
            # set env var returned None and a missing env var
            # returned Some(garbage); the bug was latent because no
            # in-tree test exercised the component path for an
            # ``option<T>`` return.
            dst_local = dst if dst is not None else "_alloc_tmp"
            self._write("i32.const 16")
            self._write("call $alloc")
            self._write(f"local.set ${dst_local}")
            # tag: WIT discriminant ^ 1 = Capa tag
            self._write(f"local.get ${dst_local}")
            self._write("local.get $_ret_area")
            self._write("i32.load offset=0")
            self._write("i32.const 1")
            self._write("i32.xor")
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
