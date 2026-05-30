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
    # Audit 2026-05-29 (slice 12): Fs.exists / Fs.is_dir / Fs.mkdir
    # / Fs.list_dir all observe or mutate the filesystem and so
    # must respect the cap's prefix attenuation just like read /
    # write. Pre-fix a Db cap scoped to "/tmp/" could
    # ``fs.mkdir("/etc/foo")`` on Wasm; the Python runtime
    # already gated all four through ``self.allows(path)``.
    ("Fs", "exists"),
    ("Fs", "is_dir"),
    ("Fs", "mkdir"),
    ("Fs", "list_dir"),
    ("Net", "get"),
    ("Net", "post"),
    ("Env", "get"),
    ("Clock", "now_secs"),
    ("Clock", "now_monotonic"),
    # Audit 2026-05-29 (slice 13): Clock.sleep is the gated op in
    # the Python runtime (silent no-op when restrict_to_after's
    # deadline hasn't passed). Pre-fix the Wasm backend ignored
    # the attenuation entirely; the inline check now compares
    # ``clock.now_secs()`` against the literal threshold at
    # emit time and skips the host call when denied.
    ("Clock", "sleep"),
    ("Db", "exec"),
    ("Db", "query"),
    # Slice 15 (2026-05): Proc.exec is the privileged op that
    # crosses the trust boundary. ``restrict_to`` is the
    # attenuator; ``allows`` is inlined (D4 Option B). Same
    # two-String-arg shape as Db.exec / Net.post but the
    # attenuation predicate is basename + suffix-boundary
    # (``$proc_allows``) rather than path-prefix.
    ("Proc", "exec"),
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
    if cap == "Db":
        return f"Db capability does not permit {method}"
    if cap == "Proc":
        return f"Proc capability does not permit {method}"
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
    # Net.get / Net.post: same canonical-ABI shape as Fs.read /
    # Fs.write respectively. The attenuation branch in
    # ``_emit_indirect_with_attenuation_check`` already handles
    # both via the receiver-host check; Net.post adds a second
    # String arg (the body) and uses the same 20-byte result
    # area as Net.get.
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
        if ("func(handle: u32, path: string) -> result<string, io-error>" in wit):
            # Slice 25.2 (2026-05-30): Fs.read now takes the cap
            # handle (i32) as the FIRST arg so the host can look
            # up the receiver's restriction in its handle table
            # and enforce it before the syscall. handle + (ptr,
            # len) + ret_area = 4 i32s.
            return (["i32", "i32", "i32", "i32"], "")
        if ("func(url: string) -> result<string, io-error>" in wit):
            # Canonical ABI indirect return: single-string arg
            # (ptr, len) + a caller-allocated 20-byte return area
            # for tag + Ok string (ptr, len) or Err io-error
            # (m_ptr, m_len, c_ptr, c_len). Materialiser rebuilds
            # a Capa Result<String, IoError>. Net.get path.
            return (["i32", "i32", "i32"], "")
        if "func() -> result<string, io-error>" in wit:
            # Stdio.read_line: no string arg, just the ret area.
            # Same 20-byte indirect-return shape as Fs.read.
            return (["i32"], "")
        if "func(handle: u32, path: string, content: string) -> result<_, io-error>" in wit:
            # Slice 25.2: Fs.write - handle + path + content +
            # ret_area = 6 i32s.
            return (["i32", "i32", "i32", "i32", "i32", "i32"], "")
        if "func(path: string, content: string) -> result<_, io-error>" in wit:
            # Canonical ABI indirect return: path + content +
            # 20-byte ret area for the result. Same layout as
            # Fs.read's Err branch; Ok carries unit (no flat
            # fields).
            return (["i32", "i32", "i32", "i32", "i32"], "")
        if "func(path: string, sql: string) -> result<_, io-error>" in wit:
            # Db.exec: same two-string-arg shape as Fs.write with a
            # Result<Unit, IoError> return. Separate pattern entry
            # because the WIT arg names are (path, sql) rather than
            # (path, content); the wire signature is identical.
            return (["i32", "i32", "i32", "i32", "i32"], "")
        if "func(url: string, body: string) -> result<string, io-error>" in wit:
            # Net.post: url (ptr, len) + body (ptr, len) + 20-byte
            # ret area for Result<String, IoError>. Same Ok arm
            # shape as Net.get (ptr, len for the response body)
            # plus the Err io-error 4-i32 fallback. The host's
            # write into the ret area is independent of the body
            # arg (which is read once and consumed by urlopen).
            return (["i32", "i32", "i32", "i32", "i32"], "")
        if "func(path: string, sql: string) -> result<string, io-error>" in wit:
            # Db.query: same shape as Net.post but the WIT arg
            # names are (path, sql) so the pattern match needs
            # its own entry. Returns the rows as a JSON-encoded
            # string in the Ok arm.
            return (["i32", "i32", "i32", "i32", "i32"], "")
        if "func(cmd: string, args-json: string) -> result<string, io-error>" in wit:
            # Proc.exec: same two-String-arg shape as Db.query /
            # Net.post. The WIT arg names are (cmd, args-json)
            # (kebab-case per WIT identifier rules) so the
            # pattern match needs its own entry; the wire
            # signature is identical.
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
        if "func(handle: u32, prefix: string) -> u32" in wit:
            # Slice 25.2 (2026-05-30): Fs.restrict_to takes the
            # parent handle + the prefix and returns a fresh
            # child handle bound to a narrower restriction. The
            # guest threads the new handle as the receiver of
            # subsequent Fs calls in this branch of the program;
            # passing the cap across a function boundary preserves
            # the restriction (the bug fixed by this slice).
            return (["i32", "i32", "i32"], "i32")
        if (("func(prefix: string)" in wit
                or "func(host: string)" in wit)
                and "->" not in wit):
            # Net.restrict_to / Db.restrict_to / Proc.restrict_to: a
            # string-arg, no-result no-op at the Wasm level. The
            # capability discipline is enforced by the analyzer; at
            # runtime the import is shared. ``prefix:`` is the Db /
            # Proc arg name; ``host:`` is Net's. All lower
            # identically. Fs.restrict_to graduated to the handle-
            # returning shape above in slice 25.2.
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
        # Slice 25.2 (2026-05-30): Fs.restrict_to is no longer a no-op
        # at the Wasm level. It crosses the host bridge with the
        # receiver's handle + the prefix string and returns a fresh
        # i32 handle bound to a narrower restriction. The dst local
        # holds the new handle and is threaded as the receiver of
        # downstream Fs calls (including across function boundaries -
        # this is what closes audit slice 25 F1).
        if cap == "Fs" and method == "restrict_to":
            self._emit_fs_restrict_to(instr)
            return
        # Attenuator methods (``restrict_to`` / ``restrict_to_keys``
        # / ``restrict_to_after``) are no-ops at the Wasm level for
        # the remaining built-in caps: their values carry no runtime
        # representation, so the inline emit-time check (audit C2)
        # at the privileged op is what enforces discipline.
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
        if method == "allows" and cap in ("Fs", "Env", "Db", "Proc"):
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
        # Slice 25.2 (2026-05-30): Fs no longer needs the inline
        # emit-time attenuation check. The host bridge now enforces
        # the receiver cap's restriction via the handle table, which
        # is sound across function boundaries (the bug audit slice 25
        # F1 documented). The handle is pushed as the FIRST arg by
        # ``_emit_fs_method_with_handle`` below. The inline machinery
        # stays intact for Net / Db / Proc / Env / Clock (they remain
        # on the old erased-cap path until their own rollout slices).
        if cap == "Fs" and indirect is not None:
            self._emit_fs_method_with_handle(instr, method, indirect)
            return
        if cap == "Fs" and method in ("exists", "is_dir"):
            self._emit_fs_bool_query_with_handle(instr, method)
            return
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
        if (attenuations and priv_op
                and cap == "Fs" and method in ("exists", "is_dir")):
            # Bool-returning queries. The Python runtime fails-
            # closed-as-absent: a denied path reports False so the
            # cap doesn't leak the existence of paths outside its
            # allowed prefixes. Mirror that on Wasm by wrapping
            # the host call with an inline allows check; on deny
            # we push 0 (Bool false) without ever touching the
            # host. Pre-fix the host bridge was called
            # unconditionally; a Fs cap scoped to "/tmp/" could
            # ``fs.exists("/etc/shadow")`` on Wasm and the host
            # answered honestly, leaking out-of-prefix existence
            # information.
            self._emit_bool_query_with_attenuation_check(
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
        elif cap == "Net" and method == "get":
            self._push_string_arg(instr.args[0])
            self._write("local.set $_atten_path_len")
            self._write("local.set $_atten_path_ptr")
        elif cap == "Net" and method == "post":
            # Net.post(url, body): two String args. Stash both
            # before the predicate check so the host-call branch
            # can re-push them without re-evaluating either IR
            # Value (which would matter if the body is a function
            # call with side effects).
            self._push_string_arg(instr.args[0])
            self._write("local.set $_atten_path_len")
            self._write("local.set $_atten_path_ptr")
            self._push_string_arg(instr.args[1])
            self._write("local.set $_atten_content_len")
            self._write("local.set $_atten_content_ptr")
        elif cap == "Db" and method in ("exec", "query"):
            # Db.exec(path, sql) / Db.query(path, sql): same
            # two-String-arg shape as Net.post + Fs.write. The
            # attenuation check fires on the path arg (prefix
            # match); sql is opaque to the cap and is passed
            # through to the host bridge as-is.
            self._push_string_arg(instr.args[0])
            self._write("local.set $_atten_path_len")
            self._write("local.set $_atten_path_ptr")
            self._push_string_arg(instr.args[1])
            self._write("local.set $_atten_content_len")
            self._write("local.set $_atten_content_ptr")
        elif cap == "Proc" and method == "exec":
            # Proc.exec(cmd, args_json): same two-String-arg
            # shape as Db.exec. The attenuation check fires on
            # the cmd arg (basename + suffix-boundary match via
            # ``$proc_allows``); args_json is opaque to the cap
            # and is passed through to the host bridge as-is.
            # Stash-local names stay ``_atten_path_*`` /
            # ``_atten_content_*`` (the locals walker declares
            # them once when any two-String-arg attenuated op is
            # present in the function).
            self._push_string_arg(instr.args[0])
            self._write("local.set $_atten_path_len")
            self._write("local.set $_atten_path_ptr")
            self._push_string_arg(instr.args[1])
            self._write("local.set $_atten_content_len")
            self._write("local.set $_atten_content_ptr")
        elif cap == "Env" and method == "get":
            self._push_string_arg(instr.args[0])
            self._write("local.set $_atten_path_len")
            self._write("local.set $_atten_path_ptr")
        elif cap == "Fs" and method in ("mkdir", "list_dir"):
            # Single-string-arg Fs ops that mutate (mkdir) or
            # observe (list_dir). Same path-prefix attenuation as
            # Fs.read / write; the inline check fires on the
            # path arg.
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
        elif cap == "Net" and method == "get":
            self._write("local.get $_atten_path_ptr")
            self._write("local.get $_atten_path_len")
        elif cap == "Net" and method == "post":
            # Push url + body in the order the host's
            # ``net.post(url_ptr, url_len, body_ptr, body_len,
            # ret_area)`` signature expects.
            self._write("local.get $_atten_path_ptr")
            self._write("local.get $_atten_path_len")
            self._write("local.get $_atten_content_ptr")
            self._write("local.get $_atten_content_len")
        elif cap == "Db" and method in ("exec", "query"):
            # Push path + sql in the order the host's
            # ``db.{exec,query}(path_ptr, path_len, sql_ptr,
            # sql_len, ret_area)`` signature expects.
            self._write("local.get $_atten_path_ptr")
            self._write("local.get $_atten_path_len")
            self._write("local.get $_atten_content_ptr")
            self._write("local.get $_atten_content_len")
        elif cap == "Proc" and method == "exec":
            # Push cmd + args_json in the order the host's
            # ``proc.exec(cmd_ptr, cmd_len, args_ptr, args_len,
            # ret_area)`` signature expects.
            self._write("local.get $_atten_path_ptr")
            self._write("local.get $_atten_path_len")
            self._write("local.get $_atten_content_ptr")
            self._write("local.get $_atten_content_len")
        elif cap == "Env" and method == "get":
            self._write("local.get $_atten_path_ptr")
            self._write("local.get $_atten_path_len")
        elif cap == "Fs" and method in ("mkdir", "list_dir"):
            # Single-string-arg push, parallel to Fs.read.
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
            self._emit_path_prefix_check(prefix)
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
        if cap == "Db":
            # Db attenuation mirrors Fs: ``restrict_to(prefix)``
            # collapses to a path-prefix check on the path arg.
            # Same machinery, same scratch locals
            # (``$_atten_path_*``).
            if att_method != "restrict_to" or not args:
                raise WasmEmissionError(
                    f"unsupported Db attenuation: {att_method!r} "
                    f"with args {args!r}"
                )
            prefix = _unquote_attenuation_arg(args[0])
            self._emit_path_prefix_check(prefix)
            return
        if cap == "Proc":
            # Proc attenuation is a basename + suffix-boundary
            # check, not a path-prefix one. ``restrict_to("git")``
            # admits ``git`` and ``git-lfs`` but rejects
            # ``gitlab`` and ``/usr/bin/git`` is normalised to
            # ``git`` before the compare. The ``$proc_allows``
            # runtime helper does the walk at runtime so the
            # check works for both literal and dynamic cmd args
            # (it reads from ``$_atten_path_*`` like the other
            # attenuation checks).
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

        The Python ``Fs.allows`` uses ``Path.is_relative_to``
        after ``os.path.realpath`` canonicalisation, which is
        strictly stronger (resolves ``..`` / symlinks). We can't
        realpath at emit time, but the component-boundary check
        closes the simple lexical bypass and matches Python's
        semantics for the common case of well-formed paths
        without traversal.

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

    def _emit_bool_query_with_attenuation_check(
        self, instr, cap: str, method: str, attenuations: list,
    ) -> None:
        """Wrap a Bool-returning Fs query (``exists`` / ``is_dir``)
        in an inline attenuation check. On pass we call the host
        and bind its i32 result to ``instr.dst``; on deny we push
        0 (Bool false) directly, never touching the host. This
        mirrors the Python runtime's fail-closed-as-absent rule
        (``Fs.allows()`` returns False, ``Fs.exists()`` returns
        False without leaking the existence of out-of-prefix
        paths).

        Uses the same ``$_atten_path_*`` + ``$_atten_ok`` scratch
        as the indirect-return path; the locals collector already
        declares them when any attenuated op is present."""
        # Stash the path arg.
        self._push_string_arg(instr.args[0])
        self._write("local.set $_atten_path_len")
        self._write("local.set $_atten_path_ptr")
        # Build the predicate: 1 = all attenuations passed, 0 = at
        # least one failed. Stash in $_atten_ok.
        self._write("i32.const 1")
        self._write("local.set $_atten_ok")
        for att in attenuations:
            self._emit_one_attenuation(cap, method, att)
        # if (ok) call host(path) else push 0 -> bind to dst.
        self._write("local.get $_atten_ok")
        self._write("if (result i32)")
        self._indent += 1
        self._write("local.get $_atten_path_ptr")
        self._write("local.get $_atten_path_len")
        self._write(f"call ${cap}_{method}")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("i32.const 0")
        self._indent -= 1
        self._write("end")
        if instr.dst is not None:
            self._write(f"local.set ${instr.dst}")

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
            # WIT-convention discriminant for ``none`` is 0 (see
            # the long comment in ``option_string`` materialisation
            # below). The materialiser XOR-flips on read, so writing
            # 0 here makes Env.get's attenuation-deny path produce
            # a Capa None record. Ptr / len at 4 / 8 stay zero.
            self._write("local.get $_ret_area")
            self._write("i32.const 0")
            self._write("i32.store offset=0")
            self._write("local.get $_ret_area")
            self._write("i32.const 0")
            self._write("i32.store offset=4")
            self._write("local.get $_ret_area")
            self._write("i32.const 0")
            self._write("i32.store offset=8")
            return
        if ret_kind == "result_list_string_io_error":
            # 20-byte ret area: tag i32 @ 0, then either the Ok
            # arm's flat (data_ptr, len) at @4 / @8 or the Err
            # arm's (m_ptr, m_len, c_ptr, c_len) at @4 / @8 / @12
            # / @16. The Err arm has the same shape as
            # ``result_string_io_error`` (4 i32s for io-error);
            # the only difference is what the Ok arm carries, and
            # we're writing an Err, so the layout matches.
            self._write("local.get $_ret_area")
            self._write("i32.const 1")
            self._write("i32.store offset=0")
            self._write("local.get $_ret_area")
            self._write(f"i32.const {m_offset}")
            self._write("i32.store offset=4")
            self._write("local.get $_ret_area")
            self._write(f"i32.const {m_length}")
            self._write("i32.store offset=8")
            self._write("local.get $_ret_area")
            self._write("i32.const 0")
            self._write("i32.store offset=12")
            self._write("local.get $_ret_area")
            self._write("i32.const 0")
            self._write("i32.store offset=16")
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
                prefix = _unquote_attenuation_arg(args[0])
                sep = prefix if prefix.endswith("/") else prefix + "/"
                if not (literal == prefix or literal.startswith(sep)):
                    result = False
                    break
        elif cap == "Proc":
            # AND over each restrict_to(prefix): the literal cmd
            # must satisfy every prefix in the chain at a basename
            # + suffix boundary (basename == prefix OR
            # basename.startswith(prefix + '-')). Mirrors the
            # Python runtime's ``Proc.allows`` rule and the
            # ``$proc_allows`` runtime helper used on the
            # dynamic-arg path. ``os.path.basename`` is computed
            # at emit time so ``/usr/bin/git`` gates against
            # ``restrict_to("git")``.
            import os as _os
            base = _os.path.basename(literal)
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
                if not (base == prefix
                        or base.startswith(prefix + "-")):
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
        # Stash the arg in the same scratch locals the privileged-
        # op path uses (declared by the locals walker whenever any
        # attenuation check is present in the function -- which is
        # always true here because we have attenuations).
        self._push_string_arg(arg)
        self._write("local.set $_atten_path_len")
        self._write("local.set $_atten_path_ptr")
        # ok = 1; AND each per-attenuation check into it. Same
        # accumulator shape as the privileged-op
        # _emit_indirect_with_attenuation_check.
        self._write("i32.const 1")
        self._write("local.set $_atten_ok")
        # Method-name parameter for _emit_one_attenuation is just
        # used in error messages; pass through the source method.
        for att in attenuations:
            self._emit_one_attenuation(cap, instr.method, att)
        self._write("local.get $_atten_ok")
        if instr.dst is not None:
            self._write(f"local.set ${instr.dst}")

    def _emit_clock_with_attenuation_check(
        self, instr: MethodCall, cap: str, method: str,
        attenuations: list,
    ) -> None:
        """``Clock.now_secs`` / ``Clock.now_monotonic`` / ``Clock.sleep``
        with a ``restrict_to_after(t)`` chain. The Python runtime
        treats the ``now_*`` family as pure queries (anyone with a
        wall clock can read it), so no check fires there. The
        Wasm backend preserves that semantic for ``now_*``: emit
        the host call as normal but leave a CAPA-RUNTIME-LIMITATION
        comment so the analyzer contract stays visible.

        ``Clock.sleep`` IS gated in the Python runtime: on a denied
        clock (max of the restrict_to_after deadlines is still in
        the future) the call becomes a silent no-op (matches the
        fail-closed information-hiding pattern of ``Fs.exists`` /
        ``Env.get``). The Wasm side mirrors this with an inline
        ``clock.now_secs() >= threshold`` check around the host
        ``$Clock_sleep`` call; if the check fails we drop the
        ``secs`` arg and skip the call. The check uses
        ``clock.now_secs()`` as the time source rather than
        ``clock.now_monotonic()`` because ``restrict_to_after``'s
        threshold is a wall-clock value (Capa source-level
        ``time.time()`` semantics), matching the Python runtime
        exactly.

        Multiple restrict_to_after thresholds combine via
        ``max``: a chain
        ``c.restrict_to_after(10.0).restrict_to_after(20.0)``
        carries the later deadline, so the inline check compares
        ``now_secs()`` against the max of every literal threshold
        in the chain.
        """
        if method != "sleep":
            # now_secs / now_monotonic: pure query, no check.
            self._write(
                ";; CAPA-RUNTIME-LIMITATION: Clock.restrict_to_after "
                "is a static-discipline attenuator; now_* are pure "
                "queries, no Wasm-side check fires."
            )
            for arg in instr.args:
                self._push_value(arg)
            self._write(f"call ${cap}_{method}")
            _params, result_ty = self._cap_method_wasm_sig(cap, method)
            if result_ty and instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return

        # Clock.sleep with restrict_to_after(threshold). Compute
        # max(threshold) across the attenuation chain at emit time
        # and emit the inline ``if (now_secs() >= threshold) sleep
        # (secs)`` guard.
        thresholds: list[float] = []
        for att in attenuations:
            if att.get("method") != "restrict_to_after":
                raise WasmEmissionError(
                    f"unsupported Clock attenuation: "
                    f"{att.get('method')!r}"
                )
            args = att.get("args", [])
            if not args:
                raise WasmEmissionError(
                    "Clock.restrict_to_after attenuation with no arg"
                )
            try:
                thresholds.append(float(args[0]))
            except (TypeError, ValueError) as e:
                raise WasmEmissionError(
                    f"Clock.restrict_to_after on Wasm requires a "
                    f"literal Float threshold; got {args[0]!r}"
                ) from e
        deadline = max(thresholds)
        # Stash the secs arg so we don't re-evaluate inside the if.
        # secs is f64; reuse the closure-result scratch slot which
        # is already declared by the locals walker whenever any
        # Float-returning method appears (Clock.now_secs counts).
        # If neither now_secs nor the HOF path declared it, the
        # locals walker's has_clock_sleep_gate flag adds it; see
        # _locals.py.
        if instr.args:
            self._push_value(instr.args[0])
            self._write("local.set $_clock_sleep_secs")
        # call $Clock_now_secs -> f64; push deadline -> f64; ge?
        self._write("call $Clock_now_secs")
        self._write(f"f64.const {deadline!r}")
        self._write("f64.ge")
        self._write("if")
        self._indent += 1
        self._write("local.get $_clock_sleep_secs")
        self._write("call $Clock_sleep")
        self._indent -= 1
        self._write("end")

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
