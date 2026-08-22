"""CIR -> WIT (WebAssembly Interface Type) generator (Phase 6B).

A Capa program that uses built-in capabilities (``Stdio``, ``Fs``,
``Env``, ``Clock``, ``Net``) needs a corresponding WIT spec the host
implements. This generator walks a lowered CIR module, discovers
which capability methods are reachable, and emits a single ``.wit``
document declaring an interface per capability plus a ``world`` that
imports them.

The WIT shape mirrors what the runtime offers, normalised to WIT
syntax (Capa's ``Result<T, E>`` -> WIT ``result<t, e>``; Capa's
``Option<T>`` -> WIT ``option<t>``; Capa's ``Unit`` -> no return).
Phase 6B emits only the method signatures that the Wasm backend
also lowers (currently Stdio.print / println / eprintln); the table
of supported methods grows alongside the emitter's coverage.

Why generate WIT per-program rather than ship one canonical
capa-stdlib.wit?
- The WIT spec only needs to cover what the program actually uses;
  unused methods would force the host to provide stubs they never
  call.
- The set of capabilities a program touches IS the manifest the
  Capa story is built around. Generating the WIT from the same
  source the manifest emitter walks keeps the two views in lockstep.
"""

from __future__ import annotations

from typing import List, Optional

from ._cap_binding import main_handle_cap_types, wit_cap_slot_name
from ._cap_discovery import classify_cap_method
from ._nodes import Module, Call
from ._walk import walk_module


# Per-capability method table: maps (capability_name, method_name)
# to a WIT signature string in the form
# "name: func(args) -> return". This list is the contract the Wasm
# emitter and the host bridge BOTH follow; adding a method here
# without backing both sides will silently fail at instantiation
# time, so the table is the single source of truth.
_WIT_SIGNATURES: dict[tuple[str, str], str] = {
    # Stdio: write-only text I/O. Phase 6B scope.
    ("Stdio", "print"):    "print: func(msg: string)",
    ("Stdio", "println"):  "println: func(msg: string)",
    ("Stdio", "eprintln"): "eprintln: func(msg: string)",
    # Stdio.read_line: reads a line from stdin. Same canonical-ABI
    # result<string, io-error> shape as Fs.read; reuses the
    # ``result_string_io_error`` materialiser. The host strips the
    # trailing newline (mirrors the Python runtime's
    # ``sys.stdin.readline().rstrip("\n")``) and returns Err on
    # empty input (EOF) or invalid UTF-8.
    ("Stdio", "read_line"): "read-line: func() -> result<string, io-error>",

    # Clock: monotonic + wall time. Phase 7A scope (Float type).
    # WIT identifiers are kebab-case; Capa keys keep snake_case so
    # the rest of the toolchain (lowerer, host bridge) reads as
    # source-level names. The Wasm import emitter rewrites the
    # method-name component to kebab-case to match this WIT.
    #
    # Slice 25.6 (2026-05-30): every Clock op takes ``handle: u32``
    # as the FIRST param so the host can look up the receiver cap's
    # ``restrict_to_after`` deadline in the per-instance handle table
    # and enforce ``clock.allows()`` before the syscall. Closes the
    # cross-function attenuation bug (audit slice 25 F1) for Clock:
    # a Clock narrowed via ``restrict_to_after(t)`` passed across a
    # function boundary now keeps its deadline. ``restrict-to-after``
    # returns a fresh ``u32`` handle bound to the later of
    # max(parent_threshold, new_threshold).
    ("Clock", "now_secs"):      "now-secs: func(handle: u32) -> f64",
    ("Clock", "now_monotonic"): "now-monotonic: func(handle: u32) -> f64",
    # Clock.sleep: handle + f64 arg, no return. The Python runtime
    # treats a denied Clock (``restrict_to_after`` threshold in the
    # future) as a silent no-op; the host bridge mirrors that.
    ("Clock", "sleep"):         "sleep: func(handle: u32, secs: f64)",
    # Clock.allows queries the cap's ``restrict_to_after`` deadline
    # against the current host clock. The host looks up the cap via
    # the handle and consults its real deadline (slice 25.6); the
    # pre-slice host hard-coded ``return 1`` (unrestricted) regardless
    # of attenuation, so a deny on a narrowed Clock crossing a
    # function boundary was lost.
    ("Clock", "allows"):        "allows: func(handle: u32) -> bool",
    # Clock.restrict_to_after: returns a fresh handle bound to a
    # later (max-merged) deadline. Mirrors fs.restrict-to / net.
    # restrict-to; the guest threads the new handle as the receiver
    # of subsequent Clock calls in this branch of the program.
    ("Clock", "restrict_to_after"):
        "restrict-to-after: func(handle: u32, t: f64) -> u32",

    # Env: process environment + argv. Phase 7B scope (Option<String>).
    #
    # Slice 25.5 (2026-05-30): every Env op takes ``handle: u32`` as
    # the FIRST param so the host looks up the receiver cap and
    # enforces ``env.allows(name)`` before reading ``os.environ``.
    # Closes the cross-function attenuation bug (audit slice 25 F1)
    # for Env: a restrict_to_keys-narrowed Env passed across a
    # function boundary now keeps its allow-list. The host bridge
    # returns ``none`` for a denied key (same fail-closed convention
    # the Python runtime uses).
    ("Env", "get"):  "get: func(handle: u32, name: string) -> option<string>",
    # Env.args returns a list<string> of program arguments. The
    # host constructs the list in linear memory via $alloc. The
    # handle is taken for symmetry with the other Env ops; argv
    # itself is not restriction-bearing (it reads ``sys.argv``).
    ("Env", "args"): "args: func(handle: u32) -> list<string>",
    # Env.restrict_to_keys: returns a fresh handle bound to an
    # allow-list (intersected with the parent). The wire layout
    # for ``list<string>`` is the same flat two-i32 (data_ptr, len)
    # the args() return uses; the host reads N packed
    # (str_ptr, str_len) i32 pairs out of the data buffer.
    ("Env", "restrict_to_keys"):
        "restrict-to-keys: func(handle: u32, keys: list<string>) -> u32",
    # Env.allows: the authoritative guest-side attenuation query
    # (GAP-2b, 2026-06-21). The host looks up the receiver Env cap
    # and returns ``env.allows(key)`` - the exact hardened method the
    # privileged ops already consult. Pre-route the query was inlined
    # guest-side and diverged silently on a dynamic restrict-to-keys
    # list (the lexical key-list reconstruction returned []).
    ("Env", "allows"): "allows: func(handle: u32, key: string) -> bool",

    # Fs: filesystem reads + writes. Phase 7C scope (Result<T, IoError>).
    # IoError is a Capa-side record with two String fields (message,
    # cause). The host constructs it via $alloc on error.
    #
    # Slice 25.2 (2026-05-30): every Fs op takes ``handle: u32`` as
    # the FIRST param so the host can look up the receiver cap's
    # restriction in the per-instance handle table and enforce it
    # before the syscall. Closes the cross-function attenuation bug
    # (audit slice 25 F1): a restricted Fs handed off to another
    # function on Wasm previously lost its restriction because the
    # emitter inlined the prefix check at the literal call site.
    # ``restrict-to`` now returns a fresh ``u32`` handle bound to a
    # narrower restriction (intersection with the parent).
    ("Fs", "read"):        "read: func(handle: u32, path: string) -> result<string, io-error>",
    ("Fs", "write"):       "write: func(handle: u32, path: string, content: string) -> result<_, io-error>",
    # Fs.exists / Fs.is_dir: queries returning bool. Mirror Python's
    # fail-closed-as-absent convention: a denied path reports false
    # so the cap doesn't leak existence outside its allowed
    # prefixes (now enforced by the host handle-table lookup).
    ("Fs", "exists"):      "exists: func(handle: u32, path: string) -> bool",
    ("Fs", "is_dir"):      "is-dir: func(handle: u32, path: string) -> bool",
    # Fs.mkdir: same canonical-ABI shape as Fs.write Ok-Unit
    # branch. Host uses ``os.makedirs(path, exist_ok=True)`` to
    # match the Python runtime's idempotent behaviour.
    ("Fs", "mkdir"):       "mkdir: func(handle: u32, path: string) -> result<_, io-error>",
    # Fs.list_dir: new canonical-ABI shape with a
    # ``list<string>`` Ok arm. Host returns sorted entry basenames
    # to match the Python runtime's deterministic ordering.
    ("Fs", "list_dir"):    "list-dir: func(handle: u32, path: string) -> result<list<string>, io-error>",
    # ``restrict-to`` returns a fresh handle (slice 25.2). The
    # host walks the parent restriction + the prefix to allocate
    # a new entry in its handle table; the guest threads the new
    # handle as the receiver of every subsequent Fs call from this
    # branch of the program.
    ("Fs", "restrict_to"): "restrict-to: func(handle: u32, prefix: string) -> u32",
    # Fs.allows: authoritative guest-side query (GAP-2b, 2026-06-21).
    # The host looks up the receiver Fs cap and returns
    # ``fs.allows(path)`` - the same realpath-canonicalising method
    # the privileged ops enforce. Pre-route the query was a guest-side
    # LEXICAL approximation (``_emit_path_prefix_check``) that could
    # not realpath and so diverged from the host enforcement on a
    # dynamic ``..`` / symlink path; routing it through the host makes
    # query == enforcement == Python.
    ("Fs", "allows"): "allows: func(handle: u32, path: string) -> bool",

    # Random: entropy source only. The actual SplitMix64 PRNG runs
    # guest-side (see ``capa.ir._emit_wasm._random``); the only thing
    # the host provides is a 64-bit seed when the program constructs
    # an unseeded ``Random()``. ``with_seed`` / ``int_range`` /
    # ``float_unit`` all stay in linear memory, so seeded sequences
    # are byte-identical with the Python backend.
    ("Random", "system_seed"): "system-seed: func() -> u64",

    # Net: HTTP GET / POST against a URL. Same canonical-ABI shape
    # as Fs.read (result<string, io-error>): a 20-byte caller-
    # allocated return area for tag + Ok string (ptr, len) or Err
    # io-error (m_ptr, m_len, c_ptr, c_len). The host enforces the
    # receiver cap's restriction via the per-instance handle table
    # then delegates to ``capa.runtime.Net.{get,post}`` so the
    # ``urlparse(url).hostname`` + ``allows(host)`` check runs in
    # one place.
    #
    # Slice 25.3 (2026-05-30): every Net op takes ``handle: u32`` as
    # the FIRST param so the host looks up the receiver cap in the
    # handle table. Closes the cross-function attenuation bug (audit
    # slice 25 F1) AND the URL substring-match bug (audit slice 25
    # F2): the pre-fix inline check was ``$str_contains(url, host)``,
    # which accepted a URL whose hostname is ``attacker.invalid`` but
    # whose path contains ``api.example.com``. ``restrict-to`` now
    # returns a fresh ``u32`` handle bound to a narrower host set
    # (intersection with the parent).
    ("Net", "get"): "get: func(handle: u32, url: string) -> result<string, io-error>",
    ("Net", "post"): "post: func(handle: u32, url: string, body: string) -> result<string, io-error>",
    # ``restrict-to`` returns a fresh handle (slice 25.3). The host
    # walks the parent restriction + the host and allocates a new
    # entry in its handle table; the guest threads the new handle
    # as the receiver of every subsequent Net call in this branch
    # of the program.
    ("Net", "restrict_to"): "restrict-to: func(handle: u32, host: string) -> u32",
    # Net.allows: authoritative guest-side query (GAP-2b,
    # 2026-06-21). The host looks up the receiver Net cap and
    # returns ``net.allows(host)`` (exact host-set membership). Pre-
    # route the query inlined ``$str_eq`` over the chain, which
    # rejected any dynamic (non-literal) host with a WasmEmissionError.
    ("Net", "allows"): "allows: func(handle: u32, host: string) -> bool",

    # Db: SQLite-backed key-value + tabular store (slice 11,
    # 2026-05). ``exec`` runs DDL / DML and returns
    # ``result<_, io-error>`` (same shape as Fs.write); ``query``
    # runs a SELECT and returns the rows as a JSON-encoded
    # ``[[col1, col2, ...], ...]`` string with the same
    # ``result<string, io-error>`` shape as Fs.read. Both methods
    # take the sqlite file path as the first arg + the SQL as
    # the second, mirroring Net.post's two-string layout. The
    # host opens a fresh ``sqlite3.connect`` per call; the cap is
    # stateless from the program's POV. Attenuation
    # (``Db.restrict_to(prefix)``) is path-prefix matched
    # identically to Fs.
    #
    # Slice 25.4 (2026-05-30): every Db op takes ``handle: u32`` as
    # the FIRST param so the host looks up the receiver cap and
    # enforces ``db.allows(path)`` before opening the SQLite
    # connection. Closes the cross-function attenuation bug (audit
    # slice 25 F1) for Db. ``restrict-to`` returns a fresh ``u32``
    # handle bound to a narrower prefix set (intersection with the
    # parent).
    ("Db", "exec"):
        "exec: func(handle: u32, path: string, sql: string) -> result<_, io-error>",
    ("Db", "query"):
        "query: func(handle: u32, path: string, sql: string) -> result<string, io-error>",
    ("Db", "restrict_to"):
        "restrict-to: func(handle: u32, prefix: string) -> u32",
    # Db.allows: authoritative guest-side query (GAP-2b, 2026-06-21).
    # Same realpath-backed prefix containment as Fs.allows; the host
    # returns ``db.allows(path)``.
    ("Db", "allows"): "allows: func(handle: u32, path: string) -> bool",

    # Proc: sandboxed subprocess execution (slice 15, 2026-05).
    # ``exec`` takes the command path + a JSON-encoded argv tail
    # (``["status", "--short"]``-style) and returns the captured
    # stdout in the Ok arm. Reuses the existing
    # ``result<string, io-error>`` materialiser; no new canonical-
    # ABI shape needed. The host runs ``subprocess.run(argv,
    # capture_output=True, timeout=30, shell=False)``. Non-zero
    # exit, timeout, malformed argv JSON all surface as Err.
    #
    # Slice 25.4 (2026-05-30): every Proc op takes ``handle: u32``
    # as the FIRST param so the host looks up the receiver cap and
    # enforces ``proc.allows(cmd)`` before spawning the subprocess.
    # Closes the cross-function attenuation bug (audit slice 25 F1)
    # for Proc. ``restrict-to`` returns a fresh ``u32`` handle bound
    # to a narrower basename + suffix-boundary allow-list
    # (intersection with the parent).
    ("Proc", "exec"):
        "exec: func(handle: u32, cmd: string, args-json: string) -> result<string, io-error>",
    ("Proc", "restrict_to"):
        "restrict-to: func(handle: u32, prefix: string) -> u32",
    # Proc.allows: authoritative guest-side query (GAP-2b,
    # 2026-06-21). The host returns ``proc.allows(cmd)`` - the
    # identity-based basename + suffix-boundary rule. Pre-route the
    # query inlined ``$proc_allows`` and rejected a dynamic cmd.
    ("Proc", "allows"): "allows: func(handle: u32, cmd: string) -> bool",

    # ``parse_json`` / ``to_json`` used to live here as a synthetic
    # ``Json`` capability so the Wasm import machinery had something
    # to plumb. They now compile to plain ``call $__capa_parse_json``
    # / ``call $__capa_to_json`` against the bundled Capa-source
    # parser injected by ``capa.ir._builtin_json.inject_into``; no
    # host import is produced, so no WIT interface is needed either.
    # The Wasm-side discovery in ``capa.ir._emit_wasm._discovery``
    # already excludes Json; this table follows.
}


# Capability names recognised by the WIT generator. Methods not
# in ``_WIT_SIGNATURES`` raise ``UnsupportedCapability`` at WIT
# generation time; the Wasm emitter mirrors this so the contract
# stays in sync.
#
# This is ``BUILTIN_CAPS`` MINUS ``PYTHON_ONLY_CAPS`` (``Unsafe``,
# ``Serve``), and the omission is deliberate, not drift.
#
# WHAT ACTUALLY KEEPS THEM OUT (corrected 2026-07; the previous
# version of this comment described a mechanism that does not exist).
# It is NOT the Wasm emitter's discovery rejection: ``capa --wit`` is
# a standalone path that never runs the Wasm emitter at all. The two
# capabilities stay out of the emitted document for two DIFFERENT
# reasons, neither of which was what this comment used to claim:
#
# - ``Serve`` DOES land in ``used`` -- it has capability methods, so
#   ``collect_used_capabilities`` records every ``serve.listen(...)``
#   call. It is dropped later, by the ``cap not in
#   _KNOWN_CAPABILITIES`` guard in the interface loop of ``emit_wit``.
# - ``Unsafe`` never lands in ``used``, but because it is METHOD-LESS
#   (no entry in ``capa.builtins.METHODS``), so there is no cap-method
#   call for the collector to see. Its authority is exercised through
#   the free functions ``py_import`` / ``py_invoke``.
#
# Both of those are SILENT drops, which is why ``emit_wit`` now raises
# ``PythonOnlyCapabilityInWit`` up front rather than relying on them:
# a document that quietly omits a capability the program genuinely
# holds misdescribes the program. This set remains the backstop for
# the interface loop.
#
# Adding a Python-only cap here would be actively wrong -- the
# interface loop would then try to emit ``interface serve { ... }``
# and raise ``UnsupportedCapabilityMethod`` on the first method
# instead of skipping the cap. Kept as a literal (rather than
# ``BUILTIN_CAPS - PYTHON_ONLY_CAPS``) so a newly added capability is
# NOT silently assumed to have WIT signatures; the guard in
# ``TestCapabilityRegistry`` (tests/test_cap_handles.py) flags the
# omission when a new cap appears.
_KNOWN_CAPABILITIES = {"Stdio", "Clock", "Env", "Fs", "Random", "Net", "Db", "Proc"}


# Per-interface type declarations injected before the method
# signatures. Some capabilities reference Capa-side record types
# (``IoError``) that have no WIT primitive equivalent; we declare
# them inline so the WIT spec is self-contained and the Component
# Model linker can resolve every name.
_IO_ERROR_RECORD: list[str] = [
    "record io-error {",
    "  message: string,",
    "  cause: string,",
    "}",
]

_INTERFACE_TYPE_PRELUDE: dict[str, list[str]] = {
    "Fs": _IO_ERROR_RECORD,
    # Stdio.read_line returns result<string, io-error>; declare the
    # record locally so the interface stays self-contained (WIT
    # interfaces cannot cross-reference each other's type
    # declarations without an explicit ``use`` clause, which the
    # core-wasm pathway does not produce).
    "Stdio": _IO_ERROR_RECORD,
    # Net.get returns result<string, io-error>; same self-contained
    # rationale as Fs / Stdio.
    "Net": _IO_ERROR_RECORD,
    # Db.exec / Db.query both reference io-error; same self-
    # contained rationale.
    "Db":  _IO_ERROR_RECORD,
    # Proc.exec returns result<string, io-error>; same self-
    # contained rationale.
    "Proc": _IO_ERROR_RECORD,
}


# Some capability methods reference ``io-error`` only conditionally
# (Stdio.read_line is the only Stdio method that does). When the
# program uses Stdio but never calls read_line, the prelude would
# inject a dead record declaration; the Wasm host doesn't care, but
# the WIT spec is less noisy if we elide it. ``_methods_needing_io_error``
# is consulted by ``emit_wit`` to decide whether to inject the
# prelude.
_METHODS_NEEDING_IO_ERROR: dict[str, frozenset[str]] = {
    "Stdio": frozenset({"read_line"}),
    # Net.restrict_to is an attenuator (no io-error); Net.get /
    # Net.post are the privileged ops that reference the record.
    # A program that only calls restrict_to (vanishingly rare; the
    # analyzer would flag the cap as unused) skips the prelude.
    "Net": frozenset({"get", "post"}),
    # Db.exec / Db.query both return io-error-bearing results;
    # restrict_to is the attenuator (no io-error).
    "Db":  frozenset({"exec", "query"}),
    # Proc.exec returns result<string, io-error>; restrict_to
    # is the attenuator (no io-error).
    "Proc": frozenset({"exec"}),
}


# Methods that the source program may name but that produce no WIT
# entry (and no host import) because the implementation lives entirely
# guest-side. ``Random.with_seed`` / ``int_range`` / ``float_unit``
# run on a SplitMix64 PRNG in linear memory; only ``system_seed``
# crosses the host boundary. Anything in here is silently skipped by
# ``emit_wit`` and by the Wasm-side import emission so the WIT and
# the core-wasm imports stay in lockstep.
_GUEST_ONLY_METHODS: dict[str, frozenset[str]] = {
    "Random": frozenset({"with_seed", "int_range", "float_unit"}),
    # GAP-2b (2026-06-21): ``Fs.allows`` / ``Env.allows`` /
    # ``Db.allows`` / ``Net.allows`` / ``Proc.allows`` used to be
    # inlined at emit time (D4 inline-attenuation Option B). That
    # inline path could not handle a dynamic (non-literal) attenuation
    # prefix - Fs / Db / Net / Proc raised a WasmEmissionError and Env
    # diverged silently (returned ``no``). They now route through a
    # ``<cap>-allows(handle, arg) -> bool`` host function that returns
    # the receiver cap's authoritative ``allows(arg)`` (the same
    # hardened method the privileged ops enforce), so they carry a
    # real WIT signature and are no longer guest-only. ``Clock.allows``
    # was already host-side (it takes no string arg and queries the
    # live wall clock against a ``restrict_to_after`` deadline).
}


# Capa scalar return types that ``main`` may declare, mapped to the
# WIT result type the Component Model world must advertise so the
# world signature matches the core module's ``(export "main")``
# result. The core module returns (see ``_emit_wasm._emit_function`` +
# ``_wasm_type``): ``Int`` -> ``i64``, ``Float`` -> ``f64``,
# ``Bool`` -> ``i32``. ``wasm-tools component new`` lifts each of those
# single-value core results into the matching WIT type below (``s64``
# because Capa ``Int`` is signed; ``f64`` direct; ``bool`` from the
# i32). ``Unit`` / absent maps to no result clause (the historical
# shape). Everything else -- ``String`` and the composite types
# (``Struct`` / ``Sum`` / ``List`` / ``Map`` / tuples) -- is rejected
# up front by ``main_result_clause`` with a clear compile-time error
# rather than the cryptic wasm-tools mismatch. See that function's
# docstring for why ``String`` cannot be supported without a core-side
# indirect-return rewrite.
_MAIN_RESULT_WIT: dict[str, str] = {
    "Int":   "s64",
    "Float": "f64",
    "Bool":  "bool",
}


class MainReturnTypeUnsupported(Exception):
    """Raised when ``main`` declares a return type the WASM component
    backend cannot lift into the WIT world export. The single-core-
    value scalars (``Int`` / ``Float`` / ``Bool``) and ``Unit`` are
    supported; ``String`` and composite returns (``Struct`` / ``Sum``
    / ``List`` / ``Map`` / tuples) are not.

    Why ``String`` is excluded: the core module returns a String as a
    flattened multi-value ``(i32 i32)`` (ptr, len). The Component
    Model canonical ABI flattens a ``string`` result past its
    single-flat-value budget, so it demands the core function return
    the pointer to an 8-byte return area indirectly (``[] -> [i32]``)
    -- a shape the current core ``main`` does not emit. There is no
    WIT result type that lifts from a flat ``(i32 i32)`` return, so
    supporting a String-returning ``main`` would require rewriting the
    core ``main`` export to the indirect-return convention (or to drop
    the discarded String and export ``func()``). Since ``main``'s
    return value is discarded at every backend (exit code is always 0),
    that rewrite buys nothing observable; we reject it with a clear
    message instead. Composite returns are rejected for the same
    "lifting a bare heap pointer into a structured CM value is not
    implemented" reason.

    Surfacing this as a Capa compile-time error means the user sees an
    actionable message instead of the raw ``wasm-tools component new``
    type-mismatch."""

    def __init__(self, return_type: str):
        super().__init__(
            f"main returning {return_type!r} is not supported by the "
            f"WASM component backend; return a scalar "
            f"(Int / Float / Bool) or Unit"
        )
        self.return_type = return_type


# Capa scalar-leaf type -> its WIT primitive. ``Int`` is signed
# (``s64``); ``String`` is the WIT ``string``.
_LEAF_WIT: dict[str, str] = {
    "Int": "s64",
    "Bool": "bool",
    "Float": "f64",
    "String": "string",
}


def capa_type_to_wit(ty: str) -> str:
    """Map a crossing Capa type STRING to its WIT type text so a typed
    foreign component's parent import and the external child export agree
    on the canonical ABI (feature #4 F2c): a struct -> ``record`` (named,
    kebab-cased), ``List<T>`` -> ``list<t>``, a tuple -> ``tuple<...>``,
    ``Option<T>`` -> ``option<t>``, ``Result<T, E>`` -> ``result<t, e>``.

    The core ``--wasm`` foreign path does not itself consume this (the
    parent import is a raw host closure whose flattened signature the host
    and guest agree on directly); it is the canonical-ABI contract a child
    fixture's WIT must match and the seam a future ``--component`` foreign
    path would generate the parent import from. A NESTED aggregate maps
    structurally too (feature #4 F2c-2): the recursion descends into
    List / Option / Result / tuple type ARGUMENTS (``List<Point>`` ->
    ``list<point>``, ``List<List<Int>>`` -> ``list<list<s64>>``,
    ``Option<List<Point>>`` -> ``option<list<point>>``). A bare user-type
    name emits a NAME reference (a WIT ``record`` / ``variant`` name), NOT
    its resolved fields, so the mapping is total AND cannot loop on a
    self-referential type (``type Tree { kids: List<Tree> }`` maps
    ``Tree`` -> ``tree`` without descending). The recursive-type
    STOP-report lives in the schema build
    (``capa.foreign_schema.build_aggregate_schema``), which DOES resolve
    fields and so must guard the cycle."""
    ty = ty.strip()
    if ty in _LEAF_WIT:
        return _LEAF_WIT[ty]
    # Tuple: ``(A, B, ...)`` -- a parenthesised, comma-separated list.
    if ty.startswith("(") and ty.endswith(")"):
        inner = ty[1:-1].strip()
        if not inner:
            return "tuple<>"
        parts = _split_top_level_commas(inner)
        return "tuple<" + ", ".join(capa_type_to_wit(p) for p in parts) + ">"
    head = ty.split("<", 1)[0]
    if "<" in ty and ty.endswith(">"):
        inner = ty[len(head) + 1:-1].strip()
        parts = _split_top_level_commas(inner)
        if head == "List":
            return f"list<{capa_type_to_wit(parts[0])}>"
        if head == "Option":
            return f"option<{capa_type_to_wit(parts[0])}>"
        if head == "Result":
            return (
                f"result<{capa_type_to_wit(parts[0])}, "
                f"{capa_type_to_wit(parts[1])}>"
            )
    # A bare user type name is a WIT record; WIT identifiers are lowercase
    # kebab-case, so lowercase the name and turn underscores into dashes.
    return head.replace("_", "-").lower()


def _split_top_level_commas(s: str) -> list[str]:
    """Split ``s`` on top-level commas (not nested inside ``<...>`` or
    ``(...)``)."""
    parts: list[str] = []
    depth = 0
    cur = []
    for ch in s:
        if ch in "<(":
            depth += 1
        elif ch in ">)":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur).strip())
    return parts


def _is_unit_return(rty: str) -> bool:
    """True when ``rty`` (``main``'s lowered ``return_type`` string) is
    a Unit return, which the component backend maps to NO result
    clause.

    Three shapes reach here (see the lowerer): the empty string (no
    annotation), the literal ``"Unit"`` (both ``fun main`` with no
    annotation and ``fun main -> Unit`` lower to this), and the AST
    ``repr`` ``"UnitType(pos=...)"`` that an EXPLICIT ``fun main -> ()``
    lowers to. All three are Unit and must be treated as supported --
    an explicit ``-> ()`` main is a Unit main, not a composite, so the
    clean-error layer must never mis-reject it with an ugly AST repr in
    the message. (A ``-> ()`` main still fails LATER in the core
    emitter with "UnitType has no Wasm encoding"; that is a separate
    pre-existing limitation, out of scope here -- this layer only
    guarantees the return-type validation does not itself produce a
    repr-in-message rejection.)"""
    return rty == "" or rty == "Unit" or rty.startswith("UnitType(")


def main_result_clause(module: Module) -> str:
    """Return the WIT result clause for the world's ``export main``,
    derived from ``main``'s source-level return type so the world
    signature matches the core module's ``main`` result.

    Returns ``""`` (no result clause) when ``main`` is absent, returns
    a Unit-ish type (no annotation / ``Unit`` / explicit ``()``). Returns
    ``" -> <wit-ty>"`` for a supported scalar (``Int`` / ``Float`` /
    ``Bool``). Raises ``MainReturnTypeUnsupported`` for a ``String`` or
    composite return type so the error is a clear Capa diagnostic
    rather than the cryptic wasm-tools core-vs-world mismatch.

    The returned string is ready to append directly after the
    ``func(...)`` of the export, e.g. ``export main: func(){clause};``.
    """
    for fn in module.functions:
        if fn.name != "main":
            continue
        rty = (fn.return_type or "").strip()
        if _is_unit_return(rty):
            return ""
        wit = _MAIN_RESULT_WIT.get(rty)
        if wit is None:
            raise MainReturnTypeUnsupported(rty)
        return f" -> {wit}"
    return ""


def validate_main_return_type(module: Module) -> None:
    """Raise ``MainReturnTypeUnsupported`` iff ``main``'s return type
    is one the WASM component backend cannot lift into its WIT world
    export (``String`` or any composite: ``Struct`` / ``Sum`` /
    ``List`` / ``Map`` / tuple / ``Option`` / ``Result`` / ``Char`` /
    ...). Scalars (``Int`` / ``Float`` / ``Bool``) and Unit-ish returns
    pass silently.

    This is the early gate the CLI runs on the ``--component`` path
    BEFORE ``compile_wasm``, so an unsupported ``main`` return surfaces
    as the clean, actionable Capa diagnostic instead of dying first in
    the core emitter with a cryptic wasm-tools dump (e.g. a
    Struct-returning ``main`` compiles a ``return_call $Struct`` the
    core module has no function for). The WIT generator applies the
    same policy via ``main_result_clause``; this entry point lets the
    CLI enforce it without lowering + emitting the whole WIT twice."""
    main_result_clause(module)


class UnsupportedCapabilityMethod(Exception):
    """Raised when a CIR ``MethodCall`` exercises a capability method
    that does not yet have a WIT signature in this generator. The
    Wasm emitter raises the same exception for the same call site,
    so a single failure surfaces a coverage gap in both layers."""

    def __init__(self, cap: str, method: str):
        super().__init__(
            f"capability method {cap}.{method!r} has no WIT signature "
            f"in Phase 6B; either widen capa.ir._emit_wit._WIT_SIGNATURES "
            f"or use a different method"
        )
        self.cap = cap
        self.method = method


class PythonOnlyCapabilityInWit(Exception):
    """Raised when WIT generation is asked to describe a program that
    holds a ``PYTHON_ONLY_CAPS`` capability (``Unsafe``, ``Serve``).

    ``capa --wit`` is a STANDALONE path: it does not run the Wasm
    emitter, so the discovery-time rejection never fires for it. Before
    this existed, ``--wit`` on such a program exited 0 and printed a
    document that silently omitted the capability -- and worse, whose
    ``world`` block declared ``export main: func()`` while the real
    ``main`` took the capability as a parameter. A document whose whole
    purpose is to describe the program's interface to a host was
    therefore describing a different program.

    Failing loud is the right call here rather than emitting a partial
    document, because a program holding one of these capabilities can
    never become a Wasm component at all: there is no host that could
    consume the WIT, so nothing legitimate is lost."""

    def __init__(self, cap: str, message: str):
        super().__init__(message)
        self.cap = cap


def collect_used_capabilities(module: Module) -> dict[str, set[str]]:
    """Walk every instruction in every function and return a
    capability_name -> set-of-method-names mapping.

    Mirrors the Wasm emitter's discovery pass: a method call is a
    capability call when the lowerer set ``cap_used`` *or* when the
    receiver's type is a built-in capability class (impl-method-
    internal calls do not always carry ``cap_used`` through).
    ``parse_json`` / ``to_json`` are deliberately ignored here:
    they compile to local-export calls into the bundled JSON
    parser (see ``capa.ir._builtin_json``), so the component never
    imports them and the WIT must not advertise an interface for
    them. The WIT and the core wasm imports must agree on the
    used-cap set or the Component Model linker rejects the
    artifact."""
    out: dict[str, set[str]] = {}

    # The shared module walk covers impl-method bodies, MakeLambda
    # bodies, and match-arm guard preludes -- the same coverage the
    # core-wasm ``_discover`` pass has. A capability used ONLY
    # inside a method or a closure must appear in the WIT too, or
    # the component link fails with a missing-import mismatch.
    for _fn, instr in walk_module(module):
        # Capability classification is single-sourced with the core-wasm
        # discovery pass in
        # ``capa.ir._cap_discovery.classify_cap_method``: it resolves the
        # receiver cap (``cap_used`` else a built-in receiver type) and
        # drops the pure attenuators elided at emit time --
        # ``restrict_to`` / ``restrict_to_keys`` / ``restrict_to_after``
        # that did NOT graduate to a real host call (audit slices
        # 25.2 - 25.6). What is left is projected here to the
        # ``cap -> {method}`` map the WIT interfaces are built from.
        classified = classify_cap_method(instr)
        if classified is None:
            continue
        cap, method = classified
        out.setdefault(cap, set()).add(method)
        # Slice 13 (2026-05-29): Clock.sleep with a restrict_to_after
        # chain compiles to an inline ``$Clock_now_secs >= deadline``
        # gate around the host sleep. The core-wasm discovery agrees with
        # this rule; WIT must advertise ``now-secs`` too or the component
        # link fails on "import interface is missing function now-secs".
        if (cap == "Clock"
                and method == "sleep"
                and getattr(instr, "attenuations", None)):
            out.setdefault(cap, set()).add("now_secs")
    # ``Random`` is special: source-level methods (``with_seed``,
    # ``int_range``, ``float_unit``) all run guest-side in pure WAT
    # (SplitMix64 over a module-local i64 state). The only host
    # touch-point is ``system_seed``, called once at lazy init to
    # draw entropy for an unseeded ``Random()``. The lowerer never
    # emits a MethodCall for ``system_seed`` because the source
    # doesn't name it, so we synthesise the import here whenever the
    # program reaches for Random at all. The Wasm-side discovery
    # ``_uses_random`` agrees with this rule.
    if "Random" in out:
        out["Random"].add("system_seed")
    return out


from ._python_only_caps import find_rejection as find_python_only_rejection


def _module_calls_panic(module: Module) -> bool:
    """True when the module reaches the BUILTIN ``panic`` free
    function, in which case the WIT world must import the
    ``capa:host/panic`` interface (the core module declares the
    matching import; see ``_emit_wasm.__init__``). Mirrors the
    Wasm emitter's ``_uses_panic`` discovery exactly, including
    the shadowing rule: a user-defined ``panic`` function wins
    and produces no import."""
    if any(fn.name == "panic" for fn in module.functions):
        return False
    from ._emit_wasm._option import methodcall_may_panic
    return any(
        (isinstance(instr, Call) and instr.callee_name == "panic")
        or methodcall_may_panic(instr)
        for _fn, instr in walk_module(module)
    )


# Experimental WASI mode: a DOCUMENTATION snapshot of the Random / Clock
# / Env (cap, method) touch-points routed off ``capa:host`` -- the
# readers (``get`` / ``args``) to canonical wasi:* interfaces and the
# attenuators (``restrict_to_keys`` / ``allows``) GUEST-SIDE (Level 2 of
# docs/design/wasi-attenuation.md, no host import). Fs is FULLY migrated
# too (metadata + streams + the guest-side restrict_to / allows), but the
# WIT generator does not consult this set for Fs: it skips the WHOLE Fs
# capa:host interface in WASI mode unconditionally (see the
# ``_WASI_FULLY_MIGRATED_CAPS`` skip in ``_emit_wit_wasi``),
# routing every Fs op to wasi:filesystem. This constant is unused by the
# generator (the per-cap skips drive the logic); it is kept only as a
# human-readable index, NOT a lockstep mirror of
# ``capa.ir._emit_wasm._wasi._WASI_MIGRATED_METHODS``.
_WASI_MIGRATED_METHODS: frozenset[tuple[str, str]] = frozenset({
    ("Random", "system_seed"),
    ("Clock", "now_secs"),
    ("Clock", "now_monotonic"),
    ("Env", "get"),
    ("Env", "args"),
    ("Env", "restrict_to_keys"),
    ("Env", "allows"),
})

# Stdio methods migrated off capa:host/stdio in --wasi. UNLIKE the
# documentation-only ``_WASI_MIGRATED_METHODS`` above, this set IS
# consulted by ``_emit_wit_wasi``: a Stdio interface is emitted on
# capa:host ONLY for methods outside this set, and these methods are
# filtered out of the interface body. With Phase 2 (2026-06-29) it covers
# the WHOLE Stdio surface -- the output ops (print / println / eprintln ->
# wasi:cli/stdout|stderr, Phase 1) AND read_line (-> wasi:cli/stdin +
# wasi:io/streams, Phase 2) -- so a program using only Stdio carries NO
# capa:host stdio interface at all (only ``panic`` may remain on capa:host
# in --wasi). Keep in lockstep with
# ``capa.ir._emit_wasm._wasi._WASI_STDIO_MIGRATED`` (the output ops) plus
# the migrated ``read_line``.
_WASI_STDIO_MIGRATED_METHODS: frozenset[str] = frozenset(
    {"print", "println", "eprintln", "read_line"}
)


# Capabilities that are FULLY migrated to wasi:* under ``--wasi``:
# every reachable method either routes to a wasi interface or is
# implemented guest-side, so the cap carries NO ``capa:host``
# interface and no ``capa:host`` world import. This is NOT a subset
# of ``HANDLE_BEARING_CAPS`` (Random is erased on the wasm side yet
# fully migrated here, and Db / Proc bear handles yet are NOT
# migrated) - the two express different axes, so this set is
# maintained independently. Stdio is migrated per-METHOD rather
# than wholesale (``_WASI_STDIO_MIGRATED_METHODS`` above), so it
# does not belong here.
_WASI_FULLY_MIGRATED_CAPS: frozenset[str] = frozenset({
    "Random", "Clock", "Env", "Fs", "Net",
})


def emit_wit(
    module: Module,
    world_name: str = "program",
    *,
    wasi: bool = False,
) -> str:
    """Generate a WIT document for ``module``. The document declares
    one ``interface`` per capability that the program touches, plus
    a ``world`` that imports each interface. If the program uses no
    built-in capabilities, returns a minimal world with no imports
    (the caller may still wrap the module in a component, just
    without external dependencies).

    ``wasi`` (experimental): when True, the migrated Random / Clock
    touch-points import the canonical ``wasi:random`` / ``wasi:clocks``
    interfaces (resolved from the vendored WIT in ``capa/wasi_wit``)
    instead of the matching ``capa:host`` interfaces; every other
    capability keeps its ``capa:host`` interface (hybrid mode). See
    ``docs/design/wasi_mode.md``.

    Raises ``PythonOnlyCapabilityInWit`` if ``module`` reaches a
    ``PYTHON_ONLY_CAPS`` capability. ``--wit`` does not run the Wasm
    emitter, so this is the only place that rejection can happen on
    this path; without it the document would silently omit the
    capability and misdescribe ``main``'s signature."""
    # Before ``used`` is even collected, so the check is independent of
    # whether the capability happens to be method-bearing (``Serve``
    # is and shows up in ``used``; ``Unsafe`` is method-less and never
    # does -- see the ``_KNOWN_CAPABILITIES`` comment). Both must be
    # rejected, so this scans SIGNATURES, exactly as the Wasm
    # discovery pass does, sharing that one implementation.
    found = find_python_only_rejection(
        module,
        note=(
            "There is no WIT to emit for it: a WIT document "
            "describes a Wasm component, and this program cannot "
            "be one."
        ),
    )
    if found is not None:
        cap, message = found
        raise PythonOnlyCapabilityInWit(cap, message)

    used = collect_used_capabilities(module)

    if wasi:
        return _emit_wit_wasi(module, used, world_name)

    lines: list[str] = []
    lines.append("package capa:host;")
    lines.append("")

    # Emit interfaces in a deterministic order so two runs of the
    # same program produce byte-identical WIT (useful for caching
    # and diffing).
    for cap in sorted(used.keys()):
        if cap not in _KNOWN_CAPABILITIES:
            # Unknown capability: not necessarily an error -- user-
            # defined capabilities lower to a different pathway. For
            # Phase 6B we only emit interfaces for the built-in set;
            # user caps are flagged as a coverage gap to be addressed
            # alongside the Wasm emitter that handles them.
            continue
        lines.append(f"interface {cap.lower()} {{")
        # Per-interface type prelude. WIT references inside this
        # interface's method signatures must resolve to a type
        # declared in the same interface (or imported from another).
        # The Fs interface uses ``io-error`` as the result-error
        # arm of ``read`` / ``write``; declare it inline so
        # ``wasm-tools component embed`` can resolve the name.
        # For Stdio the prelude is gated: only inject the io-error
        # record when a method that actually references it is in
        # use, so plain Stdio programs (the overwhelming majority)
        # don't pay the prelude tax.
        gated = _METHODS_NEEDING_IO_ERROR.get(cap)
        emit_prelude = cap in _INTERFACE_TYPE_PRELUDE and (
            gated is None or bool(used[cap] & gated)
        )
        if emit_prelude:
            for type_line in _INTERFACE_TYPE_PRELUDE.get(cap, []):
                lines.append(f"  {type_line}")
            lines.append("")
        guest_only = _GUEST_ONLY_METHODS.get(cap, frozenset())
        for method in sorted(used[cap]):
            # Guest-side methods (Random.int_range etc.) run entirely
            # in linear memory; they don't show up in WIT and they
            # don't pull host imports. Skip cleanly so the WIT and
            # the core-wasm imports agree on the import set.
            if method in guest_only:
                continue
            key = (cap, method)
            if key not in _WIT_SIGNATURES:
                raise UnsupportedCapabilityMethod(cap, method)
            lines.append(f"  {_WIT_SIGNATURES[key]};")
        lines.append("}")
        lines.append("")

    # ``panic`` is a host import outside the capability system (the
    # message must reach the host's stderr before the guest traps);
    # it gets its own one-function interface when, and only when,
    # the program reaches the builtin. Kept in lockstep with the
    # core module's ``capa:host/panic`` import via
    # ``_module_calls_panic`` (the WIT and the core imports must
    # agree or the Component Model link fails).
    uses_panic = _module_calls_panic(module)
    if uses_panic:
        lines.append("interface panic {")
        lines.append("  panic: func(msg: string);")
        lines.append("}")
        lines.append("")

    lines.append(f"world {world_name} {{")
    for cap in sorted(used.keys()):
        if cap in _KNOWN_CAPABILITIES:
            lines.append(f"  import {cap.lower()};")
    if uses_panic:
        lines.append("  import panic;")
    # Export the Capa program's entry point so external Component
    # Model runtimes can call it. ``main`` matches the Capa
    # source-level convention and the core wasm's existing
    # ``(export "main")`` clause.
    #
    # Slice 25.8 (2026-05-30): Fs / Net / Db / Proc / Env / Clock are
    # un-erased on the core wasm path (slices 25.2 - 25.6) and lower
    # to ``i32`` handle params on ``main``'s wasm signature so the
    # host can route the right root cap to each slot. The Component
    # Model world must therefore advertise the same param shape, or
    # ``wasm-tools component new`` rejects the artifact with a
    # core-vs-component signature mismatch. Stdio / Random / Unsafe
    # have no attenuation surface to thread; they stay erased (no
    # i32 param). Pure ``fun main()`` programs keep the trivial
    # ``func()`` shape.
    # The world export's result clause must mirror the core module's
    # ``main`` result (Int -> s64, Float -> f64, Bool -> bool,
    # String -> string, Unit / absent -> none) or ``wasm-tools
    # component new`` rejects the artifact with a core-vs-world
    # signature mismatch. The return VALUE is discarded at every
    # backend (exit code is always 0 barring panic); declaring the
    # result only makes the world accept + drop it. Composite returns
    # raise ``MainReturnTypeUnsupported`` here (a clear Capa error).
    result_clause = main_result_clause(module)
    main_cap_params = _main_handle_slot_labels(module)
    if main_cap_params:
        sig = ", ".join(f"{name}: u32" for name in main_cap_params)
        lines.append(f"  export main: func({sig}){result_clause};")
    else:
        lines.append(f"  export main: func(){result_clause};")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def _emit_wit_wasi(
    module: Module,
    used: dict[str, set[str]],
    world_name: str,
) -> str:
    """WASI-mode WIT generator (experimental ``--wasi``).

    Emits a ``capa:host`` package whose ``world`` imports the
    canonical ``wasi:random`` / ``wasi:clocks`` interfaces for the
    migrated Random / Clock touch-points AND every other capability's
    ``capa:host`` interface (hybrid). The wasi:* packages are
    resolved by ``wasm-tools component embed`` from the vendored WIT
    in ``capa/wasi_wit`` (copied next to the generated world as
    ``deps/``).

    Random is fully migrated (its only host touch-point is
    ``system_seed``), so no ``capa:host`` random interface is emitted.
    Clock in WASI mode supports only ``now_secs`` / ``now_monotonic``;
    any other Clock method is rejected by the Wasm emitter's
    ``_validate_wasi_caps`` before we get here, so a Clock present in
    ``used`` is always fully migrated too. Env in WASI mode routes
    ``get`` / ``args`` to ``wasi:cli/environment`` and implements its
    attenuators (``restrict_to_keys`` / ``allows``) GUEST-SIDE (Level 2
    of ``docs/design/wasi-attenuation.md``, no host import), so an Env
    present in ``used`` never carries a ``capa:host`` env interface."""
    lines: list[str] = []
    lines.append("package capa:host;")
    lines.append("")

    # ``capa:host`` interfaces for every NON-migrated capability,
    # identical to the default path. ``_WASI_FULLY_MIGRATED_CAPS``
    # is skipped (those move to wasi:*). Fs in WASI mode is
    # metadata-only (exists / is_dir / mkdir via wasi:filesystem);
    # the stream-bearing and attenuation methods are rejected by the
    # Wasm emitter's ``_validate_wasi_caps`` before we get here, so
    # an Fs present in ``used`` carries no ``capa:host`` fs
    # interface. Net is migrated the same way: the request ops
    # ``get`` (Phase 1) and ``post`` (Phase 2) route to wasi:http,
    # and the fine attenuators ``restrict_to`` / ``allows`` (Phase 3)
    # are implemented GUEST-SIDE (Level 2 of
    # ``docs/design/wasi-attenuation.md``, no host import).
    for cap in sorted(used.keys()):
        if cap not in _KNOWN_CAPABILITIES:
            continue
        if cap in _WASI_FULLY_MIGRATED_CAPS:
            continue
        # Stdio output migration (Phase 1, 2026-06-29): print / println /
        # eprintln route to wasi:cli/stdout|stderr (the world imports
        # added below). read_line is NOT migrated (it stays on
        # capa:host/stdio), so the capa:host stdio interface is emitted
        # ONLY when read_line is reached -- a print-only program carries
        # no capa:host stdio interface at all (100 % stock WASI for its
        # output). The migrated methods are filtered out of the
        # interface's method list (the loop below skips them).
        stdio_migrated = _WASI_STDIO_MIGRATED_METHODS
        if cap == "Stdio" and not (used[cap] - stdio_migrated):
            continue
        lines.append(f"interface {cap.lower()} {{")
        gated = _METHODS_NEEDING_IO_ERROR.get(cap)
        emit_prelude = cap in _INTERFACE_TYPE_PRELUDE and (
            gated is None or bool(used[cap] & gated)
        )
        if emit_prelude:
            for type_line in _INTERFACE_TYPE_PRELUDE.get(cap, []):
                lines.append(f"  {type_line}")
            lines.append("")
        guest_only = _GUEST_ONLY_METHODS.get(cap, frozenset())
        for method in sorted(used[cap]):
            if method in guest_only:
                continue
            if cap == "Stdio" and method in stdio_migrated:
                # Migrated to wasi:cli/stdout|stderr; no capa:host method.
                continue
            key = (cap, method)
            if key not in _WIT_SIGNATURES:
                raise UnsupportedCapabilityMethod(cap, method)
            lines.append(f"  {_WIT_SIGNATURES[key]};")
        lines.append("}")
        lines.append("")

    uses_panic = _module_calls_panic(module)
    if uses_panic:
        lines.append("interface panic {")
        lines.append("  panic: func(msg: string);")
        lines.append("}")
        lines.append("")

    lines.append(f"world {world_name} {{")
    # wasi:* imports for the migrated touch-points, in a deterministic
    # order. Each is its own versioned interface reference resolved
    # from the vendored deps/.
    if "Random" in used:
        lines.append("  import wasi:random/random@0.2.0;")
    if "Clock" in used:
        clock_methods = used["Clock"]
        if "now_monotonic" in clock_methods:
            lines.append("  import wasi:clocks/monotonic-clock@0.2.0;")
        if "now_secs" in clock_methods:
            lines.append("  import wasi:clocks/wall-clock@0.2.0;")
    # Env.get / Env.args both route to the single wasi:cli/environment
    # interface (get-environment / get-arguments); import it once.
    if "Env" in used:
        lines.append("  import wasi:cli/environment@0.2.0;")
    # Fs metadata (exists / is_dir / mkdir) routes to wasi:filesystem:
    # preopens.get-directories resolves the host-granted descriptors,
    # types.descriptor.{stat-at, create-directory-at} do the metadata.
    # Both interfaces are imported once when any Fs op is used.
    # Fs.list_dir (read-directory + directory-entry-stream.
    # read-directory-entry) lives entirely in wasi:filesystem/types and
    # needs no extra interface. Only the stream-bearing Fs.read
    # (input-stream.blocking-read) and Fs.write
    # (output-stream.blocking-write-and-flush / blocking-flush)
    # additionally use wasi:io/streams plus wasi:io/error (the
    # resource-drop of the error a failed stream op carries), so import
    # both when either read or write is reached.
    if "Fs" in used:
        lines.append("  import wasi:filesystem/types@0.2.0;")
        lines.append("  import wasi:filesystem/preopens@0.2.0;")
        if "read" in used["Fs"] or "write" in used["Fs"]:
            lines.append("  import wasi:io/streams@0.2.0;")
            lines.append("  import wasi:io/error@0.2.0;")
    # Net.get (Phase 1) / Net.post (Phase 2) route to wasi:http:
    # outgoing-handler.handle builds + sends the request, types carries the
    # outgoing-request / future-incoming-response / incoming-response /
    # incoming-body chain, and the RESPONSE body is read via wasi:io/streams
    # (input-stream.blocking-read) with a wasi:io/poll synchronous block and
    # a wasi:io/error drop for a carried stream error. Net.post ALSO writes
    # the REQUEST body via wasi:io/streams (output-stream.blocking-write-
    # and-flush / blocking-flush), already covered by the same streams
    # import. Import all four when either get or post is used.
    if "Net" in used and ("get" in used["Net"] or "post" in used["Net"]):
        lines.append("  import wasi:http/types@0.2.0;")
        lines.append("  import wasi:http/outgoing-handler@0.2.0;")
        # wasi:io/streams + wasi:io/error may already have been imported
        # by Fs.read / Fs.write above; a world that imports the same
        # interface twice is rejected by wasm-tools, so the trailing
        # de-dup pass below removes the duplicate (the Net import lines are
        # emitted unconditionally here and pruned if redundant).
        lines.append("  import wasi:io/streams@0.2.0;")
        lines.append("  import wasi:io/poll@0.2.0;")
        lines.append("  import wasi:io/error@0.2.0;")
    # Stdio output (Phase 1, 2026-06-29): print / println route to
    # wasi:cli/stdout (get-stdout), eprintln to wasi:cli/stderr
    # (get-stderr); all three write through wasi:io/streams
    # (output-stream.blocking-write-and-flush). Import stdout when
    # print or println is used, stderr when eprintln is used, and
    # wasi:io/streams whenever any of the three is (the trailing de-dup
    # pass below removes a wasi:io/streams already imported by Fs / Net).
    if "Stdio" in used:
        stdio_methods = used["Stdio"]
        if "print" in stdio_methods or "println" in stdio_methods:
            lines.append("  import wasi:cli/stdout@0.2.0;")
        if "eprintln" in stdio_methods:
            lines.append("  import wasi:cli/stderr@0.2.0;")
        # read_line (Phase 2, 2026-06-29): get-stdin -> input-stream, read
        # byte-at-a-time via wasi:io/streams.input-stream.blocking-read
        # until "\n" / EOF. Imports wasi:cli/stdin plus wasi:io/streams (+
        # wasi:io/error for the resource-drop of an error a failed
        # blocking-read carries), the same io interfaces the output ops
        # use, so the de-dup pass below collapses them to one import each.
        if "read_line" in stdio_methods:
            lines.append("  import wasi:cli/stdin@0.2.0;")
        if stdio_methods & _WASI_STDIO_MIGRATED_METHODS:
            lines.append("  import wasi:io/streams@0.2.0;")
            # The chunked write helper (output) and the byte read loop
            # (read_line) both drop the ``error`` resource a
            # last-operation-failed stream-error carries; wasi:io/error
            # provides its resource-drop. The de-dup pass below prunes a
            # duplicate already imported by an Fs / Net stream op.
            lines.append("  import wasi:io/error@0.2.0;")
    # capa:host imports for the non-migrated caps (hybrid coexistence).
    # Stdio is special-cased: the WHOLE Stdio surface is now migrated off
    # capa:host in --wasi -- print / println / eprintln to wasi:cli/stdout|
    # stderr (Phase 1) and read_line to wasi:cli/stdin (Phase 2) -- so a
    # Stdio-only program imports NO capa:host stdio interface. The guard
    # below (``used["Stdio"] - _WASI_STDIO_MIGRATED_METHODS`` non-empty)
    # is now always empty for the built-in Stdio methods; it is kept so a
    # future un-migrated Stdio method would re-pull the capa:host import.
    for cap in sorted(used.keys()):
        if cap == "Stdio":
            if used["Stdio"] - _WASI_STDIO_MIGRATED_METHODS:
                lines.append("  import stdio;")
            continue
        if (cap in _KNOWN_CAPABILITIES
                and cap not in _WASI_FULLY_MIGRATED_CAPS):
            lines.append(f"  import {cap.lower()};")
    # De-duplicate ``import`` lines (a wasi:io interface can be requested
    # by both an Fs stream op and Net.get); a world importing the same
    # interface twice fails to type-check. Order is preserved (first
    # occurrence wins).
    _seen: set[str] = set()
    _deduped: list[str] = []
    for ln in lines:
        if ln.lstrip().startswith("import "):
            if ln in _seen:
                continue
            _seen.add(ln)
        _deduped.append(ln)
    lines = _deduped
    if uses_panic:
        lines.append("  import panic;")
    # Same result-clause mirroring as the default path (see
    # ``main_result_clause``): the WASI world export must match the
    # core module's ``main`` result or ``component new`` rejects it.
    result_clause = main_result_clause(module)
    main_cap_params = _main_handle_slot_labels(module)
    if main_cap_params:
        sig = ", ".join(f"{name}: u32" for name in main_cap_params)
        lines.append(f"  export main: func({sig}){result_clause};")
    else:
        lines.append(f"  export main: func(){result_clause};")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def _main_handle_slot_labels(module: Module) -> list[str]:
    """Return the WIT labels for ``main``'s handle slots, in
    declaration order, filtered to caps that lower to a real i32
    handle (the wasm side erases the rest).

    Each label is ``cap<N>-<kind>`` (``cap0-net``), derived from the
    parameter's declared TYPE and position, never from its source
    name. The Component host reads the capability kind back out of
    these labels to decide which root handle each slot receives; a
    component type is not a debug section, so the information survives
    every strip. Until 2026-07-23 the label was the SOURCE parameter
    name (``p.name.lower()``), which made ``fun main(conn: Net)`` an
    unrecognised label the host quietly resolved to the ``Fs`` root.
    See [`_cap_binding.py`](_cap_binding.py).

    Returns ``[]`` if ``main`` is absent or has no handle-bearing
    cap params; the caller then emits the trivial ``func()`` shape
    so plain ``fun main()`` programs and Stdio-only programs are
    unchanged."""
    return [
        wit_cap_slot_name(i, kind)
        for i, kind in enumerate(main_handle_cap_types(module))
    ]
