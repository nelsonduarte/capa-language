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

from ._nodes import Module, Call, MethodCall
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
        if isinstance(instr, MethodCall):
            cap = instr.cap_used
            if cap is None:
                rty = instr.receiver.ty or ""
                if rty in BUILTIN_CAPS:
                    cap = rty
            if cap is not None:
                # ``restrict_to`` / ``restrict_to_keys`` /
                # ``restrict_to_after`` are pure attenuators
                # tracked in the analyzer + the Wasm emit's
                # attenuation chain. They never become host
                # calls, so they must not appear in the WIT
                # interface (which would force the host to
                # provide a matching no-op stub it never
                # calls). The core-wasm discovery pass
                # already filters them; this mirrors that rule
                # so WIT and core imports stay in lockstep.
                #
                # Slice 25.2 - 25.6 exception (2026-05-30):
                # ``Fs.restrict_to`` / ``Net.restrict_to`` /
                # ``Db.restrict_to`` / ``Proc.restrict_to`` /
                # ``Env.restrict_to_keys`` /
                # ``Clock.restrict_to_after`` graduated to real
                # host calls that take the parent handle + the
                # attenuation arg and return a child handle, so
                # they stay in the WIT.
                if (
                    cap in ("Fs", "Net", "Db", "Proc")
                    and instr.method == "restrict_to"
                ):
                    pass
                elif (
                    cap == "Env"
                    and instr.method == "restrict_to_keys"
                ):
                    pass
                elif (
                    cap == "Clock"
                    and instr.method == "restrict_to_after"
                ):
                    pass
                elif instr.method in (
                    "restrict_to",
                    "restrict_to_keys",
                    "restrict_to_after",
                ):
                    continue
                out.setdefault(cap, set()).add(instr.method)
                # Slice 13 (2026-05-29): Clock.sleep with a
                # restrict_to_after chain compiles to an
                # inline ``$Clock_now_secs >= deadline`` gate
                # around the host sleep. The core-wasm
                # discovery agrees with this rule; WIT must
                # advertise ``now-secs`` too or the component
                # link fails on "import interface is missing
                # function now-secs".
                if (cap == "Clock"
                        and instr.method == "sleep"
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


from ._capa_types import BUILTIN_CAPS


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
    return any(
        isinstance(instr, Call) and instr.callee_name == "panic"
        for _fn, instr in walk_module(module)
    )


def emit_wit(module: Module, world_name: str = "program") -> str:
    """Generate a WIT document for ``module``. The document declares
    one ``interface`` per capability that the program touches, plus
    a ``world`` that imports each interface. If the program uses no
    built-in capabilities, returns a minimal world with no imports
    (the caller may still wrap the module in a component, just
    without external dependencies)."""
    used = collect_used_capabilities(module)

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
    main_cap_params = _main_handle_param_names(module)
    if main_cap_params:
        sig = ", ".join(f"{name}: u32" for name in main_cap_params)
        lines.append(f"  export main: func({sig});")
    else:
        lines.append("  export main: func();")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


# Caps that lower to a real i32 handle on ``main``'s wasm signature
# (slices 25.2 - 25.6). Mirrors ``_emit_wasm.__init__._emit_function``
# and ``_wasm_host.WasmHost.run_main``: Fs / Net / Db / Proc / Env /
# Clock thread through the host handle table; everything else
# (Stdio / Random / Unsafe) stays erased on the wasm side and so on
# the WIT side too.
_HANDLE_BEARING_CAPS: frozenset[str] = frozenset({
    "Fs", "Net", "Db", "Proc", "Env", "Clock",
})


def _main_handle_param_names(module: Module) -> list[str]:
    """Return the lowercase cap-param names of ``main`` for the WIT
    world export, in declaration order, filtered to caps that lower
    to a real i32 handle (the wasm side erases the rest).

    Returns ``[]`` if ``main`` is absent or has no handle-bearing
    cap params; the caller then emits the trivial ``func()`` shape
    so plain ``fun main()`` programs and Stdio-only programs are
    unchanged."""
    for fn in module.functions:
        if fn.name != "main":
            continue
        out: list[str] = []
        for p in fn.params:
            if p.ty in _HANDLE_BEARING_CAPS:
                # WIT identifiers are strict kebab-case (lowercase
                # ASCII letters / digits / dashes). Capa source-
                # level param names are typically already conformant
                # (``fs`` / ``net`` / ``db`` / ``proc`` / ``env`` /
                # ``clock``); rewrite any underscores to dashes for
                # robustness against a project that named its cap
                # ``my_fs``. The wasm-side param identifier is
                # untouched (Wasm allows ``$my_fs``); only the WIT
                # spelling is sanitised.
                out.append(p.name.lower().replace("_", "-"))
        return out
    return []
