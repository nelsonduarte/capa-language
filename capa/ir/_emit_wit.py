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

from ._nodes import (
    Module, Function, Instr,
    MethodCall, If, While, For, Match,
)


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
    ("Clock", "now_secs"):      "now-secs: func() -> f64",
    ("Clock", "now_monotonic"): "now-monotonic: func() -> f64",
    # Clock.sleep: trivial f64 arg, no return. The Python runtime
    # treats a denied Clock (``restrict_to_after`` threshold in the
    # future) as a silent no-op; the host bridge mirrors that.
    ("Clock", "sleep"):         "sleep: func(secs: f64)",
    # Clock.allows queries the cap's ``restrict_to_after`` deadline
    # against the current host clock. Kept as a host bridge rather
    # than an inline-attenuation check because the literal threshold
    # is a Float, not a String, and the comparison needs the live
    # ``time.time()`` reading anyway. Static (analyzer-known)
    # attenuations cannot collapse this without a clock source.
    ("Clock", "allows"):        "allows: func() -> bool",

    # Env: process environment + argv. Phase 7B scope (Option<String>).
    ("Env", "get"):  "get: func(name: string) -> option<string>",
    # Env.args returns a list<string> of program arguments. The
    # host constructs the list in linear memory via \$alloc.
    ("Env", "args"): "args: func() -> list<string>",
    # Env.restrict_to_keys is a no-op at the Wasm host level
    # (mirrors Fs.restrict_to). The audit C2 inline attenuation
    # check on Env.get is what enforces the discipline; this
    # signature exists so the import resolves when Capa source
    # uses ``env.restrict_to_keys(["..."])``.
    ("Env", "restrict_to_keys"): "restrict-to-keys: func(keys: list<string>)",

    # Fs: filesystem reads + writes. Phase 7C scope (Result<T, IoError>).
    # IoError is a Capa-side record with two String fields (message,
    # cause). The host constructs it via $alloc on error.
    ("Fs", "read"):        "read: func(path: string) -> result<string, io-error>",
    ("Fs", "write"):       "write: func(path: string, content: string) -> result<_, io-error>",
    # Fs.exists / Fs.is_dir: queries returning bool. Mirror Python's
    # fail-closed-as-absent convention: a denied path reports false
    # so the cap doesn't leak existence outside its allowed
    # prefixes (the host bridge cannot enforce the cap's prefix
    # set; static attenuation discipline still applies).
    ("Fs", "exists"):      "exists: func(path: string) -> bool",
    ("Fs", "is_dir"):      "is-dir: func(path: string) -> bool",
    # Fs.mkdir: same canonical-ABI shape as Fs.write Ok-Unit
    # branch. Host uses ``os.makedirs(path, exist_ok=True)`` to
    # match the Python runtime's idempotent behaviour.
    ("Fs", "mkdir"):       "mkdir: func(path: string) -> result<_, io-error>",
    # Fs.list_dir: new canonical-ABI shape with a
    # ``list<string>`` Ok arm. Host returns sorted entry basenames
    # to match the Python runtime's deterministic ordering.
    ("Fs", "list_dir"):    "list-dir: func(path: string) -> result<list<string>, io-error>",
    # restrict_to is a no-op at the Wasm level: capabilities carry
    # no runtime value (their methods are imports by name), so an
    # attenuation that returns another Fs has nothing to thread.
    # The analyzer's static check is what enforces the discipline.
    ("Fs", "restrict_to"): "restrict-to: func(prefix: string)",

    # Random: entropy source only. The actual SplitMix64 PRNG runs
    # guest-side (see ``capa.ir._emit_wasm._random``); the only thing
    # the host provides is a 64-bit seed when the program constructs
    # an unseeded ``Random()``. ``with_seed`` / ``int_range`` /
    # ``float_unit`` all stay in linear memory, so seeded sequences
    # are byte-identical with the Python backend.
    ("Random", "system_seed"): "system-seed: func() -> u64",

    # Net entries follow once the request/response model is stable.

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
_KNOWN_CAPABILITIES = {"Stdio", "Clock", "Env", "Fs", "Random"}


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

    def visit(instrs: list[Instr]) -> None:
        for instr in instrs:
            if isinstance(instr, MethodCall):
                cap = instr.cap_used
                if cap is None:
                    rty = instr.receiver.ty or ""
                    if rty in BUILTIN_CAPS:
                        cap = rty
                if cap is not None:
                    out.setdefault(cap, set()).add(instr.method)
            # Recurse into nested instruction lists so we don't miss
            # method calls inside if/while/for/match arm bodies.
            if isinstance(instr, If):
                visit(instr.then_body)
                visit(instr.else_body)
            elif isinstance(instr, While):
                visit(instr.cond_setup)
                visit(instr.body)
            elif isinstance(instr, For):
                visit(instr.body)
            elif isinstance(instr, Match):
                for arm in instr.arms:
                    visit(arm.body)

    for fn in module.functions:
        visit(fn.body)
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

    lines.append(f"world {world_name} {{")
    for cap in sorted(used.keys()):
        if cap in _KNOWN_CAPABILITIES:
            lines.append(f"  import {cap.lower()};")
    # Export the Capa program's entry point so external Component
    # Model runtimes can call it. ``main`` matches the Capa
    # source-level convention and the core wasm's existing
    # ``(export "main")`` clause; capability parameters are erased
    # at the Wasm level (they become imports), so the export's
    # canonical-ABI signature is the trivial ``() -> ()`` shape.
    lines.append("  export main: func();")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)
