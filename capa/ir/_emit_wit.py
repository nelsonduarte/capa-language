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

    # Clock: monotonic + wall time. Phase 7A scope (Float type).
    # WIT identifiers are kebab-case; Capa keys keep snake_case so
    # the rest of the toolchain (lowerer, host bridge) reads as
    # source-level names. The Wasm import emitter rewrites the
    # method-name component to kebab-case to match this WIT.
    ("Clock", "now_secs"):      "now-secs: func() -> f64",
    ("Clock", "now_monotonic"): "now-monotonic: func() -> f64",

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
    # restrict_to is a no-op at the Wasm level: capabilities carry
    # no runtime value (their methods are imports by name), so an
    # attenuation that returns another Fs has nothing to thread.
    # The analyzer's static check is what enforces the discipline.
    ("Fs", "restrict_to"): "restrict-to: func(prefix: string)",

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
_KNOWN_CAPABILITIES = {"Stdio", "Clock", "Env", "Fs"}


# Per-interface type declarations injected before the method
# signatures. Some capabilities reference Capa-side record types
# (``IoError``) that have no WIT primitive equivalent; we declare
# them inline so the WIT spec is self-contained and the Component
# Model linker can resolve every name.
_INTERFACE_TYPE_PRELUDE: dict[str, list[str]] = {
    "Fs": [
        "record io-error {",
        "  message: string,",
        "  cause: string,",
        "}",
    ],
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
        for type_line in _INTERFACE_TYPE_PRELUDE.get(cap, []):
            lines.append(f"  {type_line}")
        if cap in _INTERFACE_TYPE_PRELUDE:
            lines.append("")
        for method in sorted(used[cap]):
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
