"""Capa IR (CIR): intermediate representation between the typed AST
and the emit-target backends.

Goals:

- Decouple the language semantics (lowered into IR instructions) from
  the emission of any specific target (currently Python source; in the
  future, WebAssembly Component Model bytecode + WIT, or LLVM IR, or
  Cranelift IR).
- Preserve capability annotations at every function boundary and at
  every capability-method-call site, so backends targeting capability-
  aware platforms (Wasm CM via WIT) can emit them verbatim.
- Carry per-value type information so type-aware lowering decisions
  (method dispatch, manifest extraction) stay possible after the AST
  is gone.

Phase 1 scope (this commit): the IR data classes, an AST -> IR lowering
pass for a small subset of the language (function declarations with
literal / identifier / binary-op / call / method-call expressions, plus
let / return / expression statements), and a Python emitter from IR.
The legacy direct AST -> Python transpiler remains the default; the
IR path is opt-in via the ``compile()`` entrypoint below, used by the
IR tests until coverage is complete.

The IR is intentionally three-address / ANF-flavoured: every operation
binds its result to a fresh local. This is what Wasm and LLVM-class
backends prefer; the alternative (tree-structured expressions) would
work for Python emission but force re-flattening on every other
backend.
"""

from __future__ import annotations

from .. import capa_ast as A
from ._nodes import Module, Function, Param, Local, Value, Instr
from ._lower import Lowerer, UnsupportedInIR
from ._emit_python import PythonEmitter
from ._emit_wasm import WasmEmitter, WasmEmissionError
from ._emit_wit import (
    emit_wit, collect_used_capabilities, UnsupportedCapabilityMethod,
)

__all__ = [
    "Module",
    "Function",
    "Param",
    "Local",
    "Value",
    "Instr",
    "Lowerer",
    "UnsupportedInIR",
    "PythonEmitter",
    "WasmEmitter",
    "WasmEmissionError",
    "UnsupportedCapabilityMethod",
    "lower",
    "emit_python",
    "emit_wat",
    "emit_wit",
    "collect_used_capabilities",
    "compile",
    "compile_program",
    "compile_wat",
    "compile_wasm",
    "compile_wit",
]


def lower(module: A.Module, types: dict | None = None) -> Module:
    """Lower a typed AST module to CIR.

    Raises ``UnsupportedInIR`` if the module contains constructs the
    Phase 1 lowering does not yet handle. Caller is expected to catch
    and fall back to the legacy transpiler in that case.
    """
    return Lowerer(types=types or {}).lower_module(module)


def emit_python(ir_module: Module) -> str:
    """Emit Python source from a CIR module."""
    return PythonEmitter().emit(ir_module)


def compile(module: A.Module, types: dict | None = None) -> str:
    """End-to-end AST -> CIR -> Python convenience helper."""
    return emit_python(lower(module, types=types))


def compile_program(
    module: A.Module,
    filename: str = "<input>",
    types: dict | None = None,
) -> str:
    """End-to-end AST -> CIR -> runnable Python program.

    Unlike :func:`compile`, this prepends the runtime prelude (the
    same one the legacy transpiler emits) and appends the
    ``if __name__ == "__main__":`` bootstrap when a ``main`` function
    is present. The result is directly ``exec``-runnable in a bare
    namespace and matches the legacy transpiler's emission shape for
    the subset the IR covers.

    Reuses the legacy ``_PRELUDE`` constant rather than duplicating
    the runtime-import list so the two paths stay in lockstep on
    runtime-API changes. The legacy's ``_TRY_HELPER`` (the
    ``_capa_try`` / ``_CapaTryEarlyReturn`` block) is intentionally
    omitted: the IR expands ``?`` inline via TryUnwrap, so the
    exception path is never reached.
    """
    from ..transpiler import _PRELUDE
    ir_mod = lower(module, types=types)
    body = emit_python(ir_mod)
    # Identify the main function from the IR so the bootstrap
    # instantiates its capability params correctly.
    main_fn = next((f for f in ir_mod.functions if f.name == "main"), None)
    parts: list[str] = [_PRELUDE.format(filename=filename).rstrip(), ""]
    parts.append(body.rstrip())
    if main_fn is not None:
        parts.append("")
        parts.append(_emit_main_bootstrap(main_fn))
    return "\n".join(parts).rstrip() + "\n"


def emit_wat(ir_module: Module) -> str:
    """Emit WebAssembly text format (WAT) from a CIR module.

    Phase 6A scope: integer / boolean functions only. Any CIR
    construct outside this subset raises ``WasmEmissionError`` with
    a precise reason. The output is valid WAT that ``wasm-tools
    parse`` accepts; see :func:`compile_wasm` for an assemble-to-
    bytes convenience wrapper."""
    return WasmEmitter().emit(ir_module)


def compile_wat(module: A.Module, types: dict | None = None) -> str:
    """End-to-end AST -> CIR -> WAT convenience helper. Mirrors
    :func:`compile` but targets the Wasm Component Model text form
    instead of Python source."""
    return emit_wat(lower(module, types=types))


def compile_wit(
    module: A.Module,
    types: dict | None = None,
    world_name: str = "program",
) -> str:
    """End-to-end AST -> CIR -> WIT spec.

    Returns a WIT document declaring an interface per built-in
    capability the program touches plus a ``world`` that imports
    them. Pair with :func:`compile_wasm` and a host that provides
    the interfaces to obtain a runnable component."""
    return emit_wit(lower(module, types=types), world_name=world_name)


def compile_wasm(
    module: A.Module,
    types: dict | None = None,
    wasm_tools_path: str = "wasm-tools",
) -> bytes:
    """End-to-end AST -> CIR -> WAT -> binary Wasm assembly.

    Shells out to ``wasm-tools parse`` to assemble the WAT into
    binary ``.wasm`` bytes. Returns the binary content so callers
    can write it to disk, load it into a runtime, or sign it
    without intermediate file shuffling. Raises
    ``FileNotFoundError`` if ``wasm-tools`` is not on PATH, and
    ``subprocess.CalledProcessError`` if the assembly itself fails
    (the WAT it complained about is in ``.stderr``).
    """
    import subprocess
    wat = compile_wat(module, types=types)
    proc = subprocess.run(
        [wasm_tools_path, "parse", "-"],
        input=wat.encode("utf-8"),
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"wasm-tools parse failed (exit {proc.returncode}):\n"
            f"{proc.stderr.decode('utf-8', errors='replace')}\n"
            f"--- WAT input ---\n{wat}"
        )
    return proc.stdout


def _emit_main_bootstrap(main_fn) -> str:
    """Emit the ``if __name__ == "__main__":`` block that instantiates
    each capability param and calls ``main(...)``. Mirrors the legacy
    transpiler's :meth:`_emit_main_bootstrap` so behaviour is
    identical for the same input."""
    args: list[str] = []
    for p in main_fn.params:
        # The IR's Param carries the source-level type name as a
        # string in ``p.ty``; for built-in capability params that is
        # the class name we need to instantiate (e.g. "Stdio").
        cap_name = p.ty if p.ty else "Stdio"
        args.append(f"{cap_name}()")
    call = f"main({', '.join(args)})" if args else "main()"
    return (
        'if __name__ == "__main__":\n'
        f"    {call}\n"
    )
