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
    "lower",
    "emit_python",
    "compile",
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
