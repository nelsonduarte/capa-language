"""Shared helpers for the tests/ir_wasm/ package.

_parse_lower and the two skip gates (_has_wasm_tools / _has_wasmtime_py) are
the primitives every ir_wasm test module imports; this module is their single
source, so the skip decision cannot diverge between modules. Do not re-export
capa emission entry points from here: a module that needs compile_wasm /
compile_wat / emit_wat / emit_wit / compile_wit / collect_used_capabilities /
WasmEmissionError / ... imports them directly from capa.ir.

This is NOT a test module: its name does not match the test*.py discovery
pattern, so unittest discovery and pytest never collect it as tests. Facet-
local helpers (the emission-core typestate source, the discarded-call sweep
machinery, the WAT-closure guard, and the per-class fixtures) live with their
module, not here.
"""

from __future__ import annotations

import shutil

from capa import Lexer, Parser, analyze
from capa.ir import lower


def _parse_lower(src: str):
    """Lex + parse + analyze + lower; returns (ir_module, types_map).
    Aborts the test if analysis fails so we get a clear message."""
    tokens = Lexer(src).lex()
    module = Parser(tokens, source=src).parse_module()
    result = analyze(module, source=src)
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    ir_mod = lower(module, types=result.types)
    return ir_mod, result.types, module


def _has_wasm_tools() -> bool:
    return shutil.which("wasm-tools") is not None


def _has_wasmtime_py() -> bool:
    try:
        import wasmtime  # noqa: F401
        return True
    except ImportError:
        return False
