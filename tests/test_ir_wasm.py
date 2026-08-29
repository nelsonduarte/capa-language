# pyright: reportCallIssue=none
#
# wasmtime-py types ``instance.exports(store)[name]`` as a union
# ``Func | Global | Memory | Table | SharedMemory``. Every call site
# in this file passes the resulting export through ``(...)``, so
# Pyright flags each non-callable variant of the union four times
# per call site (50+ helpers x 4 = ~200 spurious red squiggles).
# We know the relevant export is a Func because the WAT we emit
# always declares it as one; silencing ``reportCallIssue`` for the
# whole file is the smallest fix that doesn't bury the test code in
# per-line type-ignore noise. Real "not callable" errors are still
# caught by ``python -m unittest`` -- the runtime check is sharper
# than Pyright's union narrowing here.
"""Tests for the CIR -> WebAssembly backend (Phase 6).

Phase 6A coverage: Int / Bool arithmetic, comparisons, locals,
``if`` / ``while`` / ``break`` / ``continue`` / ``return``. We
exercise three levels of the pipeline:

1. **WAT shape**: the emitter produces valid WAT for a given Capa
   source. Pinning a few canonical snippets keeps regressions in
   the textual form visible.
2. **wasm-tools parse**: the WAT assembles to binary ``.wasm``
   without error. This proves we are speaking the actual textual
   grammar, not just something that looks like it.
3. **wasmtime-py execution**: the assembled module loads in a
   real Wasm runtime and the exported functions return the
   expected results when called from Python. This is the
   load-bearing check; everything else is plumbing.

Tests that need an external toolchain (``wasm-tools`` for parsing,
``wasmtime-py`` for execution) skip themselves cleanly if the
toolchain is missing, so the rest of the suite stays runnable on
machines without the Wasm side-stack installed.
"""

from __future__ import annotations

import re
import shutil
import typing
import unittest

from capa import Lexer, Parser, analyze
from capa.ir import (
    lower, emit_wat, emit_wit, compile_wat, compile_wasm, compile_wit,
    collect_used_capabilities, WasmEmissionError,
    UnsupportedCapabilityMethod, MainReturnTypeUnsupported,
)

from tests.ir_wasm._helpers import (
    _has_wasm_tools, _has_wasmtime_py, _parse_lower,
)


if __name__ == "__main__":
    unittest.main()
