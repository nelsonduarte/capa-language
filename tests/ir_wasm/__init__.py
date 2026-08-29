"""The tests/ir_wasm package: the CIR -> WebAssembly backend (Phase 6) suite.

Split out of the former tests/test_ir_wasm.py monolith. These tests exercise
three levels of the pipeline:

  1. WAT shape: the emitter produces valid WAT for a given Capa source. Pinning
     a few canonical snippets keeps regressions in the textual form visible.
  2. wasm-tools parse: the WAT assembles to binary .wasm without error, proving
     we speak the actual textual grammar, not just something that looks like it.
  3. wasmtime-py execution: the assembled module loads in a real Wasm runtime
     and the exported functions return the expected results when called from
     Python. This is the load-bearing check; everything else is plumbing.

Tests that need an external toolchain (wasm-tools for parsing, wasmtime-py for
execution) skip themselves cleanly when it is missing, so the rest of the suite
stays runnable on machines without the Wasm side-stack installed.

Growth convention:

  - One module per Wasm-emission subject; a new test routes to the module whose
    subject it exercises (emission core, WIT, stdio, patterns / match,
    aggregates, collections, strings, floats / ftoa, closures / fun-values,
    json, dispatch / generics, capabilities, safety, component / manifest, and
    the structural sweeps).
  - Module basenames stay globally unique across tests/ (hence the test_wasm_
    prefix).
  - When a module crosses ~1800 lines AND has a distinguishable facet
    sub-cluster, split that facet along a named seam: patterns -> a future
    test_wasm_match_arms.py (the match-arm / guard facet); aggregates -> a future
    test_wasm_aggregate_slots.py (the aggregate-slot / fn-ref-slot facet);
    capabilities -> a future test_wasm_capability_exec.py (the Random / Net
    runtime-execution facet). Never chunk by line count; never pre-create empty
    facet modules.
  - The shared _parse_lower and the two skip gates live once in
    tests/ir_wasm/_helpers.py, which is not a test module: its name does not
    match the test*.py discovery pattern, so it is never collected. Facet-local
    helpers (the emission-core typestate source, the discarded-call sweep
    machinery, the WAT-closure guard, and the per-class fixtures) live with
    their module.
"""
