"""The tests/wasi package: the experimental WASI Preview 2 mode test suite.

Split out of the former tests/test_wasi_mode.py monolith. Growth convention:

  - One module per WASI capability: core (Random / Clock plus cross-capability
    mechanisms), env, fs, net. A new test routes to its capability's module; a
    cross-capability mechanism test goes to core.
  - Module basenames stay globally unique across tests/.
  - The shared build / run primitives, the two wasm-tools / wasip2 skip gates,
    and the cross-module Env fixtures live in tests/wasi/_helpers.py, which is
    not a test module: its name does not match the test*.py discovery pattern,
    so it is never collected. Facet-local servers / runners live with their
    capability module.
  - When a module crosses ~1800 lines AND has a distinguishable facet
    sub-cluster, split that facet along a named seam (the named fs seam is the
    dynamic-preopen facet -> a future test_wasi_fs_dynamic.py). Never chunk by
    line count; never pre-create empty facet modules.
"""
