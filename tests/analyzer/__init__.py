"""The tests/analyzer package: the Capa semantic-analyzer test suite.

Split out of the former tests/test_analyzer.py monolith. Growth convention:

  - One module per analyzer subsystem; a new test goes to the module whose
    subject it exercises.
  - Module basenames stay globally unique across tests/.
  - When a module crosses ~1800 lines AND has a distinguishable facet
    sub-cluster, split that facet along a named seam (for example a future
    test_linear_carrier.py split out of test_linear_obligation.py when the
    carrier sub-cluster grows). Never chunk by line count; never pre-create
    empty facet modules.

The shared check/errors_of helpers live in tests/analyzer/_helpers.py, which
is not a test module: its name does not match the test*.py discovery pattern,
so unittest discovery and pytest never collect it as tests.
"""
