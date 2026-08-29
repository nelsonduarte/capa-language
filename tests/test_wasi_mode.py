"""Experimental WASI Preview 2 mode (opt-in ``--wasi``).

Validates the proof-of-concept that migrates the Random and Clock
capabilities off the custom ``capa:host`` interfaces and onto
canonical WASI Preview 2 interfaces (``wasi:random`` /
``wasi:clocks``), satisfied by wasmtime's ``add_wasip2()`` host, while
the rest of the program's capabilities (Stdio here) stay on
``capa:host`` in the SAME component Linker (hybrid coexistence).

The migrated touch-points are non-deterministic (system_seed entropy,
wall + monotonic clocks), so the validation is by PROPERTY, not by
byte-equality:

- PIPELINE: a Clock + Random + Stdio program compiles in WASI mode,
  embeds the WASI WIT, instantiates, and runs without trap.
- SEEDED PARITY: ``with_seed(fixed) + int_range`` runs 100 % guest-side
  and stays byte-identical to the Python backend (the WASI random
  import never fires on the seeded path).
- CLOCK PROPERTIES: ``now_monotonic`` does not decrease across
  successive reads; ``now_secs`` is a plausible Unix timestamp.
- SYSTEM_SEED: an unseeded ``Random()`` draws fresh entropy each run,
  so two runs of the same program produce distinct values.
- ENV ATTENUATION: ``Env.restrict_to_keys`` / ``Env.allows`` / the
  ``Env.get`` fail-closed gate are implemented GUEST-SIDE under
  ``--wasi`` (Level 2 of ``docs/design/wasi-attenuation.md``), with
  intersection + fail-closed semantics byte-identical to the Python
  backend (the oracle) and the capa:host backend.
- EXCLUSIONS: ``Clock.sleep`` and Clock attenuation
  (``restrict_to_after``) are rejected with a clear error in WASI mode.

The default ``capa:host`` path is exercised by the rest of the suite;
this file only covers the new flag.
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import time
import unittest

from capa import Lexer, Parser, analyze


if __name__ == "__main__":
    unittest.main()
