"""Shared type-level constants used by the IR backends.

Both the lowerer and the two emitters (Python + Wasm) need the
same view of "what is a built-in capability". Before this module
existed the set was duplicated across [`capa/ir/_lower.py`](_lower.py),
[`capa/ir/_emit_wit.py`](_emit_wit.py), and
[`capa/ir/_emit_wasm/_layout.py`](_emit_wasm/_layout.py); the
duplication was load-bearing because each file produced WAT or
WIT against its own copy of the set, so drift would silently
diverge backend output. Audit 2026-05-25 (item #7) called the
copies out as the single biggest correctness lever after the
inline helper duplication.

This module deliberately contains nothing except the constants
the three call sites need. Anything that ships logic alongside
the data belongs in the calling module so the dependency graph
stays shallow.
"""

from __future__ import annotations


# Built-in capability type names. Receivers of these types route
# their method calls to host imports (Wasm) or to capability
# classes from ``capa.runtime`` (Python). The set must match
# ``capa.typesys.CAPABILITY_NAMES`` and ``capa.builtins``'s
# registered capability classes; cross-check fires the
# manifest-vs-runtime property test in
# [`tests/test_properties.py`](../../tests/test_properties.py).
BUILTIN_CAPS: frozenset[str] = frozenset({
    "Stdio", "Fs", "Net", "Env", "Clock", "Random", "Proc", "Db", "Unsafe",
})
