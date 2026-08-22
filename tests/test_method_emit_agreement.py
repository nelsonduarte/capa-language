"""M2a: a fail-closed AGREEMENT net for the two Python method-emit tables.

Capa lowers a call on a built-in receiver type (``String`` / ``List`` /
``Map`` / ``Set`` / ``Range``) into a Python idiom through TWO hand-synced
tables:

- the legacy transpiler's ``capa.transpiler._methods._MethodsMixin``
  (``_emit_string_method`` / ``_emit_list_method`` / ``_emit_map_method`` /
  ``_emit_set_method`` / ``_emit_range_method``), and
- the CIR Python emitter's ``capa.ir._emit_python.PythonEmitter``
  (``_string_method`` / ``_list_method`` / ``_map_method`` / ``_set_method``,
  dispatched by ``_rewrite_builtin_method``).

Both map ``(receiver-type, method)`` to emit logic and both DELEGATE an
unlisted method to a plain ``recv.method(args)`` fallback. The two are kept
in lockstep only by a comment; a past drift between them was a real
Python-backend parity bug (audit D-C1). M2 does not consolidate them (that
is a later item); it only adds this net so a future divergence fails HERE.

WHAT THIS ASSERTS

For every ``(type, method)`` either table special-cases, the two backends
must emit the SAME Python expression for the same symbolic receiver and
arguments. Arguments are sized to the method's real arity (from
``capa.builtins.METHODS``), so a special-case that merely forwards the call
(``recv.method(args)``) compares equal to the other side's fallback, while a
special-case with different semantics compares unequal and fails.

MODELLING THE BENIGN ASYMMETRY (so the net bites on REAL drift only)

The audit measured one legitimate difference: the legacy transpiler has
``Range`` special-cases (``_emit_range_method``) that the CIR side lacks, and
those arms are VESTIGIAL -- each is behaviour-identical to the legacy's own
``recv.method(args)`` fallback (e.g. ``length`` emits ``recv.length()``). A
naive set-equality assertion would misfire on this. Two things keep the net
honest instead:

1. The per-method output comparison uses each method's real arity, so a
   vestigial pass-through arm emits exactly what the fallback would and
   compares EQUAL. A non-vestigial special-case (dropping / reshaping an
   argument) compares UNEQUAL and fails, naming the pair.
2. Any pair special-cased on exactly one side is required to appear in the
   small, explicit ``_VESTIGIAL_ONE_SIDED`` allowlist below AND to be proven
   equal to the other side's fallback. A NEW one-sided special-case that is
   not allowlisted fails here, forcing a conscious decision rather than a
   silent table drift.

This is pure Python over the two tables (no compilation), so it always
collects. It is additive: it changes no production behaviour.
"""

import inspect
import re
import unittest

from capa.builtins import METHODS
from capa.transpiler._methods import _MethodsMixin
from capa.ir._emit_python import PythonEmitter


#: The built-in receiver types with a Python-emit table. ``Range`` has a
#: legacy table but no CIR one (see ``_VESTIGIAL_ONE_SIDED``).
_TYPES = ("String", "List", "Map", "Set", "Range")

#: type -> the legacy transpiler's per-type emit function.
_LEGACY_FN = {
    "String": _MethodsMixin._emit_string_method,
    "List": _MethodsMixin._emit_list_method,
    "Map": _MethodsMixin._emit_map_method,
    "Set": _MethodsMixin._emit_set_method,
    "Range": _MethodsMixin._emit_range_method,
}

#: type -> the CIR emitter's per-type emit method name. ``Range`` is absent:
#: ``_rewrite_builtin_method`` returns ``None`` for it, so the CIR side always
#: falls back to a plain ``recv.method(args)`` call.
_CIR_FN_NAME = {
    "String": "_string_method",
    "List": "_list_method",
    "Map": "_map_method",
    "Set": "_set_method",
}

#: Pairs special-cased on exactly ONE side, each provably equivalent to the
#: shared ``recv.method(args)`` fallback (the audit-measured vestigial arms).
#: The legacy ``_emit_range_method`` forwards ``length`` / ``contains`` /
#: ``is_empty`` / ``to_list`` straight through to the same-named ``CapaRange``
#: method, which is exactly what the CIR side's fallback emits; the CIR side
#: therefore carries no Range table. A NEW one-sided special-case that is not
#: listed here fails ``test_one_sided_special_cases_are_allowlisted_vestigial``.
_VESTIGIAL_ONE_SIDED = frozenset({
    ("Range", "length"),
    ("Range", "contains"),
    ("Range", "is_empty"),
    ("Range", "to_list"),
})


#: (type, method) -> argument count, from the authoritative builtin method
#: table. Sizing the probe arguments to the real arity is what lets a
#: pass-through special-case compare equal to the fallback.
_ARITY = {
    (t, m): len(ty.params)
    for t in _TYPES
    for (m, ty, _mty_params) in METHODS.get(t, [])
}

_RECV = "R"


def _probe_args(t, m):
    return [f"A{i}" for i in range(_ARITY[(t, m)])]


def _special_cased(fn):
    """The set of method names ``fn`` special-cases, read straight from its
    source (its ``if method == "X":`` / ``if m == "X":`` guards). Reading the
    source rather than a hand-list means a newly added arm is picked up
    automatically."""
    src = inspect.getsource(fn)
    return set(re.findall(r'\b(?:m|method) == "([^"]+)"', src))


def _legacy_emit(t, m):
    """What the legacy transpiler emits for ``recv.m(args)`` on a ``t``
    receiver. The per-type function is a pure string builder (it uses only
    its arguments and the module-level ``_safe_ident``), so an unbound call
    with ``self=None`` is faithful."""
    return _LEGACY_FN[t](None, m, _RECV, _probe_args(t, m))


def _cir_emit(t, m):
    """What the CIR Python emitter emits for the same call, including its
    ``recv.method(args)`` fallback when no rewrite applies (mirrors
    ``_emit_python._emit_instr``'s MethodCall branch)."""
    args = _probe_args(t, m)
    rewritten = PythonEmitter()._rewrite_builtin_method(t, m, _RECV, args)
    if rewritten is None:
        return f"{_RECV}.{m}({', '.join(args)})"
    return rewritten


def _fallback(m, t):
    """The shared plain-call fallback both tables delegate to."""
    return f"{_RECV}.{m}({', '.join(_probe_args(t, m))})"


def _union_pairs():
    for t in _TYPES:
        legacy = _special_cased(_LEGACY_FN[t])
        cir = (
            _special_cased(getattr(PythonEmitter, _CIR_FN_NAME[t]))
            if t in _CIR_FN_NAME else set()
        )
        for m in sorted(legacy | cir):
            yield t, m


class TestMethodEmitAgreement(unittest.TestCase):
    def test_every_probe_pair_has_a_known_arity(self):
        """Guard the arity source: every special-cased method must have a
        ``METHODS`` entry, or the probe below would silently mis-size its
        arguments and the comparison would stop meaning anything."""
        missing = [
            (t, m) for (t, m) in _union_pairs() if (t, m) not in _ARITY
        ]
        self.assertEqual(sorted(missing), [])

    def test_tables_agree_on_every_special_cased_pair(self):
        """The fail-closed bite: for every method either table special-cases,
        the legacy transpiler and the CIR emitter must emit the identical
        Python expression. A drift (a special-case added to or changed in one
        table only, with semantics the other does not reproduce) fails here,
        naming the pair."""
        for t, m in _union_pairs():
            with self.subTest(type=t, method=m):
                self.assertEqual(
                    _legacy_emit(t, m), _cir_emit(t, m),
                    f"{t}.{m}: the legacy transpiler and the CIR Python "
                    f"emitter disagree on the emitted expression. Re-sync "
                    f"capa/transpiler/_methods.py and "
                    f"capa/ir/_emit_python.py, or (if the difference is "
                    f"provably a pass-through to the shared fallback) record "
                    f"it in _VESTIGIAL_ONE_SIDED.",
                )

    def test_one_sided_special_cases_are_allowlisted_vestigial(self):
        """Any pair special-cased on exactly one side must be in the
        ``_VESTIGIAL_ONE_SIDED`` allowlist AND emit exactly the shared
        fallback. A new one-sided arm that is not allowlisted, or an
        allowlisted arm that stops being a pass-through, fails here."""
        one_sided = set()
        for t in _TYPES:
            legacy = _special_cased(_LEGACY_FN[t])
            cir = (
                _special_cased(getattr(PythonEmitter, _CIR_FN_NAME[t]))
                if t in _CIR_FN_NAME else set()
            )
            for m in legacy ^ cir:
                one_sided.add((t, m))

        self.assertEqual(
            one_sided, set(_VESTIGIAL_ONE_SIDED),
            "the set of one-sided special-cases changed: "
            f"{sorted(one_sided ^ set(_VESTIGIAL_ONE_SIDED))}. Either both "
            "tables should special-case the pair, or the arm is a vestigial "
            "pass-through to record in _VESTIGIAL_ONE_SIDED.",
        )
        for t, m in _VESTIGIAL_ONE_SIDED:
            with self.subTest(type=t, method=m):
                # The special-cased side must emit exactly the plain-call
                # fallback the other side already produces.
                self.assertEqual(_legacy_emit(t, m), _fallback(m, t))
                self.assertEqual(_cir_emit(t, m), _fallback(m, t))

    def test_no_stale_allowlist_entries(self):
        """Every allowlisted pair is really special-cased on exactly one
        side. Removing a Range arm without pruning the allowlist fails here
        rather than silently widening the accepted asymmetry."""
        for t, m in _VESTIGIAL_ONE_SIDED:
            with self.subTest(type=t, method=m):
                legacy = _special_cased(_LEGACY_FN[t])
                cir = (
                    _special_cased(getattr(PythonEmitter, _CIR_FN_NAME[t]))
                    if t in _CIR_FN_NAME else set()
                )
                self.assertIn(m, legacy ^ cir)


if __name__ == "__main__":
    unittest.main()
