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

BACKEND REACHABILITY (seam 3 of .claude/STDLIB_DESIGN.md, corrected by
.claude/STDLIB_CONTEST_1.md item 3)

The agreement net above is blind to a method that is DECLARED in
``capa.builtins.METHODS`` but implemented on neither Python side: both
tables fall through to the same ``recv.method(args)`` call, so they agree,
and the call reaches whatever Python object backs the receiver at run
time. Measured: a declared ``List.pop`` with no implementation runs the
inherited ``list.pop``, mutates the list and exits 0 while the type system
promised an ``Option``. ``TestBackendReachability`` and
``TestRangeReachability`` close that hole, with a shape per owner, because
the owners are backed differently: a CLASS-BACKED owner has a Capa runtime
class per variant and every declared method must be implemented by the
Capa runtime for EVERY variant (an attribute lookup is exactly what the
inherited ``list.pop`` satisfies, so the guard asks which class defines
the name); a BARE-BUILTIN owner (``Map`` is a ``dict``, ``String`` a
``str``) has no class to check, so every declared method must be
special-cased in BOTH emit tables and can never reach the fallthrough. An
inherited-name quarantine lists the declared names that collide with the
Python builtin and proves each is routed on purpose (a Capa override, or
an arm in both tables) rather than falling through to it. ``Range``
reaches the Wasm backend only through four direct arms or the CIR
``to_list`` desugar, so its guard reads both.
"""

import inspect
import re
import unittest

from capa.builtins import METHODS
from capa.ir._emit_python import PythonEmitter
from capa.ir._emit_wasm._lists import _ListEmissionMixin
from capa.ir._lower_expr import _RANGE_DESUGAR_METHODS
from capa.runtime._json import JArr, JBool, JNull, JNum, JObj, JStr
from capa.runtime._list import CapaList, CapaRange
from capa.runtime._result import Err, Ok, Some, _NoneType
from capa.runtime._set import CapaSet
from capa.transpiler._methods import _MethodsMixin
from capa.typesys import CAPABILITY_NAMES

from tests._declared_methods import declared_methods


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


def _cir_special_cased(t):
    """The CIR emitter's special-cased names for ``t``; empty for a type
    with no CIR table (``Range``), whose calls always fall back."""
    if t not in _CIR_FN_NAME:
        return set()
    return _special_cased(getattr(PythonEmitter, _CIR_FN_NAME[t]))


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
        cir = _cir_special_cased(t)
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
            cir = _cir_special_cased(t)
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
                cir = _cir_special_cased(t)
                self.assertIn(m, legacy ^ cir)


# ----------------------------------------------------------------------
# Backend reachability (seam 3). See the module docstring.
# ----------------------------------------------------------------------

#: owner -> the runtime classes backing EVERY variant of its values. A
#: declared method must be implemented for each of them; ``Option`` and
#: ``Result`` have two variant classes with no shared Capa base, so a
#: method written on one variant only raises AttributeError the first
#: time the other variant shows up.
_RUNTIME_CLASSES: dict[str, tuple[type, ...]] = {
    "List": (CapaList,),
    "Range": (CapaRange,),
    "Set": (CapaSet,),
    "Option": (Some, _NoneType),
    "Result": (Ok, Err),
    "JsonValue": (JNull, JBool, JNum, JStr, JArr, JObj),
}

#: Owners represented by a bare Python builtin: no Capa class to check,
#: so reachability is proven by the two emit tables instead.
_BARE_BUILTIN_OWNERS: tuple[str, ...] = ("Map", "String")

#: owner -> the Python builtin its values ARE (a ``CapaList`` subclasses
#: ``list``) or are REPRESENTED AS (a Map is a ``dict``, a String a
#: ``str``). A declared name that is also an attribute of that builtin
#: is the inherited-name hazard: the fallthrough call would silently run
#: the builtin's method.
_PYTHON_BUILTIN: dict[str, type] = {
    "List": list,
    "Map": dict,
    "String": str,
}

#: Declared names that collide with an attribute of the owner's Python
#: builtin and are deliberately kept. Each is proven by
#: ``test_every_quarantined_collision_never_falls_through_to_the_builtin``
#: to be routed on purpose: a Capa override for a class-backed owner, an
#: arm in both emit tables for a bare-builtin owner. The arm may itself
#: call the builtin, wrapped or guarded (``Map.keys`` / ``Map.values`` /
#: ``String.split`` wrap ``dict.keys`` / ``dict.values`` / ``str.split``
#: in a ``CapaList``; ``String.replace`` calls ``str.replace`` when the
#: needle is non-empty); what is refused is the plain ``recv.method(args)``
#: fallback reaching the builtin with the builtin's own semantics. A NEW
#: collision that is not listed here, or a listed one that no longer
#: collides, fails
#: ``test_inherited_name_collisions_are_exactly_the_quarantined_ones``.
_QUARANTINED_COLLISIONS = frozenset({
    ("List", "reverse"),
    ("Map", "get"),
    ("Map", "keys"),
    ("Map", "values"),
    ("String", "replace"),
    ("String", "split"),
})


def _implementing_class(cls, name):
    """The class in ``cls``'s MRO whose OWN dictionary defines ``name``,
    or None. It is what an attribute lookup would find, which is why the
    guard then asks which class it was rather than whether it exists."""
    for base in cls.__mro__:
        if name in vars(base):
            return base
    return None


def _capa_implements(cls, name):
    """True iff ``name`` is defined by a class of the Capa runtime, not
    by a Python builtin further up the MRO. ``list.pop`` reached through
    ``CapaList`` is exactly what this refuses."""
    impl = _implementing_class(cls, name)
    return impl is not None and impl.__module__.startswith("capa.runtime")


def _wasm_direct_range_arms():
    """The Range methods the Wasm backend emits directly, read from the
    ``_emit_range_method_call`` dispatch arms."""
    return _special_cased(_ListEmissionMixin._emit_range_method_call)


class TestBackendReachability(unittest.TestCase):
    def test_every_non_capability_owner_is_classified(self):
        """Guard the guard: a new non-capability owner must be either
        class-backed or bare-builtin-backed, never silently unchecked.
        Capability owners are security surfaces outside this net."""
        owners = {o for o in METHODS if o not in CAPABILITY_NAMES}
        classified = set(_RUNTIME_CLASSES) | set(_BARE_BUILTIN_OWNERS)
        self.assertEqual(
            owners, classified,
            "capa.builtins.METHODS has a non-capability owner that is "
            "neither in _RUNTIME_CLASSES nor in _BARE_BUILTIN_OWNERS: "
            f"{sorted(owners ^ classified)}",
        )
        self.assertEqual(set(_RUNTIME_CLASSES) & set(_BARE_BUILTIN_OWNERS), set())

    def test_class_backed_owner_implements_every_method_on_every_variant(self):
        """The fail-closed bite for member shapes 2 and 3 of the design: a
        declared method with no Capa implementation on SOME variant class
        fails here, naming the class and, when an inherited Python
        attribute would have answered instead, naming that too."""
        for owner, classes in sorted(_RUNTIME_CLASSES.items()):
            for name in declared_methods(owner):
                for cls in classes:
                    with self.subTest(owner=owner, method=name, cls=cls.__name__):
                        impl = _implementing_class(cls, name)
                        if impl is None:
                            reached = "the call would raise AttributeError at run time"
                        else:
                            reached = (
                                f"attribute lookup reaches {impl.__module__}."
                                f"{impl.__name__}.{name}, the inherited-name hazard"
                            )
                        self.assertTrue(
                            _capa_implements(cls, name),
                            f"{owner}.{name} is declared in capa.builtins.METHODS "
                            f"but {cls.__name__} does not implement it; {reached}",
                        )

    def test_bare_builtin_owner_is_special_cased_in_both_emit_tables(self):
        """A Map / String method with no arm in one emit table would fall
        through to ``recv.method(args)`` on a bare ``dict`` / ``str``."""
        for owner in _BARE_BUILTIN_OWNERS:
            legacy = _special_cased(_LEGACY_FN[owner])
            cir = _cir_special_cased(owner)
            for name in declared_methods(owner):
                with self.subTest(owner=owner, method=name):
                    self.assertIn(
                        name, legacy,
                        f"{owner}.{name} is declared but the legacy transpiler "
                        f"has no arm for it (capa/transpiler/_methods.py)",
                    )
                    self.assertIn(
                        name, cir,
                        f"{owner}.{name} is declared but the CIR Python emitter "
                        f"has no arm for it (capa/ir/_emit_python.py)",
                    )

    def test_inherited_name_collisions_are_exactly_the_quarantined_ones(self):
        collisions = {
            (owner, name)
            for owner, builtin in _PYTHON_BUILTIN.items()
            for name in declared_methods(owner)
            if hasattr(builtin, name)
        }
        self.assertEqual(
            collisions, set(_QUARANTINED_COLLISIONS),
            "the declared names colliding with a Python builtin attribute "
            "changed: "
            f"{sorted(collisions ^ set(_QUARANTINED_COLLISIONS))}. A new "
            "collision must be implemented so it bypasses the builtin AND "
            "recorded in _QUARANTINED_COLLISIONS; a stale entry must go.",
        )

    def test_every_quarantined_collision_never_falls_through_to_the_builtin(self):
        for owner, name in sorted(_QUARANTINED_COLLISIONS):
            with self.subTest(owner=owner, method=name):
                if owner in _RUNTIME_CLASSES:
                    for cls in _RUNTIME_CLASSES[owner]:
                        self.assertTrue(
                            _capa_implements(cls, name),
                            f"{owner}.{name} collides with "
                            f"{_PYTHON_BUILTIN[owner].__name__}.{name} and "
                            f"{cls.__name__} does not override it",
                        )
                else:
                    self.assertIn(name, _special_cased(_LEGACY_FN[owner]))
                    self.assertIn(name, _cir_special_cased(owner))


class TestRangeReachability(unittest.TestCase):
    """A Range value reaches the Wasm backend only through the direct
    arms of ``_emit_range_method_call`` (length / contains / is_empty /
    to_list) or the CIR desugar ``_RANGE_DESUGAR_METHODS``, which rewrites
    ``r.m(...)`` to ``r.to_list().m(...)`` before either backend sees it.
    A Range method declared with a ``CapaRange`` implementation but in
    neither set type-checks, runs on both Python paths and is rejected by
    ``--wasm`` at compile time (contest P6)."""

    def test_every_declared_range_method_is_direct_or_desugared(self):
        declared = set(declared_methods("Range"))
        unreachable = declared - _wasm_direct_range_arms() - set(_RANGE_DESUGAR_METHODS)
        self.assertEqual(
            sorted(unreachable), [],
            "Range methods declared with no Wasm arm and no to_list "
            f"desugar: {sorted(unreachable)}. Add a direct arm in "
            "capa/ir/_emit_wasm/_lists.py or add the name to "
            "_RANGE_DESUGAR_METHODS in capa/ir/_lower_expr.py.",
        )

    def test_every_desugared_method_is_declared_on_range_and_list(self):
        # The desugar retargets the call to List, so a stale entry (a
        # name Range no longer declares, or List does not declare) would
        # rewrite a call that cannot exist or to a method that does not.
        for name in sorted(_RANGE_DESUGAR_METHODS):
            with self.subTest(method=name):
                self.assertIn(name, declared_methods("Range"))
                self.assertIn(name, declared_methods("List"))

    def test_direct_arms_and_desugar_do_not_overlap(self):
        # One lowering per name: a name in both sets would be desugared
        # before the direct arm could ever run, leaving that arm dead.
        self.assertEqual(
            _wasm_direct_range_arms() & set(_RANGE_DESUGAR_METHODS), set(),
        )


if __name__ == "__main__":
    unittest.main()
