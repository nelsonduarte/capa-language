"""M2b: a fail-closed AGREEMENT net for the two capability classifications.

A program's used capabilities are classified in TWO places, once for each
artifact the Wasm backend produces:

- ``capa.ir._emit_wasm._discovery._DiscoveryMixin._discover_instrs`` builds
  ``self._used_caps`` (the ``(cap, method)`` pairs that become core-wasm host
  imports), and
- ``capa.ir._emit_wit.collect_used_capabilities`` builds the ``cap ->
  {method}`` map the WIT interface is derived from.

The AST walk itself is already shared (``capa.ir._walk``); it is the
CLASSIFICATION that is duplicated -- the attenuator split
(``restrict_to`` / ``restrict_to_keys`` / ``restrict_to_after``), the
``allows`` host-route, and the Random / Clock host-import synthesis. The two
must agree or the Component Model linker rejects the artifact (a core-wasm
import with no matching WIT function, or vice versa). M2 does not consolidate
them (that is a later item); it only adds this net so a future divergence
fails HERE.

WHAT THIS ASSERTS

Both classifiers are run over the same synthetic instruction streams and
their ``(cap, method)`` outputs are compared. For each stream the pairs one
side produces and the other does not must lie inside the small, explicit
``_KNOWN_ASYMMETRIES`` allowlist below; anything else is drift and fails,
naming the pair.

MODELLING THE LEGITIMATE ASYMMETRIES (so the net bites on REAL drift only)

- ``Serve`` / ``Unsafe`` (``PYTHON_ONLY_CAPS``) are DELIBERATELY absent from
  the corpus. The discovery pass rejects them wholesale before classifying,
  while the WIT collector records them for the later ``_KNOWN_CAPABILITIES``
  filter in ``emit_wit`` -- a known, intentional difference, not drift. The
  corpus therefore covers exactly ``BUILTIN_CAPS - PYTHON_ONLY_CAPS`` (which
  equals ``_emit_wit._KNOWN_CAPABILITIES``).
- The three guest-side ``Random`` methods (``with_seed`` / ``int_range`` /
  ``float_unit``) and the attenuated-``Clock.sleep`` deadline gate
  (``now_secs``) are synthesised differently by the two passes but agree on
  the actual host import (``Random.system_seed`` respectively the inline
  ``now-secs`` gate). These are the ``_KNOWN_ASYMMETRIES`` allowlist, and the
  test asserts the allowlist is exactly the asymmetry the corpus witnesses,
  so a stale or missing entry fails too.

This is pure Python over hand-built IR (no wasm tooling, no compilation), so
it always collects. It is additive: it changes no production behaviour.
"""

import unittest

from capa.builtins import METHODS
from capa.ir._capa_types import BUILTIN_CAPS
from capa.ir._python_only_caps import PYTHON_ONLY_CAPS
from capa.ir._nodes import MethodCall, Value, Function, Module
from capa.ir._emit_wasm._discovery import _DiscoveryMixin
from capa.ir._emit_wit import collect_used_capabilities


#: The capabilities both passes are expected to classify identically: every
#: built-in cap except the Python-only ones the discovery pass rejects up
#: front. This is exactly ``_emit_wit._KNOWN_CAPABILITIES``.
_CLASSIFIED_CAPS = sorted(BUILTIN_CAPS - set(PYTHON_ONLY_CAPS))

#: Pairs the WIT collector records that the discovery pass does not (or vice
#: versa), each a documented synthesis difference that agrees on the real
#: host import. Guest-side Random methods collapse to
#: ``(Random, system_seed)`` in discovery but keep their source name in the
#: collector (filtered out of the WIT interface later by ``emit_wit``'s
#: guest-only set); an attenuated ``Clock.sleep`` makes the collector add
#: ``(Clock, now_secs)`` for the inline deadline gate the discovery pass
#: emits without a separate import.
_KNOWN_ASYMMETRIES = frozenset({
    ("Random", "with_seed"),
    ("Random", "int_range"),
    ("Random", "float_unit"),
    ("Clock", "now_secs"),
})


class _Discovery(_DiscoveryMixin):
    """The discovery classifier in isolation. ``_discover_instrs`` needs only
    a ``_used_caps`` set and an ``_intern_string`` sink (the string-interning
    side effect is irrelevant to the capability classification under test);
    the shared ``_values_of`` walk is inherited from the mixin."""

    def __init__(self):
        self._used_caps = set()

    def _intern_string(self, _s):
        pass


def _method_call(cap, method, attenuations=None):
    recv = Value(kind="local", name="r", ty=cap)
    return MethodCall(
        dst="d", receiver=recv, method=method, args=[],
        cap_used=cap, attenuations=attenuations,
    )


def _discovery_pairs(instrs):
    d = _Discovery()
    d._discover_instrs(instrs)
    return set(d._used_caps)


def _wit_pairs(instrs):
    fn = Function(
        name="main", params=[], return_type="Unit",
        declared_caps=[], body=instrs,
    )
    used = collect_used_capabilities(Module(functions=[fn]))
    return {(cap, m) for cap, methods in used.items() for m in methods}


def _full_corpus():
    """One call site for every source method of every classified capability,
    plus an attenuated ``Clock.sleep`` so the deadline-gate path is walked."""
    instrs = []
    for cap in _CLASSIFIED_CAPS:
        for m, _ty, _mty_params in METHODS.get(cap, []):
            instrs.append(_method_call(cap, m))
    instrs.append(_method_call(
        "Clock", "sleep",
        attenuations=[{"method": "restrict_to_after", "args": ["1"]}],
    ))
    return instrs


def _attenuated_sleep_only():
    """An attenuated ``Clock.sleep`` with no direct ``now_secs`` call, so the
    collector's synthesised ``(Clock, now_secs)`` is not masked by a shared
    direct use."""
    return [_method_call(
        "Clock", "sleep",
        attenuations=[{"method": "restrict_to_after", "args": ["1"]}],
    )]


#: (label, instruction stream) pairs the agreement is asserted over.
_SCENARIOS = [
    ("all classified capability methods", _full_corpus()),
    ("attenuated Clock.sleep only", _attenuated_sleep_only()),
]


class TestCapabilityClassificationAgreement(unittest.TestCase):
    def test_classified_caps_match_wit_known_capabilities(self):
        """The corpus's capability set is exactly the WIT side's deliberate
        ``_KNOWN_CAPABILITIES`` subset, so a cap graduating into or out of the
        Python-only set is reflected here rather than silently changing what
        the net covers."""
        from capa.ir._emit_wit import _KNOWN_CAPABILITIES
        self.assertEqual(set(_CLASSIFIED_CAPS), set(_KNOWN_CAPABILITIES))

    def test_classifications_agree_within_the_allowlist(self):
        """The fail-closed bite: for each scenario, every pair one classifier
        produces and the other does not must be an allowlisted, documented
        synthesis difference. A drift (a cap method the two passes classify
        differently) fails here, naming the pair and the scenario."""
        for label, instrs in _SCENARIOS:
            with self.subTest(scenario=label):
                disc = _discovery_pairs(instrs)
                wit = _wit_pairs(instrs)
                divergence = disc ^ wit
                unexpected = divergence - _KNOWN_ASYMMETRIES
                self.assertEqual(
                    sorted(unexpected), [],
                    f"[{label}] the Wasm discovery pass and the WIT collector "
                    f"classify these capability pairs differently: "
                    f"{sorted(unexpected)}. Re-sync the classification in "
                    f"capa/ir/_emit_wasm/_discovery.py and "
                    f"capa/ir/_emit_wit.py, or (if it is a deliberate "
                    f"synthesis difference) record it in _KNOWN_ASYMMETRIES.",
                )

    def test_classifiers_share_a_non_trivial_agreement(self):
        """Sanity: the two agree on a substantial common set, so the net is
        exercising real classification rather than comparing two empties."""
        disc = _discovery_pairs(_full_corpus())
        wit = _wit_pairs(_full_corpus())
        self.assertGreater(len(disc & wit), 10)

    def test_allowlist_is_exactly_witnessed(self):
        """No stale allowlist entries: every ``_KNOWN_ASYMMETRIES`` pair is
        actually produced as a one-sided divergence by some scenario, and the
        scenarios produce no allowlisted pair the union does not cover."""
        witnessed = set()
        for _label, instrs in _SCENARIOS:
            witnessed |= (_discovery_pairs(instrs) ^ _wit_pairs(instrs))
        self.assertEqual(witnessed, set(_KNOWN_ASYMMETRIES))


if __name__ == "__main__":
    unittest.main()
