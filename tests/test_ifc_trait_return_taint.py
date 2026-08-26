"""Trait-dispatch method return is tainted over its implementors (IFC-1).

A method call on a TRAIT-typed (dynamic-dispatch) receiver whose
implementor returns a ``@secret``-derived value used to be labelled
PUBLIC, so the secret reached a public sink with no warning at any tier
on all three backends -- a silent leak that defeated ``@strict_ifc``.

The root was an intra-vs-summary DRIFT: the trait-first result-label
ordering (a trait receiver takes the by-name union over every impl
method of this name, checked BEFORE the trait's own bodiless empty
exact-key entry so it cannot shadow the union) was applied correctly in
the cross-function summary (``_result_candidate_keys``) but open-coded
wrong in the two intra resolvers, whose empty trait exact key shadowed
the implementor union and failed the label open.

One label fix at the trait dispatch closes the whole class -- the
existing taint machinery (field-store join, interpolation join, secret
pc raise, downstream binding label feeding the cross-function sink
check) carries the now-correct SECRET label the rest of the way. These
tests pin the class:

* the seven leaking shapes (direct return, struct-field store, computed
  / interpolated return, implicit control flow, downstream cross-function
  flow, secret-param echo, mixed multi-implementor) each RED before the
  fix and GREEN after, at BOTH tiers where the tier applies; and
* four guards that MUST stay clean, since a false positive is the danger
  of a taint widening: all-public implementors (intra and cross-fn), a
  concrete receiver whose same-named user method keeps its exact key, and
  a built-in receiver whose same-named user method does not narrow its
  conservative join.
"""

import unittest

from capa import Lexer, Parser, analyze


def _analyze(src: str):
    mod = Parser(Lexer(src).lex(), source=src).parse_module()
    return analyze(mod, source=src)


def _strict(src: str, fn: str = "leak") -> str:
    """Opt the function ``fn`` (the one holding the sink / call site) into
    ``@strict_ifc``, so the leak that only warns by default becomes a hard
    error."""
    marker = "fun " + fn + "("
    return src.replace(marker, "@strict_ifc()\n" + marker, 1)


def _ifc_warns(r):
    return [w for w in r.warnings if "information-flow" in w.message]


def _ifc_errors(r):
    return [e for e in r.errors if "information-flow" in e.message]


# A trait whose implementor returns a @secret field (the INTERNAL_SECRET
# return-effect half, resolved by ``_method_call_returns_secret``).
_PROVIDER = (
    "trait Provider\n"
    "    fun provide(self) -> String\n"
    "type Vault { key: @secret String }\n"
    "impl Provider for Vault\n"
    "    fun provide(self) -> String\n"
    "        return self.key\n"
)

# A trait whose implementor ECHOES a @secret parameter (the param-echo
# return-effect half, resolved by ``_method_call_return_label``).
_ECHOER = (
    "trait Echoer\n"
    "    fun echo(self, x: String) -> String\n"
    "type E { pad: Int }\n"
    "impl Echoer for E\n"
    "    fun echo(self, x: String) -> String\n"
    "        return x\n"
)


def _assert_leaks_both_tiers(tc, src, needle=None):
    """A leaking shape: clean-but-warning by default, hard error under
    ``@strict_ifc``."""
    r = _analyze(src)
    tc.assertTrue(r.ok, [e.message for e in r.errors])
    w = _ifc_warns(r)
    tc.assertGreaterEqual(len(w), 1, [x.message for x in r.warnings])
    if needle is not None:
        tc.assertTrue(any(needle in x.message for x in w),
                      [x.message for x in w])
    rs = _analyze(_strict(src))
    tc.assertFalse(rs.ok, "expected a strict hard error")
    tc.assertGreaterEqual(len(_ifc_errors(rs)), 1,
                          [e.message for e in rs.errors])


def _assert_clean_both_tiers(tc, src):
    """A guard shape: no information-flow diagnostic at either tier."""
    for variant in (src, _strict(src)):
        r = _analyze(variant)
        tc.assertTrue(r.ok, [e.message for e in r.errors])
        tc.assertEqual(len(_ifc_warns(r)), 0, [w.message for w in r.warnings])
        tc.assertEqual(len(_ifc_errors(r)), 0, [e.message for e in r.errors])


class TestTraitReturnLeaks(unittest.TestCase):
    """The seven leaking manifestations, each RED before / GREEN after the
    single label fix, at both tiers where the tier applies."""

    def test_1_direct_sink_of_trait_return(self):
        # Case 1: implementor returns a @secret field; the trait-dispatch
        # return is sunk directly.
        src = _PROVIDER + (
            "fun leak(p: Provider, stdio: Stdio)\n"
            "    stdio.println(p.provide())\n"
        )
        _assert_leaks_both_tiers(self, src, needle="Stdio.println")

    def test_2_trait_return_stored_in_struct_field(self):
        # Case 2: the trait return is stashed in a struct field, then read
        # back and sunk (field-store join).
        src = _PROVIDER + (
            "type Wrap { data: String }\n"
            "fun leak(p: Provider, stdio: Stdio)\n"
            "    let w = Wrap { data: p.provide() }\n"
            "    stdio.println(w.data)\n"
        )
        _assert_leaks_both_tiers(self, src)

    def test_3_computed_interpolated_return(self):
        # Case 3: the trait return is interpolated into a larger string
        # (interpolation join).
        src = _PROVIDER + (
            "fun leak(p: Provider, stdio: Stdio)\n"
            "    stdio.println(\"prefix-${p.provide()}\")\n"
        )
        _assert_leaks_both_tiers(self, src)

    def test_4_implicit_flow_secret_bool_controls_sink(self):
        # Case 4: a @secret Bool trait return controls a branch that sinks.
        # An implicit flow is a strict-only mechanism BY DESIGN (the default
        # tier stays focused on explicit data leaks), so the load-bearing
        # flip here is strict rc0 -> rc1: with the bug ``p.check()`` is
        # PUBLIC, the pc stays public and no implicit flow is seen; the fix
        # labels it SECRET, the branch pc goes secret and the enclosed sink
        # is rejected. The default tier is verified to stay clean (not a
        # missed leak: implicit flows are never a default-tier warning).
        src = (
            "trait Flag\n"
            "    fun check(self) -> Bool\n"
            "type Vault { key: @secret Bool }\n"
            "impl Flag for Vault\n"
            "    fun check(self) -> Bool\n"
            "        return self.key\n"
            "fun leak(p: Flag, stdio: Stdio)\n"
            "    if p.check()\n"
            "        stdio.println(\"branch taken\")\n"
        )
        r = _analyze(src)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_ifc_warns(r)), 0, [w.message for w in r.warnings])
        rs = _analyze(_strict(src))
        self.assertFalse(rs.ok, "expected a strict implicit-flow error")
        self.assertTrue(
            any("secret control flow" in e.message for e in rs.errors),
            [e.message for e in rs.errors],
        )

    def test_5_intra_mislabel_poisons_crossfn_flow(self):
        # Case 5: the trait return is bound to a local and passed to a
        # helper that sinks its parameter. The intra label feeds the
        # cross-function boundary check.
        src = _PROVIDER + (
            "fun sink_it(s: String, stdio: Stdio)\n"
            "    stdio.println(s)\n"
            "fun leak(p: Provider, stdio: Stdio)\n"
            "    let x = p.provide()\n"
            "    sink_it(x, stdio)\n"
        )
        _assert_leaks_both_tiers(self, src, needle="sink_it")

    def test_6_trait_method_echoes_secret_param(self):
        # Case 6: the implementor returns a @secret PARAMETER (the
        # return-label half, resolved by ``_method_call_return_label``).
        src = _ECHOER + (
            "fun leak(e: Echoer, stdio: Stdio, secret: @secret String)\n"
            "    stdio.println(e.echo(secret))\n"
        )
        _assert_leaks_both_tiers(self, src, needle="Stdio.println")

    def test_7_multi_implementor_mixed(self):
        # Case 7: two implementors, only one returns a secret. The by-name
        # union fires (secret iff SOME implementor is secret).
        src = (
            "trait Provider\n"
            "    fun provide(self) -> String\n"
            "type PubVault { note: String }\n"
            "impl Provider for PubVault\n"
            "    fun provide(self) -> String\n"
            "        return self.note\n"
            "type SecVault { key: @secret String }\n"
            "impl Provider for SecVault\n"
            "    fun provide(self) -> String\n"
            "        return self.key\n"
            "fun leak(p: Provider, stdio: Stdio)\n"
            "    stdio.println(p.provide())\n"
        )
        _assert_leaks_both_tiers(self, src, needle="Stdio.println")


class TestTraitReturnGuards(unittest.TestCase):
    """The false-positive guards: a widening taint must not perturb these
    clean shapes."""

    def test_8_all_public_implementors_intra(self):
        # Guard 8: every implementor returns a public field. The by-name
        # union is all-public, so the direct sink stays clean.
        src = (
            "trait Provider\n"
            "    fun provide(self) -> String\n"
            "type PubVault { note: String }\n"
            "impl Provider for PubVault\n"
            "    fun provide(self) -> String\n"
            "        return self.note\n"
            "type Pub2 { note: String }\n"
            "impl Provider for Pub2\n"
            "    fun provide(self) -> String\n"
            "        return self.note\n"
            "fun leak(p: Provider, stdio: Stdio)\n"
            "    stdio.println(p.provide())\n"
        )
        _assert_clean_both_tiers(self, src)

    def test_9_all_public_implementors_crossfn(self):
        # Guard 9: the all-public union bound to a local and passed across a
        # boundary stays clean.
        src = (
            "trait Provider\n"
            "    fun provide(self) -> String\n"
            "type PubVault { note: String }\n"
            "impl Provider for PubVault\n"
            "    fun provide(self) -> String\n"
            "        return self.note\n"
            "type Pub2 { note: String }\n"
            "impl Provider for Pub2\n"
            "    fun provide(self) -> String\n"
            "        return self.note\n"
            "fun sink_it(s: String, stdio: Stdio)\n"
            "    stdio.println(s)\n"
            "fun leak(p: Provider, stdio: Stdio)\n"
            "    let x = p.provide()\n"
            "    sink_it(x, stdio)\n"
        )
        _assert_clean_both_tiers(self, src)

    def test_10_concrete_receiver_keeps_exact_key(self):
        # Guard 10: a CONCRETE receiver whose type has an exact impl-method
        # key must use THAT key, not the by-name union, so a same-named
        # secret-returning method on an unrelated type cannot taint it. This
        # guards that the ``_is_trait_type`` scoping did not perturb the
        # concrete path.
        src = (
            "type PubBox { note: String }\n"
            "impl PubBox\n"
            "    fun provide(self) -> String\n"
            "        return self.note\n"
            "type SecBox { key: @secret String }\n"
            "impl SecBox\n"
            "    fun provide(self) -> String\n"
            "        return self.key\n"
            "fun leak(b: PubBox, stdio: Stdio)\n"
            "    stdio.println(b.provide())\n"
        )
        _assert_clean_both_tiers(self, src)

    def test_11_builtin_receiver_conservative_join_unchanged(self):
        # Guard 11: a built-in receiver (List) with a same-named user method
        # elsewhere keeps its conservative whole-value join; the user method
        # does not narrow or taint the built-in result.
        src = (
            "type Wrapper { pad: Int }\n"
            "impl Wrapper\n"
            "    fun get(self, x: String) -> String\n"
            "        return x\n"
            "fun leak(xs: List<String>, i: Int, stdio: Stdio)\n"
            "    match xs.get(i)\n"
            "        Some(v) -> stdio.println(v)\n"
            "        None -> stdio.println(\"none\")\n"
        )
        _assert_clean_both_tiers(self, src)


if __name__ == "__main__":
    unittest.main()
