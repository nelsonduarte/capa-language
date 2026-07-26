"""Declared capability bound on ``pub`` trait methods (the ``uses [...]``
clause), the opt-in precision recovery over 1.23.0's pub-trait-fail-closed.

1.23.0 made an unannotated ``pub``-trait-typed signature position authority-
UNPROVABLE (fail closed), because a downstream package could implement the
trait with a capability-bearing type the declaring package cannot see. This
feature lets a ``pub`` trait METHOD declare the capability bound it may
exercise (``uses []`` for pure, ``uses [Net]`` for a bound), so the position
is charged precisely and each ``impl`` is checked to conform. It is purely
additive: an unannotated ``pub`` trait method keeps the fail-closed behaviour.

The amendments folded in here:

- A1 (per-position): a ``pub`` trait leaves the unprovable set IFF EVERY one
  of its methods is bounded; a bounded method beside an unbounded sibling
  keeps the whole trait unprovable.
- A2 (seed B, not the visible union): a bounded ``pub`` trait charges the
  declared bound-union; a PRIVATE trait keeps its implementor-union charge, a
  ``uses`` clause on it is redundant and never reduces the charge.
- A3 (conformance): each impl method's footprint (params, return, receiver +
  its type arguments) must be a subset of the trait method's declared bound.
- A4 (fail-closed shapes): a Fun in the impl signature, a free type parameter,
  or a nested-generic free type argument yields TOP, which is not a subset of
  any non-top bound and is rejected by construction.
"""

import unittest

from capa import Lexer, Parser, analyze
from capa.formatter import format_source
from capa.manifest import build_manifest


def _analyze(source: str):
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    return analyze(module, source=source)


def _errors(source: str) -> list[str]:
    return [e.message for e in _analyze(source).errors]


def _manifest(source: str):
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    result = analyze(module, source=source)
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    return build_manifest(module)


def _fn(manifest, name, container=None):
    for f in manifest["functions"]:
        if f["name"] == name and f["container"] == container:
            return f
    raise AssertionError(f"no function {name!r} (container={container!r})")


# =============================================================
# Parse + store + round-trip
# =============================================================

class TestParseAndStore(unittest.TestCase):
    def _method(self, source: str, trait: str, method: str):
        import capa.capa_ast as A
        tokens = Lexer(source).lex()
        module = Parser(tokens, source=source).parse_module()
        for it in module.items:
            if isinstance(it, A.TraitDecl) and it.name == trait:
                for m in it.methods:
                    if m.name == method:
                        return m
        raise AssertionError(f"no {trait}.{method}")

    def test_empty_uses_is_stored_as_empty_list(self):
        src = (
            "pub trait Reporter\n"
            "    fun render(self) -> String uses []\n"
        )
        m = self._method(src, "Reporter", "render")
        self.assertEqual(m.uses, [])

    def test_uses_with_atom_is_stored(self):
        src = (
            "pub trait Sender\n"
            "    fun send(self, netx: Net) -> Unit uses [Net]\n"
        )
        m = self._method(src, "Sender", "send")
        self.assertEqual(m.uses, ["Net"])

    def test_multiple_atoms(self):
        src = (
            "pub trait Multi\n"
            "    fun go(self, netx: Net, fsx: Fs) -> Unit uses [Net, Fs]\n"
        )
        m = self._method(src, "Multi", "go")
        self.assertEqual(m.uses, ["Net", "Fs"])

    def test_absent_clause_is_none(self):
        src = (
            "pub trait Reporter\n"
            "    fun render(self) -> String\n"
        )
        m = self._method(src, "Reporter", "render")
        self.assertIsNone(m.uses)

    def test_uses_without_return_type(self):
        src = (
            "pub trait Reporter\n"
            "    fun ping(self) uses []\n"
        )
        m = self._method(src, "Reporter", "ping")
        self.assertEqual(m.uses, [])

    def test_uses_is_a_contextual_keyword(self):
        # ``uses`` stays usable as an ordinary identifier elsewhere.
        src = (
            "fun f(uses: Int) -> Int\n"
            "    return uses\n"
        )
        self.assertTrue(_analyze(src).ok, _errors(src))

    def test_formatter_round_trips_the_clause(self):
        src = (
            "pub trait Reporter\n"
            "    fun render(self, data: String) -> String uses []\n"
            "    fun send(self, netx: Net) -> Unit uses [Net]\n"
        )
        formatted = format_source(src)
        self.assertIn("uses []", formatted)
        self.assertIn("uses [Net]", formatted)
        # Idempotent: reformatting the formatted text keeps the clause.
        self.assertEqual(format_source(formatted), formatted)


# =============================================================
# Precision restored (A2 caller-charges-B), tight ceiling
# =============================================================

_PURE_PUB_TRAIT = (
    "pub trait Greeter\n"
    "    fun greet(self) -> Unit uses []\n"
    "\n"
    "type Quiet {\n"
    "    n: Int\n"
    "}\n"
    "\n"
    "impl Greeter for Quiet\n"
    "    fun greet(self) -> Unit\n"
    "        return\n"
    "\n"
    "fun use_greeter(g: Greeter) -> Unit\n"
    "    g.greet()\n"
    "    return\n"
)


class TestPrecisionRestored(unittest.TestCase):
    def test_pure_pub_trait_is_provable_with_empty_ceiling(self):
        m = _manifest(_PURE_PUB_TRAIT)
        f = _fn(m, "use_greeter")
        self.assertTrue(f["authority_provable_from_types"])
        self.assertEqual(f["transitively_reachable_capabilities"], [])
        # And it makes no FALSE exclusion: every built-in is provably
        # excluded because the pure bound charges nothing.
        self.assertIn("Stdio", f["provably_excluded_capabilities"])
        self.assertIn("Net", f["provably_excluded_capabilities"])

    def test_unannotated_pub_trait_stays_unprovable(self):
        # No regression: dropping the clause restores 1.23.0 fail-closed.
        src = _PURE_PUB_TRAIT.replace(" uses []", "")
        m = _manifest(src)
        f = _fn(m, "use_greeter")
        self.assertFalse(f["authority_provable_from_types"])
        # Unprovable voids the exclusion list entirely.
        self.assertEqual(f["provably_excluded_capabilities"], [])

    def test_bounded_net_trait_charges_net_not_more(self):
        src = (
            "pub trait Sender\n"
            "    fun send(self, _netx: Net) -> Unit uses [Net]\n"
            "\n"
            "type S { n: Int }\n"
            "\n"
            "impl Sender for S\n"
            "    fun send(self, _netx: Net) -> Unit\n"
            "        return\n"
            "\n"
            "fun use_sender(s: Sender) -> Unit\n"
            "    return\n"
        )
        m = _manifest(src)
        f = _fn(m, "use_sender")
        self.assertTrue(f["authority_provable_from_types"])
        self.assertIn("Net", f["transitively_reachable_capabilities"])
        self.assertNotIn("Net", f["provably_excluded_capabilities"])
        # Caps outside the bound are still provably excluded.
        self.assertIn("Fs", f["provably_excluded_capabilities"])


# =============================================================
# A1: per-position precision (all-or-nothing)
# =============================================================

class TestPerPosition(unittest.TestCase):
    def test_bounded_beside_unbounded_sibling_stays_unprovable(self):
        src = (
            "pub trait Two\n"
            "    fun a(self) -> Unit uses []\n"
            "    fun b(self) -> Unit\n"
            "\n"
            "type T2 { n: Int }\n"
            "\n"
            "impl Two for T2\n"
            "    fun a(self) -> Unit\n"
            "        return\n"
            "    fun b(self) -> Unit\n"
            "        return\n"
            "\n"
            "fun use_two(t: Two) -> Unit\n"
            "    return\n"
        )
        m = _manifest(src)
        f = _fn(m, "use_two")
        self.assertFalse(f["authority_provable_from_types"])


# =============================================================
# A2: private trait keeps its implementor-union charge
# =============================================================

_PRIVATE_WITH_USES = (
    "capability Notifier\n"
    "    fun announce(self, msg: String) -> Unit\n"
    "\n"
    "type StdioThing { out: Stdio }\n"
    "\n"
    "impl Notifier for StdioThing\n"
    "    fun announce(self, msg: String) -> Unit\n"
    "        self.out.println(msg)\n"
    "        return\n"
    "\n"
    "trait Greeter\n"
    "    fun greet(self) -> Unit uses []\n"
    "\n"
    "impl Greeter for StdioThing\n"
    "    fun greet(self) -> Unit\n"
    "        self.out.println(\"hi\")\n"
    "        return\n"
    "\n"
    "fun use_greeter(g: Greeter) -> Unit\n"
    "    g.greet()\n"
    "    return\n"
)


class TestPrivateTraitUnchanged(unittest.TestCase):
    def test_private_trait_uses_clause_does_not_reduce_charge(self):
        # A ``uses []`` on a PRIVATE trait is redundant: the trait keeps
        # the implementor-union charge, so Stdio is still charged and is
        # NOT falsely excluded (A2).
        m = _manifest(_PRIVATE_WITH_USES)
        f = _fn(m, "use_greeter")
        self.assertIn("Stdio", f["transitively_reachable_capabilities"])
        self.assertNotIn("Stdio", f["provably_excluded_capabilities"])


# =============================================================
# A3: conformance rejects excess
# =============================================================

class TestConformanceRejectsExcess(unittest.TestCase):
    def test_pure_bound_but_impl_takes_fs_is_rejected(self):
        src = (
            "pub trait Writer\n"
            "    fun run(self, _fsx: Fs) -> Unit uses []\n"
            "\n"
            "type W { n: Int }\n"
            "\n"
            "impl Writer for W\n"
            "    fun run(self, _fsx: Fs) -> Unit\n"
            "        return\n"
        )
        errs = _errors(src)
        self.assertTrue(
            any("'Fs'" in e and "outside the bound []" in e for e in errs),
            errs,
        )

    def test_impl_within_bound_passes(self):
        src = (
            "pub trait Sender\n"
            "    fun send(self, _netx: Net) -> Unit uses [Net]\n"
            "\n"
            "type S { n: Int }\n"
            "\n"
            "impl Sender for S\n"
            "    fun send(self, _netx: Net) -> Unit\n"
            "        return\n"
        )
        self.assertTrue(_analyze(src).ok, _errors(src))

    def test_impl_reaches_cap_via_receiver_field_is_rejected(self):
        # The receiver struct is cap-bearing (holds Stdio through a user
        # cap); a ``uses []`` render can exercise Stdio through ``self``,
        # so it must be rejected (A3 receiver inclusion).
        src = (
            "capability Notifier\n"
            "    fun announce(self, msg: String) -> Unit\n"
            "\n"
            "type FileReporter { out: Stdio }\n"
            "\n"
            "impl Notifier for FileReporter\n"
            "    fun announce(self, msg: String) -> Unit\n"
            "        self.out.println(msg)\n"
            "        return\n"
            "\n"
            "pub trait Reporter\n"
            "    fun render(self) -> Unit uses []\n"
            "\n"
            "impl Reporter for FileReporter\n"
            "    fun render(self) -> Unit\n"
            "        self.out.println(\"x\")\n"
            "        return\n"
        )
        errs = _errors(src)
        self.assertTrue(
            any("'render'" in e and "Stdio" in e for e in errs), errs,
        )

    def test_impl_reaches_cap_via_param_type_is_rejected(self):
        # A param typed as a cap-bearing struct pulls in that struct's
        # caps (Net via Smtp), outside the pure bound (A3 param inclusion).
        src = (
            "capability Emailer\n"
            "    fun em(self) -> Unit\n"
            "\n"
            "type Smtp { net: Net }\n"
            "\n"
            "impl Emailer for Smtp\n"
            "    fun em(self) -> Unit\n"
            "        return\n"
            "\n"
            "pub trait Maker\n"
            "    fun make(self, s: Smtp) -> Unit uses []\n"
            "\n"
            "type Mk { n: Int }\n"
            "\n"
            "impl Maker for Mk\n"
            "    fun make(self, s: Smtp) -> Unit\n"
            "        return\n"
        )
        errs = _errors(src)
        self.assertTrue(
            any("'make'" in e and "Net" in e for e in errs), errs,
        )

    def test_impl_reaches_cap_via_return_type_is_rejected(self):
        # A cap-bearing return value is charged too (A3 return inclusion).
        src = (
            "capability Emailer\n"
            "    fun em(self) -> Unit\n"
            "\n"
            "type Smtp { net: Net }\n"
            "\n"
            "impl Emailer for Smtp\n"
            "    fun em(self) -> Unit\n"
            "        return\n"
            "\n"
            "pub trait Maker\n"
            "    fun make(self) -> Smtp uses []\n"
            "\n"
            "type Mk { net: Net }\n"
            "\n"
            "impl Emailer for Mk\n"
            "    fun em(self) -> Unit\n"
            "        return\n"
            "\n"
            "impl Maker for Mk\n"
            "    fun make(self) -> Smtp\n"
            "        return Smtp { net: self.net }\n"
        )
        errs = _errors(src)
        self.assertTrue(
            any("'make'" in e and "Net" in e for e in errs), errs,
        )


# =============================================================
# A4: fail-closed shapes yield TOP, rejected by construction
# =============================================================

class TestFailClosedShapes(unittest.TestCase):
    def test_fun_in_impl_signature_is_rejected(self):
        src = (
            "pub trait Runner\n"
            "    fun run(self, _f: Fun() -> Unit) -> Unit uses []\n"
            "\n"
            "type R { n: Int }\n"
            "\n"
            "impl Runner for R\n"
            "    fun run(self, _f: Fun() -> Unit) -> Unit\n"
            "        return\n"
        )
        errs = _errors(src)
        self.assertTrue(
            any("'run'" in e and "unprovable" in e for e in errs), errs,
        )

    def test_free_type_parameter_receiver_is_rejected(self):
        src = (
            "pub trait Box\n"
            "    fun peek(self) -> Unit uses []\n"
            "\n"
            "type Wrapper<T> { inner: T }\n"
            "\n"
            "impl Box for Wrapper<T>\n"
            "    fun peek(self) -> Unit\n"
            "        return\n"
        )
        errs = _errors(src)
        self.assertTrue(
            any("'peek'" in e and "unprovable" in e for e in errs), errs,
        )

    def test_nested_generic_free_type_arg_is_rejected(self):
        src = (
            "pub trait Box\n"
            "    fun peek(self) -> Unit uses []\n"
            "\n"
            "type Wrapper<T> { inner: T }\n"
            "\n"
            "impl Box for Wrapper<List<T>>\n"
            "    fun peek(self) -> Unit\n"
            "        return\n"
        )
        errs = _errors(src)
        self.assertTrue(
            any("'peek'" in e and "unprovable" in e for e in errs), errs,
        )


# =============================================================
# Atom vocabulary validation
# =============================================================

class TestAtomValidation(unittest.TestCase):
    def test_unknown_atom_is_rejected(self):
        src = (
            "pub trait Bad\n"
            "    fun go(self) -> Unit uses [Bogus]\n"
        )
        errs = _errors(src)
        self.assertTrue(
            any("unknown capability" in e and "Bogus" in e for e in errs),
            errs,
        )

    def test_user_capability_atom_is_accepted(self):
        # A same-module user ``capability`` is a valid atom.
        src = (
            "capability Logger\n"
            "    fun log(self, msg: String) -> Unit\n"
            "\n"
            "pub trait Uses\n"
            "    fun go(self, _lg: Logger) -> Unit uses [Logger]\n"
            "\n"
            "type U { n: Int }\n"
            "\n"
            "impl Uses for U\n"
            "    fun go(self, _lg: Logger) -> Unit\n"
            "        return\n"
        )
        self.assertTrue(_analyze(src).ok, _errors(src))


if __name__ == "__main__":
    unittest.main()
