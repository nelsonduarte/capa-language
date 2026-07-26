"""Capability charging for trait-typed signature positions, generic
impl type arguments, and capability-yielding borrow-Fun arrows.

Three shapes charged ZERO capabilities before this change and even
claimed to provably-EXCLUDE capabilities an implementor exercises via
dynamic dispatch:

(a) a parameter/field/return typed as a plain ``trait`` (an abstract
    interface, not a ``capability``). A PRIVATE trait is sealed, so the
    position is charged the union of its implementors' reachable caps; a
    ``pub`` trait is externally implementable, so it makes the enclosing
    function authority-UNPROVABLE, exactly like a ``Fun`` in the sig.

(b) an ``impl SomeTrait for Wrapper<Smtp>`` whose receiver TYPE ARGUMENT
    (``Smtp``, bearing ``Net``) was dropped because the implementor-union
    read ``reachable[Wrapper]`` and never consulted the type arguments.
    This shipped as a live false-exclusion on the existing user-capability
    path and the new trait path inherits the same union machinery. A
    CONCRETE argument (cap-bearing or cap-free) is charged precisely; a
    FREE/unbound generic argument (``Wrapper<T>``) names no concrete type
    and could be instantiated downstream with a cap-bearing type, so it
    fails CLOSED (authority-unprovable) rather than charging zero.

(c) a ``borrow mk: Fun() -> Net`` whose body invokes ``mk().get(...)``:
    the arrow's return type was never walked for caps, so the ceiling
    relaxation certified a Net exclusion the function actually exercises.

The charging is sound for resolvable receiver / type-argument / method-
signature caps, and an unresolvable generic type argument fails closed, so
none of these shapes produces a FALSE exclusion.
"""

import unittest

from capa import Lexer, Parser, analyze
from capa.manifest import build_manifest


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


# A cap-bearing struct (implements a user capability over Stdio) that also
# implements a PLAIN trait. A value typed as the plain trait dispatches to
# this struct's method, so it can exercise Stdio.
_PRIVATE_TRAIT = (
    "capability Notifier\n"
    "    fun announce(self, msg: String) -> Unit\n"
    "\n"
    "trait Greeter\n"
    "    fun greet(self) -> Unit\n"
    "\n"
    "type StdioThing {\n"
    "    out: Stdio\n"
    "}\n"
    "\n"
    "impl Notifier for StdioThing\n"
    "    fun announce(self, msg: String) -> Unit\n"
    "        self.out.println(msg)\n"
    "        return\n"
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


class TestPrivateTrait(unittest.TestCase):
    """(a) A private trait is sealed: charge the implementor union."""

    def test_exercised_cap_is_charged(self):
        m = _manifest(_PRIVATE_TRAIT)
        f = _fn(m, "use_greeter")
        self.assertIn("Stdio", f["transitively_reachable_capabilities"])

    def test_exercised_cap_is_not_falsely_excluded(self):
        m = _manifest(_PRIVATE_TRAIT)
        f = _fn(m, "use_greeter")
        self.assertNotIn("Stdio", f["provably_excluded_capabilities"])
        self.assertNotIn("Notifier", f["provably_excluded_capabilities"])

    def test_private_trait_stays_provable(self):
        # Sealed by construction: the exclusion proof still stands (over
        # the charged set), so authority is provable from the types.
        m = _manifest(_PRIVATE_TRAIT)
        f = _fn(m, "use_greeter")
        self.assertTrue(f["authority_provable_from_types"])
        self.assertTrue(f["ceiling_authority_provable"])

    def test_capability_free_implementors_charge_empty(self):
        # A private trait whose only implementor reaches no cap charges
        # nothing and stays clean (every built-in provably excluded).
        src = (
            "trait Greeter\n"
            "    fun greet(self) -> Unit\n"
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
        m = _manifest(src)
        f = _fn(m, "use_greeter")
        self.assertEqual(f["transitively_reachable_capabilities"], [])
        self.assertIn("Stdio", f["provably_excluded_capabilities"])
        self.assertTrue(f["authority_provable_from_types"])


class TestPubTrait(unittest.TestCase):
    """(a) A pub trait is externally implementable: fail closed."""

    def test_pub_trait_is_authority_unprovable(self):
        m = _manifest(_PRIVATE_TRAIT.replace("trait Greeter", "pub trait Greeter"))
        f = _fn(m, "use_greeter")
        self.assertFalse(f["authority_provable_from_types"])
        self.assertFalse(f["ceiling_authority_provable"])

    def test_pub_trait_makes_no_false_exclusion(self):
        m = _manifest(_PRIVATE_TRAIT.replace("trait Greeter", "pub trait Greeter"))
        f = _fn(m, "use_greeter")
        # Unprovable voids the exclusion list entirely (empty), so Stdio is
        # never falsely excluded.
        self.assertEqual(f["provably_excluded_capabilities"], [])
        self.assertNotIn("Stdio", f["provably_excluded_capabilities"])


# ``impl SomeTrait for Wrapper<Smtp>`` where Smtp bears Net. The receiver
# type ARGUMENT carries the authority; the named receiver ``Wrapper`` reaches
# nothing on its own.
def _wrapper_src(trait_kw: str, arg: str) -> str:
    return (
        "capability Emailer\n"
        "    fun send(self, msg: String) -> Unit\n"
        "\n"
        "type Smtp {\n"
        "    net: Net\n"
        "}\n"
        "\n"
        "impl Emailer for Smtp\n"
        "    fun send(self, msg: String) -> Unit\n"
        "        return\n"
        "\n"
        "type Wrapper<T> {\n"
        "    inner: T\n"
        "}\n"
        "\n"
        f"{trait_kw} Doer\n"
        "    fun do_it(self) -> Unit\n"
        "\n"
        f"impl Doer for Wrapper<{arg}>\n"
        "    fun do_it(self) -> Unit\n"
        "        return\n"
        "\n"
        "fun run_doer(d: Doer) -> Unit\n"
        "    d.do_it()\n"
        "    return\n"
    )


class TestImplTypeArguments(unittest.TestCase):
    """(b) The implementor union must charge the impl's TYPE ARGUMENTS."""

    def test_trait_path_charges_type_arg_cap(self):
        m = _manifest(_wrapper_src("trait", "Smtp"))
        f = _fn(m, "run_doer")
        self.assertIn("Net", f["transitively_reachable_capabilities"])
        self.assertNotIn("Net", f["provably_excluded_capabilities"])

    def test_user_capability_path_charges_type_arg_cap(self):
        # The SAME hole on the pre-existing user-capability path.
        m = _manifest(_wrapper_src("capability", "Smtp"))
        f = _fn(m, "run_doer")
        self.assertIn("Net", f["transitively_reachable_capabilities"])
        self.assertNotIn("Net", f["provably_excluded_capabilities"])

    def test_capability_free_type_arg_does_not_over_fail(self):
        # A cap-free type argument charges nothing (no over-fail) and the
        # position stays provable.
        m = _manifest(_wrapper_src("trait", "Int"))
        f = _fn(m, "run_doer")
        self.assertEqual(f["transitively_reachable_capabilities"], [])
        self.assertIn("Net", f["provably_excluded_capabilities"])
        self.assertTrue(f["authority_provable_from_types"])


# ``impl Doer for Wrapper<T>`` with a FREE type parameter T. The receiver
# type argument names no concrete type, so it could be instantiated
# downstream with a cap-bearing type this compilation cannot see. The
# body stays OPAQUE in the type parameter (member access on a bare T is a
# type error, since Capa has no bounds syntax), but the FREE type argument
# alone drives the charging: it must fail closed, not charge zero.
def _free_param_src(trait_kw: str) -> str:
    return (
        "capability Emailer\n"
        "    fun send(self, msg: String) -> Unit\n"
        "\n"
        "type Smtp {\n"
        "    net: Net\n"
        "}\n"
        "\n"
        "impl Emailer for Smtp\n"
        "    fun send(self, msg: String) -> Unit\n"
        "        return\n"
        "\n"
        "type Wrapper<T> {\n"
        "    inner: T\n"
        "}\n"
        "\n"
        f"{trait_kw} Doer\n"
        "    fun do_it(self) -> Unit\n"
        "\n"
        "impl Doer for Wrapper<T>\n"
        "    fun do_it(self) -> Unit\n"
        "        return\n"
        "\n"
        "fun run_doer(d: Doer) -> Unit\n"
        "    d.do_it()\n"
        "    return\n"
    )


class TestFreeGenericTypeArgument(unittest.TestCase):
    """(b) A FREE generic type argument fails closed, not charge-zero.

    ``impl Doer for Wrapper<T>`` where T is unbound could be instantiated
    downstream with a cap-bearing type, so the position is authority-
    UNPROVABLE rather than provably-excluding the caps the dispatch
    exercises. Only a free/unbound parameter fails closed; a concrete
    argument (cap-bearing or cap-free) still charges precisely."""

    def test_trait_path_free_param_is_unprovable(self):
        m = _manifest(_free_param_src("trait"))
        f = _fn(m, "run_doer")
        self.assertFalse(f["authority_provable_from_types"])
        self.assertEqual(f["provably_excluded_capabilities"], [])
        # The caps the dispatch exercises are NOT falsely excluded.
        self.assertNotIn("Net", f["provably_excluded_capabilities"])
        self.assertNotIn("Emailer", f["provably_excluded_capabilities"])

    def test_user_capability_path_free_param_is_unprovable(self):
        m = _manifest(_free_param_src("capability"))
        f = _fn(m, "run_doer")
        self.assertFalse(f["authority_provable_from_types"])
        self.assertEqual(f["provably_excluded_capabilities"], [])
        self.assertNotIn("Net", f["provably_excluded_capabilities"])

    def test_concrete_cap_bearing_arg_still_charges_not_fails(self):
        # Belt and braces alongside TestImplTypeArguments: a concrete
        # cap-bearing type argument is charged precisely and stays
        # provable (it does NOT fail closed).
        m = _manifest(_wrapper_src("trait", "Smtp"))
        f = _fn(m, "run_doer")
        self.assertIn("Net", f["transitively_reachable_capabilities"])
        self.assertTrue(f["authority_provable_from_types"])

    def test_builtin_nominal_type_args_stay_provable(self):
        # The known-builtin-type set is the analyzer's authoritative one
        # (capa.analyzer._frozen), so a nominal built-in like ``Unit`` /
        # ``Task`` / ``Self`` used as an impl type argument resolves and is
        # cap-free: charge nothing, stay provable. A re-listed copy that
        # omitted these over-failed them; this pins against that drift.
        for arg in ("Unit", "Task", "Self"):
            src = (
                "type Wrapper<T> {\n"
                "    inner: T\n"
                "}\n"
                "\n"
                "trait Doer\n"
                "    fun do_it(self) -> Unit\n"
                "\n"
                f"impl Doer for Wrapper<{arg}>\n"
                "    fun do_it(self) -> Unit\n"
                "        return\n"
                "\n"
                "fun run_doer(d: Doer) -> Unit\n"
                "    d.do_it()\n"
                "    return\n"
            )
            m = _manifest(src)
            f = _fn(m, "run_doer")
            self.assertTrue(
                f["authority_provable_from_types"],
                f"Wrapper<{arg}> should be provable, not over-fail",
            )
            self.assertEqual(f["transitively_reachable_capabilities"], [])


class TestBorrowFunArrowCaps(unittest.TestCase):
    """(c) A borrow-Fun whose arrow yields a capability charges it."""

    def test_borrow_fun_returning_cap_charges_it(self):
        src = (
            "fun run(borrow mk: Fun() -> Net) -> Unit\n"
            "    mk().get(\"http://example.com\")\n"
            "    return\n"
        )
        m = _manifest(src)
        f = _fn(m, "run")
        self.assertIn("Net", f["transitively_reachable_capabilities"])
        # The borrow relaxation still applies: the ceiling stays provable,
        # now charging Net rather than falsely excluding it.
        self.assertTrue(f["ceiling_authority_provable"])

    def test_capa_server_shape_stays_clean(self):
        # ``borrow handler: Fun(Request) -> Response`` where Response is NOT
        # a capability charges nothing and keeps a clean, provable ceiling.
        src = (
            "type Request {\n"
            "    path: String\n"
            "}\n"
            "\n"
            "type Response {\n"
            "    code: Int\n"
            "}\n"
            "\n"
            "fun serve(borrow handler: Fun(Request) -> Response) -> Unit\n"
            "    return\n"
        )
        m = _manifest(src)
        f = _fn(m, "serve")
        self.assertEqual(f["transitively_reachable_capabilities"], [])
        self.assertTrue(f["ceiling_authority_provable"])


if __name__ == "__main__":
    unittest.main()
