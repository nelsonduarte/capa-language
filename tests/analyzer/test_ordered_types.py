"""Analyzer tests: the ordered-type set and the operator rule that consults it.

``capa.typesys.ORDERED_TYPES`` names, once, the types the ordering
operators (``<`` ``<=`` ``>`` ``>=``) accept. Before it existed the same
fact was an inline three-way disjunction inside ``_check_binop``, and a
future ``sorted`` / ``min`` / ``max`` would have had to restate it. The
extraction must preserve today's behaviour exactly, which is wider than
the constant's members: the rule consults the set through ``compatible``,
so a ``Char`` (a one-code-point ``String``) orders too.

Two things are pinned here, each against a named mutation:

- the operators accept every member, Char included, and nothing else among
  the primitives (a naive name-membership rewrite of the operator arm
  rejects ``'a' < 'b'`` and fails ``TestOrderingOperators``);
- the operator arm CONSULTS the constant rather than mirroring it (adding
  ``Bool`` to the constant makes ``true < false`` type-check and fails the
  Bool rejection below; if the arm did not read the constant, that
  mutation would survive);
- the arm admits what ``compatible`` admits BEYOND the primitives: a
  flexible inference variable and ``TyUnknown`` in an ordering position
  (``TestPermissiveOperands``). No corpus program put either shape under
  an ordering operator, so an arm rewritten to refuse them survived the
  whole suite; these pins are the members that were missing.

See tests/analyzer/__init__.py for the growth convention.
"""

import unittest

from capa.typesys import (
    ORDERED_TYPES, PRIMITIVE_NAMES, TyFloat, TyInt, TyString,
)
from tests.analyzer._helpers import check, errors_of


_ORDER_OPS = ("<", "<=", ">", ">=")


def _compare(ty: str, op: str) -> str:
    return (
        f"fun f(a: {ty}, b: {ty}) -> Bool\n"
        f"    return a {op} b\n"
    )


def _operand_diagnostic(op: str, lt: str, rt: str) -> str:
    return f"operator {op!r}: incompatible operand types {lt} and {rt}"


class TestOrderedTypesConstant(unittest.TestCase):
    def test_members_are_int_float_string(self):
        self.assertEqual(ORDERED_TYPES, (TyInt, TyFloat, TyString))

    def test_every_member_is_a_primitive(self):
        for ty in ORDERED_TYPES:
            with self.subTest(member=ty.name):
                self.assertIn(ty.name, PRIMITIVE_NAMES)


class TestOrderingOperators(unittest.TestCase):
    def test_every_member_is_accepted_by_every_operator(self):
        for ty in ORDERED_TYPES:
            for op in _ORDER_OPS:
                with self.subTest(type=ty.name, op=op):
                    r = check(_compare(ty.name, op))
                    self.assertTrue(r.ok, r.errors)

    def test_char_is_accepted_through_its_string_compatibility(self):
        # Char is NOT a member of the constant; it orders because
        # ``compatible(String, Char)`` holds. The naive extraction (name
        # membership instead of ``compatible``) rejects all three shapes.
        for op in _ORDER_OPS:
            with self.subTest(op=op):
                r = check(_compare("Char", op))
                self.assertTrue(r.ok, r.errors)
                r = check(
                    "fun main(stdio: Stdio)\n"
                    f"    let cc = 'a' {op} 'b'\n"
                    f"    let cs = 'a' {op} \"b\"\n"
                    f"    let sc = \"b\" {op} 'a'\n"
                    '    stdio.println("${cc} ${cs} ${sc}")\n'
                )
                self.assertTrue(r.ok, r.errors)

    def test_bool_is_rejected_by_every_operator_with_the_operand_diagnostic(self):
        for op in _ORDER_OPS:
            with self.subTest(op=op):
                msgs = errors_of(_compare("Bool", op))
                self.assertIn(_operand_diagnostic(op, "Bool", "Bool"), msgs)

    def test_mixed_members_are_rejected(self):
        # Int against Float is not an ordering the language defines; the
        # diagnostic names both operand types, unchanged by the extraction.
        msgs = errors_of(
            "fun f(a: Int, b: Float) -> Bool\n"
            "    return a < b\n"
        )
        self.assertIn(_operand_diagnostic("<", "Int", "Float"), msgs)

    def test_accepted_primitives_are_exactly_the_members_plus_char(self):
        # Computed over every primitive rather than listed: each is either
        # accepted or rejected with the operand diagnostic, no third
        # outcome, and the accepted set is pinned.
        accepted = set()
        for name in sorted(PRIMITIVE_NAMES):
            for op in _ORDER_OPS:
                with self.subTest(type=name, op=op):
                    r = check(_compare(name, op))
                    if r.ok:
                        accepted.add(name)
                    else:
                        self.assertEqual(
                            [e.message for e in r.errors],
                            [_operand_diagnostic(op, name, name)],
                        )
        self.assertEqual(
            accepted, {ty.name for ty in ORDERED_TYPES} | {"Char"},
        )


#: Element types the compiler-ordered methods must REFUSE, each with the
#: Capa source that builds a list of it. Written out rather than derived
#: because the point is to enumerate the shapes a user can reach, which
#: is not a set the type system exposes: primitives it cannot order, a
#: user struct, the four container shapes, Unit, and a bare type
#: variable. Deriving it would mean asking the predicate, which is the
#: thing under test.
_REFUSED_ELEMENTS: tuple[tuple[str, str, str], ...] = (
    ("Bool",            "Bool",            "[true, false]"),
    # ANNOTATED, unlike the rest, and the annotation is load-bearing.
    # A bare ``[P(n: 1), P(n: 2)]`` leaves the element type UNRESOLVED
    # (``List<Unknown>``) at the method-call site, and the predicate is
    # deliberately fail-OPEN on Unknown, so that call is accepted here
    # and dies later. That is a pre-existing INFERENCE limitation and
    # not this rule's: measured, the same unannotated shape already
    # fails identically on main through ``sorted_by``, with wasm-tools
    # reporting ``unknown func: $P``. Annotating gives the checker the
    # type it needs, which is what this rule is responsible for. The
    # unresolved shape is recorded in the increment report rather than
    # asserted here, because asserting it would pin a defect that
    # belongs to inference.
    ("user struct",     "P",               "xs: List<P> = [P(n: 1), P(n: 2)]"),
    ("List<Int>",       "List<Int>",       "[[1], [2]]"),
    ("tuple",           "(Int, Int)",      "[(1, 2), (3, 4)]"),
    ("Option<Int>",     "Option<Int>",     "[Some(1), None]"),
    ("Map<String,Int>", "Map<String, Int>", "[new_map()]"),
    ("Set<Int>",        "Set<Int>",        "[new_set()]"),
)

#: Element types they must ACCEPT: every member of the constant, plus
#: Char, which is NOT a member and is exactly the row a name-membership
#: predicate gets wrong.
_ACCEPTED_ELEMENTS: tuple[tuple[str, str], ...] = (
    ("Int",    "[3, 1, 2]"),
    ("Float",  "[3.5, 1.5]"),
    ("String", '["b", "a"]'),
    ("Char",   "['b', 'a']"),
)

_ORDERED_METHODS = ("sorted", "min", "max")


def _ordered_call(elem_src: str, method: str) -> str:
    # An entry may carry its own annotated binding (``xs: T = ...``), as
    # the user-struct row does; otherwise the literal is bound plainly
    # and the checker infers the element type from it.
    binding = (
        elem_src if elem_src.startswith("xs:") else f"xs = {elem_src}"
    )
    return (
        "type P {\n"
        "    n: Int\n"
        "}\n"
        "\n"
        "fun main(stdio: Stdio)\n"
        f"    let {binding}\n"
        f"    let r = xs.{method}()\n"
        '    stdio.println("done")\n'
    )


class TestCompilerOrderedMethodsRefuseUnorderedElements(unittest.TestCase):
    """``sorted`` / ``min`` / ``max`` supply their OWN comparison, so
    they accept only element types the compiler can order. This is the
    rule increment 2 exists to add, and until this class landed NOTHING
    asserted it: deleting the ``_check_ordered_element`` call at
    dispatch left all 5991 tests green.

    What the deletion actually does, measured, is worth recording so the
    stakes are legible: ``[true, false].sorted()`` then compiles on both
    Python paths and FAILS on Wasm, where the emitter refuses the
    element type it was promised would never arrive. It is a
    three-backend divergence and an unguarded Python ``TypeError``, not
    a soundness hole, but it is precisely the surface this increment was
    built to close.

    The diagnostic is asserted to name BOTH the offending element type
    and ``sorted_by``. Naming the escape hatch is not decoration: for a
    Bool or a user struct, supplying your own comparator IS the right
    answer, and a rejection that does not say so tells the user the
    language cannot do what it can.
    """

    def test_every_unordered_element_type_is_refused(self):
        for label, _ty, src in _REFUSED_ELEMENTS:
            for method in _ORDERED_METHODS:
                with self.subTest(element=label, method=method):
                    r = check(_ordered_call(src, method))
                    self.assertFalse(
                        r.ok,
                        f"List<{label}>.{method}() was ACCEPTED; the "
                        f"compiler has no comparison for {label}, so the "
                        f"call would reach a backend with nothing to "
                        f"compare (measured: the Python paths run and "
                        f"the Wasm backend refuses)",
                    )
                    joined = " ".join(e.message for e in r.errors)
                    self.assertIn(method, joined)
                    self.assertIn(
                        "sorted_by", joined,
                        "the rejection must name sorted_by: supplying "
                        "your own comparator is how this element type "
                        "IS ordered, and a rejection that hides that "
                        "reads as 'Capa cannot sort this'",
                    )

    def test_a_bare_type_variable_is_refused(self):
        # Separate because it needs a generic function rather than a
        # literal, and because it is the fail-CLOSED direction of the
        # predicate: TyUnknown passes, TyVar does not.
        src = (
            "fun pick<T>(xs: List<T>) -> Option<T>\n"
            "    return xs.min()\n"
        )
        r = check(src)
        self.assertFalse(r.ok)
        self.assertIn(
            "sorted_by", " ".join(e.message for e in r.errors),
        )

    def test_every_ordered_element_type_is_accepted(self):
        # The negative half: the rule must not over-reject. Char is the
        # row that matters, since it is not a member of ORDERED_TYPES.
        for label, src in _ACCEPTED_ELEMENTS:
            for method in _ORDERED_METHODS:
                with self.subTest(element=label, method=method):
                    r = check(_ordered_call(src, method))
                    self.assertTrue(
                        r.ok,
                        f"List<{label}>.{method}() was REFUSED: "
                        + str([e.message for e in r.errors]),
                    )

    def test_sorted_by_stays_permissive_for_every_refused_element(self):
        # sorted_by is the escape hatch the diagnostic points at, so it
        # must keep accepting exactly what the compiler-ordered methods
        # refuse. If this ever goes red the rejection message is a lie.
        for label, ty, src in _REFUSED_ELEMENTS:
            with self.subTest(element=label):
                binding = (
                    src if src.startswith("xs:") else f"xs = {src}"
                )
                prog = (
                    "type P {\n"
                    "    n: Int\n"
                    "}\n"
                    "\n"
                    "fun main(stdio: Stdio)\n"
                    f"    let {binding}\n"
                    f"    let r = xs.sorted_by(fun (a: {ty}, b: {ty}) "
                    "-> Int => 0)\n"
                    '    stdio.println("done")\n'
                )
                r = check(prog)
                self.assertTrue(
                    r.ok,
                    f"sorted_by no longer accepts List<{label}>, but the "
                    f"sorted/min/max rejection tells users to reach for "
                    f"it: " + str([e.message for e in r.errors]),
                )


class TestPredicateAgreesWithTheOperator(unittest.TestCase):
    """``is_ordered_element`` is what ``List.sorted`` / ``min`` / ``max``
    consult, and it must accept exactly what the ``<`` family accepts on
    two operands of the same type. If the two ever disagree, a program
    could sort a list whose elements the operator refuses to compare, or
    be refused a sort of elements it would happily compare.

    Computed over every primitive by RUNNING the operator, never listed:
    a second list of ordered type names is precisely what
    ``ORDERED_TYPES`` exists to prevent, and this guard is what makes
    the single source real rather than aspirational.

    The Char row is the one that matters. ``Char`` is NOT a member of
    ``ORDERED_TYPES``, yet the operator accepts it (a Char is compatible
    with String) and every backend lowers the comparison. A predicate
    written as name membership would pass every other row here and fail
    this one.
    """

    def test_predicate_matches_the_operator_on_every_primitive(self):
        from capa.typesys import is_ordered_element, TyName
        for name in sorted(PRIMITIVE_NAMES):
            with self.subTest(type=name):
                operator_accepts = all(
                    check(_compare(name, op)).ok for op in _ORDER_OPS
                )
                self.assertEqual(
                    is_ordered_element(TyName(name)), operator_accepts,
                    f"is_ordered_element and the ordering operator "
                    f"disagree about {name}. They must not: the ordering "
                    f"methods use the predicate and the user reads the "
                    f"operator, so a disagreement is a surface that "
                    f"contradicts itself",
                )

    def test_char_is_ordered_though_it_is_not_a_member(self):
        # Pinned separately from the sweep above because it is the row a
        # name-membership implementation gets wrong, and the sweep would
        # not say WHICH row failed.
        from capa.typesys import is_ordered_element, TyName
        self.assertNotIn("Char", {ty.name for ty in ORDERED_TYPES})
        self.assertTrue(is_ordered_element(TyName("Char")))

    def test_a_bare_type_variable_is_not_ordered(self):
        # Fail-CLOSED, and consistent with the operator, which already
        # refuses ``a < b`` for two T's in a generic function. The
        # opposite direction from TyUnknown, which is fail-OPEN.
        from capa.typesys import is_ordered_element, TyVar, TyUnknown
        self.assertFalse(is_ordered_element(TyVar("T")))
        self.assertTrue(is_ordered_element(TyUnknown))


class TestPermissiveOperands(unittest.TestCase):
    """``compatible(member, t)`` holds for a flexible inference variable
    and for ``TyUnknown`` whatever the member, so an operand of either
    shape is admitted by the arm and reported, if at all, by the site
    that owns it (the empty-literal inference, the name resolver). An
    arm that short-circuits on ``is_flexible`` or ``TyUnknown`` before
    consulting the set adds an operand diagnostic these pins refuse."""

    def test_flexible_element_type_is_admitted(self):
        # ``e`` is an empty literal whose element type is fixed only
        # AFTER the comparison, so at the operator ``v`` is still a
        # flexible ``?`` variable; the program type-checks today.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let e = []\n"
            "    let v = e.first().unwrap()\n"
            "    let w = v < 1\n"
            '    e.push("s")\n'
            '    stdio.println("${w}")\n'
        )
        self.assertTrue(
            r.ok,
            "the ordering arm refused a flexible inference variable; it "
            "must admit whatever compatible() admits against a member: "
            f"{[e.message for e in r.errors]}",
        )
        # When the element type is never fixed, the ONE diagnostic is the
        # element-type one; the operator adds nothing on top of it.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let e = []\n"
            '    stdio.println("${e.first().unwrap() < 1}")\n'
        )
        self.assertEqual(
            len(msgs), 1,
            "an ordering on a flexible operand must report only the "
            f"element-type diagnostic, never an operand one: {msgs}",
        )
        self.assertTrue(
            msgs[0].startswith("cannot determine the element type"), msgs,
        )

    def test_unknown_operand_adds_no_operand_diagnostic(self):
        # An undefined name types as TyUnknown; the resolver's diagnostic
        # is the only one, on one side or on both.
        for src, expected in (
            (
                "fun main(stdio: Stdio)\n"
                '    stdio.println("${undefined_x < 1}")\n',
                ["undefined name 'undefined_x'"],
            ),
            (
                "fun main(stdio: Stdio)\n"
                '    stdio.println("${undefined_x < undefined_y}")\n',
                ["undefined name 'undefined_x'", "undefined name 'undefined_y'"],
            ),
        ):
            with self.subTest(src=src.splitlines()[1].strip()):
                self.assertEqual(
                    errors_of(src), expected,
                    "the ordering arm added an operand diagnostic for a "
                    "TyUnknown operand; the undefined-name diagnostic must "
                    "be the only one",
                )


if __name__ == "__main__":
    unittest.main()
