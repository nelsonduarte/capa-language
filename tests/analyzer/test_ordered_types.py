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
