"""Tests for the information-flow security-label foundation
(roadmap S2.1 + S2.2): the lattice algebra and the ``@secret`` /
``@public`` parse-and-attach. Propagation + enforcement are tested
separately once those land."""

import unittest

from capa import Lexer, Parser
from capa import capa_ast as A
from capa import _labels as L


class TestLabelLattice(unittest.TestCase):
    def test_join_takes_more_restricted(self):
        self.assertEqual(L.join(L.PUBLIC, L.SECRET), L.SECRET)
        self.assertEqual(L.join(L.SECRET, L.PUBLIC), L.SECRET)
        self.assertEqual(L.join(L.PUBLIC, L.PUBLIC), L.PUBLIC)
        self.assertEqual(L.join(L.SECRET, L.SECRET), L.SECRET)

    def test_none_normalizes_to_public(self):
        self.assertEqual(L.normalize(None), L.PUBLIC)
        self.assertEqual(L.normalize("bogus"), L.PUBLIC)
        self.assertEqual(L.join(None, L.SECRET), L.SECRET)

    def test_join_all(self):
        self.assertEqual(L.join_all([]), L.PUBLIC)
        self.assertEqual(L.join_all([L.PUBLIC, L.PUBLIC]), L.PUBLIC)
        self.assertEqual(L.join_all([L.PUBLIC, L.SECRET, L.PUBLIC]), L.SECRET)

    def test_flows_to_forbids_only_secret_to_public(self):
        self.assertTrue(L.flows_to(L.PUBLIC, L.SECRET))
        self.assertTrue(L.flows_to(L.PUBLIC, L.PUBLIC))
        self.assertTrue(L.flows_to(L.SECRET, L.SECRET))
        self.assertFalse(L.flows_to(L.SECRET, L.PUBLIC))  # the vector

    def test_flows_to_treats_none_as_public(self):
        self.assertTrue(L.flows_to(None, L.SECRET))
        self.assertFalse(L.flows_to(L.SECRET, None))


def _parse(src: str):
    return Parser(Lexer(src).lex(), source=src).parse_module()


class TestLabelParsing(unittest.TestCase):
    def test_secret_on_param_type(self):
        m = _parse(
            "fun h(token: @secret String, _net: Net) -> Int\n"
            "    return 0\n"
        )
        fn = m.items[0]
        self.assertEqual(fn.params[0].type_expr.label, "secret")
        self.assertIsNone(fn.params[1].type_expr.label)

    def test_public_on_return_type(self):
        m = _parse("fun f() -> @public Int\n    return 0\n")
        self.assertEqual(m.items[0].return_type.label, "public")

    def test_label_on_generic_type(self):
        m = _parse(
            "fun f(xs: @secret List<Int>) -> Int\n"
            "    return 0\n"
        )
        ty = m.items[0].params[0].type_expr
        self.assertIsInstance(ty, A.TypeName)
        self.assertEqual(ty.name, "List")
        self.assertEqual(ty.label, "secret")

    def test_label_on_let_binding_type(self):
        m = _parse(
            "fun f()\n"
            "    let x: @secret Int = 1\n"
            "    return\n"
        )
        let_stmt = m.items[0].body.stmts[0]
        self.assertEqual(let_stmt.type_expr.label, "secret")

    def test_unlabelled_type_has_none(self):
        m = _parse("fun f(x: Int) -> String\n    return \"a\"\n")
        self.assertIsNone(m.items[0].params[0].type_expr.label)
        self.assertIsNone(m.items[0].return_type.label)

    def test_attribute_syntax_not_confused_with_label(self):
        # ``@security(...)`` on a function is an attribute, not a
        # type label -- the ``(`` after the name disambiguates.
        m = _parse(
            "@security(cve: \"CVE-1\")\n"
            "fun f(_s: Stdio)\n"
            "    return\n"
        )
        self.assertEqual(m.items[0].attributes[0].name, "security")


if __name__ == "__main__":
    unittest.main()
