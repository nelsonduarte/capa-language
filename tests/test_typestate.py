"""Tests for typestate / session types foundation (roadmap S3.1).

A ``typestate`` declares named states; a value carries its state in
the type (``Name[State]``) and is linear (must be consumed /
transitioned). The state lives in the type, so the ordinary type
checker plus the S1 linearity discipline enforce the protocol. This
slice ships the type-level foundation (declaration, state-typed types,
state-exact compatibility, linear registration, validation);
construction and in-body transitions land in S3.2.
"""

import unittest

from capa import Lexer, Parser, analyze
from capa import capa_ast as A
from capa.typesys import TyName, compatible, ty_str


def _parse(src: str):
    return Parser(Lexer(src).lex(), source=src).parse_module()


def _errors(src: str):
    m = _parse(src)
    return [e.message for e in analyze(m, source=src).errors]


_BASE = (
    "typestate Socket\n"
    "    Created\n"
    "    Connected\n"
    "    Closed\n"
)


class TestTypestateParsing(unittest.TestCase):
    def test_decl_parses_states(self):
        m = _parse(_BASE)
        ts = m.items[0]
        self.assertIsInstance(ts, A.TypestateDecl)
        self.assertEqual(ts.name, "Socket")
        self.assertEqual(ts.states, ["Created", "Connected", "Closed"])

    def test_state_typed_param_and_return(self):
        m = _parse(
            _BASE
            + "fun connect(consume s: Socket[Created]) -> Socket[Connected]\n"
            + "    return s\n"
        )
        fn = m.items[1]
        self.assertEqual(fn.params[0].type_expr.name, "Socket")
        self.assertEqual(fn.params[0].type_expr.state, "Created")
        self.assertEqual(fn.return_type.state, "Connected")

    def test_duplicate_state_rejected(self):
        from capa.parser import ParserError
        with self.assertRaises(ParserError):
            _parse("typestate X\n    A\n    A\n")


class TestTypestateTypesys(unittest.TestCase):
    def test_state_makes_types_distinct(self):
        created = TyName("Socket", state="Created")
        connected = TyName("Socket", state="Connected")
        self.assertNotEqual(created, connected)
        self.assertFalse(compatible(created, connected))
        self.assertTrue(compatible(created, TyName("Socket", state="Created")))

    def test_ty_str_renders_state(self):
        self.assertEqual(ty_str(TyName("Socket", state="Connected")),
                         "Socket[Connected]")
        self.assertEqual(ty_str(TyName("Int")), "Int")


class TestTypestateAnalyzer(unittest.TestCase):
    def test_wrong_state_argument_rejected(self):
        errs = _errors(
            _BASE
            + "fun send(s: Socket[Connected], data: String)\n"
            + "    return\n"
            + "fun use(consume s: Socket[Created])\n"
            + "    send(s, \"hi\")\n"
        )
        self.assertTrue(
            any("Socket[Connected]" in e and "Socket[Created]" in e
                for e in errs),
            errs,
        )

    def test_same_state_to_consume_sink_is_ok(self):
        errs = _errors(
            _BASE
            + "fun close(consume s: Socket[Connected])\n"
            + "    return\n"
            + "fun use(consume s: Socket[Connected])\n"
            + "    close(s)\n"
        )
        self.assertEqual(errs, [])

    def test_unknown_state_rejected(self):
        errs = _errors(_BASE + "fun f(s: Socket[Bogus])\n    return\n")
        self.assertTrue(any("no state 'Bogus'" in e for e in errs), errs)

    def test_missing_state_index_rejected(self):
        errs = _errors(_BASE + "fun f(s: Socket)\n    return\n")
        self.assertTrue(
            any("must be written with a state index" in e for e in errs),
            errs,
        )

    def test_state_index_on_non_typestate_rejected(self):
        errs = _errors("fun f(x: Int[Created])\n    return\n")
        self.assertTrue(any("is not a typestate" in e for e in errs), errs)

    def test_typestate_registered_as_linear(self):
        from capa.analyzer import Analyzer
        m = _parse(_BASE)
        az = Analyzer(source=_BASE)
        az.analyze(m)
        self.assertIn("Socket", az._linear_types)
        self.assertEqual(az._typestates["Socket"],
                         ["Created", "Connected", "Closed"])


if __name__ == "__main__":
    unittest.main()
