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


_DOOR = (
    "typestate Door\n"
    "    Open\n"
    "    Closed\n"
    "fun open_door(consume d: Door[Closed]) -> Door[Open]\n"
    "    return become(d, Open)\n"
    "fun walk_through(d: Door[Open])\n"
    "    return\n"
    "fun discard(consume d: Door[Open])\n"
    "    return\n"
)


class TestTypestateConstructionAndTransition(unittest.TestCase):
    """Roadmap S3.2: ``Name[State] {}`` constructs and ``become(v,
    State)`` transitions; a full protocol type-checks and runs."""

    def test_full_protocol_checks(self):
        errs = _errors(
            _DOOR
            + "fun main(_s: Stdio)\n"
            + "    let d = Door[Closed] {}\n"
            + "    let d2 = open_door(d)\n"
            + "    walk_through(d2)\n"
            + "    discard(d2)\n"
        )
        self.assertEqual(errs, [])

    def test_wrong_state_operation_rejected(self):
        errs = _errors(
            _DOOR
            + "fun main(_s: Stdio)\n"
            + "    let d = Door[Closed] {}\n"
            + "    walk_through(d)\n"
            + "    discard(d)\n"
        )
        self.assertTrue(
            any("Door[Open]" in e and "Door[Closed]" in e for e in errs),
            errs,
        )

    def test_constructed_value_must_be_consumed(self):
        errs = _errors(
            _DOOR
            + "fun main(_s: Stdio)\n"
            + "    let d = Door[Closed] {}\n"
            + "    return\n"
        )
        self.assertTrue(any("dropped without being consumed" in e
                            for e in errs), errs)

    def test_become_to_unknown_state_rejected(self):
        errs = _errors(
            _DOOR
            + "fun main(_s: Stdio)\n"
            + "    let d = Door[Closed] {}\n"
            + "    let d2 = become(d, Ajar)\n"
            + "    discard(d2)\n"
        )
        self.assertTrue(any("no state 'Ajar'" in e for e in errs), errs)

    def test_become_on_non_typestate_rejected(self):
        errs = _errors("fun f(x: Int) -> Int\n    return become(x, Open)\n")
        self.assertTrue(any("become expects a typestate" in e
                            for e in errs), errs)

    def test_construct_non_typestate_rejected(self):
        errs = _errors("fun f()\n    let x = Int[Open] {}\n    return\n")
        self.assertTrue(any("is not a typestate" in e for e in errs), errs)

    def test_protocol_runs_on_python_backend(self):
        from capa import transpile
        src = (
            _DOOR
            + "fun main(stdio: Stdio)\n"
            + "    let d = Door[Closed] {}\n"
            + "    let d2 = open_door(d)\n"
            + "    walk_through(d2)\n"
            + "    discard(d2)\n"
            + "    stdio.println(\"done\")\n"
        )
        m = _parse(src)
        result = analyze(m, source=src)
        self.assertTrue(result.ok, [e.message for e in result.errors])
        code = transpile(m, types=result.types, bindings=result.bindings)
        import io
        from contextlib import redirect_stdout
        ns = {"__name__": "__main__"}
        buf = io.StringIO()
        with redirect_stdout(buf):
            exec(compile(code, "<ts>", "exec"), ns)
        self.assertIn("done", buf.getvalue())


_SOCK = (
    "typestate Socket { fd: Int }\n"
    "    Created\n"
    "    Connected\n"
    "fun connect(consume s: Socket[Created]) -> Socket[Connected]\n"
    "    return become(s, Connected)\n"
    "fun fd_of(s: Socket[Connected]) -> Int\n"
    "    return s.fd\n"
    "fun close(consume s: Socket[Connected])\n"
    "    return\n"
)


class TestTypestateFields(unittest.TestCase):
    """Roadmap S3.4: a typestate carries declared fields (a
    state-indexed struct). Construction validates them, field access
    reads them, and `become` preserves them across the transition."""

    def _analyze(self, src: str):
        from capa import analyze
        m = _parse(src)
        return analyze(m, source=src)

    def test_parse_fields(self):
        m = _parse(_SOCK)
        ts = m.items[0]
        self.assertEqual([f.name for f in ts.fields], ["fd"])

    def test_full_fielded_protocol_checks(self):
        errs = [e.message for e in self._analyze(
            _SOCK
            + "fun main(_s: Stdio)\n"
            + "    let s = Socket[Created] { fd: 7 }\n"
            + "    let c = connect(s)\n"
            + "    close(c)\n"
        ).errors]
        self.assertEqual(errs, [])

    def test_missing_field_rejected(self):
        errs = [e.message for e in self._analyze(
            _SOCK + "fun f()\n    close(Socket[Created] {})\n"
        ).errors]
        self.assertTrue(any("missing fields fd" in e for e in errs), errs)

    def test_wrong_field_type_rejected(self):
        errs = [e.message for e in self._analyze(
            _SOCK + "fun f()\n    close(Socket[Created] { fd: \"x\" })\n"
        ).errors]
        self.assertTrue(any("field 'fd' expects Int" in e for e in errs), errs)

    def test_unknown_field_rejected(self):
        errs = [e.message for e in self._analyze(
            _SOCK + "fun f()\n    close(Socket[Created] { port: 80 })\n"
        ).errors]
        self.assertTrue(any("has no field 'port'" in e for e in errs), errs)

    def test_capability_field_rejected(self):
        errs = [e.message for e in self._analyze(
            "typestate Bad { n: Net }\n    S\nfun f()\n    return\n"
        ).errors]
        self.assertTrue(any("cannot appear in typestate field" in e
                            for e in errs), errs)

    def test_fielded_protocol_runs_on_python(self):
        from capa import transpile
        src = (
            _SOCK
            + "fun main(stdio: Stdio)\n"
            + "    let s = Socket[Created] { fd: 7 }\n"
            + "    let c = connect(s)\n"
            + "    stdio.println(\"fd=${fd_of(c)}\")\n"
            + "    close(c)\n"
        )
        m = _parse(src)
        result = analyze(m, source=src)
        self.assertTrue(result.ok, [e.message for e in result.errors])
        code = transpile(m, types=result.types, bindings=result.bindings)
        import io
        from contextlib import redirect_stdout
        ns = {"__name__": "__main__"}
        buf = io.StringIO()
        with redirect_stdout(buf):
            exec(compile(code, "<ts>", "exec"), ns)
        self.assertIn("fd=7", buf.getvalue())


_DOOR_METHODS = (
    "typestate Door { id: Int }\n"
    "    Open\n"
    "    Closed\n"
    "impl Door[Closed]\n"
    "    fun open_it(consume self) -> Door[Open]\n"
    "        return become(self, Open)\n"
    "impl Door[Open]\n"
    "    fun label(self) -> Int\n"
    "        return self.id\n"
    "fun discard(consume d: Door[Open])\n"
    "    return\n"
)


class TestTypestateStateMethods(unittest.TestCase):
    """Roadmap S3.5: ``impl Type[State]`` methods are only callable when
    the typestate receiver is in that state; a transition method may
    ``consume self`` and return the value in a new state."""

    def _errors(self, src: str):
        m = _parse(src)
        return [e.message for e in analyze(m, source=src).errors]

    def test_state_method_protocol_checks(self):
        errs = self._errors(
            _DOOR_METHODS
            + "fun main(_s: Stdio)\n"
            + "    let d = Door[Closed] { id: 1 }\n"
            + "    let o = d.open_it()\n"
            + "    let n = o.label()\n"
            + "    discard(o)\n"
        )
        self.assertEqual(errs, [])

    def test_wrong_state_method_rejected(self):
        errs = self._errors(
            _DOOR_METHODS
            + "fun main(_s: Stdio)\n"
            + "    let d = Door[Closed] { id: 1 }\n"
            + "    let n = d.label()\n"
            + "    discard(d.open_it())\n"
        )
        self.assertTrue(
            any("requires Door[Open]" in e and "Door[Closed]" in e
                for e in errs),
            errs,
        )

    def test_impl_state_on_non_typestate_rejected(self):
        errs = self._errors(
            "type Point { x: Int }\n"
            "impl Point[Foo]\n"
            "    fun f(self) -> Int\n"
            "        return self.x\n"
        )
        self.assertTrue(any("is not a typestate" in e for e in errs), errs)

    def test_impl_unknown_state_rejected(self):
        errs = self._errors(
            "typestate D { id: Int }\n    Open\n"
            "impl D[Bogus]\n"
            "    fun f(self) -> Int\n"
            "        return self.id\n"
        )
        self.assertTrue(any("no state 'Bogus'" in e for e in errs), errs)

    def test_state_methods_run_on_python(self):
        from capa import transpile
        src = (
            _DOOR_METHODS
            + "fun main(stdio: Stdio)\n"
            + "    let d = Door[Closed] { id: 42 }\n"
            + "    let o = d.open_it()\n"
            + "    stdio.println(\"label=${o.label()}\")\n"
            + "    discard(o)\n"
        )
        m = _parse(src)
        result = analyze(m, source=src)
        self.assertTrue(result.ok, [e.message for e in result.errors])
        code = transpile(m, types=result.types, bindings=result.bindings)
        import io
        from contextlib import redirect_stdout
        ns = {"__name__": "__main__"}
        buf = io.StringIO()
        with redirect_stdout(buf):
            exec(compile(code, "<ts>", "exec"), ns)
        self.assertIn("label=42", buf.getvalue())


class TestTypestateManifest(unittest.TestCase):
    def test_protocol_states_in_manifest(self):
        from capa.manifest import build_manifest
        m = _parse(_BASE)
        manifest = build_manifest(m, filename="<test>")
        self.assertEqual(manifest["summary"]["protocol_states"], 1)
        self.assertEqual(
            manifest["typestates"],
            [{"name": "Socket",
              "states": ["Created", "Connected", "Closed"]}],
        )


if __name__ == "__main__":
    unittest.main()
