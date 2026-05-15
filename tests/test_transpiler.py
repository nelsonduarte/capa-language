"""Tests for the Capa → Python transpiler.

Each test transpiles a Capa snippet and runs it as a Python sub-process,
verifying the stdout produced. This is the only honest way to test
the transpiler, syntactic comparisons with expected Python strings are
fragile. Comparing behaviour is more robust.
"""

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from capa import Lexer, Parser, transpile, analyze


_PKG_ROOT = Path(__file__).resolve().parent.parent


def transpile_only(source: str) -> str:
    """Just transpiles, without running. Runs analyze() first so the
    transpiler has the type map for type-aware method dispatch
    (e.g. String / Map / Set method lowering)."""
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    result = analyze(module, source=source)
    return transpile(module, types=result.types)


def run_capa(source: str) -> tuple[int, str, str]:
    """Transpiles and runs a Capa program. Returns (returncode, stdout, stderr)."""
    code = transpile_only(source)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        path = f.name
    try:
        env = os.environ.copy()
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            str(_PKG_ROOT) + (os.pathsep + existing if existing else "")
        )
        # Force UTF-8 on both sides of the capture: the child Python emits
        # UTF-8 (PYTHONIOENCODING) and the parent decoder reads UTF-8 (encoding).
        # Without this, on Windows the default is cp1252 on the parent side and
        # non-ASCII characters come out corrupted for the test.
        env["PYTHONIOENCODING"] = "utf-8"
        r = subprocess.run(
            [sys.executable, path], env=env, capture_output=True, text=True,
            encoding="utf-8", timeout=10,
        )
        return r.returncode, r.stdout, r.stderr
    finally:
        os.unlink(path)


class TestTranspileBasic(unittest.TestCase):
    def test_hello(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    stdio.println("Olá")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "Olá\n")

    def test_arithmetic(self):
        rc, out, _ = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let x = 1 + 2 * 3\n'
            '    stdio.println("${x}")\n'
        )
        self.assertEqual(out, "7\n")

    def test_let_var(self):
        rc, out, _ = run_capa(
            'fun main(stdio: Stdio)\n'
            '    var i = 0\n'
            '    while i < 3\n'
            '        stdio.println("${i}")\n'
            '        i += 1\n'
        )
        self.assertEqual(out, "0\n1\n2\n")

    def test_if_elif_else(self):
        rc, out, _ = run_capa(
            'fun classify(n: Int) -> String\n'
            '    if n > 0\n'
            '        return "pos"\n'
            '    elif n < 0\n'
            '        return "neg"\n'
            '    else\n'
            '        return "zero"\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println(classify(5))\n'
            '    stdio.println(classify(-1))\n'
            '    stdio.println(classify(0))\n'
        )
        self.assertEqual(out, "pos\nneg\nzero\n")

    def test_for_in_list(self):
        rc, out, _ = run_capa(
            'fun main(stdio: Stdio)\n'
            '    for x in [1, 2, 3]\n'
            '        stdio.println("${x}")\n'
        )
        self.assertEqual(out, "1\n2\n3\n")

    def test_string_interpolation(self):
        rc, out, _ = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let nome = "Capa"\n'
            '    stdio.println("Olá, ${nome}!")\n'
        )
        self.assertEqual(out, "Olá, Capa!\n")


class TestTranspileTypes(unittest.TestCase):
    def test_struct_creation(self):
        rc, out, err = run_capa(
            'type Ponto { x: Float, y: Float }\n'
            'fun main(stdio: Stdio)\n'
            '    let p = Ponto { x: 3.0, y: 4.0 }\n'
            '    stdio.println("${p.x}, ${p.y}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "3.0, 4.0\n")

    def test_sum_type_and_match(self):
        rc, out, err = run_capa(
            'type Cor =\n'
            '    Vermelho\n'
            '    Verde\n'
            '    Azul\n'
            'fun nome(c: Cor) -> String\n'
            '    match c\n'
            '        Vermelho ->\n'
            '            return "vermelho"\n'
            '        Verde ->\n'
            '            return "verde"\n'
            '        Azul ->\n'
            '            return "azul"\n'
            '    return "?"\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println(nome(Vermelho))\n'
            '    stdio.println(nome(Azul))\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "vermelho\nazul\n")

    def test_variant_with_payload(self):
        rc, out, err = run_capa(
            'type Forma =\n'
            '    Circulo(Float)\n'
            '    Quadrado(Float)\n'
            'fun area(f: Forma) -> Float\n'
            '    match f\n'
            '        Circulo(r) ->\n'
            '            return r * r * 3.14\n'
            '        Quadrado(l) ->\n'
            '            return l * l\n'
            '    return 0.0\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${area(Quadrado(5.0))}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "25.0\n")


class TestTranspileResult(unittest.TestCase):
    def test_ok_path(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let r = Ok(42)\n'
            '    match r\n'
            '        Ok(n) ->\n'
            '            stdio.println("got ${n}")\n'
            '        Err(_) ->\n'
            '            stdio.println("err")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "got 42\n")

    def test_some_str_format(self):
        # With __str__ defined in the runtime, Some(x) prints "Some(x)"
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let o = Some(42)\n'
            '    stdio.println("${o}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "Some(42)\n")

    def test_generics_example(self):
        # The generics.capa example exercises inference in variant
        # constructors, function calls, and struct literals.
        with open("examples/generics.capa", encoding="utf-8") as f:
            src = f.read()
        rc, out, err = run_capa(src)
        self.assertEqual(rc, 0, err)
        self.assertIn("first: Some(1)", out)
        self.assertIn("pair: 1, one", out)
        self.assertIn("wrapped: 42", out)

    def test_err_path(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let r = Err("boom")\n'
            '    match r\n'
            '        Ok(_) ->\n'
            '            stdio.println("ok")\n'
            '        Err(msg) ->\n'
            '            stdio.println("err: ${msg}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "err: boom\n")

    def test_try_propagates_err(self):
        rc, out, err = run_capa(
            'fun parse(s: String) -> Result<Int, String>\n'
            '    if s == "ok"\n'
            '        return Ok(42)\n'
            '    return Err("bad")\n'
            'fun pipeline(s: String) -> Result<Int, String>\n'
            '    let n = parse(s)?\n'
            '    return Ok(n + 1)\n'
            'fun main(stdio: Stdio)\n'
            '    match pipeline("ok")\n'
            '        Ok(n) ->\n'
            '            stdio.println("ok: ${n}")\n'
            '        Err(e) ->\n'
            '            stdio.println("err: ${e}")\n'
            '    match pipeline("bad")\n'
            '        Ok(n) ->\n'
            '            stdio.println("ok: ${n}")\n'
            '        Err(e) ->\n'
            '            stdio.println("err: ${e}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "ok: 43\nerr: bad\n")


class TestTranspileImpl(unittest.TestCase):
    def test_method_call(self):
        rc, out, err = run_capa(
            'type Contador { v: Int }\n'
            'impl Contador\n'
            '    fun valor(self) -> Int\n'
            '        return self.v\n'
            'fun main(stdio: Stdio)\n'
            '    let c = Contador { v: 7 }\n'
            '    stdio.println("${c.valor()}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "7\n")


class TestMatchExpression(unittest.TestCase):
    """Match as expression, produces a value, usable in RHS of let/var/return,
    and in any expression position."""

    def test_match_as_return_value(self):
        rc, out, err = run_capa(
            'type Cor =\n'
            '    Vermelho\n'
            '    Verde\n'
            '    Azul\n'
            'fun nome(c: Cor) -> String\n'
            '    return match c\n'
            '        Vermelho -> "vermelho"\n'
            '        Verde -> "verde"\n'
            '        Azul -> "azul"\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println(nome(Vermelho))\n'
            '    stdio.println(nome(Azul))\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "vermelho\nazul\n")

    def test_match_in_let_binding(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let x = 1\n'
            '    let texto = match x\n'
            '        0 -> "zero"\n'
            '        1 -> "um"\n'
            '        _ -> "outro"\n'
            '    stdio.println(texto)\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "um\n")

    def test_match_with_guard_as_expression(self):
        rc, out, err = run_capa(
            'fun classify(n: Int) -> String\n'
            '    return match n\n'
            '        x if x > 0 -> "positivo"\n'
            '        x if x < 0 -> "negativo"\n'
            '        _ -> "zero"\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println(classify(5))\n'
            '    stdio.println(classify(-3))\n'
            '    stdio.println(classify(0))\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "positivo\nnegativo\nzero\n")

    def test_match_with_payload_as_expression(self):
        rc, out, err = run_capa(
            'type Forma =\n'
            '    Circulo(Float)\n'
            '    Quadrado(Float)\n'
            'fun area(f: Forma) -> Float\n'
            '    return match f\n'
            '        Circulo(r) -> r * r * 3.14\n'
            '        Quadrado(l) -> l * l\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${area(Quadrado(5.0))}")\n'
            '    stdio.println("${area(Circulo(2.0))}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertIn("25.0", out)
        self.assertIn("12.56", out)

    def test_match_as_statement_still_works(self):
        # In statement position, the match value is discarded.
        # Each arm with an effect (function call) runs normally.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let n = 2\n'
            '    match n\n'
            '        1 -> stdio.println("um")\n'
            '        2 -> stdio.println("dois")\n'
            '        _ -> stdio.println("outro")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "dois\n")


class TestRangeExpressions(unittest.TestCase):
    """Range expressions: `0..n` (exclusive) and `0..=n` (inclusive).
    Tested via end-to-end execution since the materialised List<Int>
    semantics depend on Python's range() behaviour."""

    def test_exclusive_range_loop(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    var total: Int = 0\n'
            '    for i in 0..5\n'
            '        total = total + i\n'
            '    stdio.println("${total}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "10\n")  # 0+1+2+3+4

    def test_inclusive_range_loop(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    var total: Int = 0\n'
            '    for i in 1..=5\n'
            '        total = total + i\n'
            '    stdio.println("${total}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "15\n")  # 1+2+3+4+5

    def test_range_length(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${(0..10).length()}")\n'
            '    stdio.println("${(0..=10).length()}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "10\n11\n")

    def test_range_to_list_in_pipeline(self):
        # The List-API surface (filter, fold, map) on a range now
        # requires explicit materialisation via `.to_list()`.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let xs = (0..10).to_list()\n'
            '    let evens = xs.filter(fun (x: Int) -> Bool => x % 2 == 0)\n'
            '    let total = evens.fold(0, fun (a: Int, x: Int) -> Int => a + x)\n'
            '    stdio.println("${evens.length()}")\n'
            '    stdio.println("${total}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "5\n20\n")  # 5 evens (0,2,4,6,8), sum 20

    def test_for_range_is_lazy(self):
        # The naive lowering of `for x in a..b` was
        # `for x in CapaList(range(a, b))`, which materialises the
        # full list (28 bytes per int on CPython). For large ranges
        # this allocated gigabytes. The transpiler now special-cases
        # the RangeExpr-iterator form to emit `for x in range(a, b)`
        # directly. This test asserts that property at the emitted
        # text level.
        code = transpile_only(
            'fun main(stdio: Stdio)\n'
            '    var total: Int = 0\n'
            '    for i in 0..1000\n'
            '        total = total + i\n'
            '    stdio.println("${total}")\n'
        )
        # The lazy form is `for i in range(0, 1000):` with no
        # `CapaList(` wrapper around it.
        self.assertIn("for i in range(0, 1000):", code)
        self.assertNotIn("for i in CapaList(range", code)

    def test_for_inclusive_range_is_lazy(self):
        code = transpile_only(
            'fun main(stdio: Stdio)\n'
            '    var total: Int = 0\n'
            '    for i in 1..=5\n'
            '        total = total + i\n'
            '    stdio.println("${total}")\n'
        )
        self.assertIn("for i in range(1, (5) + 1):", code)
        self.assertNotIn("for i in CapaList(range", code)

    def test_bound_range_is_capa_range(self):
        # Binding a range to a name now produces a CapaRange
        # (lazy iterable) rather than a materialised CapaList.
        # The for-loop iteration goes through CapaRange.__iter__
        # which delegates to Python's range, so no allocation
        # happens for the iteration either. The direct
        # `for x in a..b` form remains lazy via the fast path
        # in _emit_for.
        code = transpile_only(
            'fun main(stdio: Stdio)\n'
            '    let xs = 0..5\n'
            '    for i in xs\n'
            '        stdio.println("${i}")\n'
        )
        self.assertIn("xs = CapaRange(0, 5)", code)
        self.assertNotIn("xs = CapaList(range", code)


class TestInlineMatch(unittest.TestCase):
    """Inline match form: ``match scrutinee { p -> e, p -> e, ... }``.

    Single-expression arm bodies only, comma-separated. Lives in
    expression position (RHS of let/var/return, inside string
    interpolation, inside other expressions).
    """

    def test_inline_match_in_let(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let n = 2\n'
            '    let s = match n { 0 -> "zero", 1 -> "one", _ -> "other" }\n'
            '    stdio.println(s)\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "other\n")

    def test_inline_match_in_return(self):
        rc, out, err = run_capa(
            'fun describe(n: Int) -> String\n'
            '    return match n { 0 -> "zero", 1 -> "one", _ -> "other" }\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println(describe(0))\n'
            '    stdio.println(describe(1))\n'
            '    stdio.println(describe(7))\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "zero\none\nother\n")

    def test_inline_match_with_guards(self):
        rc, out, err = run_capa(
            'fun sign(n: Int) -> String\n'
            '    return match n { x if x > 0 -> "+", x if x < 0 -> "-", _ -> "0" }\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println(sign(5))\n'
            '    stdio.println(sign(-3))\n'
            '    stdio.println(sign(0))\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "+\n-\n0\n")

    def test_inline_match_with_or_pattern(self):
        rc, out, err = run_capa(
            'fun classify(n: Int) -> String\n'
            '    return match n { 0 | 1 -> "binary", 2 | 3 | 5 | 7 -> "small prime", _ -> "other" }\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println(classify(1))\n'
            '    stdio.println(classify(5))\n'
            '    stdio.println(classify(9))\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "binary\nsmall prime\nother\n")

    def test_inline_match_trailing_comma(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let s = match 1 {\n'
            '        0 -> "zero",\n'
            '        1 -> "one",\n'
            '        _ -> "other",\n'
            '    }\n'
            '    stdio.println(s)\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "one\n")

    def test_inline_match_inside_interpolation(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let n = 2\n'
            '    stdio.println("n is ${match n { 0 -> \\"zero\\", _ -> \\"nonzero\\" }}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "n is nonzero\n")

    def test_inline_match_with_pascalcase_scrutinee(self):
        # Critical disambiguation test: `match Red { ... }` must parse
        # as inline match, not as `match (Red { ... })` (struct literal).
        rc, out, err = run_capa(
            'type Color =\n'
            '    Red\n'
            '    Green\n'
            '    Blue\n'
            'fun main(stdio: Stdio)\n'
            '    let s = match Red { Red -> "r", Green -> "g", Blue -> "b" }\n'
            '    stdio.println(s)\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "r\n")

    def test_inline_match_with_variant_payload(self):
        rc, out, err = run_capa(
            'type Shape =\n'
            '    Circle(Float)\n'
            '    Square(Float)\n'
            'fun area(s: Shape) -> Float\n'
            '    return match s { Circle(r) -> r * r * 3.14, Square(l) -> l * l }\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${area(Square(5.0))}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "25.0\n")

    def test_inline_match_empty_is_error(self):
        # `match x {}` is invalid, must have at least one arm.
        from capa import Lexer, Parser, ParserError
        src = (
            'fun main(stdio: Stdio)\n'
            '    let s = match 1 {}\n'
            '    stdio.println(s)\n'
        )
        with self.assertRaises((ParserError, Exception)):
            tokens = Lexer(src).lex()
            Parser(tokens, source=src).parse_module()


class TestLambdaExpr(unittest.TestCase):
    """Closures (lambda expressions): ``fun (params) -> Ret => body``."""

    def test_lambda_basic(self):
        rc, out, err = run_capa(
            "fun main(stdio: Stdio)\n"
            "    let dobro = fun (x: Int) -> Int => x * 2\n"
            "    stdio.println(\"${dobro(21)}\")\n"
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "42\n")

    def test_lambda_multiple_params(self):
        rc, out, err = run_capa(
            "fun main(stdio: Stdio)\n"
            "    let soma = fun (a: Int, b: Int) -> Int => a + b\n"
            "    stdio.println(\"${soma(3, 4)}\")\n"
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "7\n")

    def test_lambda_no_return_annotation(self):
        # Without return annotation, it's inferred from the body.
        rc, out, err = run_capa(
            "fun main(stdio: Stdio)\n"
            "    let inc = fun (x: Int) => x + 1\n"
            "    stdio.println(\"${inc(41)}\")\n"
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "42\n")


class TestTranspileExamples(unittest.TestCase):
    """Smoke tests for the example files."""

    def _run_example(self, path: str) -> tuple[int, str, str]:
        # .capa files are UTF-8 by convention (EBNF section 3.1). Being
        # explicit avoids the Windows locale default (cp1252) corrupting
        # non-ASCII characters.
        with open(path, encoding="utf-8") as f:
            return run_capa(f.read())

    def test_hello(self):
        rc, out, err = self._run_example("examples/hello.capa")
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "Hello, world!")

    def test_basics(self):
        rc, out, err = self._run_example("examples/basics.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("distance squared = 25.0", out)
        self.assertIn("even: 0", out)
        self.assertIn("even: 8", out)

    def test_tasks(self):
        rc, out, err = self._run_example("examples/tasks.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("Review article: urgent", out)
        self.assertIn("Buy bread: deferrable", out)

    def test_grades(self):
        rc, out, err = self._run_example("examples/grades.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("=== Roster ===", out)
        self.assertIn("Excellent", out)
        self.assertIn("Passed:  5", out)

    def test_user_capabilities(self):
        rc, out, err = self._run_example("examples/user_capabilities.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("sent welcome email", out)

    def test_demo_event_stream(self):
        # The supply-chain-attack walkthrough. The .capa file is the
        # *safe* version of the library; the matching writeup in
        # docs/demo-event-stream.md is what shows what the analyzer
        # rejects.
        rc, out, err = self._run_example("examples/demo_event_stream.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("flat_map produced 9 words from 2 lines", out)

    def test_spdx_parser(self):
        # Real-world SBOM parsing in Capa: reads an SPDX 2.3 JSON
        # sample, builds typed Capa structs, prints a summary,
        # then validates referential integrity. Exercises
        # ?-chaining on Result through deeply-nested JsonValue
        # extraction, plus a Set<String> sweep over relationships.
        rc, out, err = self._run_example("examples/spdx_parser.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("SPDX document: capa-demo-sbom", out)
        self.assertIn("Packages (1):", out)
        self.assertIn("capa 0.6.0-alpha", out)
        self.assertIn("SHA1 = aaaabbbbcccc", out)
        self.assertIn("Relationships (1):", out)
        self.assertIn("DESCRIBES", out)
        self.assertIn("Validation: ok (refs resolve + acyclic)", out)

    def test_cve_torchtriton(self):
        # Fifth CVE walkthrough: the PyTorch nightly typosquat that
        # exfiltrated SSH keys + env via Fs/Net/Env abuse from a
        # package whose legitimate role (Triton kernel runtime)
        # needed none of those. Same clean-win shape as
        # eslint-scope and event-stream, different ecosystem
        # (Python / PyPI) and different attack vector (pip
        # resolution preferring public PyPI over private index).
        rc, out, err = self._run_example("examples/cve_torchtriton.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("launch plan: grid=4 block=256 args=3", out)
        self.assertIn("launch plan: grid=8 block=128 args=4", out)
        self.assertIn("launch plan: grid=16 block=64 args=2", out)

    def test_vex_demo(self):
        # End-to-end smoke test of the VEX example: compiles, runs,
        # and prints both UA-parser and HTML-rendering output. The
        # VEX-specific assertions live in tests/test_attributes.py
        # under TestVEX; this just makes sure the example file does
        # not regress at the build / run level.
        rc, out, err = self._run_example("examples/vex_demo.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("parsed UA: Chrome", out)
        self.assertIn("rendered:", out)

    def test_sbom_diff(self):
        # Reads two CycloneDX SBOMs (demo-sbom.json + demo-sbom-v2.json)
        # and reports capability-level changes per function: additions,
        # removals, widenings (alert), narrowings (improvement). The
        # auditor-facing piece of the compiler-as-evidence-producer
        # story.
        rc, out, err = self._run_example("examples/sbom_diff.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("Added functions (1):", out)
        self.assertIn("+ compute_hash", out)
        self.assertIn("Removed functions (1):", out)
        self.assertIn("- notify_remote", out)
        self.assertIn("log_event widened: +[Net]", out)
        self.assertIn("save_report narrowed: -[Fs]", out)
        self.assertIn("Unchanged: 2", out)

    def test_empirical_config(self):
        # Empirical micro-validation paired with the naive Python
        # version at examples/empirical_config_naive.py. The Capa
        # side splits the same logic into 8 functions (3 pure, 3
        # single-capability, 1 composer, 1 main) whose declared
        # capabilities flow through to the CycloneDX SBOM. Companion
        # writeup at docs/empirical_micro.md.
        rc, out, err = self._run_example("examples/empirical_config.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("name = capa-demo", out)

    def test_cve_pickle(self):
        # Tenth CVE walkthrough, fourth of the design-pattern
        # (vs supply-chain delivery) class: pickle / Java
        # ObjectInputStream gadget-chain unserialisation. The
        # Capa decode signature returns a closed algebraic type
        # (JsonValue or a typed struct), so there is no place to
        # construct arbitrary runtime types. Completes the four
        # canonical design-pattern bug classes. Companion writeup
        # at docs/cve_pickle.md.
        rc, out, err = self._run_example("examples/cve_pickle.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("safe: name=alice age=30", out)
        self.assertIn("gadget input parsed safely:", out)
        self.assertIn("typed error:", out)

    def test_cve_lxml_xxe(self):
        # Ninth CVE walkthrough, third of the design-pattern
        # (vs supply-chain delivery) class: XML external entity
        # (XXE), the lxml CVE family. The Capa parse_xml signature
        # has no Fs and no Net, so resolution of file:// or
        # http:// entities is structurally impossible. Companion
        # writeup at docs/cve_lxml_xxe.md.
        rc, out, err = self._run_example("examples/cve_lxml_xxe.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("safe: tag=user text=alice", out)
        self.assertIn("xxe attempt rejected:", out)
        self.assertIn("ssrf-via-xxe attempt rejected:", out)

    def test_cve_jinja2_ssti(self):
        # Eighth CVE walkthrough, second of the design-pattern
        # (vs supply-chain delivery) class: Jinja2 SSTI (server-
        # side template injection). The Capa version's template
        # engine has a render signature with no Unsafe, and the
        # substitution parser refuses to accept attribute
        # traversal or method calls. Companion writeup at
        # docs/cve_jinja2_ssti.md.
        rc, out, err = self._run_example("examples/cve_jinja2_ssti.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("safe: Welcome, alice", out)
        self.assertIn("ssti attempt rejected:", out)
        self.assertIn("method-call attempt rejected:", out)
        self.assertIn("unknown name handled:", out)

    def test_cve_pyyaml(self):
        # Seventh CVE walkthrough, first of the design-pattern
        # (vs supply-chain delivery) class: PyYAML CVE-2017-18342
        # arbitrary code execution via yaml.load. The Capa version
        # has a parse_structured signature with no Unsafe, so the
        # bug class is ruled out structurally. Companion writeup
        # at docs/cve_pyyaml.md.
        rc, out, err = self._run_example("examples/cve_pyyaml.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("safe input:", out)
        self.assertIn("malicious input parsed as data:", out)
        self.assertIn("command field stays a String, never executed", out)

    def test_cve_ua_parser_js(self):
        # Sixth CVE walkthrough: the ua-parser-js npm account
        # hijack of October 2021. Same attack mechanism as
        # eslint-scope (compromised maintainer credentials) but
        # different payload (cryptominer + DanaBot RAT vs npm
        # token exfiltration). In the repo specifically to make
        # the payload-independence point: Capa's rejection is
        # structurally identical regardless of what the attacker
        # intended to do with the ambient authority.
        rc, out, err = self._run_example("examples/cve_ua_parser_js.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("ua-parsed: Chrome on Linux (desktop)", out)
        self.assertIn("ua-parsed: Safari on macOS (desktop)", out)
        self.assertIn("ua-parsed: Firefox on Windows (desktop)", out)
        self.assertIn("ua-parsed: Chrome on Linux (mobile)", out)

    def test_cve_xz_utils(self):
        # Fourth CVE walkthrough, deliberately chosen because it
        # is the *most pessimistic* case: the actual xz-utils
        # backdoor ran at build-script + dynamic-linker level,
        # below the language layer entirely. Capa cannot catch
        # IFUNC indirection or .m4 autotools payloads. The case
        # study is in the repo precisely because any claim of
        # supply-chain defence has to acknowledge this kind of
        # attack. Companion writeup at docs/cve_xz_utils.md.
        rc, out, err = self._run_example("examples/cve_xz_utils.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("compressed 5 bytes -> 5 -> 5", out)
        self.assertIn("authentication result for alice: True", out)

    def test_cve_node_ipc(self):
        # The third CVE case study, deliberately picked because it
        # is where Capa partially LOSES: an IPC library legitimately
        # needs Net and Fs, so a rogue maintainer with that
        # authority cannot be stopped by the structural discipline
        # alone (only by attenuation in the caller). Companion
        # writeup at docs/cve_node_ipc.md.
        rc, out, err = self._run_example("examples/cve_node_ipc.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("sent via unrestricted Net to 127.0.0.1:8000", out)
        self.assertIn("sent via attenuated Net to api.example.com", out)
        self.assertIn("log_message holds only Stdio, by design", out)

    def test_cve_eslint_scope(self):
        # The eslint-scope credential-theft case study: a pure AST
        # scope analyser whose signature precludes the malicious
        # behaviour (Fs + Net) that the real eslint-scope@3.7.2
        # carried. Companion writeup at docs/cve_eslint_scope.md.
        rc, out, err = self._run_example("examples/cve_eslint_scope.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("scope analysis produced 3 bindings:", out)
        self.assertIn("let x in scope #0", out)
        self.assertIn("const API_URL in scope #0", out)
        self.assertIn("var config in scope #0", out)

    def test_sbom_capability_audit(self):
        # The headline "auditable supply chain" demo: a Capa
        # program reads a CycloneDX SBOM (the shape `capa
        # --cyclonedx` emits), extracts every function's
        # declared capabilities via the `capa:*` properties, and
        # checks them against an inline allow-list policy. The
        # sample includes one function deliberately missing from
        # the policy so the audit fires.
        rc, out, err = self._run_example("examples/sbom_capability_audit.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("Auditing demo.capa (CycloneDX 1.5)", out)
        self.assertIn("Functions found in SBOM (5):", out)
        self.assertIn("main: declares { Stdio, Net, Fs }", out)
        self.assertIn("log_event: declares { Stdio }", out)
        # The audit must flag the deliberately-unauthorised function
        self.assertIn("Audit: 1 violation(s)", out)
        self.assertIn("notify_remote declares 'Net'", out)
        self.assertIn("function not listed in policy", out)

    def test_spdx_license_expr(self):
        # SPDX 2.3 Annex D license-expression parser, recursive
        # descent over a tokenised input. Verifies precedence
        # handling on both axes: redundant parens dropped on
        # round-trip, load-bearing parens preserved.
        rc, out, err = self._run_example("examples/spdx_license_expr.capa")
        self.assertEqual(rc, 0, err)
        # Simple ident round-trips.
        self.assertIn("input:    MIT\n  parsed: MIT", out)
        # WITH binds tighter than OR; redundant parens removed.
        self.assertIn(
            "parsed: GPL-2.0-only WITH Classpath-exception-2.0 OR Apache-2.0",
            out,
        )
        # OR has lower precedence than AND; parens MUST survive.
        self.assertIn("parsed: (MIT OR Apache-2.0) AND GPL-3.0-only", out)
        # Custom licence references.
        self.assertIn("parsed: LicenseRef-MyCustomLicense", out)
        # Error paths surface structured messages.
        self.assertIn("ERROR:  unexpected end of expression", out)
        self.assertIn("ERROR:  missing ')'", out)
        self.assertIn("ERROR:  'AND' is not a valid license identifier", out)

    def test_cyclonedx_parser(self):
        # The other half of the SBOM-parsing pair: CycloneDX 1.5
        # JSON, also written in Capa. Verifies metadata, both
        # license shapes (`{license: {id: ...}}` and
        # `{expression: ...}`), the flat dependsOn graph, and
        # the bom-ref referential-integrity validator.
        rc, out, err = self._run_example("examples/cyclonedx_parser.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("CycloneDX 1.5 document", out)
        self.assertIn("Components (2):", out)
        self.assertIn("lodash 4.17.21", out)
        self.assertIn("chalk 5.3.0", out)
        # SPDX-id license shape (lodash)
        self.assertIn("license: MIT (SPDX id)", out)
        # SPDX-expression license shape (chalk)
        self.assertIn("license: MIT OR Apache-2.0 (expression)", out)
        # Dependency graph: chalk depends on lodash
        self.assertIn("pkg:npm/chalk@5.3.0", out)
        self.assertIn("-> pkg:npm/lodash@4.17.21", out)
        self.assertIn("Validation: ok (refs resolve + acyclic)", out)

    def test_net_attenuation(self):
        rc, out, err = self._run_example("examples/net_attenuation.capa")
        self.assertEqual(rc, 0, err)
        # Baseline: unrestricted Net allows everything.
        self.assertIn("=== before attenuation ===", out)
        self.assertIn("api.example.com allowed?   True", out)
        # After restrict_to: only the named host.
        self.assertIn("=== after net.restrict_to(api.example.com) ===", out)
        self.assertRegex(
            out, r"api\.example\.com allowed\?\s+True"
        )
        self.assertRegex(
            out, r"evil\.example\.com allowed\?\s+False"
        )
        # Monotonic narrowing: intersecting two disjoint single-host
        # restrictions leaves nothing allowed.
        self.assertIn("narrower allows 'api.example.com'? False", out)
        self.assertIn("narrower allows 'other.example.com'? False", out)


class TestNetRuntime(unittest.TestCase):
    """Unit tests against the runtime Net class directly, the behaviour
    that the analyzer types describe."""

    def test_fresh_net_is_unrestricted(self):
        from capa.runtime import Net
        n = Net()
        self.assertTrue(n.allows("a.com"))
        self.assertTrue(n.allows("evil.example.com"))

    def test_restrict_to_narrows(self):
        from capa.runtime import Net
        n = Net()
        api = n.restrict_to("api.example.com")
        self.assertTrue(api.allows("api.example.com"))
        self.assertFalse(api.allows("evil.example.com"))
        # The original Net is not mutated.
        self.assertTrue(n.allows("evil.example.com"))

    def test_monotonic_narrowing_to_empty(self):
        # Two disjoint restrictions intersect to nothing.
        from capa.runtime import Net
        api = Net().restrict_to("a.com")
        narrower = api.restrict_to("b.com")
        self.assertFalse(narrower.allows("a.com"))
        self.assertFalse(narrower.allows("b.com"))
        self.assertFalse(narrower.allows("anything"))

    def test_get_blocked_returns_err(self):
        from capa.runtime import Net, Err, IoError
        api = Net().restrict_to("api.example.com")
        result = api.get("https://evil.example.com/x")
        self.assertIsInstance(result, Err)
        self.assertIsInstance(result.error, IoError)
        self.assertIn("evil.example.com", str(result.error))


if __name__ == "__main__":
    unittest.main()
