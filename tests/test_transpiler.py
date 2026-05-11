"""Tests for the Capa → Python transpiler.

Each test transpiles a Capa snippet and runs it as a Python sub-process,
verifying the stdout produced. This is the only honest way to test
the transpiler — syntactic comparisons with expected Python strings are
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
    """Just transpiles — without running."""
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    return transpile(module)


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
    """Match as expression — produces a value, usable in RHS of let/var/return,
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


if __name__ == "__main__":
    unittest.main()
