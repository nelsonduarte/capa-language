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
    return transpile(module, types=result.types, bindings=result.bindings)


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

    def test_string_char_at_in_range(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let s = "hello"\n'
            '    let c = match s.char_at(1)\n'
            '        None -> "?"\n'
            '        Some(x) -> x\n'
            '    stdio.println(c)\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "e\n")

    def test_string_char_at_out_of_range(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let s = "ab"\n'
            '    let c = match s.char_at(100)\n'
            '        None -> "OOB"\n'
            '        Some(x) -> x\n'
            '    stdio.println(c)\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "OOB\n")

    def test_string_substring(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let s = "hello world"\n'
            '    stdio.println(s.substring(6, 11))\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "world\n")

    def test_string_substring_raises_on_oob(self):
        # Audit fix C1: ``s.substring(start, end)`` traps on
        # ``end > len(s)`` instead of clamping. The pre-C1 contract
        # mirrored Python's silent slice clamp; both backends now
        # refuse so a "substring that returned less than asked"
        # can't slip past a parser as a quietly-shortened token. The
        # full negative-side coverage lives in
        # ``TestBoundsRaise::test_substring_out_of_bounds_raises``.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let s = "hi"\n'
            '    stdio.println(s.substring(0, 100))\n'
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("ValueError", err)

    def test_string_index_of_found(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let s = "hello world"\n'
            '    let idx = match s.index_of("world")\n'
            '        None -> 0 - 1\n'
            '        Some(i) -> i\n'
            '    stdio.println("${idx}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "6\n")

    def test_string_index_of_missing(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let s = "hello"\n'
            '    let idx = match s.index_of("xyz")\n'
            '        None -> 0 - 1\n'
            '        Some(i) -> i\n'
            '    stdio.println("${idx}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "-1\n")

    def test_string_interpolation(self):
        rc, out, _ = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let nome = "Capa"\n'
            '    stdio.println("Olá, ${nome}!")\n'
        )
        self.assertEqual(out, "Olá, Capa!\n")


class TestNestedStringInterpolation(unittest.TestCase):
    """fix/interp-nested-strings (2026-06-25): a string literal nested
    inside a ``${...}`` interpolation must not terminate the outer
    string. Before the fix, ``"a is ${m.get("a")...}"`` failed with
    "unterminated interpolation in string literal" because the lexer
    closed the outer literal at the inner ``"``. The lexer now consumes
    a nested string verbatim inside an interpolation (its quotes and
    braces are stepped over), and the parser's matching-``}`` scan does
    the same.
    """

    def test_nested_string_in_interpolation(self):
        # The book idiom that triggered the bug report.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let m: Map<String, Int> = new_map()\n'
            '    m.set("a", 1)\n'
            '    stdio.println("a is ${m.get("a").unwrap_or(0)}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "a is 1\n")

    def test_chained_method_with_nested_string(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let m: Map<String, Int> = new_map()\n'
            '    m.set("key", 42)\n'
            '    let d: Int = 0\n'
            '    stdio.println("v=${m.get("key").unwrap_or(d)}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "v=42\n")

    def test_literal_brace_inside_nested_string(self):
        # A ``}`` living inside the nested string must NOT be mistaken
        # for the interpolation's closing brace.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let m: Map<String, Int> = new_map()\n'
            '    m.set("}", 7)\n'
            '    stdio.println("got ${m.get("}").unwrap_or(0)}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "got 7\n")

    def test_recursive_nested_interpolation(self):
        # An interpolation inside a string inside an interpolation.
        rc, out, err = run_capa(
            'fun greet(name: String) -> String\n'
            '    return "hi ${name}"\n'
            '\n'
            'fun main(stdio: Stdio)\n'
            '    let y: String = "bob"\n'
            '    stdio.println("${greet("${y}")}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "hi bob\n")

    def test_dollar_escape_preserved(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let x: Int = 5\n'
            '    stdio.println("escape $${x}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "escape ${x}\n")

    def test_raw_string_preserved(self):
        # Raw strings are lexed by a separate path (``_lex_raw_string``)
        # that this fix does not touch: no escape processing and the
        # lexer attaches no interpolation positions. Backslashes pass
        # through literally and the value is emitted verbatim.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    stdio.println(r"raw text \\n untouched")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "raw text \\n untouched\n")

    def test_raw_string_has_no_interp_positions(self):
        # The lexer must NOT record interpolation positions for a raw
        # string, even when its text contains a literal ``${...}``: a
        # raw string is never interpolated at the lexer/parser level.
        toks = Lexer('let s = r"raw ${x} here"').lex()
        lits = [t for t in toks if t.kind.name == "STRING_LIT"]
        self.assertEqual(len(lits), 1)
        self.assertEqual(lits[0].value, "raw ${x} here")
        self.assertEqual(lits[0].interp_positions, [])

    def test_literal_brace_outside_interpolation(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    stdio.println("a } literal")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "a } literal\n")

    def test_unterminated_nested_string_still_errors(self):
        # A genuinely unterminated nested string must remain an error
        # (no swallowing the rest of the line).
        from capa.errors import LexerError
        src = (
            'fun main(stdio: Stdio)\n'
            '    let m: Map<String, Int> = new_map()\n'
            '    stdio.println("v ${m.get("a}")\n'
        )
        with self.assertRaises(LexerError):
            Lexer(src).lex()


class TestStringLitInterpolationInvariant(unittest.TestCase):
    """fix/polish-followups: the transpiler's ``_emit_string_lit`` only
    ever sees plain ``StringLit`` values, never ones carrying ``${``.
    The parser's ``_build_string_lit`` routes any ``${``-bearing string
    to an ``InterpolatedString`` node (emitted by
    ``_emit_interpolated_string``, the only place that applies the
    Bool/Display formatting rules). The old ``${`` branch inside
    ``_emit_string_lit`` was dead code that silently lacked those rules;
    it is now a single ``assert`` pinning the invariant.
    """

    def test_parser_never_makes_stringlit_with_interp(self):
        from capa import Parser
        import capa.capa_ast as A

        src = (
            'fun main(stdio: Stdio)\n'
            '    let x: Int = 5\n'
            '    stdio.println("a ${x} b")\n'
            '    stdio.println("no interp here")\n'
        )
        module = Parser(Lexer(src).lex(), source=src).parse_module()

        def walk(node):
            yield node
            for v in vars(node).values() if hasattr(node, "__dict__") else []:
                items = v if isinstance(v, (list, tuple)) else [v]
                for it in items:
                    if isinstance(it, A.Node):
                        yield from walk(it)
                    elif isinstance(it, (list, tuple)):
                        for inner in it:
                            if isinstance(inner, A.Node):
                                yield from walk(inner)

        string_lits = [
            n for n in walk(module) if isinstance(n, A.StringLit)
        ]
        self.assertTrue(string_lits)  # at least the plain one
        for lit in string_lits:
            self.assertNotIn("${", lit.value)

    def test_emit_string_lit_asserts_on_interp(self):
        # The invariant is enforced, not silently mishandled: feeding a
        # ``${``-bearing value directly trips the assertion.
        from capa.transpiler import Transpiler

        t = Transpiler()
        with self.assertRaises(AssertionError):
            t._emit_string_lit("a ${x} b")

    def test_plain_string_lit_emits_repr(self):
        from capa.transpiler import Transpiler

        t = Transpiler()
        self.assertEqual(t._emit_string_lit("hello"), repr("hello"))


def _pep701_offenders(code):
    """Return the f-strings in ``code`` that only parse on Python >= 3.12
    (PEP 701): a nested f-string, or a plain string literal inside a
    ``${...}`` field that reuses the enclosing f-string's quote char.

    ``ast.parse(code, feature_version=(3, 10))`` does NOT catch this: on a
    >= 3.12 interpreter the new f-string tokenizer accepts the syntax and
    ``feature_version`` does not downgrade it. So we walk the f-string
    tokens directly. A pre-3.12 tokenizer reads an f-string as a single
    STRING token and terminates it at the first matching quote, so any of
    these shapes raises ``SyntaxError: f-string: ...`` on Python 3.10/3.11.
    """
    import io
    import tokenize

    offenders = []
    quote_stack = []
    toks = tokenize.generate_tokens(io.StringIO(code).readline)
    for tok in toks:
        name = tokenize.tok_name[tok.type]
        if name == "FSTRING_START":
            quote = tok.string.lstrip("fFrRbB")
            if quote_stack:
                offenders.append((tok.start, "nested f-string"))
            quote_stack.append(quote)
        elif name == "FSTRING_END":
            if quote_stack:
                quote_stack.pop()
        elif name == "STRING" and quote_stack:
            inner_quote = '"' if '"' in tok.string[:2] else "'"
            if inner_quote == quote_stack[-1]:
                offenders.append((tok.start, "quote reuse inside f-string"))
    return offenders


class TestInterpolationPython310Compatible(unittest.TestCase):
    """Regression: v1.11.1 (commit c4c3522) let nested-string and
    recursive interpolation reach the transpiler, but the f-string
    emitter then produced output like ``f"{greet(f"{y}")}"`` that reuses
    the ``"`` quote inside the field. That only parses on Python >= 3.12
    (PEP 701); on the 3.10 / 3.11 interpreters ``pyproject`` supports it
    is a ``SyntaxError: f-string: unmatched '('``, so the ``tests`` CI
    gate went red on every OS for Python 3.10 while 3.12 / 3.14 passed.

    The emitter now lowers interpolation to a ``str(...) + repr(...)``
    concatenation instead of an f-string, so the output never depends on
    PEP 701. These tests transpile representative interpolation shapes
    and assert the emitted Python contains no PEP-701-only f-string,
    which fails on the old emitter and pins the fix on every runner
    (including this 3.14 machine) without needing a 3.10 interpreter.
    """

    def _assert_310_clean(self, source):
        code = transpile_only(source)
        offenders = _pep701_offenders(code)
        self.assertEqual(
            offenders,
            [],
            "transpiled Python uses PEP-701-only f-string syntax that "
            "fails on Python 3.10/3.11:\n" + code,
        )
        return code

    def test_recursive_interpolation_is_310_compatible(self):
        # The exact shape that broke CI: an interpolation inside a string
        # inside an interpolation -> ``f"{greet(f"{y}")}"`` on the old
        # emitter, which is a SyntaxError on Python 3.10/3.11.
        self._assert_310_clean(
            'fun greet(name: String) -> String\n'
            '    return "hi ${name}"\n'
            '\n'
            'fun main(stdio: Stdio)\n'
            '    let y: String = "bob"\n'
            '    stdio.println("${greet("${y}")}")\n'
        )

    def test_nested_string_interpolation_is_310_compatible(self):
        self._assert_310_clean(
            'fun main(stdio: Stdio)\n'
            '    let m: Map<String, Int> = new_map()\n'
            '    m.set("a", 1)\n'
            '    stdio.println("a is ${m.get("a").unwrap_or(0)}")\n'
        )

    def test_assorted_interpolation_shapes_are_310_compatible(self):
        # Simple, arithmetic, multiple-in-one-string, $$ escape, and an
        # adjacency case all stay 3.10-clean too (the new emitter applies
        # uniformly, so this guards against a future partial regression).
        self._assert_310_clean(
            'fun main(stdio: Stdio)\n'
            '    let x: Int = 5\n'
            '    let n: Int = 7\n'
            '    stdio.println("simple ${x}")\n'
            '    stdio.println("arith ${n * 2}")\n'
            '    stdio.println("multi ${x} and ${n} done")\n'
            '    stdio.println("escape $${x} literal")\n'
            '    stdio.println("x=${x}!")\n'
        )


class TestBoolInterpolationLowercase(unittest.TestCase):
    """Capa renders a Bool as ``true`` / ``false`` (lowercase) inside a
    ``${...}`` interpolation, matching JSON and the Wasm backend, never
    Python's capitalised ``True`` / ``False``.

    The transpiler keys this lowering off the analyzer-recorded type of
    the interpolated sub-expression. BUG #9: a Bool reached via a tuple
    index (``t[0]``) was rendered as ``True`` because the analyzer records
    ``TyUnknown`` for a tuple index (it only resolves element types for
    ``List`` receivers), so the lowering never fired. The transpiler now
    derives the tuple element type from the receiver's ``TyTuple`` for a
    constant index. See ``_interp_type`` in
    capa/transpiler/_expressions.py.
    """

    def test_bool_tuple_index_renders_lowercase(self):
        rc, out, _ = run_capa(
            'fun main(s: Stdio)\n'
            '    let t = (true, false)\n'
            '    s.println("${t[0]}")\n'
            '    s.println("${t[1]}")\n'
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, "true\nfalse\n")

    def test_int_tuple_index_unaffected(self):
        rc, out, _ = run_capa(
            'fun main(s: Stdio)\n'
            '    let t = (1, 2)\n'
            '    s.println("${t[0]}")\n'
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, "1\n")

    def test_other_bool_shapes_still_lowercase(self):
        rc, out, _ = run_capa(
            'fun ret_bool() -> Bool\n'
            '    return true\n'
            '\n'
            'fun main(s: Stdio)\n'
            '    let b = true\n'
            '    let xs = [true, false]\n'
            '    s.println("${b}")\n'
            '    s.println("${xs[0]}")\n'
            '    s.println("${ret_bool()}")\n'
            '    s.println("${1 == 2}")\n'
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, "true\ntrue\ntrue\nfalse\n")


class TestIntegerDivision(unittest.TestCase):
    """Regression tests for the Int/Int `/` lowering.

    The analyzer types `Int / Int -> Int` (see
    capa/analyzer/_expressions.py around the binop section) and the
    Wasm backend already lowered it to `i64.div_s`. The Python
    transpiler used to emit Python's `/` (true division) for every
    `BinOp("/")`, which silently returned a Float at runtime, so
    `${10 / 3}` printed `3.3333333333333335` instead of `3`. The fix
    in capa/transpiler/_expressions.py inspects the typer's recorded
    operand types and emits `//` when both sides are Int.
    """

    def test_int_div_int_runtime_is_integer(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${10 / 3}")\n'
            '    stdio.println("${20 / 4}")\n'
            '    stdio.println("${7 / 2}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "3\n5\n3\n")

    def test_int_div_int_emits_floor_division(self):
        # Bug #1: Int ``/`` routes through the ``_capa_idiv`` runtime
        # helper, which floors (like ``//``) AND traps on ``b == 0``
        # and ``i64::MIN / -1`` (plain ``//`` does neither in a way
        # that matches the Wasm trap). Must not be true division.
        code = transpile_only(
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${10 / 3}")\n'
        )
        self.assertIn("_capa_idiv(10, 3)", code)
        self.assertNotIn("(10 / 3)", code)
        self.assertNotIn("10 // 3", code)

    def test_int_div_int_via_let_bindings(self):
        # Ensure the type-lookup also works when the operands are
        # Ident nodes referring to Int-typed locals (not just
        # IntLits). The typer must have populated `types[id(left)]`
        # / `types[id(right)]` for the BinOp branch to fire.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let a = 17\n'
            '    let b = 5\n'
            '    stdio.println("${a / b}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "3\n")

    def test_float_div_float_runtime_is_float(self):
        # The fix must NOT have broken Float/Float, which should
        # still go through Python's true division.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${10.0 / 4.0}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "2.5\n")

    def test_float_div_float_emits_true_division(self):
        code = transpile_only(
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${10.0 / 4.0}")\n'
        )
        # Single slash, not floor division.
        self.assertIn("10.0 / 4.0", code)
        self.assertNotIn("10.0 // 4.0", code)

    def test_mixed_int_float_div_rejected_by_analyzer(self):
        # The analyzer rejects mixed Int/Float for `/` per its
        # binop rule. Confirm the error is recorded so the typer-
        # driven `//` lowering only fires for genuine Int/Int.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let a: Int = 10\n'
            '    let b: Float = 3.0\n'
            '    stdio.println("${a / b}")\n'
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertFalse(result.ok)
        joined = "\n".join(str(e) for e in result.errors)
        self.assertIn("operator '/'", joined)
        self.assertIn("Int", joined)
        self.assertIn("Float", joined)

    # ---- Augmented Int /= and %= mirror the binary forms ----------
    #
    # The Python backend routed Int ``+= -= *= <<= >>=`` through the
    # floor / overflow helpers but let ``/=`` and ``%=`` fall through
    # to the raw Python augmented operators. ``x /= 4`` is true
    # division in Python (Float, wrong rounding), so it printed
    # ``6.0`` where the explicit ``x = x / 4`` and the Wasm backend
    # both yield ``6``. These pin the augmented forms to the same
    # ``_capa_idiv`` / floored-``%`` lowering as the binary forms.

    def test_aug_int_div_runtime_is_integer(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    var x = 24\n'
            '    x /= 4\n'
            '    stdio.println("${x}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "6\n")

    def test_aug_int_div_is_floored(self):
        # ``-7 /= 2`` must floor to ``-4`` (Python true division would
        # give ``-3.5``; truncation would give ``-3``).
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    var x = -7\n'
            '    x /= 2\n'
            '    stdio.println("${x}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "-4\n")

    def test_aug_int_div_emits_idiv_helper(self):
        code = transpile_only(
            'fun main(stdio: Stdio)\n'
            '    var x = 24\n'
            '    x /= 4\n'
        )
        self.assertIn("_capa_idiv(x, 4)", code)
        # Must NOT leave a raw float-division augmented operator.
        self.assertNotIn("x /= 4", code)

    def test_aug_int_mod_runtime_floored(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    var x = -7\n'
            '    x %= 3\n'
            '    stdio.println("${x}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "2\n")

    def test_aug_int_div_struct_field_rmw(self):
        # The struct field read-modify-write form (``c.x /= 4``)
        # surfaces the same lowering as the plain local.
        rc, out, err = run_capa(
            'type Acc {\n'
            '    x: Int\n'
            '}\n'
            'fun main(stdio: Stdio)\n'
            '    var c = Acc { x: -7 }\n'
            '    c.x /= 2\n'
            '    stdio.println("${c.x}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "-4\n")

    def test_aug_float_div_stays_true_division(self):
        # Float ``/=`` must be UNAFFECTED: it stays true division and
        # produces a Float result.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    var x = 7.0\n'
            '    x /= 2.0\n'
            '    stdio.println("${x}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "3.5\n")

    def test_aug_float_div_emits_true_division(self):
        code = transpile_only(
            'fun main(stdio: Stdio)\n'
            '    var x = 7.0\n'
            '    x /= 2.0\n'
        )
        # Float target keeps the raw Python augmented operator (the
        # ``_capa_idiv`` symbol still appears in the import preamble,
        # so check for the call form, not the bare name).
        self.assertIn("x /= ", code)
        self.assertNotIn("_capa_idiv(", code)

    def test_aug_int_div_by_zero_raises(self):
        # ``/=`` by zero on Int must trap, matching the binary form
        # (``_capa_idiv`` raises ``ZeroDivisionError``).
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    var x = 7\n'
            '    let z = 0\n'
            '    x /= z\n'
            '    stdio.println("${x}")\n'
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("ZeroDivisionError", err)

    def test_aug_int_mod_by_zero_raises(self):
        # ``%=`` by zero on Int raises ``ZeroDivisionError`` (Python's
        # native ``%`` 0), matching the binary ``%``.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    var x = 7\n'
            '    let z = 0\n'
            '    x %= z\n'
            '    stdio.println("${x}")\n'
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("ZeroDivisionError", err)


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

    def test_uppercase_constant_not_treated_as_variant(self):
        # Regression: bare-Ident emission used a PascalCase heuristic
        # that turned every uppercase name into ``Name()``, breaking
        # idiomatic UPPERCASE constants like ``INFO`` or ``MAX``.
        # The fix plumbs the analyzer's ident-to-symbol bindings
        # through to the transpiler so it can tell a payload-less
        # variant from a CONSTANT and emit accordingly.
        rc, out, err = run_capa(
            'const INFO: Int = 1\n'
            'const WARN: Int = 2\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println("info=${INFO} warn=${WARN}")\n'
            '    let level = INFO\n'
            '    stdio.println("level=${level}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "info=1 warn=2\nlevel=1\n")


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


class TestQuestionMarkHoisting(unittest.TestCase):
    """The ``?`` operator: the transpiler hoists ``?`` inline when it
    sits directly as a let / return / expression-statement value
    (the fast path, no exception). Everywhere else it falls back to
    the existing ``_capa_try`` exception-based path.

    Also exercises ``?`` on ``Option<T>``; the runtime helper was
    only wired for Result before this iteration.
    """

    def _transpile(self, src: str) -> str:
        from capa.lexer import Lexer
        from capa.parser import Parser
        from capa.analyzer import analyze
        from capa.transpiler import transpile
        tokens = Lexer(src, filename="<probe>").lex()
        module = Parser(
            tokens, source=src, filename="<probe>",
        ).parse_module()
        result = analyze(module, source=src, filename="<probe>")
        self.assertTrue(result.ok, result.errors)
        return transpile(module, types=result.types)

    def test_hoisted_let_emits_inline_check(self):
        # `let x = expr?` should not contain `_capa_try(`; it should
        # emit an isinstance check and an early return.
        code = self._transpile(
            "fun first(xs: List<Int>) -> Option<Int>\n"
            "    let a = xs.first()?\n"
            "    return Some(a)\n"
        )
        # The hoisted form's identifying token:
        self.assertIn("__capa_try_0 = ", code)
        self.assertIn("if isinstance(__capa_try_0, Err) or __capa_try_0 is None_:", code)
        # The exception-path helper must not be involved:
        self.assertNotIn("_capa_try(xs.first()", code)

    def test_hoisted_expr_stmt_emits_inline_check(self):
        # `expr?` as a bare statement: discards the unwrapped
        # payload but still propagates None_ / Err. Valid when the
        # function returns the matching wrapper.
        code = self._transpile(
            "fun ensure_first(xs: List<Int>) -> Option<Int>\n"
            "    xs.first()?\n"
            "    return Some(99)\n"
        )
        self.assertIn("__capa_try_0 = xs.first()", code)
        self.assertIn(
            "if isinstance(__capa_try_0, Err) or __capa_try_0 is None_:",
            code,
        )
        self.assertNotIn("_capa_try(xs.first()", code)

    def test_hoisted_position_still_skips_capa_try_call(self):
        # The hoist optimisation: a ? at a statement-top position
        # (let / var / assign / return / expr-stmt) is lowered to an
        # inline isinstance check, NOT a _capa_try(...) call. The
        # @_capa_wrap decorator is now emitted defensively whenever
        # any ? is in the function (even hoist-eligible ones), so
        # the optimisation is observable at the call-site level
        # rather than at the decorator level: _capa_try(...) is the
        # slow path the hoist avoids.
        code = self._transpile(
            "fun first(xs: List<Int>) -> Option<Int>\n"
            "    let a = xs.first()?\n"
            "    return Some(a)\n"
        )
        self.assertNotIn(
            "_capa_try(xs.first()", code,
            "hoist-eligible ? should not call _capa_try",
        )
        # The decorator is emitted as the soundness safety net for
        # ANY ? in the function (defensive: see _uses_exception_try).
        self.assertIn("@_capa_wrap", code)

    def test_expression_position_still_uses_capa_wrap(self):
        # `?` inside a sub-expression (here, a multiplication) is not
        # hoist-eligible; the function must still carry @_capa_wrap
        # and the expression must still call _capa_try.
        code = self._transpile(
            "fun doubled(xs: List<Int>) -> Option<Int>\n"
            "    return Some(xs.first()? * 2)\n"
        )
        self.assertIn("@_capa_wrap", code)
        self.assertIn("_capa_try(", code)

    def test_question_mark_in_var_propagates_err(self):
        # Regression: ``var x = foo()?`` used to crash at runtime
        # because the transpiler did not hoist the Try value but
        # the analyzer's _uses_exception_try also skipped the
        # decorator, so the raised _CapaTryEarlyReturn escaped
        # the function uncaught.
        rc, out, err = run_capa(
            "type Bad =\n"
            "    Oops(String)\n"
            "fun via(b: Bool) -> Result<Int, Bad>\n"
            "    var x = produce(b)?\n"
            "    return Ok(x + 1)\n"
            "fun produce(b: Bool) -> Result<Int, Bad>\n"
            "    if b\n"
            "        return Err(Oops(\"boom\"))\n"
            "    return Ok(42)\n"
            "fun main(stdio: Stdio)\n"
            "    match via(false)\n"
            "        Ok(n) -> stdio.println(\"ok: ${n}\")\n"
            "        Err(Oops(m)) -> stdio.println(\"err: ${m}\")\n"
            "    match via(true)\n"
            "        Ok(n) -> stdio.println(\"ok: ${n}\")\n"
            "        Err(Oops(m)) -> stdio.println(\"err: ${m}\")\n"
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "ok: 43\nerr: boom\n")

    def test_question_mark_in_assignment_propagates_err(self):
        # Same regression as above, but for plain ``x = foo()?``.
        rc, out, err = run_capa(
            "type Bad =\n"
            "    Oops(String)\n"
            "fun via(b: Bool) -> Result<Int, Bad>\n"
            "    var x = 0\n"
            "    x = produce(b)?\n"
            "    return Ok(x)\n"
            "fun produce(b: Bool) -> Result<Int, Bad>\n"
            "    if b\n"
            "        return Err(Oops(\"boom\"))\n"
            "    return Ok(7)\n"
            "fun main(stdio: Stdio)\n"
            "    match via(false)\n"
            "        Ok(n) -> stdio.println(\"ok: ${n}\")\n"
            "        Err(Oops(m)) -> stdio.println(\"err: ${m}\")\n"
            "    match via(true)\n"
            "        Ok(n) -> stdio.println(\"ok: ${n}\")\n"
            "        Err(Oops(m)) -> stdio.println(\"err: ${m}\")\n"
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "ok: 7\nerr: boom\n")

    def test_question_mark_in_compound_assignment(self):
        # `x += foo()?` is hoisted: tmp = foo(); if Err return tmp;
        # x += tmp.value. The previous slow path (op-passed to
        # _capa_try) crashed because the decorator was skipped.
        rc, out, err = run_capa(
            "type Bad =\n"
            "    Oops(String)\n"
            "fun via(b: Bool) -> Result<Int, Bad>\n"
            "    var x = 10\n"
            "    x += produce(b)?\n"
            "    return Ok(x)\n"
            "fun produce(b: Bool) -> Result<Int, Bad>\n"
            "    if b\n"
            "        return Err(Oops(\"boom\"))\n"
            "    return Ok(5)\n"
            "fun main(stdio: Stdio)\n"
            "    match via(false)\n"
            "        Ok(n) -> stdio.println(\"ok: ${n}\")\n"
            "        Err(Oops(m)) -> stdio.println(\"err: ${m}\")\n"
            "    match via(true)\n"
            "        Ok(n) -> stdio.println(\"ok: ${n}\")\n"
            "        Err(Oops(m)) -> stdio.println(\"err: ${m}\")\n"
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "ok: 15\nerr: boom\n")

    def test_question_mark_works_on_option(self):
        # Regression: ? on Option<T> used to raise
        # `RuntimeError: ? applied to non-Result value` because
        # _capa_try only knew about Ok/Err. After the fix it handles
        # Some/None_ too.
        rc, out, err = run_capa(
            "fun first(xs: List<Int>) -> Option<Int>\n"
            "    let a = xs.first()?\n"
            "    return Some(a)\n"
            "fun main(stdio: Stdio)\n"
            "    match first([7])\n"
            "        Some(n) ->\n"
            "            stdio.println(\"got: ${n}\")\n"
            "        None ->\n"
            "            stdio.println(\"none\")\n"
            "    match first([])\n"
            "        Some(n) ->\n"
            "            stdio.println(\"got: ${n}\")\n"
            "        None ->\n"
            "            stdio.println(\"none\")\n"
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "got: 7\nnone\n")

    def test_question_mark_on_option_expression_position(self):
        # Expression-position ? on Option also goes through
        # _capa_try; verifies the Some / None_ branches of the
        # updated runtime helper.
        rc, out, err = run_capa(
            "fun first_doubled(xs: List<Int>) -> Option<Int>\n"
            "    return Some(xs.first()? * 2)\n"
            "fun main(stdio: Stdio)\n"
            "    match first_doubled([5])\n"
            "        Some(n) ->\n"
            "            stdio.println(\"${n}\")\n"
            "        None ->\n"
            "            stdio.println(\"none\")\n"
            "    match first_doubled([])\n"
            "        Some(n) ->\n"
            "            stdio.println(\"${n}\")\n"
            "        None ->\n"
            "            stdio.println(\"none\")\n"
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "10\nnone\n")

    def test_question_mark_chains_in_let(self):
        # Two ? in two lets: each gets its own temp.
        code = self._transpile(
            "fun two(xs: List<Int>) -> Option<Int>\n"
            "    let a = xs.first()?\n"
            "    let b = xs.get(1)?\n"
            "    return Some(a + b)\n"
        )
        self.assertIn("__capa_try_0 = ", code)
        self.assertIn("__capa_try_1 = ", code)

    def test_question_mark_in_result_block_lambda(self):
        # Regression: ``?`` inside a lambda body would raise
        # _CapaTryEarlyReturn that escaped past the lambda's caller
        # (which had no @_capa_wrap of its own). The transpiler now
        # wraps any lambda whose body uses ``?`` with @_capa_wrap so
        # the exception is caught at the lambda's own boundary.
        # The legitimate shape is a Result-returning block lambda.
        rc, out, err = run_capa(
            "type Bad =\n"
            "    Oops(String)\n"
            "fun produce(b: Bool) -> Result<Int, Bad>\n"
            "    if b\n"
            "        return Err(Oops(\"boom\"))\n"
            "    return Ok(7)\n"
            "fun build() -> Fun(Bool) -> Result<Int, Bad>\n"
            "    let f = fun (b: Bool) -> Result<Int, Bad> =>\n"
            "        let x = produce(b)?\n"
            "        return Ok(x + 1)\n"
            "    return f\n"
            "fun main(stdio: Stdio)\n"
            "    let f = build()\n"
            "    match f(false)\n"
            "        Ok(n) -> stdio.println(\"ok: ${n}\")\n"
            "        Err(Oops(m)) -> stdio.println(\"err: ${m}\")\n"
            "    match f(true)\n"
            "        Ok(n) -> stdio.println(\"ok: ${n}\")\n"
            "        Err(Oops(m)) -> stdio.println(\"err: ${m}\")\n"
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "ok: 8\nerr: boom\n")

    def test_result_block_lambda_emits_capa_wrap_decorator(self):
        # Pin the emission: a Result-returning block lambda with ``?``
        # inside its body should be lowered with the @_capa_wrap
        # decorator on the generated nested function. Without the
        # decorator, the _CapaTryEarlyReturn exception escapes past
        # the lambda's caller.
        code = self._transpile(
            "type Bad =\n"
            "    Oops(String)\n"
            "fun produce() -> Result<Int, Bad>\n"
            "    return Ok(1)\n"
            "fun build() -> Fun() -> Result<Int, Bad>\n"
            "    let f = fun () -> Result<Int, Bad> =>\n"
            "        let x = produce()?\n"
            "        return Ok(x + 1)\n"
            "    return f\n"
        )
        self.assertIn("@_capa_wrap", code)
        # The lambda body lives in a nested def named _lambda_<n>.
        self.assertIn("def _lambda_", code)


class TestBuiltinSpecialisations(unittest.TestCase):
    """The transpiler uses the analyser's type information to skip the
    runtime-wrapper dispatch on a handful of well-known built-in
    methods (List.{length, push, contains, is_empty, get}) and to
    lower payload-less variant ``match`` to ``if isinstance(...)``
    chains. These tests pin the emitted Python so an accidental
    regression in the type-aware dispatcher (or in the analyser's
    type assignments) is caught at the transpile boundary instead of
    waiting for a benchmark regression."""

    def _transpile(self, src: str) -> str:
        from capa.lexer import Lexer
        from capa.parser import Parser
        from capa.analyzer import analyze
        from capa.transpiler import transpile
        tokens = Lexer(src, filename="<probe>").lex()
        module = Parser(
            tokens, source=src, filename="<probe>",
        ).parse_module()
        result = analyze(module, source=src, filename="<probe>")
        self.assertTrue(result.ok, result.errors)
        return transpile(module, types=result.types)

    def test_list_push_lowers_to_native_append(self):
        code = self._transpile(
            "fun main(stdio: Stdio)\n"
            "    let xs: List<Int> = []\n"
            "    xs.push(1)\n"
            "    xs.push(2)\n"
            "    stdio.println(\"ok\")\n"
        )
        # Native list.append; no CapaList.push wrapper call.
        self.assertIn("xs.append(1)", code)
        self.assertIn("xs.append(2)", code)
        self.assertNotIn("xs.push(", code)

    def test_list_length_lowers_to_len(self):
        code = self._transpile(
            "fun main(stdio: Stdio)\n"
            "    let xs: List<Int> = [1, 2, 3]\n"
            "    stdio.println(\"${xs.length()}\")\n"
        )
        # Native len(...); no CapaList.length method call.
        self.assertIn("len(xs)", code)
        self.assertNotIn("xs.length()", code)

    def test_list_contains_lowers_to_in(self):
        code = self._transpile(
            "fun main(stdio: Stdio)\n"
            "    let xs: List<Int> = [1, 2, 3]\n"
            "    if xs.contains(2)\n"
            "        stdio.println(\"yes\")\n"
        )
        self.assertIn("(2 in xs)", code)
        self.assertNotIn("xs.contains(", code)

    def test_list_is_empty_lowers_to_len_zero(self):
        code = self._transpile(
            "fun main(stdio: Stdio)\n"
            "    let xs: List<Int> = []\n"
            "    if xs.is_empty()\n"
            "        stdio.println(\"empty\")\n"
        )
        self.assertIn("(len(xs) == 0)", code)
        self.assertNotIn("xs.is_empty()", code)

    def test_list_get_lowers_to_lambda_inline(self):
        # `get` returns Option<T>; the inline lambda evaluates the
        # receiver and the index exactly once and mirrors the runtime
        # bounds-check semantics.
        code = self._transpile(
            "fun head(xs: List<Int>) -> Option<Int>\n"
            "    return xs.get(0)\n"
        )
        self.assertIn(
            "(lambda _xs, _i: Some(_xs[_i]) if 0 <= _i < len(_xs) else None_)(xs, 0)",
            code,
        )
        self.assertNotIn("xs.get(0)", code)

    def test_list_map_stays_as_wrapper_call(self):
        # Higher-order methods stay as direct .map/.filter/.fold calls
        # on the CapaList wrapper because their semantics live in the
        # runtime helper (chained CapaList returns).
        code = self._transpile(
            "fun double_all(xs: List<Int>) -> List<Int>\n"
            "    return xs.map(fun (x: Int) -> Int => x * 2)\n"
        )
        # Direct method call survives; we did not strip the wrapper.
        self.assertIn(".map(", code)

    def test_match_payloadless_variant_lowers_to_isinstance(self):
        code = self._transpile(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "    Azul\n"
            "fun letra(c: Cor) -> String\n"
            "    return match c\n"
            "        Vermelho -> \"R\"\n"
            "        Verde -> \"G\"\n"
            "        _ -> \"B\"\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(letra(Verde))\n"
        )
        # The fast path: ``if isinstance / elif / else`` rather than
        # Python ``match`` / ``case``.
        self.assertIn("isinstance(", code)
        self.assertNotIn("match c", code)
        self.assertNotIn("case Vermelho()", code)

    def test_match_or_pattern_lowers_to_tuple_isinstance(self):
        code = self._transpile(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "    Azul\n"
            "fun is_warm(c: Cor) -> Bool\n"
            "    return match c\n"
            "        Vermelho | Verde -> true\n"
            "        _ -> false\n"
        )
        # Or-pattern collapses to ``isinstance(x, (A, B))``.
        self.assertIn("isinstance(", code)
        self.assertIn("(Vermelho, Verde)", code)

    def test_match_with_payload_stays_on_match_case(self):
        # As soon as one arm destructures a payload, the dispatch
        # falls back to Python ``match`` / ``case``.
        code = self._transpile(
            "fun unwrap_or(o: Option<Int>, d: Int) -> Int\n"
            "    return match o\n"
            "        Some(x) -> x\n"
            "        None -> d\n"
        )
        self.assertIn("match ", code)
        self.assertIn("case Some(x)", code)

    def test_match_with_guard_stays_on_match_case(self):
        code = self._transpile(
            "fun classify(n: Int) -> String\n"
            "    return match n\n"
            "        x if x > 0 -> \"pos\"\n"
            "        _ -> \"non-pos\"\n"
        )
        self.assertIn("match ", code)
        self.assertIn("if (x > 0):", code)


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

    def test_inherent_impl_with_multiple_methods(self):
        # ``impl Type`` (no trait/cap after) lets a type carry
        # methods directly. Several methods + use of one method
        # inside another via ``self.`` works end-to-end.
        rc, out, err = run_capa(
            'type Vec { x: Float, y: Float }\n'
            'impl Vec\n'
            '    fun length_sq(self) -> Float\n'
            '        return self.x * self.x + self.y * self.y\n'
            '    fun translated(self, dx: Float, dy: Float) -> Vec\n'
            '        return Vec { x: self.x + dx, y: self.y + dy }\n'
            'fun main(stdio: Stdio)\n'
            '    let v = Vec { x: 3.0, y: 4.0 }\n'
            '    stdio.println("${v.length_sq()}")\n'
            '    let w = v.translated(1.0, 1.0)\n'
            '    stdio.println("${w.x},${w.y}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "25.0\n4.0,5.0\n")

    def test_inherent_impl_on_sum_type(self):
        # ``impl`` blocks attach methods to sum types just as to
        # struct types. ``self`` in the method is the variant
        # instance; the method dispatches via the dataclass shape.
        rc, out, err = run_capa(
            'type Shape =\n'
            '    Circle(Float)\n'
            '    Square(Float)\n'
            'impl Shape\n'
            '    fun area(self) -> Float\n'
            '        return match self\n'
            '            Circle(r) -> r * r * 3.14\n'
            '            Square(l) -> l * l\n'
            'fun main(stdio: Stdio)\n'
            '    let c = Circle(2.0)\n'
            '    let s = Square(3.0)\n'
            '    stdio.println("${c.area()}")\n'
            '    stdio.println("${s.area()}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "12.56\n9.0\n")


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

    def test_match_arm_with_multi_statement_block_yields_trailing_expr(self):
        # Block-as-expression: a block arm body whose final statement is a
        # bare expression contributes that expression's value to the match.
        # Previously the arm always typed as Unit, forcing a ``var x; if`` rewrite.
        rc, out, err = run_capa(
            'fun pick(b: Bool) -> Int\n'
            '    let x = match b\n'
            '        true -> 42\n'
            '        false ->\n'
            '            let tmp = 7\n'
            '            tmp + 1\n'
            '    return x\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${pick(true)}")\n'
            '    stdio.println("${pick(false)}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "42\n8\n")

    def test_match_arm_block_with_only_trailing_expression(self):
        # Single-statement block whose statement is an expression also
        # carries the value out (degenerate case of the rule above).
        rc, out, err = run_capa(
            'fun rate(n: Int) -> String\n'
            '    return match n\n'
            '        0 ->\n'
            '            "zero"\n'
            '        _ ->\n'
            '            "non-zero"\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println(rate(0))\n'
            '    stdio.println(rate(5))\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "zero\nnon-zero\n")

    def test_match_arm_block_unit_arms_still_type_check(self):
        # A block whose trailing statement is not an ExprStmt
        # (e.g. ends in a let) still types as Unit. Used as a
        # statement-position match here so we don't need a Unit-
        # typed binding site.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let n = 1\n'
            '    match n\n'
            '        1 ->\n'
            '            let s = "one"\n'
            '            stdio.println(s)\n'
            '        _ -> stdio.println("other")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "one\n")

    def test_variant_with_multiple_payloads(self):
        # Variants with N > 1 payload types: declaration, construction,
        # and match with positional sub-pattern destructure all wire up
        # end-to-end.
        rc, out, err = run_capa(
            'type PathTest =\n'
            '    PathEquals(String, Int)\n'
            '    PathExists(String)\n'
            '    Always\n'
            'fun describe(t: PathTest) -> String\n'
            '    return match t\n'
            '        PathEquals(path, val) -> "${path}=${val}"\n'
            '        PathExists(path) -> "exists ${path}"\n'
            '        Always -> "always"\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println(describe(PathEquals("a.b", 42)))\n'
            '    stdio.println(describe(PathExists("x")))\n'
            '    stdio.println(describe(Always))\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "a.b=42\nexists x\nalways\n")

    def test_variant_three_payloads_match(self):
        # Three-payload variant exercises field indexing past 1.
        rc, out, err = run_capa(
            'type Vec3 =\n'
            '    V(Float, Float, Float)\n'
            'fun show(v: Vec3) -> String\n'
            '    return match v\n'
            '        V(x, y, z) -> "${x},${y},${z}"\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println(show(V(1.0, 2.0, 3.0)))\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "1.0,2.0,3.0\n")

    def test_match_arm_block_with_payload_destructure_and_trailing_expr(self):
        # The fast-path (isinstance dispatch) covers payload-less
        # variants only. With a payload-destructure arm, the general
        # path runs; verify it too handles trailing-expression blocks.
        rc, out, err = run_capa(
            'type Result2 =\n'
            '    Win(Int)\n'
            '    Lose\n'
            'fun score(r: Result2) -> Int\n'
            '    let s = match r\n'
            '        Win(n) ->\n'
            '            let bonus = 10\n'
            '            n + bonus\n'
            '        Lose -> 0\n'
            '    return s\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${score(Win(5))}")\n'
            '    stdio.println("${score(Lose)}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "15\n0\n")


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
        # The List-API surface (filter, fold, map) chains off an
        # explicit `.to_list()`.
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

    def test_range_transform_methods_direct(self):
        # A range carries the List transform methods directly:
        # `range.map(f)` == `range.to_list().map(f)`. The book's exact
        # example `(0..10).filter(x % 2 == 0)` must yield the evens
        # below 10; map / fold likewise mirror the materialised form.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let evens = (0..10).filter(fun (x: Int) -> Bool => x % 2 == 0)\n'
            '    let squares = (0..5).map(fun (x: Int) -> Int => x * x)\n'
            '    let total = (1..=5).fold(0, fun (a: Int, x: Int) -> Int => a + x)\n'
            '    stdio.println("${evens.length()}")\n'
            '    stdio.println("${squares.length()}")\n'
            '    stdio.println("${total}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "5\n5\n15\n")  # 5 evens, 5 squares, sum 1..=5 = 15

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


class TestMatchArmDivergent(unittest.TestCase):
    """Single-line match arms can be a divergent statement (``return``,
    ``break``, ``continue``) instead of an expression. Divergent arms
    do not contribute to the match's result type; other arms are
    free to produce any value type.
    """

    def test_return_in_single_line_arm(self):
        rc, out, err = run_capa(
            'fun unwrap_or_negative(r: Result<Int, String>) -> Int\n'
            '    let n = match r\n'
            '        Err(_) -> return 0 - 1\n'
            '        Ok(v) -> v\n'
            '    return n + 100\n'
            'fun main(stdio: Stdio)\n'
            '    let a: Result<Int, String> = Ok(5)\n'
            '    let b: Result<Int, String> = Err("oops")\n'
            '    stdio.println("${unwrap_or_negative(a)}")\n'
            '    stdio.println("${unwrap_or_negative(b)}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "105\n-1\n")

    def test_break_in_single_line_arm(self):
        rc, out, err = run_capa(
            'fun find_zero(xs: List<Int>) -> Int\n'
            '    var idx = 0\n'
            '    for x in xs\n'
            '        let _ = match x\n'
            '            0 -> break\n'
            '            _ -> false\n'
            '        idx = idx + 1\n'
            '    return idx\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${find_zero([3, 5, 0, 7])}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "2\n")

    def test_continue_in_single_line_arm(self):
        rc, out, err = run_capa(
            'fun sum_skipping_zero(xs: List<Int>) -> Int\n'
            '    var s = 0\n'
            '    for x in xs\n'
            '        let _ = match x\n'
            '            0 -> continue\n'
            '            _ -> false\n'
            '        s = s + x\n'
            '    return s\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${sum_skipping_zero([1, 0, 2, 0, 3])}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "6\n")

    def test_multi_line_arm_with_return_still_works(self):
        # Regression: the old multi-line form must keep working.
        rc, out, err = run_capa(
            'fun unwrap_or_die(r: Option<Int>) -> Int\n'
            '    let v = match r\n'
            '        None ->\n'
            '            return 0 - 999\n'
            '        Some(v) -> v\n'
            '    return v + 1\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${unwrap_or_die(Some(10))}")\n'
            '    stdio.println("${unwrap_or_die(None)}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "11\n-999\n")

    def test_all_divergent_arms_is_accepted(self):
        # A match where every arm diverges should still type-check;
        # the overall match expression has TyUnknown (which we
        # accept rather than forcing a Never type).
        rc, out, err = run_capa(
            'fun classify(x: Int) -> Int\n'
            '    let _ = match x\n'
            '        0 -> return 0\n'
            '        _ -> return 1\n'
            '    return 0 - 1\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${classify(0)}")\n'
            '    stdio.println("${classify(7)}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "0\n1\n")


class TestStdlibStringsListsMapsJson(unittest.TestCase):
    """Round-trip tests for stdlib additions in this iteration.
    Each method has a positive case and (where relevant) a
    negative-bound or empty-input case.
    """

    def test_list_find_hit(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let xs = [3, 1, 4, 1, 5, 9, 2]\n'
            '    let r = match xs.find(fun (x: Int) -> Bool => x > 4)\n'
            '        None -> 0 - 1\n'
            '        Some(v) -> v\n'
            '    stdio.println("${r}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "5\n")

    def test_list_find_miss(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let xs = [1, 2, 3]\n'
            '    let r = match xs.find(fun (x: Int) -> Bool => x > 100)\n'
            '        None -> 0 - 1\n'
            '        Some(v) -> v\n'
            '    stdio.println("${r}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "-1\n")

    def test_list_sorted_by_ascending(self):
        # Comparator returns a - b for ascending order. The original
        # list is not mutated; sorted_by returns a fresh CapaList.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let xs: List<Int> = [3, 1, 4, 1, 5, 9, 2, 6]\n'
            '    let r = xs.sorted_by(fun (a: Int, b: Int) -> Int => a - b)\n'
            '    for n in r\n'
            '        stdio.print("${n} ")\n'
            '    stdio.println("")\n'
            '    // Original list untouched.\n'
            '    stdio.println("${xs.get(0).unwrap_or(0 - 1)}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "1 1 2 3 4 5 6 9 \n3\n")

    def test_list_sorted_by_descending(self):
        # Comparator returns b - a for descending order.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let xs: List<Int> = [3, 1, 4, 1, 5]\n'
            '    let r = xs.sorted_by(fun (a: Int, b: Int) -> Int => b - a)\n'
            '    for n in r\n'
            '        stdio.print("${n} ")\n'
            '    stdio.println("")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "5 4 3 1 1 \n")

    def test_list_sorted_by_string_length(self):
        # A non-numeric comparator: by string length. Demonstrates
        # the comparator can call methods on the elements.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let xs: List<String> = ["pear", "fig", "apple", "kiwi"]\n'
            '    let r = xs.sorted_by(fun (a: String, b: String) -> Int => a.length() - b.length())\n'
            '    for s in r\n'
            '        stdio.print("${s} ")\n'
            '    stdio.println("")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "fig pear kiwi apple \n")

    def test_string_trim_start(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let s = "  hello  "\n'
            '    stdio.println("[${s.trim_start()}]")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "[hello  ]\n")

    def test_string_trim_end(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let s = "  hello  "\n'
            '    stdio.println("[${s.trim_end()}]")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "[  hello]\n")

    def test_list_find_index(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let xs = ["a", "bb", "ccc", "dddd"]\n'
            '    let r = match xs.find_index(fun (s: String) -> Bool => s.length() == 3)\n'
            '        None -> 0 - 1\n'
            '        Some(i) -> i\n'
            '    stdio.println("${r}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "2\n")

    def test_map_pairs(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let m: Map<String, Int> = new_map()\n'
            '    m.set("a", 1)\n'
            '    m.set("b", 2)\n'
            '    for pair in m.pairs()\n'
            '        let (k, v) = pair\n'
            '        stdio.println("${k}=${v}")\n'
        )
        self.assertEqual(rc, 0, err)
        # Map order is insertion-order in Python 3.7+
        self.assertEqual(out, "a=1\nb=2\n")

    def test_json_as_number_alias(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let r = parse_json("42")\n'
            '    match r\n'
            '        Ok(v) ->\n'
            '            let n = v.as_number().unwrap_or(0.0)\n'
            '            stdio.println("${n}")\n'
            '        Err(_) ->\n'
            '            stdio.println("err")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "42.0\n")

    def test_json_as_int_integer_value(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let r = parse_json("42")\n'
            '    match r\n'
            '        Ok(v) ->\n'
            '            let i = v.as_int().unwrap_or(0 - 1)\n'
            '            stdio.println("${i}")\n'
            '        Err(_) ->\n'
            '            stdio.println("err")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "42\n")

    def test_json_as_int_non_integer_returns_none(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let r = parse_json("3.14")\n'
            '    match r\n'
            '        Ok(v) ->\n'
            '            let i = v.as_int().unwrap_or(0 - 1)\n'
            '            stdio.println("${i}")\n'
            '        Err(_) ->\n'
            '            stdio.println("err")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "-1\n")

    def test_assignment_in_single_line_match_arm(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let xs = [1, 0, 2, 0, 3]\n'
            '    var sum = 0\n'
            '    for x in xs\n'
            '        let _ = match x\n'
            '            0 -> continue\n'
            '            _ -> sum = sum + x\n'
            '    stdio.println("${sum}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "6\n")


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
        self.assertIn("annotations: 1", out)
        self.assertIn("OTHER by Tool: capa-0.6: summary:total_functions=42", out)
        self.assertIn("Extracted licenses (1):", out)
        self.assertIn("- LicenseRef-AcmeProprietary", out)
        self.assertIn("name:     Acme Proprietary License", out)
        self.assertIn("https://example.org/acme-license", out)
        self.assertIn("Snippets (1):", out)
        self.assertIn("- SPDXRef-Snippet-1 (GPL helper)", out)
        self.assertIn("file:      SPDXRef-File-vendored-kernel-h", out)
        self.assertIn("range:     310-420", out)
        self.assertIn("copyright: Copyright Linus Torvalds", out)
        self.assertIn("External document refs (1):", out)
        self.assertIn("- DocumentRef-spdx-tools-1.2", out)
        self.assertIn("uri:    https://spdx.org/spdxdocs", out)
        self.assertIn("SHA1 =  d6a770ba38583ed4bb4525bd96e50461655d2759", out)
        self.assertIn("Validation: ok (refs resolve + acyclic)", out)

    def test_spdx_tag_parser(self):
        # SPDX 2.3 tag-value (text format) parsing in Capa: the
        # text-format companion to test_spdx_parser. Reads a
        # line-oriented `Tag: Value` SBOM, accumulates a typed
        # Capa AST via a stateful one-pass parser distinct from
        # the JSON tree-walker, then validates referential
        # integrity. Exercises substring-scan tokenisation and
        # the package / annotation flush state machine.
        rc, out, err = self._run_example("examples/spdx_tag_parser.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("SPDX document (tag-value): capa-demo-sbom", out)
        self.assertIn("version:   SPDX-2.3", out)
        self.assertIn("Packages (1):", out)
        self.assertIn("capa 0.6.0-alpha", out)
        self.assertIn("SHA1 = aaaabbbbcccc", out)
        self.assertIn("Relationships (1):", out)
        self.assertIn("DESCRIBES", out)
        self.assertIn("annotations: 1", out)
        self.assertIn("Validation: ok (refs resolve)", out)

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

    def test_llm_tool_sandbox(self):
        # The LLM tool-use sandboxing demo. Three user-defined
        # capabilities (SearchWeb, SendEmail, RunCode), three
        # implementors, and an agent that receives only Search +
        # Email but not RunCode. Smoke-tests the end-to-end run;
        # the discipline assertions (process_request provably
        # excludes RunCode) are covered by the manifest checks
        # below.
        rc, out, err = self._run_example("examples/llm_tool_sandbox.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("agent received query: 'Capa language news'", out)
        self.assertIn("(stub) results for 'Capa language news' on capa-language.com", out)
        self.assertIn("email sent", out)
        self.assertIn("done", out)

    def test_llm_agent_runner(self):
        # End-to-end runner with a scripted mock LLM. Tests that the
        # agent dispatches tool calls correctly and terminates on a
        # final Reply. The discipline assertion lives in the
        # manifest test below.
        rc, out, err = self._run_example("examples/llm_agent_runner.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("user: what is new with the Capa language?", out)
        self.assertIn("tool_use: search_web", out)
        self.assertIn("tool_use: send_email", out)
        self.assertIn("assistant: Done.", out)

    def test_llm_agent_runner_manifest_agent_loop_excludes_net(self):
        # The agent_loop function's signature names four caps
        # (Stdio, LlmClient, SearchWeb, SendEmail). Under per-impl
        # reachability the ``transitively_reachable_capabilities``
        # field adds the user-caps each named cap implements plus
        # any built-in caps those impls reach through their fields,
        # and ``provably_excluded_capabilities`` is computed against
        # that transitive set. Audit 2026-06-17 C5: Unsafe is the
        # FFI escape hatch and is no longer allowed to hide inside a
        # capability-bearing struct, so the AnthropicLlmClient
        # skeleton no longer carries it. None of agent_loop's impls
        # reach Unsafe or Net (the stubs hold no built-in cap), so
        # the agent honestly provably excludes both - the strongest
        # form of the headline claim.
        import json
        import subprocess
        import sys
        r = subprocess.run(
            [sys.executable, "-m", "capa", "--manifest",
             "examples/llm_agent_runner.capa"],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        m = json.loads(r.stdout)
        loop = next(
            f for f in m["functions"] if f["name"] == "agent_loop"
        )
        # Declared: exactly the four caps in the agent's signature,
        # nothing more.
        self.assertEqual(
            sorted(loop["declared_capabilities"]),
            sorted(["Stdio", "LlmClient", "SearchWeb", "SendEmail"]),
        )
        # Transitively reachable: the four declared caps and nothing
        # else - the stub impls hold no built-in authority.
        for cap in ("Stdio", "LlmClient", "SearchWeb", "SendEmail"):
            self.assertIn(cap, loop["transitively_reachable_capabilities"])
        self.assertNotIn(
            "Unsafe", loop["transitively_reachable_capabilities"],
        )
        self.assertNotIn(
            "Net", loop["transitively_reachable_capabilities"],
        )
        # Exclusion now honestly names Unsafe and Net: no impl in
        # this function's reach holds either, and Unsafe can no
        # longer be smuggled through a cap-bearing struct field.
        self.assertIn("Unsafe", loop["provably_excluded_capabilities"])
        self.assertIn("Net", loop["provably_excluded_capabilities"])
        self.assertFalse(loop["has_unsafe"])

    def test_llm_anthropic_real_compiles_and_handles_missing_key(self):
        # The real-API demo: cannot exercise the HTTP round-trip in
        # CI (no Anthropic API key, would burn quota). We do verify
        # the whole pipeline up to and including the helper round-
        # trip: sys.path bootstrap, py_import of
        # llm_anthropic_helper, py_invoke into chat(), JSON
        # response parsing, and the Result-chain error propagation
        # back to Capa. With ANTHROPIC_API_KEY empty the helper
        # returns {"ok": false, "error": "ANTHROPIC_API_KEY is
        # empty"} which the Capa side maps to Err(IoError).
        import os
        import subprocess
        import sys
        env = dict(os.environ)
        env["ANTHROPIC_API_KEY"] = ""
        r = subprocess.run(
            [sys.executable, "-m", "capa", "--run",
             "examples/llm_anthropic_real.capa"],
            capture_output=True, text=True, encoding="utf-8",
            env=env,
        )
        # The demo prints the user prompt to stdout, the error to
        # stderr, then exits 0 (the agent function returns cleanly
        # via the Err arm).
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("In one sentence: what is capability-based security?", r.stdout)
        self.assertIn("ANTHROPIC_API_KEY is empty", r.stderr)

    def test_llm_anthropic_agent_compiles_and_handles_missing_key(self):
        # End-to-end agent: real Anthropic + Capa-typed tool dispatch
        # loop. Cannot exercise the success path in CI (no API key),
        # but the empty-key path exercises everything else: sys.path
        # bootstrap, py_import of the helper, py_invoke into
        # chat_with_tools, JSON parsing, the parse_turn pattern that
        # dispatches Reply/ToolUse/Failed, and the Result chain back
        # to the agent_loop. With the key empty the helper returns
        # the structured error and the agent prints it via eprintln.
        import os
        import subprocess
        import sys
        env = dict(os.environ)
        env["ANTHROPIC_API_KEY"] = ""
        r = subprocess.run(
            [sys.executable, "-m", "capa", "--run",
             "examples/llm_anthropic_agent.capa"],
            capture_output=True, text=True, encoding="utf-8",
            env=env,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Use the search_web tool", r.stdout)
        self.assertIn("ANTHROPIC_API_KEY is empty", r.stderr)

    def test_llm_anthropic_agent_manifest_agent_loop_caps(self):
        # The headline audit claim of the full end-to-end demo,
        # restated under per-impl reachability (audit slice 21
        # closure, 2026-05-29): ``declared_capabilities`` is the
        # exact narrow surface the agent asked for at the
        # signature level. The LLM cannot grow that set at runtime;
        # the dispatch string-matching only fires for tool names
        # the agent was given. The ``transitively_reachable``
        # surface adds Unsafe because the LlmClient impl holds an
        # Unsafe (the urllib bridge into Anthropic's API). The
        # honest SBOM surfaces that authority chain.
        import json
        import subprocess
        import sys
        r = subprocess.run(
            [sys.executable, "-m", "capa", "--manifest",
             "examples/llm_anthropic_agent.capa"],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        m = json.loads(r.stdout)
        loop = next(
            f for f in m["functions"] if f["name"] == "agent_loop"
        )
        for cap in ("Stdio", "LlmClient", "SearchWeb"):
            self.assertIn(cap, loop["declared_capabilities"])
        # Unsafe is transitively reachable via the LlmClient impl;
        # the regulator-facing exclusion is therefore empty.
        self.assertIn("Unsafe", loop["transitively_reachable_capabilities"])
        self.assertEqual(loop["provably_excluded_capabilities"], [])
        self.assertTrue(loop["has_unsafe"])

    # capa_cli / capa_datetime / capa_log / capa_http are no longer
    # vendored in this repo; they live in their own standalone
    # repositories and are consumed via the package manager. The
    # integration tests that used to live here moved with them;
    # verification of the capability claims now happens via the
    # downstream demos (audit-trail-reporter, sbom-watch,
    # policy-eval) and via each library's own CI.

    def test_llm_anthropic_real_manifest_run_chat_caps(self):
        # Audit 2026-06-17 C5: a real LLM turn crosses the Python FFI
        # boundary, so the Unsafe escape hatch is no longer laundered
        # through a cap-bearing struct field (that is now a compile
        # error). It is threaded explicitly through ``ask`` and
        # ``run_chat``, so ``run_chat`` honestly DECLARES Stdio +
        # LlmClient + Unsafe at the signature level. The SBOM records
        # Unsafe as a first-class disclosure rather than a hidden
        # reachable; exclusion is empty, ``has_unsafe`` is True.
        import json
        import subprocess
        import sys
        r = subprocess.run(
            [sys.executable, "-m", "capa", "--manifest",
             "examples/llm_anthropic_real.capa"],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        m = json.loads(r.stdout)
        run_chat = next(
            f for f in m["functions"] if f["name"] == "run_chat"
        )
        # Signature surface: Stdio + LlmClient + Unsafe, all named.
        self.assertIn("Stdio", run_chat["declared_capabilities"])
        self.assertIn("LlmClient", run_chat["declared_capabilities"])
        self.assertIn("Unsafe", run_chat["declared_capabilities"])
        # Transitive surface includes Unsafe (now via the explicit
        # parameter rather than a hidden field).
        self.assertIn("Unsafe", run_chat["transitively_reachable_capabilities"])
        # Exclusion: empty, because Unsafe is in scope.
        self.assertEqual(run_chat["provably_excluded_capabilities"], [])
        self.assertTrue(run_chat["has_unsafe"])

    def test_llm_tool_sandbox_manifest_excludes_runcode(self):
        # The headline audit claim: process_request provably
        # excludes RunCode. Per-impl reachability (audit slice
        # 21 closure, 2026-05-29) sharpens this - it now also
        # surfaces Net in the transitive reachable set because
        # the SearchWeb / SendEmail impls hold ``net: Net`` for
        # the actual HTTP/SMTP calls. RunCode and Unsafe stay
        # excluded because no in-scope impl holds either: the
        # only RunCode impl is StubRunner, but process_request
        # doesn't take a RunCode and never reaches its impl
        # chain. The auditor reads the SBOM as: "uses Net via
        # the tools, provably cannot run arbitrary code."
        import json
        import subprocess
        import sys
        r = subprocess.run(
            [sys.executable, "-m", "capa", "--manifest",
             "examples/llm_tool_sandbox.capa"],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        m = json.loads(r.stdout)
        process = next(
            f for f in m["functions"] if f["name"] == "process_request"
        )
        # process_request declares Stdio + the two tools it uses.
        self.assertIn("Stdio", process["declared_capabilities"])
        self.assertIn("SearchWeb", process["declared_capabilities"])
        self.assertIn("SendEmail", process["declared_capabilities"])
        self.assertNotIn("RunCode", process["declared_capabilities"])
        # Transitive: also Net (via the tools' Net field).
        self.assertIn("Net", process["transitively_reachable_capabilities"])
        # RunCode and Unsafe remain provably excluded - no impl
        # in this function's reach holds either.
        excluded = process["provably_excluded_capabilities"]
        self.assertIn("RunCode", excluded)
        self.assertIn("Unsafe", excluded)
        # Net is NOT excluded - it's transitively reachable.
        self.assertNotIn("Net", excluded)
        self.assertFalse(process["has_unsafe"])

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
        self.assertIn("authentication result for alice: true", out)

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
        # checks them against an inline allow-list policy plus
        # cross-function structural rules. The sample fires three
        # times: one per-function violation (notify_remote not in
        # policy) and two structural violations (main and
        # notify_remote both declare Net without sitting inside
        # the NetClient container required by the structural rule).
        rc, out, err = self._run_example("examples/sbom_capability_audit.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("Auditing demo.capa (CycloneDX 1.5)", out)
        self.assertIn("Functions found in SBOM (5):", out)
        self.assertIn("main: declares { Stdio, Net, Fs }", out)
        self.assertIn("log_event: declares { Stdio }", out)
        # Per-function + structural violations stack additively.
        self.assertIn("Audit: 3 violation(s)", out)
        self.assertIn("notify_remote declares 'Net'", out)
        self.assertIn("function not listed in policy", out)
        # Structural rule fires for both main and notify_remote
        # (neither lives inside the NetClient container).
        self.assertIn(
            "violates structural rule 'net-confined-to-NetClient'",
            out,
        )
        self.assertIn("main declares 'Net'", out)
        # And the active structural rules are echoed in the output.
        self.assertIn("Structural rules (1):", out)
        self.assertIn(
            "net-confined-to-NetClient: 'Net' allowed in [NetClient]",
            out,
        )

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
        # Vulnerabilities[] / VEX block: one entry with rating,
        # affects, and analysis lines.
        self.assertIn("Vulnerabilities (1):", out)
        self.assertIn("- CVE-2024-7890 (high)", out)
        self.assertIn("affects: pkg:npm/lodash@4.17.21", out)
        self.assertIn("analysis: exploitable (code-uses-vulnerable-template)", out)
        # services[] block: one entry with provider, data classification,
        # and the authenticated / trust-boundary flag line.
        self.assertIn("Services (1):", out)
        self.assertIn("- payments-api 2024-06-20 (com.stripe)", out)
        self.assertIn("provider: Stripe", out)
        self.assertIn("authenticated: true; trust-boundary: true", out)
        self.assertIn("PII (outbound)", out)
        # evidence sub-block on the lodash component: identity + a
        # single manifest-analysis method, plus an occurrence and a
        # copyright line. chalk stays evidence-free.
        self.assertIn("evidence:", out)
        self.assertIn("identity: purl @ 1.0", out)
        self.assertIn("method: manifest-analysis @ 1.0 (package-lock.json)", out)
        self.assertIn("node_modules/lodash/index.js", out)
        self.assertIn("Copyright OpenJS Foundation and contributors", out)
        # signature block: JSF header with algorithm + keyId + value.
        # value is matched as a prefix to keep the truncation idiom free.
        self.assertIn("Signature: present", out)
        self.assertIn("algorithm: RS256", out)
        self.assertIn("key-id:    build-key-2024", out)
        self.assertIn("MEUCIQDXample", out)
        # externalReferences[] block on the lodash component: two
        # entries (website + vcs); chalk stays externalReferences-free
        # to exercise the absent-array branch.
        self.assertIn("external refs (2):", out)
        self.assertIn("[website]", out)
        self.assertIn("https://lodash.com", out)
        self.assertIn("[vcs]", out)
        self.assertIn("https://github.com/lodash/lodash", out)
        # compositions[] block: one entry exercising every sub-array
        # (assemblies + dependencies + vulnerabilities). The vuln
        # bom-ref entry uses the unique vuln- prefix so it doesn't
        # collide with the lodash component assertion above.
        self.assertIn("Compositions (1):", out)
        self.assertIn("- composition-1 (incomplete)", out)
        self.assertIn("assemblies (1):", out)
        self.assertIn("vulnerabilities (1):", out)
        self.assertIn("- vuln-CVE-2024-7890", out)
        self.assertIn("Validation: ok (refs resolve + acyclic)", out)

    def test_net_attenuation(self):
        rc, out, err = self._run_example("examples/net_attenuation.capa")
        self.assertEqual(rc, 0, err)
        # Baseline: unrestricted Net allows everything.
        self.assertIn("=== before attenuation ===", out)
        self.assertIn("api.example.com allowed?   true", out)
        # After restrict_to: only the named host.
        self.assertIn("=== after net.restrict_to(api.example.com) ===", out)
        self.assertRegex(
            out, r"api\.example\.com allowed\?\s+true"
        )
        self.assertRegex(
            out, r"evil\.example\.com allowed\?\s+false"
        )
        # Monotonic narrowing: intersecting two disjoint single-host
        # restrictions leaves nothing allowed.
        self.assertIn("narrower allows 'api.example.com'? false", out)
        self.assertIn("narrower allows 'other.example.com'? false", out)


    def _manifest_caps(self, example_path):
        # Helper for the migration tests: run --manifest and return a
        # dict mapping function name to its declared_capabilities list.
        import json
        import subprocess
        import sys
        r = subprocess.run(
            [sys.executable, "-m", "capa", "--manifest", example_path],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        m = json.loads(r.stdout)
        return {f["name"]: f["declared_capabilities"] for f in m["functions"]}

    def test_migrate_logfetcher_step1_manifest_is_unsafe_blob(self):
        # Step 1 of the Python -> Capa migration walkthrough. The Capa
        # file does nothing but py_import + py_invoke into the original
        # Python module, so the manifest says exactly what an SBOM
        # consumer should see at this stage: main exercises Stdio and
        # Unsafe, nothing more is auditable from source.
        caps = self._manifest_caps(
            "examples/migrate_logfetcher_step1_unsafe.capa"
        )
        self.assertEqual(set(caps["main"]), {"Stdio", "Unsafe"})
        self.assertEqual(set(caps["bootstrap_path"]), {"Unsafe"})

    def test_migrate_logfetcher_step2_manifest_save_response_is_fs_only(self):
        # Step 2: one function (save_response) has been moved into
        # typed Capa. The headline assertion is that save_response
        # declares Fs and nothing else, even though the rest of the
        # program still touches Unsafe.
        caps = self._manifest_caps(
            "examples/migrate_logfetcher_step2_mixed.capa"
        )
        self.assertEqual(set(caps["save_response"]), {"Fs"})
        self.assertNotIn("Unsafe", caps["save_response"])
        # main still has Unsafe because the other helpers are still
        # delegated to Python, but Fs is now visible there too.
        self.assertEqual(set(caps["main"]), {"Stdio", "Fs", "Unsafe"})

    def test_migrate_logfetcher_step3_manifest_no_unsafe_anywhere(self):
        # Step 3: every function is typed; Unsafe has been completely
        # eliminated; main's authority surface is exactly the four
        # capabilities the program actually exercises.
        caps = self._manifest_caps(
            "examples/migrate_logfetcher_step3_typed.capa"
        )
        # No function carries Unsafe.
        for name, declared in caps.items():
            self.assertNotIn(
                "Unsafe", declared,
                f"{name} should not declare Unsafe at step 3",
            )
        # main aggregates the four real capabilities.
        self.assertEqual(
            set(caps["main"]), {"Stdio", "Fs", "Env", "Net"},
        )
        # Per-helper attribution is the migration's payoff: each
        # function declares exactly the capability it needs.
        self.assertEqual(set(caps["load_config"]),   {"Fs"})
        self.assertEqual(set(caps["get_api_key"]),   {"Env"})
        self.assertEqual(set(caps["fetch_status"]),  {"Net"})
        self.assertEqual(set(caps["save_response"]), {"Fs"})
        # Pure helpers carry no capabilities at all.
        self.assertEqual(caps["build_url"],   [])
        self.assertEqual(caps["config_field"], [])


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


class TestSafetyTrapsRaise(unittest.TestCase):
    """Audit 2026-05 safety fixes: assert the Python backend raises
    at the same input the Wasm backend traps on. Pairs with
    ``tests/ir_wasm/test_wasm_safety.py::TestWasmSafetyTraps``; together they
    pin "both backends fail loud at the same point".

    These tests run the transpiled Capa code as a subprocess (same
    machinery as the rest of this file) and check the non-zero exit
    code + the expected exception name in stderr."""

    # ---- Fix C3: shift count out of [0, 64) raises ----------------

    def test_shift_left_count_64_raises(self):
        # ``a << 64`` on Int routes through ``_capa_shl``; the
        # helper raises ``OverflowError`` when the count is outside
        # ``[0, 64)``.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let n = 1 << 64\n'
            '    stdio.println("${n}")\n'
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("OverflowError", err)

    def test_shift_left_count_negative_raises(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let n = 1 << -1\n'
            '    stdio.println("${n}")\n'
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("OverflowError", err)

    def test_shift_right_count_64_raises(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let n = 1024 >> 64\n'
            '    stdio.println("${n}")\n'
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("OverflowError", err)

    # ---- Fix C6: Float % zero raises ZeroDivisionError ------------

    def test_float_modulo_zero_raises(self):
        # Python's float ``%`` 0 already raises ``ZeroDivisionError``
        # natively; the test pins the raise so a future change that
        # silently swaps for a no-trap fast path can't slip past.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let r = 7.5 % 0.0\n'
            '    stdio.println("${r}")\n'
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("ZeroDivisionError", err)

    # ---- Fix C2: Int +/-/* overflow raises OverflowError ----------

    def test_int_add_overflow_raises(self):
        # ``(1 << 62) + (1 << 62) + (1 << 62)``: well past i64::MAX.
        # ``_capa_iadd`` raises on the result-out-of-window check.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let a = (1 << 62) + (1 << 62)\n'
            '    let b = a + a\n'
            '    stdio.println("${b}")\n'
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("OverflowError", err)

    def test_int_mul_overflow_raises(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let n = 3000000000 * 4000000000\n'
            '    stdio.println("${n}")\n'
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("OverflowError", err)

    def test_int_sub_overflow_raises(self):
        # ``i64::MIN - 1`` overflows below the signed window.
        # The construction ``-(1 << 62) - (1 << 62) - 1`` reaches the
        # bottom of the window plus one extra subtract.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let lo = -(1 << 62) - (1 << 62)\n'
            '    let n = lo - 1\n'
            '    stdio.println("${n}")\n'
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("OverflowError", err)

    # ---- Fix C4: to_int out-of-range raises -----------------------

    def test_to_int_in_range_works(self):
        # Positive parity: ``to_int(1.5)`` truncates to 1 on both
        # backends.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let n = to_int(1.5)\n'
            '    stdio.println("${n}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "1\n")

    def test_to_int_overflow_raises(self):
        # ``1e20`` lies far outside the signed 64-bit window. Wasm
        # traps via ``i64.trunc_f64_s``; Python's ``to_int`` raises
        # ``OverflowError`` to match.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let n = to_int(1.0e20)\n'
            '    stdio.println("${n}")\n'
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("OverflowError", err)

    def test_to_int_negative_overflow_raises(self):
        # Below the signed 64-bit window: same trap on Wasm, same
        # ``OverflowError`` on Python.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let n = to_int(-1.0e20)\n'
            '    stdio.println("${n}")\n'
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("OverflowError", err)

    # ---- Fix C5: parse_int overflow returns None ------------------

    def test_parse_int_too_big_returns_none(self):
        # ``parse_int`` on an out-of-window string returns ``None``
        # (not Some(wrapped-value)); the Capa match prints "None".
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    match parse_int("99999999999999999999")\n'
            '        Some(n) -> stdio.println("Some(${n})")\n'
            '        None -> stdio.println("None")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "None\n")


class TestBoundsRaise(unittest.TestCase):
    """Audit fix C1: List indexing and String.substring route through
    the bounds-check runtime helpers so the Python backend raises at
    the same input the Wasm backend traps on (see
    ``tests/ir_wasm/test_wasm_safety.py::TestWasmBoundsChecks``).

    Capa indices are non-negative-only on both backends; the helper
    rejects negative indices that Python's native ``[]`` would
    otherwise resolve to "from the end". The clamp-vs-trap call for
    substring is trap: a "substring that returned less than asked"
    is a security footgun for parsers / tokenisers."""

    # ---- xs[i] -----------------------------------------------------

    def test_list_index_in_bounds_works(self):
        # Positive parity: a valid index prints the element.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let xs = [10, 20, 30]\n'
            '    stdio.println("${xs[1]}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "20\n")

    def test_list_index_out_of_bounds_raises(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let xs = [10, 20, 30]\n'
            '    stdio.println("${xs[100]}")\n'
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("IndexError", err)

    def test_list_index_negative_raises(self):
        # ``xs[0 - 1]`` resolves to ``xs[-1]``: Python's native list
        # semantics would return the last element; the helper rejects
        # it so both backends agree (Wasm traps on the same input).
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let xs = [10, 20, 30]\n'
            '    let neg = 0 - 1\n'
            '    stdio.println("${xs[neg]}")\n'
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("IndexError", err)

    # ---- s.substring(start, end) -----------------------------------

    def test_substring_in_bounds_works(self):
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let s = "abcdef"\n'
            '    stdio.println("${s.substring(1, 4)}")\n'
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "bcd\n")

    def test_substring_out_of_bounds_raises(self):
        # ``s.substring(0, 100)`` on a 6-byte string: Python's native
        # slice would clamp to ``s[0:6]``; the helper refuses so the
        # Wasm backend's trap is mirrored loudly.
        rc, out, err = run_capa(
            'fun main(stdio: Stdio)\n'
            '    let s = "abcdef"\n'
            '    stdio.println("${s.substring(0, 100)}")\n'
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("ValueError", err)


if __name__ == "__main__":
    unittest.main()
