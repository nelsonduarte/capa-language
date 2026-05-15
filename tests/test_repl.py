"""Tests for capa.repl, the interactive REPL.

The REPL itself is invoked as a subprocess (``python -m capa
repl``) with scripted stdin so we can verify end-to-end
behaviour. Lower-level helpers (``_is_top_level_form``,
``_is_bare_expression``, etc.) get focused unit tests in the
same file.
"""

from __future__ import annotations

import subprocess
import sys
import unittest

from capa.repl import (
    _ReplState,
    _is_bare_expression,
    _is_top_level_form,
    _is_unit_typed_call,
)


class TestReplHelpers(unittest.TestCase):

    def test_top_level_form_detection(self):
        for keyword in (
            "fun main()", "type Foo", "trait Bar",
            "capability Baz", "impl Foo", "const X = 1",
            "import foo",
        ):
            self.assertTrue(
                _is_top_level_form(keyword + " ..."),
                f"expected top-level form: {keyword!r}",
            )

    def test_not_top_level_form(self):
        for line in (
            "let x = 7",
            "var y = 3",
            "1 + 2",
            "stdio.println(\"hi\")",
            "if true",
        ):
            self.assertFalse(
                _is_top_level_form(line),
                f"unexpectedly classified as top-level: {line!r}",
            )

    def test_bare_expression_detection(self):
        # Things that *are* bare expressions.
        # Note: the heuristic rejects anything starting with
        # ``match`` because the common form is statement-shaped
        # ``match x ... arm -> body``; inline ``match x { ... }``
        # at the REPL is an unusual pattern and currently routes
        # to the statement bucket. Future iterations can refine.
        for line in (
            "1 + 2", "x", "foo(3)", "[1, 2, 3]",
            "fs.read(\"/tmp/x\")",
        ):
            self.assertTrue(
                _is_bare_expression(line),
                f"expected bare expression: {line!r}",
            )

    def test_statements_are_not_bare_expressions(self):
        for line in (
            "let x = 7", "var y = 3", "return 1",
            "if true", "while x > 0", "for n in xs",
            "break", "continue",
        ):
            self.assertFalse(
                _is_bare_expression(line),
                f"unexpectedly bare expression: {line!r}",
            )

    def test_assignment_is_not_bare_expression(self):
        self.assertFalse(_is_bare_expression("x = 5"))
        self.assertFalse(_is_bare_expression("obj.field = 1"))

    def test_equality_is_a_bare_expression(self):
        # `==` is comparison, not assignment.
        self.assertTrue(_is_bare_expression("x == 5"))
        self.assertTrue(_is_bare_expression("a == b == c"))

    def test_unit_typed_call_detection(self):
        for line in (
            "stdio.println(\"hi\")",
            "println(x)",
            "stdio.eprintln(\"oops\")",
            "print(123)",
        ):
            self.assertTrue(
                _is_unit_typed_call(line),
                f"expected Unit-typed call: {line!r}",
            )
        for line in ("1 + 2", "foo(3)", "x * 2"):
            self.assertFalse(_is_unit_typed_call(line))

    def test_starts_block_statement_detection(self):
        from capa.repl import _starts_block_statement
        for line in ("if x > 0", "for i in 1..4",
                     "while cond", "match x"):
            self.assertTrue(
                _starts_block_statement(line),
                f"expected block start: {line!r}",
            )
        for line in ("let x = 1", "x + 1", "stdio.println(\"hi\")",
                     "return 0", "if_function()"):
            self.assertFalse(
                _starts_block_statement(line),
                f"expected non-block: {line!r}",
            )

    def test_repl_state_assemble_with_no_body(self):
        s = _ReplState()
        program = s.assemble()
        # Every standard capability is pre-bound in main's signature.
        self.assertIn("fun main(stdio: Stdio", program)
        for cap in ("fs: Fs", "net: Net", "env: Env",
                    "clock: Clock", "random: Random"):
            self.assertIn(cap, program)
        # Each pre-bound cap has a silencer probe in the body so
        # the analyzer's "declared but never used" check passes.
        self.assertIn('stdio.print("")', program)
        for probe in ("fs.allows", "net.allows", "env.allows",
                      "clock.now_secs", "random.float_unit"):
            self.assertIn(probe, program)

    def test_repl_state_assemble_accumulates(self):
        s = _ReplState()
        s.top_lines.append("fun double(n: Int) -> Int\n    return n * 2")
        s.main_lines.append("    let x = double(5)")
        s.main_lines.append('    stdio.println("${x}")')
        program = s.assemble()
        self.assertIn("fun double(n: Int)", program)
        self.assertIn("fun main(stdio: Stdio", program)
        self.assertIn("let x = double(5)", program)


class TestReplEndToEnd(unittest.TestCase):
    """End-to-end via ``python -m capa repl``. Inputs are scripted
    through stdin. The first banner line is always present; the
    rest of stdout depends on the inputs.
    """

    def _run(self, script: str, timeout: int = 30) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "capa", "repl"],
            input=script, capture_output=True, text=True,
            encoding="utf-8", timeout=timeout,
        )

    def test_banner_and_clean_exit(self):
        result = self._run(".exit\n")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Capa REPL", result.stdout)

    def test_bare_expression_is_printed(self):
        result = self._run("1 + 2\n.exit\n")
        self.assertEqual(result.returncode, 0)
        self.assertIn("3", result.stdout)

    def test_let_then_use(self):
        result = self._run("let x = 7\nx * 2\n.exit\n")
        self.assertEqual(result.returncode, 0)
        self.assertIn("14", result.stdout)

    def test_function_decl_and_call(self):
        # Multi-line function declaration terminated by blank line.
        script = (
            "fun double(n: Int) -> Int\n"
            "    return n * 2\n"
            "\n"
            "double(5)\n"
            ".exit\n"
        )
        result = self._run(script)
        self.assertEqual(result.returncode, 0)
        self.assertIn("10", result.stdout)

    def test_stdio_println_emits_unwrapped(self):
        # When the user calls stdio.println directly, the REPL must
        # NOT wrap it (which would try to interpolate Unit).
        result = self._run('stdio.println("hello")\n.exit\n')
        self.assertEqual(result.returncode, 0)
        self.assertIn("hello", result.stdout)

    def test_reset_clears_state(self):
        script = (
            "let x = 7\n"
            "x\n"
            ".reset\n"
            "x\n"        # should error; x is gone
            ".exit\n"
        )
        result = self._run(script)
        self.assertEqual(result.returncode, 0)
        # The first `x` prints 7 (after let x = 7). After reset,
        # the second `x` produces a compile error visible in
        # stderr (REPL keeps running).
        self.assertIn("7", result.stdout)
        self.assertIn("undefined", result.stderr.lower())

    def test_show_prints_program(self):
        script = "let x = 7\n.show\n.exit\n"
        result = self._run(script)
        self.assertEqual(result.returncode, 0)
        self.assertIn("fun main(stdio: Stdio", result.stdout)
        self.assertIn("let x = 7", result.stdout)

    def test_help_lists_meta_commands(self):
        result = self._run(".help\n.exit\n")
        self.assertEqual(result.returncode, 0)
        self.assertIn(".exit", result.stdout)
        self.assertIn(".reset", result.stdout)

    def test_error_on_bad_input_keeps_repl_alive(self):
        # `undefined_name` triggers a compile error; the REPL
        # should print the error and accept the next input.
        script = "undefined_name\nlet x = 99\nx\n.exit\n"
        result = self._run(script)
        self.assertEqual(result.returncode, 0)
        self.assertIn("99", result.stdout)

    def test_clock_is_pre_bound(self):
        # ``clock`` is pre-bound; calling ``clock.now_secs()`` at
        # the prompt should succeed and print a number.
        script = "clock.now_secs()\n.exit\n"
        result = self._run(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        # Output should contain at least one digit from the timestamp.
        # We don't assert the exact value (it depends on the wall
        # clock); just that the REPL printed something numeric.
        self.assertRegex(result.stdout, r"\d")

    def test_types_command_primitive(self):
        script = ".types 1 + 2\n.exit\n"
        result = self._run(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(": Int", result.stdout)

    def test_types_command_capability(self):
        # `let _ = stdio` is illegal (capabilities can't be aliased
        # to a let); .types uses an ExprStmt probe so capability
        # references still type-check.
        script = ".types stdio\n.exit\n"
        result = self._run(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(": Stdio", result.stdout)

    def test_types_command_uses_current_scope(self):
        # A previous `let x = "hello"` puts x in scope; .types x
        # should see it as String.
        script = "let x = \"hello\"\n.types x\n.exit\n"
        result = self._run(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(": String", result.stdout)

    def test_types_command_no_run(self):
        # The probe must NOT execute the expression. We type-check
        # ``stdio.println("MARKER")`` and assert the literal does
        # not appear in the REPL's stdout.
        script = ".types stdio.println(\"MARKER\")\n.exit\n"
        result = self._run(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("MARKER", result.stdout)

    def test_types_command_usage_when_empty(self):
        script = ".types\n.exit\n"
        result = self._run(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage", result.stdout)

    def test_types_command_compile_error(self):
        # A typed expression that references an undefined name
        # should produce an error rather than crashing the REPL.
        script = ".types undefined_name\nlet y = 1\n.exit\n"
        result = self._run(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("undefined", result.stderr)

    def test_multiline_if_block(self):
        # if/else statement spanning four lines + blank terminator.
        script = (
            "let x = 5\n"
            "if x > 0\n"
            "    stdio.println(\"positive\")\n"
            "else\n"
            "    stdio.println(\"non-positive\")\n"
            "\n"
            ".exit\n"
        )
        result = self._run(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("positive", result.stdout)
        self.assertNotIn("non-positive", result.stdout)

    def test_multiline_for_block(self):
        script = (
            "for i in 1..4\n"
            "    stdio.println(\"hit\")\n"
            "\n"
            ".exit\n"
        )
        result = self._run(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        # Loop ran three times.
        self.assertEqual(result.stdout.count("hit"), 3)

    def test_multiline_while_block(self):
        script = (
            "var n = 0\n"
            "while n < 3\n"
            "    stdio.println(\"tick\")\n"
            "    n = n + 1\n"
            "\n"
            ".exit\n"
        )
        result = self._run(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("tick"), 3)

    def test_random_is_pre_bound(self):
        # ``random.float_unit()`` is a pure read; pre-binding should
        # make it accessible at the prompt. The auto-wrap path
        # avoids the bare-expression-with-quotes corner that breaks
        # `env.allows("...")` style probes, so we use this one.
        script = "random.float_unit()\n.exit\n"
        result = self._run(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        # Floats in [0, 1) print with a decimal point.
        self.assertRegex(result.stdout, r"\d+\.\d+")


if __name__ == "__main__":
    unittest.main()
