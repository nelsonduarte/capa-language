"""Tests for capa.repl, the interactive REPL.

The REPL itself is invoked as a subprocess (``python -m capa
repl``) with scripted stdin so we can verify end-to-end
behaviour. Lower-level helpers (``_is_top_level_form``,
``_is_bare_expression``, etc.) get focused unit tests in the
same file.

``TestReplInProcess`` drives ``serve()`` in-process by
monkey-patching ``builtins.input`` plus capturing
``sys.stdout`` / ``sys.stderr``; that path actually exercises
the REPL's branches under the test runner's coverage instance,
where the subprocess-based ``TestReplEndToEnd`` cases do not.
"""

from __future__ import annotations

import builtins
import io
import subprocess
import sys
import unittest
from unittest import mock

from pathlib import Path

from capa import repl as _repl_module
from capa.repl import (
    _exec_in_process,
    _HISTORY_FILE,
    _ReplState,
    _find_probe_value,
    _is_bare_expression,
    _is_top_level_form,
    _is_unit_typed_call,
    _starts_block_statement,
    _try_compile_and_run,
    _typeof_expr,
    serve,
)
from capa import capa_ast as A
from capa.lexer import Lexer
from capa.parser import Parser
from capa.transpiler import transpile
from capa.analyzer import analyze


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

    def test_parser_error_keeps_repl_alive(self):
        # Lock in the assumption that ``ParserError`` is a subclass
        # of ``LexerError`` and that the REPL's ``except LexerError``
        # catches it. Audit 2026-05-25 (item #6) initially flagged
        # this as a bug; investigation showed the inheritance makes
        # the catch correct, but no test exercised the parser-error
        # path. If someone ever decouples ``ParserError`` from
        # ``LexerError``, this test fails and forces the catch site
        # to be widened.
        script = "let x =\nlet y = 42\ny\n.exit\n"
        result = self._run(script)
        self.assertEqual(result.returncode, 0)
        # The first line is a parser error (incomplete let); the
        # REPL must keep accepting input so the third line (a
        # bare ``y``) prints 42.
        self.assertIn("42", result.stdout)
        # And the parser-error message itself made it to stderr.
        self.assertIn("error", result.stderr.lower())

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


class _ScriptedInput:
    """Feeds a fixed list of lines into ``builtins.input``,
    raising ``EOFError`` once exhausted. Mirrors how the LSP
    harness drives a stubbed workspace.
    """

    def __init__(self, lines):
        self._iter = iter(lines)

    def __call__(self, prompt=""):
        try:
            return next(self._iter)
        except StopIteration:
            raise EOFError


def _run_repl(inputs):
    """Drive ``serve()`` through the scripted input list.
    Returns ``(rc, stdout, stderr)``.
    """
    out = io.StringIO()
    err = io.StringIO()
    with mock.patch.object(builtins, "input", _ScriptedInput(inputs)), \
         mock.patch.object(sys, "stdout", out), \
         mock.patch.object(sys, "stderr", err):
        rc = serve()
    return rc, out.getvalue(), err.getvalue()


class TestReplInProcess(unittest.TestCase):
    """In-process coverage for ``capa.repl``. The existing
    end-to-end suite drives the REPL via subprocess, which does
    not register against the parent's coverage instance. These
    cases monkey-patch ``builtins.input`` plus ``sys.stdout`` /
    ``sys.stderr`` so the real ``serve()`` loop runs under the
    test runner's coverage.
    """

    # --- _ReplState direct tests -------------------------------------

    def test_state_reset_clears_all_fields(self):
        s = _ReplState()
        s.top_lines.append("fun foo() -> Int\n    return 1")
        s.main_lines.append("    let x = 1")
        s.last_output = "old output"
        s.reset()
        self.assertEqual(s.top_lines, [])
        self.assertEqual(s.main_lines, [])
        self.assertEqual(s.last_output, "")

    def test_state_assemble_empty_parses(self):
        s = _ReplState()
        src = s.assemble()
        # The synthesised skeleton must parse cleanly via the
        # real parser, since every REPL turn feeds it through.
        tokens = Lexer(src, filename="<test>").lex()
        module = Parser(tokens, source=src, filename="<test>").parse_module()
        # main is the only item.
        funs = [it for it in module.items
                if isinstance(it, A.FunDecl) and it.name == "main"]
        self.assertEqual(len(funs), 1)

    def test_state_assemble_with_top_and_main_parses(self):
        s = _ReplState()
        s.top_lines.append("fun double(n: Int) -> Int\n    return n * 2")
        s.main_lines.append("    let x = double(3)")
        src = s.assemble()
        tokens = Lexer(src, filename="<test>").lex()
        module = Parser(tokens, source=src, filename="<test>").parse_module()
        names = sorted(
            it.name for it in module.items if isinstance(it, A.FunDecl)
        )
        self.assertEqual(names, ["double", "main"])

    # --- _try_compile_and_run paths ---------------------------------

    def test_try_compile_and_run_success(self):
        src = 'fun main(stdio: Stdio)\n    stdio.println("hi")\n'
        ok, out, err = _try_compile_and_run(src)
        self.assertTrue(ok, err)
        self.assertEqual(out, "hi\n")
        self.assertEqual(err, "")

    def test_try_compile_and_run_parse_error(self):
        ok, out, err = _try_compile_and_run("fun broken(\n")
        self.assertFalse(ok)
        self.assertIn("error", err.lower())

    def test_try_compile_and_run_analyse_error(self):
        # Undefined identifier referenced inside main.
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${undefined_var}")\n'
        )
        ok, out, err = _try_compile_and_run(src)
        self.assertFalse(ok)
        self.assertIn("undefined", err.lower())

    # --- _typeof_expr paths -----------------------------------------

    def test_typeof_expr_primitive(self):
        ok, msg = _typeof_expr("1 + 2", _ReplState())
        self.assertTrue(ok, msg)
        self.assertIn("Int", msg)

    def test_typeof_expr_capability(self):
        ok, msg = _typeof_expr("stdio", _ReplState())
        self.assertTrue(ok, msg)
        self.assertIn("Stdio", msg)

    def test_typeof_expr_uses_state_scope(self):
        s = _ReplState()
        s.main_lines.append('    let greeting = "hello"')
        ok, msg = _typeof_expr("greeting", s)
        self.assertTrue(ok, msg)
        self.assertIn("String", msg)

    def test_typeof_expr_unknown_identifier(self):
        ok, msg = _typeof_expr("nope_no_such_name", _ReplState())
        self.assertFalse(ok)
        self.assertIn("undefined", msg.lower())

    def test_typeof_expr_parse_error(self):
        # Malformed expression: the inner parser raises and the
        # error gets surfaced through the (False, msg) tuple.
        ok, msg = _typeof_expr("1 +", _ReplState())
        self.assertFalse(ok)
        self.assertIn("error", msg.lower())

    # --- _find_probe_value -----------------------------------------

    def test_find_probe_value_returns_last_expr(self):
        s = _ReplState()
        s.main_lines.append("    1 + 2")
        src = s.assemble()
        tokens = Lexer(src, filename="<test>").lex()
        module = Parser(tokens, source=src, filename="<test>").parse_module()
        probe = _find_probe_value(module)
        self.assertIsNotNone(probe)
        # The trailing main_line is a BinOp; that's what should
        # come back as the probe value.
        self.assertIsInstance(probe, A.BinOp)

    def test_find_probe_value_no_main_returns_none(self):
        src = "fun foo() -> Int\n    return 1\n"
        tokens = Lexer(src, filename="<test>").lex()
        module = Parser(tokens, source=src, filename="<test>").parse_module()
        self.assertIsNone(_find_probe_value(module))

    def test_find_probe_value_last_stmt_not_exprstmt(self):
        # If main's last stmt is a return (or any non-ExprStmt),
        # _find_probe_value returns None.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let x = 1\n"
            "    return\n"
        )
        tokens = Lexer(src, filename="<test>").lex()
        module = Parser(tokens, source=src, filename="<test>").parse_module()
        self.assertIsNone(_find_probe_value(module))

    def test_find_probe_value_main_with_empty_body_returns_none(self):
        # A main with no body statements (e.g. empty body) hits
        # the early "not stmts" branch. The Capa parser would
        # reject a literally empty main body, so we construct
        # the AST shape directly.
        from capa.tokens import Pos
        pos = Pos(1, 1, 0, "<test>")
        fun = A.FunDecl(
            pos=pos, name="main", params=[],
            body=A.Block(pos=pos, stmts=[]),
        )

        class _Mod:
            items = [fun]
        self.assertIsNone(_find_probe_value(_Mod()))

    # --- serve(): exits and EOF -------------------------------------

    def test_serve_exit_command(self):
        rc, out, err = _run_repl([".exit"])
        self.assertEqual(rc, 0)
        self.assertIn("Capa REPL", out)
        self.assertEqual(err, "")

    def test_serve_quit_command(self):
        rc, out, err = _run_repl([".quit"])
        self.assertEqual(rc, 0)
        self.assertIn("Capa REPL", out)

    def test_serve_eof_clean_exit(self):
        # No inputs at all: the first input() raises EOFError.
        rc, out, err = _run_repl([])
        self.assertEqual(rc, 0)
        self.assertIn("Capa REPL", out)

    # --- serve(): meta commands -------------------------------------

    def test_serve_help_command(self):
        rc, out, _ = _run_repl([".help", ".exit"])
        self.assertEqual(rc, 0)
        self.assertIn(".exit", out)
        self.assertIn(".reset", out)
        self.assertIn(".types", out)

    def test_serve_show_empty_state(self):
        rc, out, _ = _run_repl([".show", ".exit"])
        self.assertEqual(rc, 0)
        self.assertIn("fun main(stdio: Stdio", out)

    def test_serve_reset_clears_accumulated_state(self):
        rc, out, err = _run_repl([
            "let x = 1", ".reset", ".show", ".exit",
        ])
        self.assertEqual(rc, 0)
        self.assertIn("REPL state cleared.", out)
        # The reset must have wiped the let from the program;
        # .show must not echo it back.
        post_reset = out.split("REPL state cleared.", 1)[1]
        self.assertNotIn("let x = 1", post_reset)

    def test_serve_empty_line_ignored(self):
        rc, out, err = _run_repl(["", "   ", ".exit"])
        self.assertEqual(rc, 0)
        # Banner only, no errors.
        self.assertEqual(err, "")
        self.assertIn("Capa REPL", out)

    # --- serve(): .types branch --------------------------------------

    def test_serve_types_primitive(self):
        rc, out, _ = _run_repl([".types 1 + 2", ".exit"])
        self.assertEqual(rc, 0)
        self.assertIn(": Int", out)

    def test_serve_types_no_expression_usage(self):
        rc, out, _ = _run_repl([".types", ".exit"])
        self.assertEqual(rc, 0)
        self.assertIn("usage", out)

    def test_serve_types_invalid_expression(self):
        rc, out, err = _run_repl(
            [".types undefined_xyz", ".exit"]
        )
        self.assertEqual(rc, 0)
        self.assertIn("undefined", err.lower())

    # --- serve(): evaluation paths -----------------------------------

    def test_serve_bare_expression_printed(self):
        rc, out, err = _run_repl(["1 + 2", ".exit"])
        self.assertEqual(rc, 0, err)
        self.assertIn("3", out)

    def test_serve_let_then_use(self):
        rc, out, err = _run_repl(["let x = 5", "x", ".exit"])
        self.assertEqual(rc, 0, err)
        self.assertIn("5", out)

    def test_serve_stdio_println_not_double_wrapped(self):
        # _is_unit_typed_call must short-circuit the auto-wrap;
        # we expect a single "hello" in stdout, not interpolation
        # noise or duplicates.
        rc, out, err = _run_repl([
            'stdio.println("hello")', ".exit",
        ])
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.count("hello"), 1)

    def test_serve_top_level_function_declaration(self):
        rc, out, err = _run_repl([
            "fun double(n: Int) -> Int",
            "    return n * 2",
            "",                # blank line terminates the block
            "double(7)",
            ".exit",
        ])
        self.assertEqual(rc, 0, err)
        self.assertIn("14", out)

    def test_serve_for_loop_block_statement(self):
        # Exercises the _starts_block_statement gather path.
        rc, out, err = _run_repl([
            "for i in 1..4",
            '    stdio.println("tick")',
            "",
            ".exit",
        ])
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.count("tick"), 3)

    def test_serve_compile_error_keeps_loop_alive(self):
        # The first input is a parse error; the loop must keep
        # accepting input so the second bare expression prints 9.
        rc, out, err = _run_repl([
            "fun broken(",
            "",                # close the multi-line gather
            "let y = 9",
            "y",
            ".exit",
        ])
        self.assertEqual(rc, 0)
        self.assertIn("error", err.lower())
        self.assertIn("9", out)

    def test_serve_output_delta_no_double_print(self):
        # After the first println, the second turn should only
        # add the new "beta" line to stdout; the delta logic must
        # not re-emit "alpha".
        rc, out, err = _run_repl([
            'stdio.println("alpha")',
            'stdio.println("beta")',
            ".exit",
        ])
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.count("alpha"), 1)
        self.assertEqual(out.count("beta"), 1)


class TestReplReadline(unittest.TestCase):
    """Coverage for the readline / history bootstrap added in v2.

    The REPL must boot cleanly whether or not a line-editing
    implementation is importable; both branches are exercised
    here.
    """

    def test_serve_does_not_crash_without_readline(self):
        # Simulate ``import readline`` failing by stashing a None
        # entry in ``sys.modules``; the import statement then
        # raises ``ImportError`` and ``_init_readline`` falls
        # through. ``pyreadline3`` is masked the same way so the
        # Windows fallback path is also forced shut.
        with mock.patch.dict(sys.modules, {
            "readline": None, "pyreadline3": None,
        }):
            rc, out, err = _run_repl([".exit"])
        self.assertEqual(rc, 0)
        self.assertIn("Capa REPL", out)

    def test_history_file_path_default(self):
        # The on-disk history must live under the user's home so a
        # session persists across invocations; the constant is the
        # contract that future config (env override, --history flag)
        # will hang off of.
        self.assertEqual(_HISTORY_FILE, Path.home() / ".capa_repl_history")


class TestReplInProcessExec(unittest.TestCase):
    """Coverage for the in-process ``exec`` path that replaced the
    pre-v2 subprocess fork.
    """

    def _transpile(self, source: str) -> str:
        tokens = Lexer(source, filename="<test>").lex()
        module = Parser(
            tokens, source=source, filename="<test>",
        ).parse_module()
        result = analyze(module, source=source, filename="<test>")
        self.assertTrue(result.ok, result.errors)
        return transpile(module, types=result.types)

    def test_in_process_exec_captures_stdout_like_subprocess(self):
        # ``println("hello")`` should land in the captured stdout
        # buffer the same way the old subprocess capture surfaced
        # ``proc.stdout``. We compare against the unified
        # ``_try_compile_and_run`` contract: (True, "hello\n", "").
        src = 'fun main(stdio: Stdio)\n    stdio.println("hello")\n'
        code = self._transpile(src)
        ok, out, err = _exec_in_process(code)
        self.assertTrue(ok, err)
        self.assertEqual(out, "hello\n")
        self.assertEqual(err, "")

    def test_in_process_exec_surfaces_python_traceback(self):
        # A runtime panic in the Capa program lowers to a Python
        # ``raise``; the in-process path must catch ``BaseException``
        # and route the formatted traceback into the error channel,
        # preserving any stdout the program had already printed
        # before the failure.
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.println("before")\n'
            '    let _ = 1 / 0\n'
        )
        code = self._transpile(src)
        ok, out, err = _exec_in_process(code)
        self.assertFalse(ok)
        # Stdout up to the failure must survive.
        self.assertIn("before", out)
        # The Python traceback (or at least the error noun) made
        # it through the redirect.
        self.assertIn("ZeroDivisionError", err)


if __name__ == "__main__":
    unittest.main()
