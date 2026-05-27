"""Tests for statement-level source maps and traceback rewriting.

Covers two pieces:

- The transpiler's ``out_line_map`` side channel: a
  ``python_line -> Pos`` map populated at statement-emit boundaries.
- ``capa._debug._rewrite_traceback``: turning a Python ``<transpiled>``
  traceback into a Capa-level ``file:line:col`` summary via that map,
  with a source-line + caret snippet (matching the compile-error
  formatting) when the source text is available.
"""

import types
import unittest

from capa import Lexer, Parser, transpile, analyze
from capa.tokens import Pos
from capa._debug import _rewrite_traceback


def _transpile_with_map(source: str):
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    result = analyze(module, source=source)
    line_map: dict[int, Pos] = {}
    code = transpile(
        module,
        types=result.types,
        bindings=result.bindings,
        out_line_map=line_map,
    )
    return code, line_map


class LineMapTests(unittest.TestCase):
    def test_line_map_populated_for_statements(self):
        # Capa line 2 holds `let x = 1`, line 3 holds `let y = 2`.
        source = "fun main(stdio: Stdio)\n    let x = 1\n    let y = 2\n"
        _, line_map = _transpile_with_map(source)
        self.assertTrue(line_map, "expected a non-empty line map")
        capa_lines = {pos.line for pos in line_map.values()}
        self.assertIn(2, capa_lines)
        self.assertIn(3, capa_lines)

    def test_line_map_round_trips_a_known_statement(self):
        # The `stdio.println(...)` statement is on Capa line 3.
        source = (
            "fun main(stdio: Stdio)\n"
            "    let x = 1\n"
            '    stdio.println("hi")\n'
        )
        code, line_map = _transpile_with_map(source)
        # Every recorded python line must exist in the emitted file.
        n_lines = len(code.split("\n"))
        for py_line in line_map:
            self.assertGreaterEqual(py_line, 1)
            self.assertLessEqual(py_line, n_lines)
        capa_lines = {pos.line for pos in line_map.values()}
        self.assertIn(3, capa_lines)

    def test_line_map_keys_point_at_real_python_statements(self):
        # A divide-by-zero on Capa line 3 maps to a python line whose
        # text mentions the division, proving the rebase is correct.
        source = (
            "fun main(stdio: Stdio)\n"
            "    let z = 0\n"
            "    let bad = 1 / z\n"
        )
        code, line_map = _transpile_with_map(source)
        lines = code.split("\n")
        # Find the python line for Capa line 3.
        py_for_3 = [k for k, v in line_map.items() if v.line == 3]
        self.assertTrue(py_for_3)
        # The mapped python line (1-based) should contain the division.
        target = lines[py_for_3[0] - 1]
        self.assertIn("/", target)


def _make_tb(filename: str, lineno: int):
    """Build a real traceback whose innermost frame names ``filename``
    at ``lineno`` by exec'ing padded source under that filename."""
    pad = "\n" * (lineno - 1)
    src = pad + "raise ValueError('boom')\n"
    code = compile(src, filename, "exec")
    try:
        exec(code, {})
    except ValueError:
        import sys
        return sys.exc_info()
    raise AssertionError("expected ValueError")


class RewriteTracebackTests(unittest.TestCase):
    def test_rewrite_traceback_maps_transpiled_frame_to_capa_pos(self):
        exc_info = _make_tb("<transpiled>", 12)
        line_map = {10: Pos(line=4, col=5, offset=0, filename="prog.capa")}
        out = _rewrite_traceback(exc_info, line_map)
        self.assertIn("Capa traceback", out)
        self.assertIn("prog.capa:4", out)
        self.assertIn("ValueError: boom", out)

    def test_rewrite_traceback_falls_back_when_no_mapping(self):
        # Frame at line 12, but the only map entry is at a higher line:
        # nothing qualifies (<= 12), so the rewriter yields "".
        exc_info = _make_tb("<transpiled>", 12)
        line_map = {99: Pos(line=4, col=5, offset=0, filename="prog.capa")}
        out = _rewrite_traceback(exc_info, line_map)
        self.assertEqual(out, "")

    def test_rewrite_traceback_ignores_non_transpiled_frames(self):
        exc_info = _make_tb("somewhere_else.py", 12)
        line_map = {10: Pos(line=4, col=5, offset=0, filename="prog.capa")}
        out = _rewrite_traceback(exc_info, line_map)
        self.assertEqual(out, "")

    def test_rewrite_traceback_uses_transpiled_when_pos_filename_empty(self):
        exc_info = _make_tb("<transpiled>", 12)
        line_map = {10: Pos(line=4, col=5, offset=0, filename="")}
        out = _rewrite_traceback(exc_info, line_map)
        self.assertIn("<transpiled>:4", out)


class RewriteTracebackSnippetTests(unittest.TestCase):
    """The ``:col`` header and the source-line + caret snippet."""

    def test_default_source_renders_line_and_caret(self):
        # Pos points at Capa line 3, col 5 of the supplied source.
        source = (
            "fun main(stdio: Stdio)\n"
            "    let z = 0\n"
            "    let bad = 1 / z\n"
        )
        exc_info = _make_tb("<transpiled>", 12)
        line_map = {10: Pos(line=3, col=5, offset=0, filename="prog.capa")}
        out = _rewrite_traceback(exc_info, line_map, default_source=source)
        # Header now carries :col.
        self.assertIn("prog.capa:3:5", out)
        # The offending source line appears with its gutter.
        self.assertIn("3 |     let bad = 1 / z", out)
        # A caret line is present, padded to the column.
        lines = out.split("\n")
        caret_lines = [ln for ln in lines if ln.strip() == "^"]
        self.assertTrue(caret_lines, "expected a caret line")
        # The caret sits under the statement start (col 5 within a
        # gutter of width len('   3 | ') == 7, so index 7 + (5 - 1)).
        gutter_width = len(f"{3:>4} | ")
        self.assertEqual(caret_lines[0].index("^"), gutter_width + 4)

    def test_sources_map_selects_per_file_snippet(self):
        # A frame whose Pos.filename is in ``sources`` renders that
        # file's snippet, proving the multi-file resolution path.
        root_source = "fun main(stdio: Stdio)\n    helper()\n"
        helper_source = (
            "fun helper()\n"
            "    let q = 0\n"
            "    let r = 7 / q\n"
        )
        sources = {"root.capa": root_source, "helper.capa": helper_source}
        exc_info = _make_tb("<transpiled>", 12)
        line_map = {10: Pos(line=3, col=5, offset=0, filename="helper.capa")}
        out = _rewrite_traceback(
            exc_info, line_map,
            sources=sources, default_source=root_source,
        )
        self.assertIn("helper.capa:3:5", out)
        self.assertIn("let r = 7 / q", out)
        # The root file's text must not leak in.
        self.assertNotIn("helper()", out)

    def test_out_of_range_line_falls_back_to_header_only(self):
        # Pos.line beyond the source's line count: header only, no
        # snippet, no crash.
        source = "fun main(stdio: Stdio)\n    let x = 1\n"
        exc_info = _make_tb("<transpiled>", 12)
        line_map = {10: Pos(line=99, col=5, offset=0, filename="prog.capa")}
        out = _rewrite_traceback(exc_info, line_map, default_source=source)
        self.assertIn("prog.capa:99:5", out)
        self.assertNotIn("^", out)

    def test_end_to_end_divide_by_zero_snippet(self):
        # Transpile a real divide-by-zero, exec it under <transpiled>
        # to build a genuine traceback, and confirm the rewriter names
        # the right Capa line with a caret snippet.
        source = (
            "fun main(stdio: Stdio)\n"
            "    let z = 0\n"
            "    let bad = 1 / z\n"
            '    stdio.println("${bad}")\n'
        )
        code, line_map = _transpile_with_map(source)
        run_globals = {"__name__": "__main__", "__file__": "<transpiled>"}
        try:
            exec(compile(code, "<transpiled>", "exec"), run_globals)
        except ZeroDivisionError:
            import sys
            exc_info = sys.exc_info()
        else:
            self.fail("expected ZeroDivisionError")
        out = _rewrite_traceback(exc_info, line_map, default_source=source)
        self.assertIn("Capa traceback", out)
        # Capa line 3 holds the division.
        self.assertIn(":3:", out)
        self.assertIn("let bad = 1 / z", out)
        self.assertIn("^", out)
        self.assertIn("ZeroDivisionError", out)


if __name__ == "__main__":
    unittest.main()
