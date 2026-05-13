"""Tests for ``capa.lsp_server.compute_diagnostics``.

We do not boot the full LSP server in unit tests (stdio JSON-RPC
is awkward to drive synthetically). Instead, we cover the
diagnostic computation: clean source, lexer errors, parser
errors, analyzer errors. The mapping from Capa positions
(1-based line/col) to LSP positions (0-based) is also exercised
since editors rely on it.

These tests skip cleanly when ``pygls`` (and its sibling
``lsprotocol``) are not installed, so the rest of the suite
continues to run in a stock-Python environment.
"""

import unittest

try:
    import lsprotocol  # noqa: F401
    _HAVE_LSP = True
except ImportError:
    _HAVE_LSP = False


@unittest.skipUnless(_HAVE_LSP, "requires `pygls` extra (pip install '.[lsp]')")
class TestComputeDiagnostics(unittest.TestCase):
    def setUp(self):
        from capa.lsp_server import compute_diagnostics
        self.compute = compute_diagnostics

    def test_clean_source_yields_no_diagnostics(self):
        src = 'fun main(stdio: Stdio)\n    stdio.println("hi")\n'
        self.assertEqual(self.compute(src, "t.capa"), [])

    def test_undefined_name_becomes_diagnostic(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let x = undefiend_var\n"
            "    stdio.println(\"${x}\")\n"
        )
        diags = self.compute(src, "t.capa")
        self.assertTrue(diags, "expected at least one diagnostic")
        msgs = [d.message for d in diags]
        self.assertTrue(
            any("undefined name 'undefiend_var'" in m for m in msgs),
            msgs,
        )

    def test_lsp_position_is_zero_based(self):
        # Capa reports positions as 1-based; LSP expects 0-based.
        # An undefined name on line 2, column 13 of the source
        # should appear at line=1, character=12 in the diagnostic.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let x = undefiend\n"  # col 13 = the 'u'
            "    stdio.println(\"${x}\")\n"
        )
        diags = self.compute(src, "t.capa")
        d = next(
            d for d in diags
            if "undefined name" in d.message and "undefiend" in d.message
        )
        self.assertEqual(d.range.start.line, 1)
        self.assertEqual(d.range.start.character, 12)

    def test_diagnostic_carries_error_severity(self):
        from lsprotocol import types as lsp
        src = "fun main()\n    let = 1\n"  # parser error
        diags = self.compute(src, "t.capa")
        self.assertTrue(diags)
        self.assertEqual(diags[0].severity, lsp.DiagnosticSeverity.Error)
        self.assertEqual(diags[0].source, "capa-lsp")

    def test_lexer_error_short_circuits(self):
        # When the lexer fails, parser and analyzer are skipped:
        # we expect exactly one diagnostic carrying the lexer
        # message.
        src = "fun main()\n\tlet x = 1\n"  # leading tab is a lexer error
        diags = self.compute(src, "t.capa")
        self.assertEqual(len(diags), 1)
        self.assertIn("tab", diags[0].message.lower())

    def test_parser_error_short_circuits(self):
        src = "fun main()\n    let = 1\n"  # missing pattern after let
        diags = self.compute(src, "t.capa")
        # Exactly one parser error; analyzer never runs.
        self.assertEqual(len(diags), 1)

    def test_analyzer_yields_multiple_diagnostics(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let a = aaa\n"
            "    let b = bbb\n"
        )
        diags = self.compute(src, "t.capa")
        # Both undefined names + a "stdio unused" capability warning
        # come through; we just check there are several.
        self.assertGreaterEqual(len(diags), 2)

    def test_did_you_mean_hint_is_visible_in_diagnostic(self):
        # The CLI-level message improvement should appear in the
        # diagnostic text shown by editors.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let n = \"hi\".lenght()\n"
            "    stdio.println(\"${n}\")\n"
        )
        diags = self.compute(src, "t.capa")
        self.assertTrue(
            any("did you mean 'length'?" in d.message for d in diags),
            [d.message for d in diags],
        )


if __name__ == "__main__":
    unittest.main()
