"""Tests for ``capa migrate`` gradual-hardening progress reporting."""

import json
import unittest
from pathlib import Path

from capa import Lexer, Parser, analyze
from capa.migrate import migrate_report, render_report


_EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _module_from_source(source: str, filename: str = "<test>"):
    """Lex + parse + analyse source, returning the analysed module."""
    tokens = Lexer(source, filename=filename).lex()
    module = Parser(tokens, source=source, filename=filename).parse_module()
    result = analyze(module, source=source, filename=filename)
    assert result.ok, result.errors
    return module


def _report_for_example(name: str) -> dict:
    source = (_EXAMPLES / name).read_text(encoding="utf-8")
    module = _module_from_source(source, filename=name)
    return migrate_report(module, filename=name)


class TestMigrateExamples(unittest.TestCase):
    """Drive the shipped 3-stage migration demo end to end."""

    def test_step1_all_unsafe(self):
        rep = _report_for_example("migrate_logfetcher_step1_unsafe.capa")
        s = rep["summary"]
        # Everything is still behind Unsafe.
        self.assertEqual(s["functions_using_unsafe"], s["total_functions"])
        self.assertEqual(s["percent_unsafe_free"], 0)

    def test_step2_mixed_has_one_typed_function(self):
        rep = _report_for_example("migrate_logfetcher_step2_mixed.capa")
        s = rep["summary"]
        # save_response is now typed (Fs only), so at least one function
        # is Unsafe-free and the percentage has moved off zero.
        free = s["total_functions"] - s["functions_using_unsafe"]
        self.assertGreaterEqual(free, 1)
        self.assertGreater(s["percent_unsafe_free"], 0)
        self.assertLess(s["percent_unsafe_free"], 100)

    def test_step3_fully_typed(self):
        rep = _report_for_example("migrate_logfetcher_step3_typed.capa")
        s = rep["summary"]
        self.assertEqual(s["functions_using_unsafe"], 0)
        self.assertEqual(s["percent_unsafe_free"], 100)
        self.assertEqual(rep["removable"], [])
        self.assertEqual(rep["next_candidates"], [])

    def test_next_candidates_ranked_by_bridge_calls(self):
        # Cheapest-to-harden (fewest bridge calls) comes first.
        rep = _report_for_example("migrate_logfetcher_step1_unsafe.capa")
        counts = [c["bridge_call_count"] for c in rep["next_candidates"]]
        self.assertEqual(counts, sorted(counts))


class TestRemovableDetection(unittest.TestCase):
    """The conservative 'Unsafe declared but never exercised' check."""

    def test_silenced_dead_unsafe_is_removable(self):
        # The analyser rejects a capability param referenced nowhere
        # unless it is underscore-prefixed; the live removable case is
        # that silenced-but-dead param.
        src = (
            "fun f(_u: Unsafe) -> Int\n"
            "    return 42\n"
        )
        rep = migrate_report(_module_from_source(src))
        self.assertEqual(rep["summary"]["functions_removable_unsafe"], 1)
        r = rep["removable"][0]
        self.assertEqual(r["source_name"], "f")
        self.assertEqual(r["param_name"], "_u")

    def test_unsafe_used_via_bridge_is_not_removable(self):
        src = (
            "fun f(u: Unsafe)\n"
            "    let os_mod = py_import(u, \"os\")\n"
        )
        rep = migrate_report(_module_from_source(src))
        self.assertEqual(rep["summary"]["functions_removable_unsafe"], 0)
        self.assertEqual(rep["summary"]["functions_using_unsafe"], 1)

    def test_forwarded_unsafe_is_not_removable(self):
        # g forwards its Unsafe to f; even though g makes no bridge call
        # itself, the token is exercised, so it is not removable.
        src = (
            "fun f(u: Unsafe)\n"
            "    let os_mod = py_import(u, \"os\")\n"
            "\n"
            "fun g(u: Unsafe)\n"
            "    f(u)\n"
        )
        rep = migrate_report(_module_from_source(src))
        names = {r["source_name"] for r in rep["removable"]}
        self.assertNotIn("g", names)
        self.assertNotIn("f", names)

    def test_no_unsafe_at_all_is_fully_hardened(self):
        src = (
            "fun greet(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        rep = migrate_report(_module_from_source(src))
        self.assertEqual(rep["summary"]["functions_using_unsafe"], 0)
        self.assertEqual(rep["summary"]["percent_unsafe_free"], 100)


class TestRenderAndDispatch(unittest.TestCase):
    def test_render_is_nonempty_text(self):
        rep = _report_for_example("migrate_logfetcher_step2_mixed.capa")
        out = render_report(rep)
        self.assertIn("Migration progress", out)
        self.assertIn("Unsafe-free", out)

    def test_dispatch_json_is_valid(self):
        # The CLI --json path must emit parseable JSON with the
        # documented keys.
        import io
        import contextlib
        from capa.cli import _dispatch_migrate
        path = _EXAMPLES / "migrate_logfetcher_step2_mixed.capa"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = _dispatch_migrate([str(path), "--json"])
        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue())
        self.assertIn("summary", payload)
        self.assertIn("removable", payload)
        self.assertIn("next_candidates", payload)
        self.assertIn("percent_unsafe_free", payload["summary"])

    def test_dispatch_missing_file_errors(self):
        from capa.cli import _dispatch_migrate
        rc = _dispatch_migrate(["does_not_exist_xyz.capa"])
        self.assertNotEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
