"""Instrument (d): the scrub, the two halves, and a same-tree run that must
be GREEN. The bites on a changed compiler are its landing-time acceptance
tests, run against extracted trees, not part of the suite."""

import shutil
import tempfile
import unittest
from pathlib import Path

from tests.implicit_flow._harness import check_source
from tests.instruments import release_differential as D
from tests.instruments._provenance import REPO_ROOT


def _manifest(src: str, name: str) -> dict:
    from capa import Lexer, Parser
    from capa.manifest import build_manifest
    res = check_source(src)
    mod = Parser(Lexer(src).lex(), source=src).parse_module()
    return build_manifest(mod, filename=name, bindings=res.bindings, expr_labels=res.expr_labels)


class ScrubTests(unittest.TestCase):
    def test_paths_positions_and_versions_are_scrubbed(self):
        a = D.scrub_line(r"C:\work\x\prog.capa:12:5: error: bad thing (capa 1.32.0)")
        b = D.scrub_line("/home/ci/prog.capa:3:9: error: bad thing (capa 1.33.0)")
        self.assertEqual(a, b)
        self.assertIn("PATH:L:C: error: bad thing (capa V)", a)

    def test_diagnostic_set_classes(self):
        rc, lines = D.diagnostic_set({"outcome": "ABORT:rc1", "stderr": "x.capa:1:1: error: e\n\n"})
        self.assertEqual(rc, "rc!=0")
        self.assertEqual(lines, frozenset({"PATH:L:C: error: e"}))
        self.assertEqual(D.diagnostic_set({"outcome": "OK", "stderr": ""})[0], "rc0")
        self.assertEqual(D.diagnostic_set({"outcome": "TIMEOUT", "stderr": ""})[0], "TIMEOUT")

    def test_diff_check_reports_lost_gained_and_rc_moves(self):
        base = {"a": ("rc!=0", frozenset({"e1", "e2"})), "b": ("rc0", frozenset())}
        cand = {"a": ("rc0", frozenset({"e2", "e3"})), "b": ("rc0", frozenset())}
        d = D.diff_check(base, cand)
        self.assertEqual(d["rc_moves"], [("a", "rc!=0", "rc0")])
        self.assertEqual(d["lost"], [("a", "e1")])
        self.assertEqual(d["gained"], [("a", "e3")])

    def test_manifest_scrub_drops_volatile_fields_and_first_diff_names_the_path(self):
        a = {"functions": [{"name": "f", "declared_capabilities": ["Fs"]}], "digest": "1", "capa_version": "1.32.0"}
        b = {"functions": [{"name": "f", "declared_capabilities": ["Fs"]}], "digest": "2", "capa_version": "1.33.0"}
        self.assertIsNone(D.first_diff(D.scrub_manifest(a), D.scrub_manifest(b)))
        c = {"functions": [{"name": "f", "declared_capabilities": []}], "digest": "2"}
        self.assertEqual(D.first_diff(D.scrub_manifest(a), D.scrub_manifest(c)),
                         "/functions[0]/declared_capabilities[len]")


class ManifestLayersTests(unittest.TestCase):
    def test_a_dropped_capability_is_seen_by_both_layers(self):
        with_fs = "pub fun go(fs: Fs, stdio: Stdio)\n    stdio.println(\"x\")\nfun main(stdio: Stdio)\n    stdio.println(\"y\")\n"
        without = "pub fun go(stdio: Stdio)\n    stdio.println(\"x\")\nfun main(stdio: Stdio)\n    stdio.println(\"y\")\n"
        base = {"p.capa": _manifest(with_fs, "p.capa")}
        cand = {"p.capa": _manifest(without, "p.capa")}
        d = D.diff_manifest(base, cand)
        self.assertEqual(len(d["layer1"]), 1, d)
        self.assertEqual(len(d["layer2"]), 1, d)
        same = D.diff_manifest(base, {"p.capa": _manifest(with_fs, "p.capa")})
        self.assertEqual(same, {"layer1": [], "layer2": []})


class SameTreeRunTests(unittest.TestCase):
    def test_a_tree_against_itself_is_green(self):
        work = Path(tempfile.mkdtemp(prefix="capa_rd_"))
        try:
            programs = D.seeded_negative_corpus(work / "seeded")[:4]
            self.assertTrue(programs)
            result = D.run(REPO_ROOT, REPO_ROOT, programs, work)
            self.assertEqual(result["verdict"], "GREEN", result)
            self.assertEqual(result["files"], len(programs))
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def test_the_seeded_corpus_produces_diagnostics_on_this_tree(self):
        # Without programs that produce a diagnostic, a deletion shows nothing.
        work = Path(tempfile.mkdtemp(prefix="capa_rd_"))
        try:
            programs = D.seeded_negative_corpus(work / "seeded")
            refused = [p.name for p in programs if p.name.endswith("_sec.capa")]
            self.assertTrue(refused)
            sets = D.check_half(REPO_ROOT, [p for p in programs if p.name in refused[:3]])
            for name, (rc, lines) in sets.items():
                with self.subTest(program=name):
                    self.assertEqual(rc, "rc!=0")
                    self.assertTrue(lines)
        finally:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
