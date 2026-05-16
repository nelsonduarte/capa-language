"""Tests for ``capa init`` project scaffolding."""

import tempfile
import unittest
from pathlib import Path

from capa.init_project import init_project


class TestInitProject(unittest.TestCase):
    def _tmpdir(self) -> Path:
        d = tempfile.mkdtemp()
        self.addCleanup(_rmtree, Path(d))
        return Path(d)

    def test_creates_all_expected_files_in_new_dir(self):
        root = self._tmpdir()
        target = root / "my-proj"
        rc = init_project(target, capa_version="0.8.2")
        self.assertEqual(rc, 0)
        self.assertTrue((target / "main.capa").is_file())
        self.assertTrue((target / "README.md").is_file())
        self.assertTrue((target / ".gitignore").is_file())
        self.assertTrue((target / ".capa-version").is_file())

    def test_main_capa_uses_project_name(self):
        root = self._tmpdir()
        target = root / "cool-thing"
        init_project(target, capa_version="0.8.2")
        body = (target / "main.capa").read_text(encoding="utf-8")
        self.assertIn("cool-thing", body)
        # The starter must declare fun main with a Stdio parameter,
        # so the capability discipline is visible from the first line
        # the user reads.
        self.assertIn("fun main(stdio: Stdio)", body)

    def test_main_capa_is_a_runnable_capa_program(self):
        # The scaffold must parse + analyse cleanly; this is what
        # makes `capa init` + `capa --run main.capa` a five-second
        # path to success.
        from capa import Lexer, Parser, analyze
        root = self._tmpdir()
        target = root / "p"
        init_project(target, capa_version="0.8.2")
        source = (target / "main.capa").read_text(encoding="utf-8")
        tokens = Lexer(source, filename="main.capa").lex()
        module = Parser(tokens, source=source, filename="main.capa").parse_module()
        result = analyze(module, source=source, filename="main.capa")
        self.assertTrue(result.ok, result.errors)

    def test_main_capa_is_in_canonical_format(self):
        # Scaffolded source should pass capa-fmt's --fmt-check, so
        # `capa --fmt-check main.capa` does not flag a fresh project.
        from capa import is_formatted
        root = self._tmpdir()
        target = root / "p"
        init_project(target, capa_version="0.8.2")
        source = (target / "main.capa").read_text(encoding="utf-8")
        self.assertTrue(is_formatted(source))

    def test_capa_version_file_pins_version(self):
        root = self._tmpdir()
        target = root / "p"
        init_project(target, capa_version="1.2.3-alpha")
        v = (target / ".capa-version").read_text(encoding="utf-8")
        self.assertEqual(v.strip(), "1.2.3-alpha")

    def test_empty_existing_dir_is_accepted(self):
        root = self._tmpdir()
        target = root / "blank"
        target.mkdir()
        rc = init_project(target, capa_version="0.8.2")
        self.assertEqual(rc, 0)
        self.assertTrue((target / "main.capa").is_file())

    def test_non_empty_dir_is_rejected(self):
        root = self._tmpdir()
        target = root / "occupied"
        target.mkdir()
        (target / "existing.txt").write_text("hands off", encoding="utf-8")
        rc = init_project(target, capa_version="0.8.2")
        self.assertNotEqual(rc, 0)
        # Existing file must be untouched.
        self.assertEqual(
            (target / "existing.txt").read_text(encoding="utf-8"),
            "hands off",
        )
        # main.capa must NOT have been created.
        self.assertFalse((target / "main.capa").exists())

    def test_target_is_a_file_is_rejected(self):
        root = self._tmpdir()
        target = root / "a-file"
        target.write_text("not a directory", encoding="utf-8")
        rc = init_project(target, capa_version="0.8.2")
        self.assertNotEqual(rc, 0)

    def test_parent_does_not_exist_is_rejected(self):
        root = self._tmpdir()
        target = root / "nope" / "nested"
        # Parent ``root/nope`` does not exist.
        rc = init_project(target, capa_version="0.8.2")
        self.assertNotEqual(rc, 0)
        self.assertFalse(target.exists())

    def test_gitignore_covers_pyc_and_editor_cruft(self):
        root = self._tmpdir()
        target = root / "p"
        init_project(target, capa_version="0.8.2")
        body = (target / ".gitignore").read_text(encoding="utf-8")
        # A few representative entries; the test should not pin the
        # exact format, just the intent of what is covered.
        for needle in ("__pycache__", "*.pyc", ".vscode", ".idea"):
            self.assertIn(needle, body)


def _rmtree(path: Path) -> None:
    """Best-effort recursive delete. Used as a unittest cleanup."""
    import shutil
    shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
