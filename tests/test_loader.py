"""Tests for capa.loader, the module loader / linker.

Each test writes its source files to a tmpdir and invokes the
loader on the root file; assertions check the merged AST,
diagnostics on cycles / conflicts / missing files, and the
end-to-end run-via-CLI path.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from capa.loader import LoaderError, ModuleLoader
from capa import capa_ast as A


class _TempDirMixin:
    """Each test gets a fresh directory torn down at the end."""

    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="capa_loader_test_"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write(self, name: str, body: str) -> Path:
        p = self._tmp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        return p


class TestModuleLoader(_TempDirMixin, unittest.TestCase):

    def test_no_imports_returns_root_module_only(self):
        root = self._write(
            "root.capa",
            "fun main(stdio: Stdio)\n"
            '    stdio.println("hi")\n'
        )
        loader = ModuleLoader()
        linked = loader.load_root(root.read_text(), str(root))
        # Single function from the root; no Import items survive
        # (there were none to begin with) and no extras.
        names = [
            item.name for item in linked.module.items
            if isinstance(item, A.FunDecl)
        ]
        self.assertEqual(names, ["main"])

    def test_single_import_merges_items(self):
        self._write(
            "util.capa",
            "fun helper(x: Int) -> Int\n"
            "    return x + 1\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("hi")\n'
        )
        loader = ModuleLoader()
        linked = loader.load_root(root.read_text(), str(root))
        # Both functions are present; no Import items survive.
        funs = [
            item.name for item in linked.module.items
            if isinstance(item, A.FunDecl)
        ]
        self.assertIn("helper", funs)
        self.assertIn("main", funs)
        imports = [
            item for item in linked.module.items
            if isinstance(item, A.Import)
        ]
        self.assertEqual(imports, [])

    def test_transitive_import(self):
        self._write(
            "leaf.capa",
            "fun shout(s: String) -> String\n"
            "    return s.to_upper()\n"
        )
        self._write(
            "mid.capa",
            "import leaf\n"
            "fun wrap(s: String) -> String\n"
            "    return shout(s) + \"!\"\n"
        )
        root = self._write(
            "root.capa",
            "import mid\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(wrap(\"hi\"))\n"
        )
        loader = ModuleLoader()
        linked = loader.load_root(root.read_text(), str(root))
        names = {
            item.name for item in linked.module.items
            if isinstance(item, A.FunDecl)
        }
        self.assertEqual(names, {"shout", "wrap", "main"})

    def test_dotted_path_resolves_to_subdir(self):
        self._write(
            "stuff/inner.capa",
            "fun inner_fn() -> Int\n"
            "    return 42\n"
        )
        root = self._write(
            "root.capa",
            "import stuff.inner\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${inner_fn()}\")\n"
        )
        loader = ModuleLoader()
        linked = loader.load_root(root.read_text(), str(root))
        names = {
            item.name for item in linked.module.items
            if isinstance(item, A.FunDecl)
        }
        self.assertIn("inner_fn", names)
        self.assertIn("main", names)

    def test_cycle_is_reported(self):
        self._write(
            "a.capa",
            "import b\n"
            "fun a_fn() -> Int\n"
            "    return 1\n"
        )
        self._write(
            "b.capa",
            "import a\n"
            "fun b_fn() -> Int\n"
            "    return 2\n"
        )
        root = self._write(
            "root.capa",
            "import a\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${a_fn()}\")\n"
        )
        loader = ModuleLoader()
        with self.assertRaises(LoaderError) as ctx:
            loader.load_root(root.read_text(), str(root))
        self.assertIn("cyclic import", ctx.exception.message)

    def test_name_conflict_is_reported(self):
        self._write(
            "x.capa", "fun shared() -> Int\n    return 1\n",
        )
        self._write(
            "y.capa", "fun shared() -> Int\n    return 2\n",
        )
        root = self._write(
            "root.capa",
            "import x\n"
            "import y\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${shared()}\")\n"
        )
        loader = ModuleLoader()
        with self.assertRaises(LoaderError) as ctx:
            loader.load_root(root.read_text(), str(root))
        msg = ctx.exception.message
        self.assertIn("name conflict", msg)
        self.assertIn("shared", msg)

    def test_missing_file_is_reported(self):
        root = self._write(
            "root.capa",
            "import nonexistent\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        loader = ModuleLoader()
        with self.assertRaises(LoaderError) as ctx:
            loader.load_root(root.read_text(), str(root))
        self.assertIn("cannot resolve", ctx.exception.message)

    def test_diamond_import_is_deduplicated(self):
        # root -> a -> shared
        # root -> b -> shared
        # `shared` should appear in the linked module exactly once.
        self._write(
            "shared.capa",
            "fun common() -> Int\n    return 7\n",
        )
        self._write(
            "a.capa",
            "import shared\n"
            "fun a_use() -> Int\n    return common()\n"
        )
        self._write(
            "b.capa",
            "import shared\n"
            "fun b_use() -> Int\n    return common()\n"
        )
        root = self._write(
            "root.capa",
            "import a\n"
            "import b\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${a_use() + b_use()}\")\n"
        )
        loader = ModuleLoader()
        linked = loader.load_root(root.read_text(), str(root))
        common_count = sum(
            1 for item in linked.module.items
            if isinstance(item, A.FunDecl) and item.name == "common"
        )
        self.assertEqual(common_count, 1)


class TestImportedFileErrorRendering(_TempDirMixin, unittest.TestCase):
    """Errors that originate in an imported module should render
    with the *imported* file's source snippet, not the root
    file's. Position info is per-Pos via the filename field added
    to Pos; the analyzer's _err looks up the right source from
    the sources map passed by the CLI.
    """

    def test_error_in_imported_module_shows_imported_snippet(self):
        # An obvious type error in the imported file.
        self._write(
            "util.capa",
            "fun mul(n: Int) -> Int\n"
            "    return n * \"oops\"\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${mul(3)}\")\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--check", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(result.returncode, 0)
        # The snippet should be the imported file's line, not the
        # root file's. The literal "oops" only appears in util.capa.
        self.assertIn("oops", result.stderr)
        # And the filename in the diagnostic should be util.capa.
        self.assertIn("util.capa", result.stderr)

    def test_error_in_root_module_still_shows_root_snippet(self):
        # Regression: single-file errors must not regress.
        root = self._write(
            "root.capa",
            "fun main(stdio: Stdio)\n"
            "    let x = 1 + \"two\"\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--check", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("two", result.stderr)
        self.assertIn("root.capa", result.stderr)


class TestModuleSystemEndToEnd(_TempDirMixin, unittest.TestCase):
    """End-to-end: capa --run with an imported file produces the
    expected output and exit code 0.
    """

    def test_main_imports_util_and_runs(self):
        self._write(
            "util.capa",
            "fun greet(name: String) -> String\n"
            "    return \"Hello, \" + name\n"
        )
        root = self._write(
            "main.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(greet(\"Capa\"))\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "Hello, Capa\n")

    def test_cyclic_import_exits_nonzero(self):
        self._write(
            "a.capa", "import b\nfun a_fn() -> Int\n    return 1\n"
        )
        self._write(
            "b.capa", "import a\nfun b_fn() -> Int\n    return 2\n"
        )
        root = self._write(
            "root.capa",
            "import a\nfun main(stdio: Stdio)\n    stdio.println(\"hi\")\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cyclic import", result.stderr)


if __name__ == "__main__":
    unittest.main()
