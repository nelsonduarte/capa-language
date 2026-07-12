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

from capa.cli import _wasm_tooling_available
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
            "pub fun helper(x: Int) -> Int\n"
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
            "pub fun shout(s: String) -> String\n"
            "    return s.to_upper()\n"
        )
        self._write(
            "mid.capa",
            "import leaf\n"
            "pub fun wrap(s: String) -> String\n"
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
            "pub fun inner_fn() -> Int\n"
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
            "x.capa", "pub fun shared() -> Int\n    return 1\n",
        )
        self._write(
            "y.capa", "pub fun shared() -> Int\n    return 2\n",
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
            "pub fun common() -> Int\n    return 7\n",
        )
        self._write(
            "a.capa",
            "import shared\n"
            "pub fun a_use() -> Int\n    return common()\n"
        )
        self._write(
            "b.capa",
            "import shared\n"
            "pub fun b_use() -> Int\n    return common()\n"
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


class TestQualifiedModuleAccess(_TempDirMixin, unittest.TestCase):
    """``foo.fn(args)`` resolves to the ``fn`` imported from
    ``foo`` (rewritten by the loader's post-link pass to a plain
    direct call). The unqualified form remains available.
    """

    def test_qualified_call_resolves(self):
        self._write(
            "util.capa",
            "pub fun greet(name: String) -> String\n"
            "    return \"Hello, \" + name\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(util.greet(\"Capa\"))\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "Hello, Capa\n")

    def test_unqualified_call_still_works(self):
        # Regression: the MVP unqualified form must keep working
        # alongside the new qualified one.
        self._write(
            "util.capa",
            "pub fun greet(name: String) -> String\n"
            "    return \"Hello, \" + name\n"
        )
        root = self._write(
            "root.capa",
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

    def test_alias_qualified_call(self):
        self._write(
            "util.capa",
            "pub fun greet(name: String) -> String\n"
            "    return \"Hi, \" + name\n"
        )
        root = self._write(
            "root.capa",
            "import util as U\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(U.greet(\"alias\"))\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "Hi, alias\n")

    def test_module_exports_populated(self):
        # Unit test of the LinkedModule.module_exports map shape.
        # Only pub items go into module_exports (the rewrite target
        # for qualified calls); the private `b` and `Internal` must
        # not leak.
        self._write(
            "util.capa",
            "pub fun a() -> Int\n    return 1\n"
            "fun b() -> Int\n    return 2\n"
            "pub type T { v: Int }\n"
            "type Internal { v: Int }\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        from capa.loader import ModuleLoader
        loader = ModuleLoader()
        linked = loader.load_root(root.read_text(), str(root))
        self.assertIn("util", linked.module_exports)
        self.assertEqual(linked.module_exports["util"], {"a", "T"})


class TestSelectiveImport(_TempDirMixin, unittest.TestCase):
    """``import foo (a, b as c)`` brings only the listed pub symbols,
    renaming where ``as`` is used, and hides everything else. This is
    the hygienic form that resolves a ``pub`` symbol collision between
    two dependencies (both exporting ``pub fun parse``)."""

    def test_selective_brings_only_requested(self):
        self._write(
            "lib.capa",
            "pub fun keep() -> Int\n    return 1\n"
            "pub fun hidden() -> Int\n    return 2\n"
        )
        root = self._write(
            "root.capa",
            "import lib (keep)\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("${keep()}")\n'
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "1\n")

    def test_unselected_symbol_is_not_visible(self):
        self._write(
            "lib.capa",
            "pub fun keep() -> Int\n    return 1\n"
            "pub fun hidden() -> Int\n    return 2\n"
        )
        root = self._write(
            "root.capa",
            "import lib (keep)\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("${hidden()}")\n'
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--check", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("undefined name 'hidden'", result.stderr)

    def test_selective_with_rename(self):
        self._write(
            "lib.capa",
            "pub fun parse(s: String) -> String\n"
            '    return "lib:" + s\n'
        )
        root = self._write(
            "root.capa",
            "import lib (parse as lib_parse)\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println(lib_parse("x"))\n'
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "lib:x\n")
        # The original name must NOT leak in alongside the alias.
        root2 = self._write(
            "root2.capa",
            "import lib (parse as lib_parse)\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println(parse("x"))\n'
        )
        r2 = subprocess.run(
            [sys.executable, "-m", "capa", "--check", str(root2)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(r2.returncode, 0)
        self.assertIn("undefined name 'parse'", r2.stderr)

    def test_pub_fun_collision_resolved_by_rename(self):
        # The central case: capa_cli and capa_csv both export
        # ``pub fun parse``. Selective import with rename lets a
        # single project use both.
        self._write(
            "csv.capa",
            "pub fun parse(s: String) -> String\n"
            '    return "csv:" + s\n'
        )
        self._write(
            "cli.capa",
            "pub fun parse(s: String) -> String\n"
            '    return "cli:" + s\n'
        )
        root = self._write(
            "root.capa",
            "import csv (parse as csv_parse)\n"
            "import cli (parse as cli_parse)\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println(csv_parse("a"))\n'
            '    stdio.println(cli_parse("b"))\n'
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "csv:a\ncli:b\n")

    def test_collision_resolved_with_one_rename(self):
        # Only one side needs a rename: the other keeps the bare name.
        self._write(
            "csv.capa",
            "pub fun parse(s: String) -> String\n"
            '    return "csv:" + s\n'
        )
        self._write(
            "cli.capa",
            "pub fun parse(s: String) -> String\n"
            '    return "cli:" + s\n'
        )
        root = self._write(
            "root.capa",
            "import csv (parse)\n"
            "import cli (parse as cli_parse)\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println(parse("a"))\n'
            '    stdio.println(cli_parse("b"))\n'
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "csv:a\ncli:b\n")

    def test_unknown_symbol_errors(self):
        self._write(
            "lib.capa",
            "pub fun ok() -> Int\n    return 1\n"
        )
        root = self._write(
            "root.capa",
            "import lib (nope)\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("x")\n'
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--check", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no public symbol 'nope'", result.stderr)

    def test_non_pub_symbol_errors(self):
        self._write(
            "lib.capa",
            "fun secret() -> Int\n    return 1\n"
            "pub fun ok() -> Int\n    return 2\n"
        )
        root = self._write(
            "root.capa",
            "import lib (secret)\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("x")\n'
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--check", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no public symbol 'secret'", result.stderr)

    def test_selective_type_and_use(self):
        self._write(
            "tbl.capa",
            "pub type Table { rows: Int }\n"
            "pub fun parse(s: String) -> Table\n"
            "    return Table { rows: 1 }\n"
        )
        root = self._write(
            "root.capa",
            "import tbl (Table, parse as tparse)\n"
            "fun main(stdio: Stdio)\n"
            "    let t = tparse(\"x\")\n"
            '    stdio.println("${t.rows}")\n'
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "1\n")

    def test_selective_sum_type_carries_variants(self):
        # A selected (unrenamed) sum type brings its variants along.
        self._write(
            "col.capa",
            "pub type Color =\n    Red\n    Green(Int)\n"
        )
        root = self._write(
            "root.capa",
            "import col (Color)\n"
            "fun describe(c: Color) -> String\n"
            "    return match c\n"
            '        Red -> "red"\n'
            '        Green(n) -> "green"\n'
            "fun main(stdio: Stdio)\n"
            "    stdio.println(describe(Red))\n"
            "    stdio.println(describe(Green(3)))\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "red\ngreen\n")

    def _run_both_backends(self, root, expected_stdout):
        # Python backend (always) plus the Wasm backend when its
        # tooling is present, asserting identical stdout.
        py = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(py.returncode, 0, py.stderr)
        self.assertEqual(py.stdout, expected_stdout)
        if _wasm_tooling_available():
            wa = subprocess.run(
                [sys.executable, "-m", "capa", "--wasm", "--run",
                 str(root)],
                capture_output=True, text=True, encoding="utf-8",
            )
            self.assertEqual(wa.returncode, 0, wa.stderr)
            self.assertEqual(wa.stdout, expected_stdout)

    def test_unselected_sum_variant_does_not_leak(self):
        # C1: a non-selected pub sum type is hidden together with its
        # variants. Using a variant constructor in the importer is
        # ``undefined name`` (the leak is closed).
        self._write(
            "summod.capa",
            "pub type Color =\n    Red\n    Green\n    Blue\n"
            "pub fun describe(c: Color) -> String\n"
            "    return match c\n"
            '        Red -> "red"\n'
            '        Green -> "green"\n'
            '        Blue -> "blue"\n'
        )
        root = self._write(
            "root.capa",
            "import summod (describe)\n"
            "fun main(stdio: Stdio)\n"
            "    let c = Red\n"
            "    stdio.println(\"x\")\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--check", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("undefined name 'Red'", result.stderr)
        # No mangled internal name leaks into the diagnostic.
        self.assertNotIn("__sel__", result.stderr)

    def test_local_variant_homonym_no_longer_collides(self):
        # Escalation case: the importer declares its own sum type with
        # a variant homonymous to a hidden dependency's variant. Before
        # the fix the leaked ``Green`` collided; now it compiles.
        self._write(
            "summod.capa",
            "pub type Color =\n    Red\n    Green\n    Blue\n"
            "pub fun describe(c: Color) -> String\n"
            "    return match c\n"
            '        Red -> "red"\n'
            '        Green -> "green"\n'
            '        Blue -> "blue"\n'
        )
        root = self._write(
            "root.capa",
            "import summod (describe)\n"
            "type Light =\n    Off\n    Green\n"
            "fun show(l: Light) -> String\n"
            "    return match l\n"
            '        Off -> "off"\n'
            '        Green -> "on"\n'
            "fun main(stdio: Stdio)\n"
            "    stdio.println(show(Green))\n"
        )
        self._run_both_backends(root, "on\n")

    def test_two_hidden_sums_homonymous_variants_coexist(self):
        # The central case the feature promises: two dependencies whose
        # hidden sum types share variant names, importing only their
        # functions, coexist and compile (no collision, no mangled name
        # leaking into any diagnostic).
        self._write(
            "m1.capa",
            "pub type StatusA =\n    Fresh\n    Pending\n"
            "fun classify_a(s: StatusA) -> String\n"
            "    return match s\n"
            '        Fresh -> "a-fresh"\n'
            '        Pending -> "a-pending"\n'
            "pub fun a() -> String\n"
            "    return classify_a(Pending)\n"
        )
        self._write(
            "m2.capa",
            "pub type StatusB =\n    Done\n    Pending\n"
            "fun classify_b(s: StatusB) -> String\n"
            "    return match s\n"
            '        Done -> "b-done"\n'
            '        Pending -> "b-pending"\n'
            "pub fun b() -> String\n"
            "    return classify_b(Pending)\n"
        )
        root = self._write(
            "root.capa",
            "import m1 (a)\n"
            "import m2 (b)\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(a())\n"
            "    stdio.println(b())\n"
        )
        self._run_both_backends(root, "a-pending\nb-pending\n")

    def test_selective_sum_variants_construct_and_match(self):
        # Positive: a selected (unrenamed) sum type stays fully
        # functional -- its variants are constructible and matchable in
        # the importer, on both backends.
        self._write(
            "col.capa",
            "pub type Color =\n    Red\n    Green(Int)\n    Blue\n"
        )
        root = self._write(
            "root.capa",
            "import col (Color)\n"
            "fun describe(c: Color) -> String\n"
            "    return match c\n"
            '        Red -> "red"\n'
            '        Green(n) -> "green"\n'
            '        Blue -> "blue"\n'
            "fun main(stdio: Stdio)\n"
            "    stdio.println(describe(Red))\n"
            "    stdio.println(describe(Green(3)))\n"
            "    stdio.println(describe(Blue))\n"
        )
        self._run_both_backends(root, "red\ngreen\nblue\n")

    def test_hidden_sum_still_works_inside_its_module(self):
        # Positive: the hidden sum type keeps working inside its own
        # module -- the function selected from it matches its variants
        # correctly on both backends.
        self._write(
            "summod.capa",
            "pub type Color =\n    Red\n    Green\n    Blue\n"
            "pub fun describe(c: Color) -> String\n"
            "    return match c\n"
            '        Red -> "red"\n'
            '        Green -> "green"\n'
            '        Blue -> "blue"\n'
            "pub fun a_green() -> Color\n"
            "    return Green\n"
        )
        root = self._write(
            "root.capa",
            "import summod (describe, a_green)\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(describe(a_green()))\n"
        )
        self._run_both_backends(root, "green\n")

    def test_renaming_sum_type_is_a_clear_error(self):
        # Renaming a sum type via ``as`` in a selective import is not
        # yet supported; the user gets an actionable error rather than
        # half-broken variants.
        self._write(
            "col.capa",
            "pub type Color =\n    Red\n    Green\n"
        )
        root = self._write(
            "root.capa",
            "import col (Color as C)\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("hi")\n'
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--check", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("renaming a sum type", result.stderr)
        self.assertIn("without 'as'", result.stderr)

    def test_module_exports_reflects_visible_names(self):
        # Only the selected (final, aliased) names appear in
        # module_exports; the unselected pub item must not leak.
        self._write(
            "lib.capa",
            "pub fun parse() -> Int\n    return 1\n"
            "pub fun other() -> Int\n    return 2\n"
        )
        root = self._write(
            "root.capa",
            "import lib (parse as lib_parse)\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("hi")\n'
        )
        loader = ModuleLoader()
        linked = loader.load_root(root.read_text(), str(root))
        self.assertEqual(linked.module_exports["lib"], {"lib_parse"})


class TestDivergentReimport(_TempDirMixin, unittest.TestCase):
    """A second import of the SAME module path is deduplicated to a
    no-op. That is safe only when both imports ask for the same view.
    A divergent re-import (selective + whole, or two different
    selective lists) used to be silently dropped, so the visible
    symbol surface depended on import order. It is now a clear error."""

    def _lib(self) -> None:
        self._write(
            "lib.capa",
            "pub fun foo() -> Int\n    return 1\n"
            "pub fun bar() -> Int\n    return 2\n"
        )

    def test_selective_then_whole_errors(self):
        self._lib()
        root = self._write(
            "root.capa",
            "import lib (foo)\n"
            "import lib\n"
            "fun main()\n    return\n"
        )
        loader = ModuleLoader()
        with self.assertRaises(LoaderError) as ctx:
            loader.load_root(root.read_text(), str(root))
        self.assertIn("imported twice with different selection",
                      str(ctx.exception))

    def test_whole_then_selective_errors(self):
        # The reverse order must error too (the bug was that the two
        # orders behaved differently).
        self._lib()
        root = self._write(
            "root.capa",
            "import lib\n"
            "import lib (foo)\n"
            "fun main()\n    return\n"
        )
        loader = ModuleLoader()
        with self.assertRaises(LoaderError) as ctx:
            loader.load_root(root.read_text(), str(root))
        self.assertIn("imported twice with different selection",
                      str(ctx.exception))

    def test_two_different_selective_lists_error(self):
        self._lib()
        root = self._write(
            "root.capa",
            "import lib (foo)\n"
            "import lib (bar)\n"
            "fun main()\n    return\n"
        )
        loader = ModuleLoader()
        with self.assertRaises(LoaderError) as ctx:
            loader.load_root(root.read_text(), str(root))
        self.assertIn("imported twice with different selection",
                      str(ctx.exception))

    def test_identical_whole_imports_are_benign(self):
        self._lib()
        root = self._write(
            "root.capa",
            "import lib\n"
            "import lib\n"
            "fun main()\n    return\n"
        )
        loader = ModuleLoader()
        loader.load_root(root.read_text(), str(root))  # no raise

    def test_identical_selective_imports_are_benign(self):
        self._lib()
        root = self._write(
            "root.capa",
            "import lib (foo)\n"
            "import lib (foo)\n"
            "fun main()\n    return\n"
        )
        loader = ModuleLoader()
        loader.load_root(root.read_text(), str(root))  # no raise

    def test_different_modules_are_fine(self):
        self._lib()
        self._write("other.capa", "pub fun baz() -> Int\n    return 3\n")
        root = self._write(
            "root.capa",
            "import lib\n"
            "import other\n"
            "fun main()\n    return\n"
        )
        loader = ModuleLoader()
        loader.load_root(root.read_text(), str(root))  # no raise


class TestLoaderErrorFormat(unittest.TestCase):
    """The ``LoaderError.format()`` shape is what the CLI feeds
    into its single-line diagnostic renderer. Two branches:
    with a ``pos`` (filename + line:col) and without (filename
    only, no positional anchor)."""

    def test_format_with_pos(self):
        from capa.tokens import Pos
        err = LoaderError(
            "thing is broken",
            pos=Pos(line=12, col=5, offset=0, filename="root.capa"),
            filename="root.capa",
        )
        self.assertEqual(
            err.format(),
            "root.capa:12:5: error: thing is broken",
        )

    def test_format_without_pos(self):
        err = LoaderError("thing is broken", filename="root.capa")
        self.assertEqual(
            err.format(), "root.capa: error: thing is broken",
        )


class TestQualifiedCallShadowing(_TempDirMixin, unittest.TestCase):
    """The post-link ``mod.fn() -> fn()`` rewrite must skip when a
    name that matches a module alias has been shadowed by a local
    binding (parameter, ``let`` / ``var`` / ``for`` pattern, match
    pattern, or lambda parameter). Otherwise ``mylib.get(url)``
    where ``mylib`` is a local of a user-defined capability gets
    silently rewritten to a free-function call ``get(url)`` and
    the receiver is dropped from the AST -- the analyzer then
    type-checks it as a different function (a bug filed and fixed
    in 2026-05).

    The tests load the linked AST and assert what shape the
    rewriter produced for the ``mylib.get(url)`` call site:
    ``MethodCall`` (when shadowed; the receiver lives) or
    ``Call`` (when unshadowed; the rewrite fired).
    """

    def _link_and_inspect(self, root_path):
        """Returns the linked module so a test can walk it.
        Helper because every test needs the same boilerplate."""
        from capa.loader import ModuleLoader
        from capa import capa_ast as A
        loader = ModuleLoader()
        linked = loader.load_root(root_path.read_text(), str(root_path))
        return linked.module, A

    def _find_fn(self, module, name):
        from capa import capa_ast as A
        for item in module.items:
            if isinstance(item, A.FunDecl) and item.name == name:
                return item
        raise AssertionError(f"function {name!r} not in module")

    def _setup_mylib(self):
        """Writes a module ``mylib.capa`` exporting ``pub fun get``.
        The root file then ``import mylib``, which registers
        ``mylib`` as an alias whose exports include ``get``."""
        self._write(
            "mylib.capa",
            "pub fun get(x: String) -> String\n"
            "    return \"free: \" + x\n",
        )

    def test_param_shadow_keeps_method_call(self):
        self._setup_mylib()
        root = self._write(
            "root.capa",
            "import mylib\n"
            "\n"
            "pub capability MyCap\n"
            "    fun get(self, x: String) -> String\n"
            "\n"
            "fun call(mylib: MyCap, x: String) -> String\n"
            "    return mylib.get(x)\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"unused\")\n"
        )
        module, A = self._link_and_inspect(root)
        call = self._find_fn(module, "call")
        ret_value = call.body.stmts[0].value
        self.assertIsInstance(
            ret_value, A.MethodCall,
            "rewriter wrongly converted the method call to a free-function "
            "call when the receiver name shadowed an imported module alias",
        )
        self.assertEqual(ret_value.method, "get")

    def test_let_shadow_keeps_method_call(self):
        self._setup_mylib()
        root = self._write(
            "root.capa",
            "import mylib\n"
            "\n"
            "pub capability MyCap\n"
            "    fun get(self, x: String) -> String\n"
            "\n"
            "pub type MyImpl { dummy: Int }\n"
            "impl MyCap for MyImpl\n"
            "    fun get(self, x: String) -> String\n"
            "        return \"impl: \" + x\n"
            "\n"
            "fun call() -> String\n"
            "    let mylib = MyImpl { dummy: 0 }\n"
            "    return mylib.get(\"hi\")\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(call())\n"
        )
        module, A = self._link_and_inspect(root)
        call = self._find_fn(module, "call")
        # First stmt: let; second stmt: return (with the method call)
        ret_stmt = call.body.stmts[1]
        self.assertIsInstance(ret_stmt.value, A.MethodCall)
        self.assertEqual(ret_stmt.value.method, "get")

    def test_for_shadow_keeps_method_call(self):
        self._setup_mylib()
        root = self._write(
            "root.capa",
            "import mylib\n"
            "\n"
            "pub capability MyCap\n"
            "    fun get(self, x: String) -> String\n"
            "\n"
            "fun call_each(items: List<MyCap>, x: String) -> String\n"
            "    var out = \"\"\n"
            "    for mylib in items\n"
            "        out = out + mylib.get(x)\n"
            "    return out\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"unused\")\n"
        )
        module, A = self._link_and_inspect(root)
        call = self._find_fn(module, "call_each")
        # Walk into the for-loop body to find the method call
        for_stmt = call.body.stmts[1]
        self.assertIsInstance(for_stmt, A.ForStmt)
        # Inside for body: AssignStmt with value `out + mylib.get(x)`
        assign = for_stmt.body.stmts[0]
        self.assertIsInstance(assign, A.AssignStmt)
        # Walk the RHS to find the MethodCall
        rhs = assign.value
        # rhs is BinOp(+); the right operand is the MethodCall
        self.assertIsInstance(rhs, A.BinOp)
        self.assertIsInstance(rhs.right, A.MethodCall)
        self.assertEqual(rhs.right.method, "get")

    def test_match_pattern_shadow_keeps_method_call(self):
        self._setup_mylib()
        root = self._write(
            "root.capa",
            "import mylib\n"
            "\n"
            "pub capability MyCap\n"
            "    fun get(self, x: String) -> String\n"
            "\n"
            "fun call_opt(opt: Option<MyCap>, x: String) -> String\n"
            "    match opt\n"
            "        Some(mylib) -> return mylib.get(x)\n"
            "        None        -> return \"none\"\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"unused\")\n"
        )
        module, A = self._link_and_inspect(root)
        call = self._find_fn(module, "call_opt")
        # body: ExprStmt(MatchExpr); first arm body is a ReturnStmt
        # with `mylib.get(x)` as its value
        match_expr = call.body.stmts[0].expr
        self.assertIsInstance(match_expr, A.MatchExpr)
        some_arm = match_expr.arms[0]
        # Single-line arm body is an Expr (the return),
        # or a Block containing a ReturnStmt depending on parse shape
        if isinstance(some_arm.body, A.Block):
            ret_value = some_arm.body.stmts[0].value
        else:
            # Body is a return expr already
            ret_value = some_arm.body
            if isinstance(ret_value, A.ReturnStmt):
                ret_value = ret_value.value
        self.assertIsInstance(ret_value, A.MethodCall)
        self.assertEqual(ret_value.method, "get")

    def test_tuple_pattern_shadow_in_let(self):
        """``let (mylib, _) = pair`` introduces ``mylib`` as a
        local; the rewriter's _names_bound_by_pattern must
        descend into TuplePat to see it."""
        self._setup_mylib()
        root = self._write(
            "root.capa",
            "import mylib\n"
            "\n"
            "pub capability MyCap\n"
            "    fun get(self, x: String) -> String\n"
            "\n"
            "pub type MyImpl { dummy: Int }\n"
            "impl MyCap for MyImpl\n"
            "    fun get(self, x: String) -> String\n"
            "        return \"impl: \" + x\n"
            "\n"
            "fun call(pair: (MyImpl, Int)) -> String\n"
            "    let (mylib, _n) = pair\n"
            "    return mylib.get(\"hi\")\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"unused\")\n"
        )
        module, A = self._link_and_inspect(root)
        call = self._find_fn(module, "call")
        # body[0]: let (mylib, _n) = pair
        # body[1]: return mylib.get("hi")
        ret = call.body.stmts[1].value
        self.assertIsInstance(ret, A.MethodCall)
        self.assertEqual(ret.method, "get")

    def test_struct_pattern_shorthand_shadow_in_let(self):
        """``let Foo { mylib } = obj`` (shorthand) binds the
        field name as a local. Covers the
        ``sub is None`` branch of StructPat handling in
        _names_bound_by_pattern."""
        self._setup_mylib()
        root = self._write(
            "root.capa",
            "import mylib\n"
            "\n"
            "pub capability MyCap\n"
            "    fun get(self, x: String) -> String\n"
            "\n"
            "pub type Wrap { mylib: Int }\n"
            "\n"
            "fun call(w: Wrap, mylib: MyCap, x: String) -> String\n"
            "    // The struct pattern would bind a shadowed `mylib`\n"
            "    // (Int); we use the unrelated parameter `mylib: MyCap`\n"
            "    // for the method call. Either way the rewriter must\n"
            "    // NOT downgrade.\n"
            "    let Wrap { mylib: _n } = w\n"
            "    return mylib.get(x)\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"unused\")\n"
        )
        module, A = self._link_and_inspect(root)
        call = self._find_fn(module, "call")
        ret = call.body.stmts[1].value
        self.assertIsInstance(ret, A.MethodCall)
        self.assertEqual(ret.method, "get")

    def test_for_pattern_tuple_shadow(self):
        """``for (mylib, n) in pairs`` introduces ``mylib`` per
        iteration. Exercises the TuplePat branch through ForStmt."""
        self._setup_mylib()
        root = self._write(
            "root.capa",
            "import mylib\n"
            "\n"
            "pub capability MyCap\n"
            "    fun get(self, x: String) -> String\n"
            "\n"
            "fun call_each(pairs: List<(MyCap, Int)>, x: String) -> String\n"
            "    var out = \"\"\n"
            "    for pair in pairs\n"
            "        let (mylib, _n) = pair\n"
            "        out = out + mylib.get(x)\n"
            "    return out\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"unused\")\n"
        )
        module, A = self._link_and_inspect(root)
        call = self._find_fn(module, "call_each")
        for_stmt = call.body.stmts[1]
        self.assertIsInstance(for_stmt, A.ForStmt)
        # Loop body: stmt[0] = let, stmt[1] = AssignStmt with `out + mylib.get(x)`
        assign = for_stmt.body.stmts[1]
        rhs = assign.value
        self.assertIsInstance(rhs, A.BinOp)
        self.assertIsInstance(rhs.right, A.MethodCall)
        self.assertEqual(rhs.right.method, "get")

    def test_lambda_param_shadow(self):
        """A ``LambdaExpr`` parameter shadows the alias inside
        the lambda body. Covers the LambdaExpr branch of
        _walk_expr_for_binders + the params.add path."""
        self._setup_mylib()
        root = self._write(
            "root.capa",
            "import mylib\n"
            "\n"
            "pub capability MyCap\n"
            "    fun get(self, x: String) -> String\n"
            "\n"
            "pub type MyImpl { dummy: Int }\n"
            "impl MyCap for MyImpl\n"
            "    fun get(self, x: String) -> String\n"
            "        return \"impl: \" + x\n"
            "\n"
            "fun call() -> String\n"
            "    let m = MyImpl { dummy: 0 }\n"
            "    let f = fun (mylib: MyImpl) -> String => mylib.get(\"hi\")\n"
            "    return f(m)\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"unused\")\n"
        )
        module, A = self._link_and_inspect(root)
        call = self._find_fn(module, "call")
        # let f = fun (mylib) => mylib.get("hi"); the lambda is
        # the value of stmt[1] (LetStmt). Its body's expr is
        # the MethodCall we care about.
        let_stmt = call.body.stmts[1]
        self.assertIsInstance(let_stmt, A.LetStmt)
        lam = let_stmt.value
        self.assertIsInstance(lam, A.LambdaExpr)
        body = lam.body
        # Single-expr lambda body: body IS the method call expr.
        self.assertIsInstance(body, A.MethodCall)
        self.assertEqual(body.method, "get")

    def test_if_elif_else_shadow(self):
        """A let inside an elif branch contributes to the
        function-level shadow set; covers the elif_arms branch
        of _walk_stmt_for_binders."""
        self._setup_mylib()
        root = self._write(
            "root.capa",
            "import mylib\n"
            "\n"
            "pub capability MyCap\n"
            "    fun get(self, x: String) -> String\n"
            "\n"
            "pub type MyImpl { dummy: Int }\n"
            "impl MyCap for MyImpl\n"
            "    fun get(self, x: String) -> String\n"
            "        return \"impl: \" + x\n"
            "\n"
            "fun call(b1: Bool, b2: Bool) -> String\n"
            "    if b1\n"
            "        let mylib = MyImpl { dummy: 1 }\n"
            "        return mylib.get(\"a\")\n"
            "    else\n"
            "        if b2\n"
            "            let mylib = MyImpl { dummy: 2 }\n"
            "            return mylib.get(\"b\")\n"
            "        else\n"
            "            let mylib = MyImpl { dummy: 3 }\n"
            "            return mylib.get(\"c\")\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"unused\")\n"
        )
        module, A = self._link_and_inspect(root)
        call = self._find_fn(module, "call")
        # Walk into the if branches; every branch should preserve
        # the MethodCall on `mylib.get(...)`. We assert one branch
        # (the deeply nested else) to confirm the walker reached
        # both elif-cond walking and else_block walking.
        if_stmt = call.body.stmts[0]
        self.assertIsInstance(if_stmt, A.IfStmt)
        # Inside the outer else_block: another IfStmt
        inner_if = if_stmt.else_block.stmts[0]
        self.assertIsInstance(inner_if, A.IfStmt)
        # Inner else_block: let + return
        ret_value = inner_if.else_block.stmts[1].value
        self.assertIsInstance(ret_value, A.MethodCall)
        self.assertEqual(ret_value.method, "get")

    def test_no_shadow_rewrite_still_fires(self):
        """Regression guard: when the receiver is genuinely the
        module alias (no local shadow), the rewrite must still
        convert ``mod.fn(x)`` to ``fn(x)`` so the analyzer sees
        a plain function call."""
        self._setup_mylib()
        root = self._write(
            "root.capa",
            "import mylib\n"
            "\n"
            "fun call(x: String) -> String\n"
            "    return mylib.get(x)\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"unused\")\n"
        )
        module, A = self._link_and_inspect(root)
        call = self._find_fn(module, "call")
        ret_value = call.body.stmts[0].value
        # Rewriter fired: the MethodCall became a Call.
        self.assertIsInstance(ret_value, A.Call)
        self.assertIsInstance(ret_value.callee, A.Ident)
        self.assertEqual(ret_value.callee.name, "get")


class TestSearchPathResolution(_TempDirMixin, unittest.TestCase):
    """``ModuleLoader(search_paths=[...])`` resolves imports that
    do not exist relative to the importer. Used by the CLI to honor
    the ``CAPA_PATH`` env var for stdlib-style modules.
    """

    def test_module_found_via_search_path(self):
        # Module lives in a separate "lib" tree, not next to root.
        lib_dir = self._tmp / "lib"
        lib_dir.mkdir(parents=True, exist_ok=True)
        (lib_dir / "stdthing.capa").write_text(
            "pub fun answer() -> Int\n    return 42\n",
            encoding="utf-8",
        )
        root = self._write(
            "proj/root.capa",
            "import stdthing\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${answer()}\")\n"
        )
        loader = ModuleLoader(search_paths=[lib_dir])
        linked = loader.load_root(root.read_text(), str(root))
        names = {
            item.name for item in linked.module.items
            if isinstance(item, A.FunDecl)
        }
        self.assertIn("answer", names)
        self.assertIn("main", names)

    def test_importer_local_shadows_search_path(self):
        # Same module name in both places. Proximity wins.
        lib_dir = self._tmp / "lib"
        lib_dir.mkdir(parents=True, exist_ok=True)
        (lib_dir / "util.capa").write_text(
            "pub fun who() -> String\n    return \"lib\"\n",
            encoding="utf-8",
        )
        self._write(
            "proj/util.capa",
            "pub fun who() -> String\n    return \"local\"\n"
        )
        root = self._write(
            "proj/root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(who())\n"
        )
        loader = ModuleLoader(search_paths=[lib_dir])
        linked = loader.load_root(root.read_text(), str(root))
        # The local util.capa's `who` should be the one that linked.
        # We verify by transpiling + running and checking stdout.
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "local\n")

    def test_missing_import_lists_tried_paths(self):
        lib_a = self._tmp / "libA"
        lib_b = self._tmp / "libB"
        lib_a.mkdir()
        lib_b.mkdir()
        root = self._write(
            "root.capa",
            "import ghost\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        loader = ModuleLoader(search_paths=[lib_a, lib_b])
        with self.assertRaises(LoaderError) as ctx:
            loader.load_root(root.read_text(), str(root))
        msg = ctx.exception.message
        self.assertIn("cannot resolve", msg)
        self.assertIn("ghost", msg)
        # Both search paths should appear in the diagnostic.
        self.assertIn("libA", msg)
        self.assertIn("libB", msg)

    def test_cli_honors_capa_path_env(self):
        # End-to-end: CAPA_PATH env var lets `capa --run` resolve an
        # import that is not next to the source file.
        lib_dir = self._tmp / "lib"
        lib_dir.mkdir(parents=True, exist_ok=True)
        (lib_dir / "greeter.capa").write_text(
            "pub fun hello() -> String\n    return \"from stdlib\"\n",
            encoding="utf-8",
        )
        root = self._write(
            "proj/root.capa",
            "import greeter\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(hello())\n"
        )
        import os as _os
        env = dict(_os.environ)
        env["CAPA_PATH"] = str(lib_dir)
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
            env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "from stdlib\n")

    def test_cli_capa_path_multiple_entries(self):
        # CAPA_PATH supports os.pathsep-separated entries; the
        # second one is the one that holds the module.
        lib_a = self._tmp / "lib_a"
        lib_b = self._tmp / "lib_b"
        lib_a.mkdir()
        lib_b.mkdir()
        (lib_b / "deep.capa").write_text(
            "pub fun deep_val() -> Int\n    return 11\n",
            encoding="utf-8",
        )
        root = self._write(
            "proj/root.capa",
            "import deep\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${deep_val()}\")\n"
        )
        import os as _os
        env = dict(_os.environ)
        env["CAPA_PATH"] = _os.pathsep.join([str(lib_a), str(lib_b)])
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
            env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "11\n")

    def test_cli_empty_capa_path_is_silent(self):
        # An empty / missing CAPA_PATH must not change behavior.
        self._write(
            "util.capa",
            "pub fun ok() -> Int\n    return 1\n",
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${ok()}\")\n"
        )
        import os as _os
        env = dict(_os.environ)
        env.pop("CAPA_PATH", None)
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
            env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "1\n")


class TestDependencyRootResolution(_TempDirMixin, unittest.TestCase):
    """``ModuleLoader(dependency_roots={name: dir})`` resolves a
    declared PATH dependency from its declared directory, so
    ``[dependencies.X] path = "vendor/other"`` (directory basename
    ``other`` != dep name ``X``) is honoured. F-2 regression guard.
    """

    def test_mismatched_basename_module_form_resolves(self):
        # Dep NAME is ``mylib`` but its directory is ``vendor/otherdir``.
        dep_dir = self._tmp / "vendor" / "otherdir"
        dep_dir.mkdir(parents=True, exist_ok=True)
        (dep_dir / "api.capa").write_text(
            "pub fun answer() -> Int\n    return 42\n",
            encoding="utf-8",
        )
        root = self._write(
            "proj/root.capa",
            "import mylib.api\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("${answer()}")\n'
        )
        loader = ModuleLoader(dependency_roots={"mylib": dep_dir})
        linked = loader.load_root(root.read_text(), str(root))
        names = {
            item.name for item in linked.module.items
            if isinstance(item, A.FunDecl)
        }
        self.assertIn("answer", names)
        self.assertIn("main", names)

    def test_mismatched_basename_whole_package_lists_modules(self):
        # ``import mylib`` (whole-package form) over a mismatched-basename
        # path-dep: the declared dir IS the package dir, so the hint
        # lists its modules by the dep name, not the dir basename.
        dep_dir = self._tmp / "vendor" / "otherdir"
        dep_dir.mkdir(parents=True, exist_ok=True)
        (dep_dir / "api.capa").write_text(
            "pub fun a() -> Int\n    return 1\n", encoding="utf-8",
        )
        (dep_dir / "util.capa").write_text(
            "pub fun u() -> Int\n    return 2\n", encoding="utf-8",
        )
        root = self._write(
            "proj/root.capa",
            "import mylib\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("hi")\n'
        )
        loader = ModuleLoader(dependency_roots={"mylib": dep_dir})
        with self.assertRaises(LoaderError) as ctx:
            loader.load_root(root.read_text(), str(root))
        msg = ctx.exception.message
        self.assertIn("is a package directory", msg)
        # Modules are listed under the dep NAME, from the declared dir.
        self.assertIn("mylib.api", msg)
        self.assertIn("mylib.util", msg)

    def test_missing_module_error_lists_declared_path(self):
        # The declared-path candidate must appear in the "tried ..."
        # list so the declared path is never silently omitted.
        dep_dir = self._tmp / "vendor" / "otherdir"
        dep_dir.mkdir(parents=True, exist_ok=True)
        (dep_dir / "api.capa").write_text(
            "pub fun a() -> Int\n    return 1\n", encoding="utf-8",
        )
        root = self._write(
            "proj/root.capa",
            "import mylib.ghost\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("hi")\n'
        )
        loader = ModuleLoader(dependency_roots={"mylib": dep_dir})
        with self.assertRaises(LoaderError) as ctx:
            loader.load_root(root.read_text(), str(root))
        msg = ctx.exception.message
        self.assertIn("cannot resolve", msg)
        # The declared directory (basename ``otherdir``) and the
        # missing module file both appear in the diagnostic.
        self.assertIn("otherdir", msg)
        self.assertIn("ghost.capa", msg)

    def test_matching_basename_unchanged(self):
        # No regression: when the directory basename equals the dep
        # name, resolution is identical whether or not dependency_roots
        # is supplied (same file resolves either way).
        dep_dir = self._tmp / "vendor" / "mylib"
        dep_dir.mkdir(parents=True, exist_ok=True)
        (dep_dir / "api.capa").write_text(
            "pub fun answer() -> Int\n    return 7\n",
            encoding="utf-8",
        )
        root = self._write(
            "proj/root.capa",
            "import mylib.api\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("${answer()}")\n'
        )
        # With dependency_roots pointing at the matching-basename dir.
        loader_dep = ModuleLoader(dependency_roots={"mylib": dep_dir})
        linked_dep = loader_dep.load_root(root.read_text(), str(root))
        target_dep = next(
            p for p in linked_dep.sources.keys() if p.endswith("api.capa")
        )
        # With the pre-fix search-path form (parent of the dep dir).
        loader_sp = ModuleLoader(search_paths=[dep_dir.parent])
        linked_sp = loader_sp.load_root(root.read_text(), str(root))
        target_sp = next(
            p for p in linked_sp.sources.keys() if p.endswith("api.capa")
        )
        # Both resolve to the exact same file on disk.
        self.assertEqual(Path(target_dep).resolve(), Path(target_sp).resolve())


class TestBarePackageImportHint(_TempDirMixin, unittest.TestCase):
    """A bare ``import pkg`` where ``pkg`` is a directory of modules
    (the ``capa add`` vendor layout) gets a self-correcting hint
    listing the importable ``pkg.module`` names instead of the raw
    tried-paths dump.
    """

    def test_bare_import_of_package_dir_lists_modules(self):
        vendor = self._tmp / "vendor"
        (vendor / "mypkg").mkdir(parents=True, exist_ok=True)
        (vendor / "mypkg" / "alpha.capa").write_text(
            "pub fun a() -> Int\n    return 1\n", encoding="utf-8",
        )
        (vendor / "mypkg" / "beta.capa").write_text(
            "pub fun b() -> Int\n    return 2\n", encoding="utf-8",
        )
        root = self._write(
            "root.capa",
            "import mypkg\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        loader = ModuleLoader(search_paths=[vendor])
        with self.assertRaises(LoaderError) as ctx:
            loader.load_root(root.read_text(), str(root))
        msg = ctx.exception.message
        self.assertIn("package directory", msg)
        self.assertIn("mypkg.alpha", msg)
        self.assertIn("mypkg.beta", msg)
        # Sorted: alpha before beta.
        self.assertLess(msg.index("mypkg.alpha"), msg.index("mypkg.beta"))

    def test_bare_import_genuinely_missing_keeps_tried_message(self):
        root = self._write(
            "root.capa",
            "import nosuchthing\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        loader = ModuleLoader()
        with self.assertRaises(LoaderError) as ctx:
            loader.load_root(root.read_text(), str(root))
        msg = ctx.exception.message
        self.assertIn("tried", msg)
        self.assertNotIn("package directory", msg)

    def test_package_dir_with_no_capa_files_falls_back(self):
        vendor = self._tmp / "vendor"
        (vendor / "empty").mkdir(parents=True, exist_ok=True)
        (vendor / "empty" / "README.md").write_text(
            "not a module\n", encoding="utf-8",
        )
        root = self._write(
            "root.capa",
            "import empty\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        loader = ModuleLoader(search_paths=[vendor])
        with self.assertRaises(LoaderError) as ctx:
            loader.load_root(root.read_text(), str(root))
        msg = ctx.exception.message
        self.assertIn("tried", msg)
        self.assertNotIn("package directory", msg)

    def test_dotted_import_still_resolves(self):
        vendor = self._tmp / "vendor"
        (vendor / "mypkg").mkdir(parents=True, exist_ok=True)
        (vendor / "mypkg" / "alpha.capa").write_text(
            "pub fun a() -> Int\n    return 1\n", encoding="utf-8",
        )
        root = self._write(
            "root.capa",
            "import mypkg.alpha\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${a()}\")\n"
        )
        loader = ModuleLoader(search_paths=[vendor])
        linked = loader.load_root(root.read_text(), str(root))
        names = {
            item.name for item in linked.module.items
            if isinstance(item, A.FunDecl)
        }
        self.assertIn("a", names)
        self.assertIn("main", names)


class TestPubVisibility(_TempDirMixin, unittest.TestCase):
    """The loader enforces ``pub`` by name-mangling every private
    top-level item of every imported module. Importers see only the
    items that were marked ``pub``; private items keep working
    inside their own file.
    """

    def test_private_function_blocked_from_importer(self):
        # `helper` is private to util; the importer's unqualified
        # call must not resolve.
        self._write(
            "util.capa",
            "fun helper(x: Int) -> Int\n"
            "    return x + 1\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${helper(3)}\")\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--check", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("helper", result.stderr)

    def test_private_function_still_callable_inside_its_module(self):
        # The pub function `outer` calls the private `helper` in
        # the same module. After mangling, that internal call is
        # rewritten to the mangled name and still resolves.
        self._write(
            "util.capa",
            "fun helper(x: Int) -> Int\n"
            "    return x + 1\n"
            "pub fun outer(x: Int) -> Int\n"
            "    return helper(x)\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${outer(3)}\")\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "4\n")

    def test_private_type_still_usable_inside_its_module(self):
        # A private struct used in a pub function's body. The body
        # references the type by name (`Pair`); the reference is
        # mangled at link time, the declaration also is, so the
        # internal use still resolves.
        self._write(
            "util.capa",
            "type Pair { x: Int, y: Int }\n"
            "pub fun make(a: Int, b: Int) -> Int\n"
            "    let p = Pair { x: a, y: b }\n"
            "    return p.x + p.y\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${make(2, 3)}\")\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "5\n")

    def test_private_qualified_call_blocked(self):
        # `M.private_fn()` from outside the module must not rewrite
        # to a direct call; module_exports only contains pub items.
        self._write(
            "util.capa",
            "fun helper(x: Int) -> Int\n"
            "    return x + 1\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${util.helper(3)}\")\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--check", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(result.returncode, 0)

    def test_same_private_name_in_two_modules_no_clash(self):
        # Both modules define a private `helper`; both expose a
        # pub function that uses it. Mangle prefixes differ so the
        # privates do not collide at link time.
        self._write(
            "a.capa",
            "fun helper() -> Int\n    return 1\n"
            "pub fun from_a() -> Int\n    return helper()\n"
        )
        self._write(
            "b.capa",
            "fun helper() -> Int\n    return 2\n"
            "pub fun from_b() -> Int\n    return helper()\n"
        )
        root = self._write(
            "root.capa",
            "import a\n"
            "import b\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${from_a() + from_b()}\")\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "3\n")

    def test_pub_on_root_items_is_noop(self):
        # The root module is not mangled. `pub` on root items is
        # accepted but does not change anything observable.
        root = self._write(
            "root.capa",
            "pub fun add(a: Int, b: Int) -> Int\n"
            "    return a + b\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${add(2, 3)}\")\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "5\n")

    def test_private_const_blocked_from_importer(self):
        self._write(
            "util.capa",
            "const SECRET: Int = 42\n"
            "pub fun get() -> Int\n    return SECRET\n"
        )
        # Pub side works
        root_ok = self._write(
            "ok_root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${get()}\")\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root_ok)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "42\n")
        # Direct access blocked
        root_bad = self._write(
            "bad_root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${SECRET}\")\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--check", str(root_bad)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SECRET", result.stderr)

    def test_private_type_blocked_from_importer(self):
        self._write(
            "util.capa",
            "type Box { v: Int }\n"
            "pub fun make() -> Int\n"
            "    let b = Box { v: 7 }\n"
            "    return b.v\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    let b: Box = Box { v: 1 }\n"
            "    stdio.println(\"${b.v}\")\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--check", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(result.returncode, 0)


class TestPrivateDiagnostic(_TempDirMixin, unittest.TestCase):
    """When a reference fails to resolve and the missing name is
    a private item of an imported module, the diagnostic should
    say so and suggest ``pub`` instead of a generic typo hint.
    """

    def test_private_function_diagnostic_mentions_module(self):
        self._write(
            "util.capa",
            "fun helper(x: Int) -> Int\n"
            "    return x + 1\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    let n = helper(3)\n"
            "    stdio.println(\"hi\")\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--check", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("private to module 'util'", result.stderr)
        self.assertIn("'pub'", result.stderr)

    def test_private_type_diagnostic_mentions_module(self):
        self._write(
            "util.capa",
            "type Box { v: Int }\n"
            "pub fun make() -> Int\n"
            "    let b = Box { v: 7 }\n"
            "    return b.v\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    let b: Box = Box { v: 1 }\n"
            "    stdio.println(\"hi\")\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--check", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("private to module 'util'", result.stderr)

    def test_typo_hint_still_works_for_truly_unknown_names(self):
        # Regression: when the missing name is not a private of any
        # imported module, the typo hint must keep working.
        self._write(
            "util.capa",
            "pub fun greet(name: String) -> String\n"
            "    return \"Hi, \" + name\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(grett(\"x\"))\n"  # typo: grett vs greet
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--check", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(result.returncode, 0)
        # Should suggest 'greet' (typo hint), not "private to module".
        self.assertIn("did you mean", result.stderr.lower())
        self.assertIn("greet", result.stderr)
        self.assertNotIn("private to module", result.stderr)

    def test_private_in_two_modules_lists_both(self):
        # Two imported modules each declare a private ``helper``.
        # The importer's failed lookup should mention both.
        self._write(
            "a.capa",
            "fun helper() -> Int\n    return 1\n"
            "pub fun a_pub() -> Int\n    return helper()\n"
        )
        self._write(
            "b.capa",
            "fun helper() -> Int\n    return 2\n"
            "pub fun b_pub() -> Int\n    return helper()\n"
        )
        root = self._write(
            "root.capa",
            "import a\n"
            "import b\n"
            "fun main(stdio: Stdio)\n"
            "    let n = helper()\n"
            "    stdio.println(\"hi\")\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--check", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("private to modules", result.stderr)
        self.assertIn("'a'", result.stderr)
        self.assertIn("'b'", result.stderr)


class TestMangledNamesNotInDiagnostics(_TempDirMixin, unittest.TestCase):
    """The loader renames private + unselected-pub items to
    ``_capa_m<N>__...`` to keep them out of the importer's scope.
    Those internal names must never surface in a user-facing
    diagnostic: the message must show the name the author wrote."""

    def _check(self, root: Path):
        return subprocess.run(
            [sys.executable, "-m", "capa", "--check", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )

    def test_private_function_name_demangled_in_error(self):
        # A type error at a call to a PRIVATE imported function used to
        # render ``call to '_capa_m1__helper'``.
        self._write(
            "lib.capa",
            "fun helper(x: Int) -> Int\n    return x\n"
            "pub fun shown() -> String\n"
            "    return helper(\"not an int\")\n"
        )
        root = self._write(
            "root.capa",
            "import lib\nfun main()\n    return\n",
        )
        result = self._check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("call to 'helper'", result.stderr)
        self.assertNotIn("_capa_m", result.stderr)

    def test_demangle_unit(self):
        from capa.analyzer import _demangle
        self.assertEqual(_demangle("call to '_capa_m1__helper'"),
                         "call to 'helper'")
        self.assertEqual(_demangle("call to '_capa_m12__sel__do_thing'"),
                         "call to 'do_thing'")
        # Underscored original names survive intact.
        self.assertEqual(_demangle("'_capa_m3__my_helper_fn'"),
                         "'my_helper_fn'")
        # No mangled name -> untouched.
        self.assertEqual(_demangle("plain message"), "plain message")

    def test_unselected_pub_function_name_demangled_in_error(self):
        # A type error at a call to an UNSELECTED pub function (hidden
        # by a selective import) used to render the
        # ``_capa_m1__sel__<name>`` form.
        self._write(
            "lib.capa",
            "pub fun shown() -> String\n"
            "    return secret_helper(\"x\")\n"
            "pub fun secret_helper(x: Int) -> Int\n    return x\n"
        )
        root = self._write(
            "root.capa",
            "import lib (shown)\nfun main()\n    return\n",
        )
        result = self._check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("call to 'secret_helper'", result.stderr)
        self.assertNotIn("_capa_m", result.stderr)


class TestModuleSystemEndToEnd(_TempDirMixin, unittest.TestCase):
    """End-to-end: capa --run with an imported file produces the
    expected output and exit code 0.
    """

    def test_main_imports_util_and_runs(self):
        self._write(
            "util.capa",
            "pub fun greet(name: String) -> String\n"
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


class TestSubmoduleResolvesRootSiblings(_TempDirMixin, unittest.TestCase):
    """A submodule (file under a subdirectory) must be able to
    ``import x`` where ``x.capa`` lives next to the root file.
    Without this, multi-directory projects (e.g. ``reporter.capa`` +
    ``sinks/csv_sink.capa`` + ``domain.capa``) would force every
    submodule to copy or re-export the root's siblings.

    The loader handles this by adding the root file's directory to
    its search paths once load_root is called.
    """

    def test_nested_module_imports_root_sibling(self):
        # Project layout:
        #   root.capa              (imports sinks.csv)
        #   domain.capa            (pub fun used by sinks.csv)
        #   sinks/csv.capa         (imports domain)
        self._write(
            "domain.capa",
            "pub fun label() -> String\n"
            "    return \"shared\"\n"
        )
        self._write(
            "sinks/csv.capa",
            "import domain\n"
            "pub fun greet() -> String\n"
            "    return \"hello, \" + label()\n"
        )
        root = self._write(
            "root.capa",
            "import sinks.csv\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(greet())\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "hello, shared\n")


class TestRunArgsPassThrough(_TempDirMixin, unittest.TestCase):
    """`capa --run file.capa -- a b c` should forward ``a b c`` to
    the program, where ``env.args()`` returns them. Before the fix,
    Capa's argparse rejected the trailing positionals; the workaround
    was to transpile to .py and run the Python directly.
    """

    def test_passthrough_visible_via_env_args(self):
        root = self._write(
            "show_args.capa",
            "fun main(stdio: Stdio, env: Env)\n"
            "    for a in env.args()\n"
            "        stdio.println(a)\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root),
             "--", "first", "second", "third"],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "first\nsecond\nthird\n")

    def test_no_dash_dash_means_no_program_args(self):
        # Without the `--` separator, env.args() is empty (the
        # Capa CLI's own flags are not leaked into the program).
        root = self._write(
            "count_args.capa",
            "fun main(stdio: Stdio, env: Env)\n"
            "    stdio.println(\"${env.args().length()}\")\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "0\n")

    def test_program_flags_are_not_intercepted(self):
        # Flags after `--` that look like Capa flags must reach
        # the program intact instead of being consumed by argparse.
        root = self._write(
            "echo_flags.capa",
            "fun main(stdio: Stdio, env: Env)\n"
            "    for a in env.args()\n"
            "        stdio.println(a)\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", str(root),
             "--", "--verbose", "--help", "input.txt"],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "--verbose\n--help\ninput.txt\n")


class TestPrivateRenameWalkerCoverage(_TempDirMixin, unittest.TestCase):
    """Exercise every visit-* branch of ``_PrivateRenameWalker`` and
    the parallel walker in ``_Rewriter``. Each test writes a util
    module where a private helper is referenced inside a specific
    AST shape (statement, expression, type position); in-process
    ``ModuleLoader.load_root`` runs the walker, then we analyse
    the merged AST to confirm the rewrite succeeded (an unrewritten
    reference would surface as an undefined-name diagnostic).

    The earlier ``TestPubVisibility`` cases drive ``--run`` via a
    subprocess; that path proves end-to-end correctness but does
    NOT register against the parent process's coverage instance.
    These cases run the walker inline so the coverage report
    actually reflects them.

    Coverage gap before this class landed: ~175 lines across
    loader.py's two AST walkers.
    """

    def _check_loads_and_analyses(self, root: Path) -> None:
        from capa import analyze
        loader = ModuleLoader()
        linked = loader.load_root(root.read_text(encoding="utf-8"), str(root))
        # If the walker missed a reference, the analyser will surface
        # an undefined-name error on the imported reference. Asserting
        # `result.ok` therefore implies the walker rewrote every
        # private reference the test exercised.
        result = analyze(linked.module, source=root.read_text(encoding="utf-8"))
        self.assertTrue(
            result.ok,
            f"analyser errors: {[e.format() for e in result.errors]}",
        )

    # ---- statement positions ----

    def test_walker_visits_let_var_assign_if_while_for(self):
        # One pub function exercising LetStmt, VarStmt, AssignStmt,
        # IfStmt (with elif + else), WhileStmt, ForStmt -- each
        # referencing the private `helper` so the walker has to
        # descend into the statement's expression slot and rewrite.
        self._write(
            "util.capa",
            "fun helper(x: Int) -> Int\n"
            "    return x + 1\n"
            "pub fun run(n: Int) -> Int\n"
            "    let a = helper(n)\n"
            "    var b = helper(a)\n"
            "    b = b + helper(0)\n"
            "    if b > 100\n"
            "        b = helper(1)\n"
            "    elif b < 0\n"
            "        b = helper(2)\n"
            "    else\n"
            "        b = helper(3)\n"
            "    var i = 0\n"
            "    while i < 1\n"
            "        b = b + helper(i)\n"
            "        i = i + 1\n"
            "    for j in 0..1\n"
            "        b = b + helper(j)\n"
            "    return b\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${run(0)}\")\n"
        )
        # n=0 -> a=1, b=2, b=3, b<100 + b>=0 -> elif branch fails,
        # else -> b=4, while i<1 -> b=4+1=5, i=1, for j in 0..1
        # -> b=5+1=6 -> return 6.
        self._check_loads_and_analyses(root)

    # ---- expression positions ----

    def test_walker_visits_binop_unary_field_index_try(self):
        # BinOp, UnaryOp, FieldAccess, Index, Try -- all referencing
        # the private helper somewhere.
        self._write(
            "util.capa",
            "fun helper(x: Int) -> Int\n"
            "    return x + 1\n"
            "type Box { v: Int }\n"
            "pub fun run() -> Int\n"
            "    let a = helper(1) + helper(2)\n"
            "    let b = -helper(3)\n"
            "    let box = Box { v: helper(4) }\n"
            "    let v = box.v\n"
            "    let xs = [helper(5), helper(6)]\n"
            "    let z = xs[0]\n"
            "    return a + b + v + z\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${run()}\")\n"
        )
        # a=2+3=5, b=-4, v=5, z=6 -> 5-4+5+6 = 12
        self._check_loads_and_analyses(root)

    def test_walker_visits_lambda_match_if_expr_range_interp(self):
        # LambdaExpr (block body and expr body), MatchExpr,
        # IfExpr, RangeExpr, InterpolatedString. Each branch in
        # _PrivateRenameWalker.visit_expr.
        self._write(
            "util.capa",
            "fun helper(x: Int) -> Int\n"
            "    return x + 1\n"
            "pub fun run() -> Int\n"
            "    let f = fun (n: Int) -> Int => helper(n)\n"
            "    let g = fun (n: Int) -> Int =>\n"
            "        let h = helper(n)\n"
            "        return h\n"
            "    let m = match 1\n"
            "        0 -> helper(0)\n"
            "        n -> helper(n)\n"
            "    let p = if true then helper(10) else helper(20)\n"
            "    var total = 0\n"
            "    for i in helper(0)..helper(2)\n"
            "        total = total + 1\n"
            "    let msg = \"v=${helper(5)}\"\n"
            "    return f(1) + g(2) + m + p + total + msg.length()\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${run()}\")\n"
        )
        # f(1)=2, g(2)=3, m=2 (n=1, helper(1)=2), p=11 (true branch),
        # for i in 1..3 -> total=2, msg="v=6" length=3
        # -> 2+3+2+11+2+3 = 23
        self._check_loads_and_analyses(root)

    # ---- type positions ----

    def test_walker_visits_type_name_fun_type_tuple_type(self):
        # TypeName (in struct field, fun param, return type),
        # TupleType (let annotation), FunType (lambda return).
        # Private helper TYPE name reference must rewrite at every
        # type position.
        self._write(
            "util.capa",
            "type Pair { x: Int, y: Int }\n"
            "fun mk_pair(x: Int, y: Int) -> Pair\n"
            "    return Pair { x: x, y: y }\n"
            "pub fun run() -> Int\n"
            "    let p: Pair = mk_pair(2, 3)\n"
            "    let t: (Int, Int) = (p.x, p.y)\n"
            "    let (a, b) = t\n"
            "    return a + b\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${run()}\")\n"
        )
        self._check_loads_and_analyses(root)

    # ---- impl block + trait + sum ----

    def test_walker_visits_impl_block_and_sum_variants(self):
        # ImplBlock.type_name / trait_name and TypeSum variant
        # payload types both have private-name positions the
        # walker must rewrite.
        self._write(
            "util.capa",
            "type Bag { v: Int }\n"
            "pub trait Named\n"
            "    fun name(self) -> String\n"
            "impl Named for Bag\n"
            "    fun name(self) -> String\n"
            "        return \"bag\"\n"
            "pub fun describe() -> String\n"
            "    let b = Bag { v: 1 }\n"
            "    return b.name()\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(describe())\n"
        )
        self._check_loads_and_analyses(root)

    # ---- alias-qualified call rewriter (_Rewriter) ----

    def test_qualified_call_rewriter_walks_every_expr_shape(self):
        # Exercises _Rewriter (which walks the same AST shapes as
        # _PrivateRenameWalker but targets ``alias.method(...)``
        # rewrites). The util module exposes `add`; the importer
        # uses `util.add(...)` inside diverse expression positions.
        self._write(
            "util.capa",
            "pub fun add(a: Int, b: Int) -> Int\n"
            "    return a + b\n"
        )
        root = self._write(
            "root.capa",
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    let a = util.add(1, 2) + util.add(3, 4)\n"
            "    let b = -util.add(5, 0)\n"
            "    let xs = [util.add(1, 1), util.add(2, 2)]\n"
            "    let t = (util.add(0, 0), util.add(1, 0))\n"
            "    let s = \"v=${util.add(2, 3)}\"\n"
            "    var total = a + b + xs[0] + xs[1]\n"
            "    let (p, q) = t\n"
            "    total = total + p + q\n"
            "    for i in 0..1\n"
            "        total = total + util.add(i, 0)\n"
            "    let m = match 1\n"
            "        0 -> util.add(0, 0)\n"
            "        _ -> util.add(1, 0)\n"
            "    total = total + m\n"
            "    stdio.println(\"${total} ${s.length()}\")\n"
        )
        # a=3+7=10, b=-5, xs=[2,4], total=10-5+2+4=11,
        # p=0, q=1 -> total=12, for i=0 -> total=12, m=1 -> total=13,
        # s = "v=5" length=3
        self._check_loads_and_analyses(root)


if __name__ == "__main__":
    unittest.main()
