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


if __name__ == "__main__":
    unittest.main()
