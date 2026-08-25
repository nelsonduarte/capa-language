"""Tests for ``capa test`` (:mod:`capa.testrunner` + CLI dispatch).

Three layers:

  * pure-unit coverage of discovery / root-walking / the
    missing-vendored-deps probe (no subprocesses);
  * the ``--both`` divergence machinery with ``_run_file`` mocked,
    so the diff path is covered on machines without the Wasm
    toolchain;
  * end-to-end runs of real Capa test files through the dispatch
    (subprocess per test file, exactly what users get). The
    Wasm-backed cases are skipped when the toolchain is absent.

The honest cross-backend divergence fixture is ``parse_json`` on
malformed input: both backends return ``Err`` and exit 0, but the
error TEXT comes from the host JSON engine on Python and from the
bundled parser on Wasm, so printing it diverges by construction.
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from capa import testrunner
from capa.cli import _wasm_tooling_available, main


_MANIFEST = '''\
[package]
name = "demo"
version = "0.1.0"
'''

_PASSING = (
    'fun main(stdio: Stdio)\n'
    '    stdio.println("fine")\n'
)

# Failure mechanism per the result contract: a runtime error
# escaping main makes the program exit 1 on both backends.
_FAILING = (
    'fun main(stdio: Stdio)\n'
    '    stdio.println("before the boom")\n'
    '    let x = 1 / 0\n'
    '    stdio.println("${x}")\n'
)

# Honest backend divergence: the Err text of parse_json differs
# between the Python host engine and the bundled Wasm parser.
_DIVERGING = (
    'fun main(stdio: Stdio)\n'
    '    let r = parse_json("{bad json")\n'
    '    match r\n'
    '        Ok(_) -> stdio.println("parsed")\n'
    '        Err(msg) -> stdio.println("error: ${msg}")\n'
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content), encoding="utf-8")


def _run_main(argv, cwd=None):
    """Drive ``capa.cli.main()`` in-process; returns (rc, out, err).
    The test-file subprocesses it spawns are real."""
    out, err = io.StringIO(), io.StringIO()
    patches = [
        mock.patch.object(sys, "argv", ["capa"] + list(argv)),
        mock.patch.object(sys, "stdout", out),
        mock.patch.object(sys, "stderr", err),
    ]
    original_cwd = os.getcwd()
    try:
        if cwd is not None:
            os.chdir(str(cwd))
        for p in patches:
            p.start()
        try:
            rc = main()
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else (
                0 if e.code is None else 1
            )
        return rc, out.getvalue(), err.getvalue()
    finally:
        for p in reversed(patches):
            p.stop()
        os.chdir(original_cwd)


class _TempProjectMixin:
    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="capa_test_cmd_")).resolve()

    def tearDown(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _project(self, manifest: str = _MANIFEST) -> Path:
        root = self._tmp / "proj"
        _write(root / "capa.toml", manifest)
        return root


class TestDiscovery(_TempProjectMixin, unittest.TestCase):
    """File discovery + project-root walking, no subprocesses."""

    def test_discovery_is_sorted_by_name(self):
        root = self._project()
        for name in ("test_zeta.capa", "test_alpha.capa", "test_mid.capa"):
            _write(root / "tests" / name, _PASSING)
        found = [p.name for p in testrunner.discover_tests(root)]
        self.assertEqual(
            found, ["test_alpha.capa", "test_mid.capa", "test_zeta.capa"],
        )

    def test_discovery_skips_helpers_and_nested_dirs(self):
        root = self._project()
        _write(root / "tests" / "test_a.capa", _PASSING)
        _write(root / "tests" / "testutil.capa", "// helper, not a test\n")
        _write(root / "tests" / "nested" / "test_b.capa", _PASSING)
        found = [p.name for p in testrunner.discover_tests(root)]
        self.assertEqual(found, ["test_a.capa"])

    def test_discovery_empty_without_tests_dir(self):
        root = self._project()
        self.assertEqual(testrunner.discover_tests(root), [])

    def test_project_root_walks_up_to_manifest(self):
        root = self._project()
        deep = root / "src" / "inner"
        deep.mkdir(parents=True)
        self.assertEqual(testrunner.find_project_root(deep), root)

    def test_project_root_falls_back_to_start(self):
        bare = self._tmp / "no_manifest"
        bare.mkdir()
        self.assertEqual(testrunner.find_project_root(bare), bare.resolve())

    def test_missing_vendored_deps_reports_unvendored_git_deps(self):
        root = self._project('''\
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            mylib = { git = "https://example.invalid/mylib", tag = "v1" }

            [dev-dependencies]
            testkit = { git = "https://example.invalid/testkit", tag = "v1" }
            local = { path = "." }
        ''')
        # Neither git dep is vendored; the path dep never counts.
        self.assertEqual(
            testrunner.missing_vendored_deps(root), ["mylib", "testkit"],
        )
        # Vendoring one of them clears it from the report.
        (root / "vendor" / "testkit").mkdir(parents=True)
        self.assertEqual(testrunner.missing_vendored_deps(root), ["mylib"])

    def test_missing_vendored_deps_empty_without_manifest(self):
        bare = self._tmp / "no_manifest"
        bare.mkdir()
        self.assertEqual(testrunner.missing_vendored_deps(bare), [])


class TestBothModeUnit(_TempProjectMixin, unittest.TestCase):
    """--both semantics with the backend runs mocked, so the
    divergence / per-backend-failure paths are covered without the
    Wasm toolchain."""

    def _run_with_fake_backends(self, root, fake):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(testrunner, "_run_file", side_effect=fake):
            rc = testrunner.run_tests(root, mode="both", out=out, err=err)
        return rc, out.getvalue(), err.getvalue()

    def test_divergent_stdout_is_its_own_failure_kind(self):
        root = self._project()
        _write(root / "tests" / "test_div.capa", _PASSING)

        def fake(test_file, project_root, *, wasm):
            return 0, ("WASM\n" if wasm else "PYTHON\n"), ""

        rc, out, _ = self._run_with_fake_backends(root, fake)
        self.assertEqual(rc, 1)
        self.assertIn("test_div.capa ... DIVERGED", out)
        self.assertIn("both backends exited 0 but their stdout differs", out)
        # The unified diff names both sides and carries the lines.
        self.assertIn("--- python backend", out)
        self.assertIn("+++ wasm backend", out)
        self.assertIn("-PYTHON", out)
        self.assertIn("+WASM", out)
        self.assertIn("1 test(s): 0 passed, 1 failed (1 diverged)", out)

    def test_single_backend_failure_is_a_plain_fail(self):
        root = self._project()
        _write(root / "tests" / "test_w.capa", _PASSING)

        def fake(test_file, project_root, *, wasm):
            if wasm:
                return 1, "", "trap: out of bounds\n"
            return 0, "same\n", ""

        rc, out, _ = self._run_with_fake_backends(root, fake)
        self.assertEqual(rc, 1)
        self.assertIn("test_w.capa ... FAIL", out)
        self.assertIn("[wasm]", out)
        self.assertIn("trap: out of bounds", out)
        self.assertNotIn("DIVERGED", out)

    def test_matching_outputs_pass(self):
        root = self._project()
        _write(root / "tests" / "test_m.capa", _PASSING)

        def fake(test_file, project_root, *, wasm):
            return 0, "same\n", ""

        rc, out, _ = self._run_with_fake_backends(root, fake)
        self.assertEqual(rc, 0)
        self.assertIn("test_m.capa ... ok", out)
        self.assertIn("1 test(s): 1 passed, 0 failed", out)


class TestCapaTestEndToEnd(_TempProjectMixin, unittest.TestCase):
    """Real runs through the CLI dispatch (Python backend)."""

    def test_all_passing_project_exits_zero_in_order(self):
        root = self._project()
        _write(root / "tests" / "test_b.capa", _PASSING)
        _write(root / "tests" / "test_a.capa", _PASSING)
        rc, out, err = _run_main(["test"], cwd=root)
        self.assertEqual(rc, 0, err)
        self.assertIn("test_a.capa ... ok", out)
        self.assertIn("test_b.capa ... ok", out)
        self.assertLess(
            out.index("test_a.capa"), out.index("test_b.capa"),
            "discovery order must be sorted by file name",
        )
        self.assertIn("2 test(s): 2 passed, 0 failed", out)

    def test_failing_test_shows_captured_output_and_exits_one(self):
        root = self._project()
        _write(root / "tests" / "test_ok.capa", _PASSING)
        _write(root / "tests" / "test_boom.capa", _FAILING)
        rc, out, err = _run_main(["test"], cwd=root)
        self.assertEqual(rc, 1)
        self.assertIn("test_boom.capa ... FAIL", out)
        self.assertIn("test_ok.capa ... ok", out)
        # The failing file's captured stdout and stderr are shown.
        self.assertIn("before the boom", out)
        self.assertIn("captured stderr", out)
        self.assertIn("2 test(s): 1 passed, 1 failed", out)

    def test_runs_from_subdirectory_of_project(self):
        root = self._project()
        _write(root / "tests" / "test_a.capa", _PASSING)
        sub = root / "src"
        sub.mkdir()
        rc, out, _ = _run_main(["test"], cwd=sub)
        self.assertEqual(rc, 0)
        self.assertIn("test_a.capa ... ok", out)

    def test_no_tests_found_exits_two(self):
        root = self._project()
        rc, _out, err = _run_main(["test"], cwd=root)
        self.assertEqual(rc, 2)
        self.assertIn("no test files", err)
        self.assertIn("tests/test_*.capa", err)

    def test_unvendored_dev_dep_points_at_capa_install(self):
        root = self._project('''\
            [package]
            name = "demo"
            version = "0.1.0"

            [dev-dependencies]
            testkit = { git = "https://example.invalid/testkit", tag = "v1" }
        ''')
        _write(root / "tests" / "test_a.capa", _PASSING)
        rc, _out, err = _run_main(["test"], cwd=root)
        self.assertEqual(rc, 2)
        self.assertIn("testkit", err)
        self.assertIn("capa install", err)

    def test_broken_manifest_exits_two(self):
        root = self._project("this is { not toml\n")
        _write(root / "tests" / "test_a.capa", _PASSING)
        rc, _out, err = _run_main(["test"], cwd=root)
        self.assertEqual(rc, 2)
        self.assertIn("broken capa.toml", err)

    def test_wasm_without_tooling_errors_cleanly(self):
        root = self._project()
        _write(root / "tests" / "test_a.capa", _PASSING)
        with mock.patch(
            "capa.cli.subcommands._wasm_tooling_available", return_value=False,
        ):
            rc, _out, err = _run_main(["test", "--wasm"], cwd=root)
        self.assertEqual(rc, 2)
        self.assertIn("Wasm toolchain", err)

    def test_wasm_and_both_are_mutually_exclusive(self):
        root = self._project()
        _write(root / "tests" / "test_a.capa", _PASSING)
        rc, _out, _err = _run_main(["test", "--wasm", "--both"], cwd=root)
        self.assertEqual(rc, 2)

    def test_dev_path_dep_importable_from_test_file(self):
        # A dev-dep's modules resolve for test files just like
        # regular deps (Part A + Part B integration). The declared
        # path is relative to the manifest dir (``<tmp>/proj``), so
        # ``../kit`` is the helper at ``<tmp>/kit``. It used to read
        # ``../../kit``, a directory that never existed: the import
        # resolved anyway because the project root's parent was an
        # open search root and happened to hold a ``kit/``. With that
        # fallback gone the declared path has to be right, which is
        # the point of the test.
        helper = self._tmp / "kit"
        _write(
            helper / "asserts.capa",
            'pub fun tag() -> String\n    return "dev dep speaking"\n',
        )
        root = self._project('''\
            [package]
            name = "demo"
            version = "0.1.0"

            [dev-dependencies]
            kit = { path = "../kit" }
        ''')
        _write(root / "tests" / "test_kit.capa", '''\
            import kit.asserts
            fun main(stdio: Stdio)
                stdio.println(tag())
        ''')
        rc, out, err = _run_main(["test"], cwd=root)
        self.assertEqual(rc, 0, err + out)
        self.assertIn("test_kit.capa ... ok", out)

    def test_package_self_reference_resolves_in_test_files(self):
        # The seed-library shape: the repository IS the package, and a
        # test file imports the package's own modules by package name.
        # Served by ``[package].name`` in ``_capa_dependency_roots``,
        # not by putting the root's parent on the search path.
        root = self._project('''\
            [package]
            name = "proj"
            version = "0.1.0"
        ''')
        _write(
            root / "model.capa",
            'pub fun tag() -> String\n    return "own module"\n',
        )
        _write(root / "tests" / "test_self.capa", '''\
            import proj.model
            fun main(stdio: Stdio)
                stdio.println(tag())
        ''')
        rc, out, err = _run_main(["test"], cwd=root)
        self.assertEqual(rc, 0, err + out)
        self.assertIn("test_self.capa ... ok", out)

    def test_sibling_of_project_root_is_not_importable(self):
        # Supply-chain regression, ``capa test`` edition: the runner
        # used to inject the project root's PARENT into the child's
        # CAPA_PATH, so any sibling directory could satisfy an import
        # that no dependency declared. A test run must fail closed on
        # such an import instead of linking unverified sources.
        _write(
            self._tmp / "sneaky" / "mod.capa",
            'pub fun tag() -> String\n    return "sibling"\n',
        )
        root = self._project()
        _write(root / "tests" / "test_sneak.capa", '''\
            import sneaky.mod
            fun main(stdio: Stdio)
                stdio.println(tag())
        ''')
        rc, out, err = _run_main(["test"], cwd=root)
        self.assertEqual(rc, 1, err + out)
        self.assertIn("cannot resolve 'import sneaky.mod'", out)

    def test_child_env_does_not_expose_the_project_parent(self):
        root = self._project()
        entries = testrunner._child_env(root)["CAPA_PATH"].split(os.pathsep)
        self.assertIn(str(root), entries)
        self.assertNotIn(str(root.parent), entries)


class TestChildCommandShape(_TempProjectMixin, unittest.TestCase):
    """How the runner spawns a child ``capa``.

    ``_run_file`` hard-coded ``[sys.executable, "-m", "capa"]``. Under a
    PyInstaller build ``sys.executable`` IS the capa binary, which
    rejects ``-m``, so every released binary failed every test with
    ``error: unrecognized arguments: -m <file>``. These cases pin the
    two forms, because the broken one passes every test that runs from
    a source checkout."""

    def _spawned_command(self, *, frozen: bool) -> list:
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = cmd
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("capa._selfexec.is_frozen", return_value=frozen), \
                mock.patch.object(sys, "executable", "/opt/capa/capa"), \
                mock.patch.object(testrunner.subprocess, "run", fake_run):
            testrunner._run_file(
                Path("tests/test_a.capa"), self._tmp, wasm=False,
            )
        return seen["cmd"]

    def test_source_checkout_goes_through_dash_m(self):
        cmd = self._spawned_command(frozen=False)
        self.assertEqual(cmd[:4], ["/opt/capa/capa", "-m", "capa", "--run"])

    def test_frozen_binary_takes_the_arguments_directly(self):
        cmd = self._spawned_command(frozen=True)
        # The exact regression: no `-m` anywhere, because the frozen
        # binary is not an interpreter.
        self.assertNotIn("-m", cmd)
        self.assertEqual(cmd[:2], ["/opt/capa/capa", "--run"])

    def test_frozen_wasm_run_keeps_the_backend_flag(self):
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = cmd
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("capa._selfexec.is_frozen", return_value=True), \
                mock.patch.object(sys, "executable", "/opt/capa/capa"), \
                mock.patch.object(testrunner.subprocess, "run", fake_run):
            testrunner._run_file(
                Path("tests/test_a.capa"), self._tmp, wasm=True,
            )
        self.assertEqual(seen["cmd"][:2], ["/opt/capa/capa", "--wasm"])

    def test_unstartable_child_fails_only_its_own_test(self):
        # Process isolation is the reason each test gets its own
        # process; a child that cannot be started at all must cost one
        # test, not the whole report.
        root = self._project()
        _write(root / "tests" / "test_a.capa", _PASSING)
        _write(root / "tests" / "test_b.capa", _PASSING)
        calls = []
        real_run = testrunner.subprocess.run

        def flaky_run(cmd, **kw):
            calls.append(cmd)
            if len(calls) == 1:
                raise OSError("Too many open files")
            return real_run(cmd, **kw)

        with mock.patch.object(testrunner.subprocess, "run", flaky_run):
            out = io.StringIO()
            rc = testrunner.run_tests(root, out=out, err=out)
        text = out.getvalue()
        self.assertEqual(rc, 1, text)
        self.assertEqual(len(calls), 2, "the second test never ran")
        self.assertIn("could not start the test process", text)
        self.assertIn("2 test(s): 1 passed, 1 failed", text)


class TestSelfExec(unittest.TestCase):
    """The shared seam itself (:mod:`capa._selfexec`), used by both
    ``capa test`` and ``capa --watch``."""

    def test_frozen_detection_reads_sys_frozen(self):
        from capa import _selfexec
        self.assertFalse(_selfexec.is_frozen())
        with mock.patch.object(sys, "frozen", True, create=True):
            self.assertTrue(_selfexec.is_frozen())

    def test_command_forms(self):
        from capa._selfexec import capa_child_command
        with mock.patch.object(sys, "executable", "/usr/bin/python3"):
            self.assertEqual(
                capa_child_command(["--run", "x.capa"]),
                ["/usr/bin/python3", "-m", "capa", "--run", "x.capa"],
            )
            with mock.patch.object(sys, "frozen", True, create=True):
                self.assertEqual(
                    capa_child_command(["--run", "x.capa"]),
                    ["/usr/bin/python3", "--run", "x.capa"],
                )

    def test_watch_uses_the_same_seam(self):
        # --watch carried its own copy of the broken command, so it is
        # pinned here too: one seam, both callers.
        from capa import cli
        target = self._watch_target()
        seen = {}

        def fake_run(cmd, *a, **kw):
            seen["cmd"] = cmd
            raise KeyboardInterrupt

        with mock.patch.object(sys, "frozen", True, create=True), \
                mock.patch.object(sys, "executable", "/opt/capa/capa"), \
                mock.patch.object(cli.subprocess, "run", fake_run), \
                mock.patch.object(sys, "stdout", io.StringIO()):
            rc = cli._run_watch_loop(str(target), [])
        self.assertEqual(rc, 0)
        self.assertNotIn("-m", seen["cmd"])
        self.assertEqual(seen["cmd"][:2], ["/opt/capa/capa", "--run"])

    def _watch_target(self) -> Path:
        tmp = Path(tempfile.mkdtemp(prefix="capa_watch_"))
        self.addCleanup(shutil.rmtree, str(tmp), True)
        target = tmp / "prog.capa"
        target.write_text(_PASSING, encoding="utf-8")
        return target


@unittest.skipUnless(
    _wasm_tooling_available(),
    "wasm-tools + wasmtime not available",
)
class TestCapaTestWasmBackends(_TempProjectMixin, unittest.TestCase):
    """Real Wasm-backed runs: --wasm and the honest --both
    divergence via parse_json's backend-specific error text."""

    def test_wasm_backend_passes(self):
        root = self._project()
        _write(root / "tests" / "test_a.capa", _PASSING)
        rc, out, err = _run_main(["test", "--wasm"], cwd=root)
        self.assertEqual(rc, 0, err + out)
        self.assertIn("[backend: wasm]", out)
        self.assertIn("test_a.capa ... ok", out)

    def test_both_detects_real_backend_divergence(self):
        root = self._project()
        _write(root / "tests" / "test_same.capa", _PASSING)
        _write(root / "tests" / "test_div.capa", _DIVERGING)
        rc, out, err = _run_main(["test", "--both"], cwd=root)
        self.assertEqual(rc, 1, err + out)
        self.assertIn("[backend: python+wasm]", out)
        self.assertIn("test_same.capa ... ok", out)
        self.assertIn("test_div.capa ... DIVERGED", out)
        self.assertIn("--- python backend", out)
        self.assertIn("+++ wasm backend", out)
        self.assertIn("2 test(s): 1 passed, 1 failed (1 diverged)", out)


if __name__ == "__main__":
    unittest.main()
