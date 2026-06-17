"""In-process tests for ``capa.cli``.

The existing ``tests/test_transpiler.py`` suite drives the CLI
through ``subprocess.run``, which means the child process's
coverage data never reaches the parent's coverage instance.
``TestCliInProcess`` calls ``main()`` directly with monkey-patched
``sys.argv`` / ``sys.stdout`` / ``sys.stderr`` so the real argparse
+ dispatch surface registers under the test runner's coverage.

Each test that needs file I/O runs in a fresh
``tempfile.TemporaryDirectory()`` to keep the working tree clean
(and to avoid stepping on the repo's ``capa.toml``-less assumptions
for some CLI paths).
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capa.cli import _wasm_tooling_available, main


class _EnvKeyRemoval:
    """Start/stop patch object that removes an env key for its lifetime
    and restores the prior value on stop. Shaped like the other
    ``mock.patch`` objects so ``_run_main`` can drive it uniformly.
    """

    def __init__(self, key):
        self._key = key
        self._had = False
        self._prev = None

    def start(self):
        self._had = self._key in os.environ
        if self._had:
            self._prev = os.environ.pop(self._key)

    def stop(self):
        if self._had:
            os.environ[self._key] = self._prev
        else:
            os.environ.pop(self._key, None)


def _run_main(argv, stdin=None, cwd=None, env=None):
    """Drive ``main()`` in-process. Returns ``(rc, stdout, stderr)``.

    ``stdin``: optional string fed to ``sys.stdin``.
    ``cwd``: optional directory to ``chdir`` into for the duration
    of the call (restored afterwards).
    ``env``: optional mapping merged into ``os.environ`` for the
    duration of the call. Only the keys supplied are patched; a key
    mapped to ``None`` is removed for the duration (lets a test assert
    behaviour when a variable is *absent*).
    """
    out, err = io.StringIO(), io.StringIO()
    full_argv = ["capa"] + list(argv)
    patches = [
        mock.patch.object(sys, "argv", full_argv),
        mock.patch.object(sys, "stdout", out),
        mock.patch.object(sys, "stderr", err),
    ]
    if stdin is not None:
        patches.append(mock.patch.object(sys, "stdin", io.StringIO(stdin)))
    if env is not None:
        set_keys = {k: v for k, v in env.items() if v is not None}
        del_keys = [k for k, v in env.items() if v is None]
        if set_keys:
            patches.append(mock.patch.dict(os.environ, set_keys, clear=False))
        for k in del_keys:
            patches.append(_EnvKeyRemoval(k))
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


def _write_capa(tmpdir: Path, name: str, contents: str) -> Path:
    p = tmpdir / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(contents, encoding="utf-8")
    return p


_HELLO = (
    'fun main(stdio: Stdio)\n'
    '    stdio.println("Hi")\n'
)


_HELLO_DOC = (
    '/// Demo program.\n'
    'fun main(stdio: Stdio)\n'
    '    stdio.println("Hi")\n'
)


class TestCliInProcess(unittest.TestCase):
    """In-process exercise of ``main()`` across every flag combo
    that can be driven without spinning a subprocess.
    """

    # --- Early-return / meta cases ----------------------------------

    def test_version_prints_and_exits_zero(self):
        rc, out, err = _run_main(["--version"])
        # argparse's ``action="version"`` prints to stdout and calls
        # sys.exit(0); _run_main catches the SystemExit.
        self.assertEqual(rc, 0)
        self.assertIn("capa", (out + err).lower())

    def test_help_prints_usage(self):
        rc, _out, _err = _run_main(["--help"])
        self.assertEqual(rc, 0)
        # argparse writes the help text to stdout; the SystemExit's
        # code is 0 on --help.

    def test_no_args_prints_usage_to_stderr(self):
        rc, _out, err = _run_main([])
        self.assertEqual(rc, 2)
        self.assertIn("usage", err.lower())

    # --- init subcommand --------------------------------------------

    def test_init_in_empty_cwd(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            rc, _out, err = _run_main(["init"], cwd=td_path)
            self.assertEqual(rc, 0, err)
            for name in ("main.capa", "README.md", ".gitignore",
                         ".capa-version"):
                self.assertTrue(
                    (td_path / name).exists(),
                    f"{name} not created",
                )

    def test_init_with_explicit_name(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            rc, _out, _err = _run_main(["init", "myproj"], cwd=td_path)
            self.assertEqual(rc, 0)
            for name in ("main.capa", "README.md"):
                self.assertTrue((td_path / "myproj" / name).exists())

    def test_init_into_non_empty_dir_errors(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            (td_path / "stray.txt").write_text("x", encoding="utf-8")
            rc, _out, err = _run_main(["init"], cwd=td_path)
            self.assertNotEqual(rc, 0)
            self.assertIn("not empty", err.lower())

    # --- --check ----------------------------------------------------

    def test_check_ok(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, err = _run_main(["--check", str(p)], cwd=td_path)
            self.assertEqual(rc, 0, err)
            self.assertIn("ok", out)

    def test_check_parser_error(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            # Unterminated function declaration: syntactically broken.
            p = _write_capa(td_path, "broken.capa", "fun main(\n")
            rc, _out, err = _run_main(["--check", str(p)], cwd=td_path)
            self.assertNotEqual(rc, 0)
            self.assertIn("error", err.lower())

    def test_check_analyser_error(self):
        # Reference to an undeclared identifier triggers the analyser.
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${nope}")\n'
        )
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "bad.capa", src)
            rc, _out, err = _run_main(["--check", str(p)], cwd=td_path)
            self.assertNotEqual(rc, 0)
            self.assertIn("error", err.lower())

    def test_deep_flat_chain_parse_no_traceback(self):
        # A pathological flat chain must yield a clean diagnostic under
        # both --parse and --check, never a raw RecursionError traceback
        # (which the left-deep AST would otherwise trigger in the AST
        # dump and the analyzer's recursive walks).
        n = 3000
        bodies = {
            "binary": "    let x = " + "1+" * n + "1",
            "field": "    let x = a" + ".f" * n,
            "index": "    let x = a" + "[0]" * n,
            "call": "    let x = a" + "()" * n,
            "or": "    let x = a" + " or a" * n,
        }
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            for kind, body in bodies.items():
                src = "fun main()\n" + body + "\n"
                p = _write_capa(td_path, f"deep_{kind}.capa", src)
                for flag in ("--parse", "--check"):
                    with self.subTest(kind=kind, flag=flag):
                        rc, out, err = _run_main([flag, str(p)], cwd=td_path)
                        self.assertNotEqual(rc, 0)
                        self.assertNotIn("Traceback", err)
                        self.assertNotIn("RecursionError", err)
                        self.assertIn("error", err.lower())

    def test_check_missing_file(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            missing = td_path / "no_such.capa"
            rc, _out, err = _run_main(
                ["--check", str(missing)], cwd=td_path,
            )
            self.assertEqual(rc, 2)
            self.assertIn("no_such.capa", err)

    def test_check_via_stdin(self):
        rc, out, err = _run_main(
            ["--check", "--stdin"], stdin=_HELLO,
        )
        self.assertEqual(rc, 0, err)
        self.assertIn("ok", out)

    # --- --transpile ------------------------------------------------

    def test_transpile_emits_python(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, err = _run_main(["--transpile", str(p)], cwd=td_path)
            self.assertEqual(rc, 0, err)
            # Transpiled Python should at minimum mention the runtime
            # import or define main.
            self.assertTrue(
                "def main" in out or "from capa.runtime" in out,
                f"unexpected transpile output: {out[:200]!r}",
            )

    def test_transpile_ir_path(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, err = _run_main(
                ["--transpile", "--ir", str(p)], cwd=td_path,
            )
            self.assertEqual(rc, 0, err)
            self.assertTrue(
                "def main" in out or "from capa.runtime" in out,
                f"unexpected transpile output: {out[:200]!r}",
            )

    # --- --run ------------------------------------------------------

    def test_run_hello(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, err = _run_main(["--run", str(p)], cwd=td_path)
            self.assertEqual(rc, 0, err)
            # The transpiled program writes to the real stdout, which
            # we have replaced with a StringIO buffer, so "Hi" should
            # appear in ``out``.
            self.assertIn("Hi", out)

    def test_run_program_args_via_separator(self):
        # Capa source that inspects env.args() and echoes each one.
        # A for loop is the idiomatic way to walk a List in Capa; we
        # then assert all three values land in stdout.
        src = (
            'fun main(stdio: Stdio, env: Env)\n'
            '    let xs = env.args()\n'
            '    for x in xs\n'
            '        stdio.println("arg=${x}")\n'
        )
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "argc.capa", src)
            rc, out, err = _run_main(
                ["--run", str(p), "--", "alpha", "beta", "gamma"],
                cwd=td_path,
            )
            self.assertEqual(rc, 0, err)
            self.assertIn("arg=alpha", out)
            self.assertIn("arg=beta", out)
            self.assertIn("arg=gamma", out)

    def test_run_propagates_nonzero_exit_code(self):
        # ``exit(2)`` is not a Capa builtin; instead raise an error
        # by referencing a private from another module would require
        # extra files. Easier: trigger a runtime panic via integer
        # division by zero and assert rc != 0.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let x = 1 / 0\n'
            '    stdio.println("${x}")\n'
        )
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "boom.capa", src)
            rc, _out, err = _run_main(["--run", str(p)], cwd=td_path)
            self.assertNotEqual(rc, 0)
            # A traceback or panic message is expected on stderr.
            self.assertTrue(len(err) > 0)

    def test_run_prefer_wasm_flag(self):
        # The flag itself is honoured even when the Wasm path falls
        # back to Python (e.g. because the program uses constructs
        # outside the Phase-6 subset). The CLI's contract is "silent
        # fallback": rc 0, stdout still has the expected output.
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, err = _run_main(
                ["--run", "--prefer-wasm", str(p)], cwd=td_path,
            )
            self.assertEqual(rc, 0, err)
            self.assertIn("Hi", out)

    def test_run_prefer_wasm_env_var(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, err = _run_main(
                ["--run", str(p)],
                cwd=td_path,
                env={"CAPA_PREFER_WASM": "1"},
            )
            self.assertEqual(rc, 0, err)
            self.assertIn("Hi", out)

    def test_run_prefer_wasm_falls_back_when_tooling_missing(self):
        # Force the toolchain probe to report False so we exercise
        # the "skip the Wasm path entirely" branch even on a machine
        # with wasm-tools installed.
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            with mock.patch(
                "capa.cli._wasm_tooling_available", return_value=False,
            ):
                rc, out, err = _run_main(
                    ["--run", "--prefer-wasm", str(p)], cwd=td_path,
                )
            self.assertEqual(rc, 0, err)
            self.assertIn("Hi", out)

    # --- SBOM / artefact emitters -----------------------------------

    def test_manifest_emits_json(self):
        import json
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, err = _run_main(["--manifest", str(p)], cwd=td_path)
            self.assertEqual(rc, 0, err)
            doc = json.loads(out)
            self.assertIsInstance(doc, dict)

    def test_cyclonedx_emits_json(self):
        import json
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, err = _run_main(["--cyclonedx", str(p)], cwd=td_path)
            self.assertEqual(rc, 0, err)
            doc = json.loads(out)
            self.assertEqual(doc.get("bomFormat"), "CycloneDX")

    def test_spdx_emits_json(self):
        import json
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, err = _run_main(["--spdx", str(p)], cwd=td_path)
            self.assertEqual(rc, 0, err)
            doc = json.loads(out)
            self.assertIn("spdxVersion", doc)

    def test_vex_emits_json(self):
        import json
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, err = _run_main(["--vex", str(p)], cwd=td_path)
            self.assertEqual(rc, 0, err)
            doc = json.loads(out)
            self.assertIsInstance(doc, dict)

    def test_provenance_emits_json(self):
        import json
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, err = _run_main(["--provenance", str(p)], cwd=td_path)
            self.assertEqual(rc, 0, err)
            doc = json.loads(out)
            self.assertIn("predicateType", doc)

    def test_doc_emits_html(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO_DOC)
            rc, out, err = _run_main(["--doc", str(p)], cwd=td_path)
            self.assertEqual(rc, 0, err)
            self.assertIn("<html", out.lower())

    def test_wit_emits_text(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, err = _run_main(["--wit", str(p)], cwd=td_path)
            self.assertEqual(rc, 0, err)
            # WIT documents always declare a package or world.
            self.assertTrue(
                "package" in out or "world" in out,
                f"unexpected --wit output: {out[:120]!r}",
            )

    # --- --parse (AST dump) ----------------------------------------

    def test_parse_dumps_ast(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, err = _run_main(["--parse", str(p)], cwd=td_path)
            self.assertEqual(rc, 0, err)
            # The AST dump includes the function name.
            self.assertIn("main", out)

    # --- Formatter --------------------------------------------------

    def test_fmt_rewrites_file(self):
        # Trailing whitespace gets stripped by the formatter.
        src = (
            'fun main(stdio: Stdio)   \n'
            '    stdio.println("Hi")   \n'
        )
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "msgy.capa", src)
            rc, _out, err = _run_main(["--fmt", str(p)], cwd=td_path)
            self.assertEqual(rc, 0, err)
            rewritten = p.read_text(encoding="utf-8")
            # No more trailing whitespace before a newline.
            for line in rewritten.splitlines():
                self.assertEqual(line, line.rstrip())

    def test_fmt_via_stdin_prints_to_stdout(self):
        rc, out, err = _run_main(
            ["--fmt", "--stdin"], stdin="fun main(stdio: Stdio)   \n",
        )
        self.assertEqual(rc, 0, err)
        # Output goes to stdout, trailing whitespace removed.
        for line in out.splitlines():
            self.assertEqual(line, line.rstrip())

    def test_fmt_check_ok_when_canonical(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "ok.capa", _HELLO)
            rc, _out, _err = _run_main(["--fmt-check", str(p)], cwd=td_path)
            self.assertEqual(rc, 0)

    def test_fmt_check_fails_when_not_canonical(self):
        src = 'fun main(stdio: Stdio)   \n    stdio.println("Hi")   \n'
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "dirty.capa", src)
            rc, _out, err = _run_main(["--fmt-check", str(p)], cwd=td_path)
            self.assertEqual(rc, 1)
            self.assertIn("canonical", err.lower())

    # --- Default token-dump path -----------------------------------

    def test_default_token_dump(self):
        # No flag at all: the CLI dumps the lex stream.
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, _err = _run_main([str(p)], cwd=td_path)
            self.assertEqual(rc, 0)
            # KW_FUN appears once for ``fun main`` and IDENT for the
            # identifier ``main``.
            self.assertIn("KW_FUN", out)
            self.assertIn("IDENT", out)

    def test_default_token_dump_no_layout(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, _err = _run_main(
                [str(p), "--no-layout"], cwd=td_path,
            )
            self.assertEqual(rc, 0)
            # Layout kinds should not appear.
            for kind in ("NEWLINE", "INDENT", "DEDENT", "EOF"):
                self.assertNotIn(kind, out)

    # --- --wasm (conditional) ---------------------------------------

    @unittest.skipUnless(
        _wasm_tooling_available(),
        "wasm-tools / wasmtime missing",
    )
    def test_wasm_transpile_emits_wat(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, err = _run_main(
                ["--wasm", "--transpile", str(p)], cwd=td_path,
            )
            self.assertEqual(rc, 0, err)
            # WAT modules open with ``(module``.
            self.assertIn("(module", out)

    @unittest.skipUnless(
        _wasm_tooling_available(),
        "wasm-tools / wasmtime missing",
    )
    def test_wasm_output_writes_core_module(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            out_path = td_path / "core.wasm"
            rc, _out, err = _run_main(
                ["--wasm", "-o", str(out_path), str(p)], cwd=td_path,
            )
            self.assertEqual(rc, 0, err)
            self.assertTrue(out_path.exists())
            blob = out_path.read_bytes()
            # Wasm binaries start with the magic \0asm.
            self.assertEqual(blob[:4], b"\x00asm")

    @unittest.skipUnless(
        _wasm_tooling_available(),
        "wasm-tools / wasmtime missing",
    )
    def test_wasm_output_writes_component(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            out_path = td_path / "component.wasm"
            rc, _out, err = _run_main(
                ["--wasm", "--component", "-o", str(out_path), str(p)],
                cwd=td_path,
            )
            self.assertEqual(rc, 0, err)
            self.assertTrue(out_path.exists())
            # Component still has the \0asm magic at the head.
            self.assertEqual(out_path.read_bytes()[:4], b"\x00asm")

    # --- Error / edge cases ----------------------------------------

    def test_unknown_flag_errors(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, _out, err = _run_main(
                ["--nope", str(p)], cwd=td_path,
            )
            self.assertEqual(rc, 2)
            self.assertIn("unrecognized", err.lower())

    def test_watch_without_file_errors(self):
        rc, _out, err = _run_main(["--watch"])
        self.assertEqual(rc, 2)
        self.assertIn("--watch", err)

    # --- Subcommand smoke-tests ------------------------------------

    def test_repl_subcommand_dispatches_to_serve(self):
        with mock.patch("capa.repl.serve", return_value=0) as serve_mock:
            rc, _out, _err = _run_main(["repl"])
        self.assertEqual(rc, 0)
        serve_mock.assert_called_once()

    def test_lsp_subcommand_dispatches_to_serve(self):
        with mock.patch("capa.lsp_server.serve", return_value=0) as serve_mock:
            rc, _out, _err = _run_main(["lsp"])
        self.assertEqual(rc, 0)
        serve_mock.assert_called_once()

    # --- install subcommand ----------------------------------------

    def test_install_subcommand_success(self):
        # Mock ``capa.pkg.install`` so we exercise the dispatcher
        # without touching git or the filesystem.
        fake_manifest = mock.MagicMock(
            name="manifest", dependencies=[],
            name_=None,
        )
        fake_manifest.name = "demo"
        fake_manifest.version = "0.1.0"
        with mock.patch("capa.pkg.install", return_value=fake_manifest):
            rc, out, _err = _run_main(["install", "."])
        self.assertEqual(rc, 0)
        self.assertIn("demo", out)
        self.assertIn("0.1.0", out)

    def test_install_subcommand_propagates_install_error(self):
        from capa.pkg import InstallError
        with mock.patch(
            "capa.pkg.install",
            side_effect=InstallError("git fetch failed"),
        ):
            rc, _out, err = _run_main(["install", "."])
        self.assertEqual(rc, 2)
        self.assertIn("git fetch failed", err)

    # --- _capa_search_paths integration ----------------------------

    def test_capa_path_env_var_is_consulted(self):
        # Put a tiny ``util`` module on disk, point CAPA_PATH at its
        # parent, and run a root file that imports it. If CAPA_PATH
        # is wired through correctly, the loader resolves the
        # import.
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            libs = td_path / "libs"
            libs.mkdir()
            _write_capa(
                libs, "util.capa",
                "pub fun bump(n: Int) -> Int\n    return n + 1\n",
            )
            root = _write_capa(
                td_path, "root.capa",
                "import util\n"
                "fun main(stdio: Stdio)\n"
                '    stdio.println("${bump(2)}")\n',
            )
            rc, out, err = _run_main(
                ["--run", str(root)],
                cwd=td_path,
                env={"CAPA_PATH": str(libs)},
            )
            self.assertEqual(rc, 0, err)
            self.assertIn("3", out)

    def test_libraries_fallback_dir_is_consulted(self):
        # Same shape as the CAPA_PATH test but resolved through the
        # conventional ``./libraries`` fallback.
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            libs = td_path / "libraries"
            libs.mkdir()
            _write_capa(
                libs, "util.capa",
                "pub fun bump(n: Int) -> Int\n    return n + 1\n",
            )
            root = _write_capa(
                td_path, "root.capa",
                "import util\n"
                "fun main(stdio: Stdio)\n"
                '    stdio.println("${bump(2)}")\n',
            )
            rc, out, err = _run_main(["--run", str(root)], cwd=td_path)
            self.assertEqual(rc, 0, err)
            self.assertIn("3", out)

    # --- --wasm --run (full pipeline, when toolchain available) ----

    @unittest.skipUnless(
        _wasm_tooling_available(),
        "wasm-tools / wasmtime missing",
    )
    def test_wasm_run_executes_program(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, err = _run_main(
                ["--wasm", "--run", str(p)], cwd=td_path,
            )
            self.assertEqual(rc, 0, err)
            self.assertIn("Hi", out)

    # --- color_for helper -----------------------------------------

    def test_color_for_covers_token_kind_branches(self):
        # The CLI's coloured-output branch (when stdout is a TTY)
        # routes every TokenKind through ``color_for``. The helper
        # is otherwise unreachable under captured stdio.
        from capa.cli import C, color_for
        from capa.tokens import TokenKind

        # KW_*, layout, INT_LIT/FLOAT_LIT, STRING_LIT/CHAR_LIT,
        # IDENT, and the catch-all all map to a known color code.
        self.assertEqual(color_for(TokenKind.KW_FUN), C.MAGENTA)
        self.assertEqual(color_for(TokenKind.INDENT), C.GRAY)
        self.assertEqual(color_for(TokenKind.INT_LIT), C.CYAN)
        self.assertEqual(color_for(TokenKind.STRING_LIT), C.GREEN)
        self.assertEqual(color_for(TokenKind.IDENT), C.BLUE)
        # Catch-all: an operator-like kind falls through to YELLOW.
        self.assertEqual(color_for(TokenKind.PLUS), C.YELLOW)

    def test_default_token_dump_colored_branch(self):
        # Pretend the captured stdout is a TTY so the
        # ``use_color`` branch in the token-dump loop runs.
        # ``io.StringIO`` is immutable in CPython 3.14, so we use a
        # tiny subclass that reports ``isatty() == True`` instead.

        class _TtyBuf(io.StringIO):
            def isatty(self):  # noqa: D401
                return True

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            out, err = _TtyBuf(), io.StringIO()
            with mock.patch.object(sys, "argv", ["capa", str(p)]), \
                 mock.patch.object(sys, "stdout", out), \
                 mock.patch.object(sys, "stderr", err):
                original_cwd = os.getcwd()
                try:
                    os.chdir(str(td_path))
                    rc = main()
                finally:
                    os.chdir(original_cwd)
            self.assertEqual(rc, 0)
            # ANSI escape sequences must appear in the output.
            self.assertIn("\x1b[", out.getvalue())

    # --- --ir fallback ---------------------------------------------

    def test_ir_falls_back_to_legacy_on_unsupported(self):
        # When CIR rejects a construct, the legacy transpiler takes
        # over and a yellow stderr breadcrumb is emitted. We force
        # the unsupported branch by patching ``compile_program`` to
        # raise.
        from capa.ir import UnsupportedInIR
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            with mock.patch(
                "capa.ir.compile_program",
                side_effect=UnsupportedInIR("forced for test"),
            ):
                rc, out, err = _run_main(
                    ["--transpile", "--ir", str(p)], cwd=td_path,
                )
            self.assertEqual(rc, 0, err)
            self.assertIn("falling back to legacy", err)
            # The legacy transpiler still produced Python.
            self.assertTrue("def main" in out or "from capa.runtime" in out)

    # --- --wit error path ------------------------------------------

    def test_wit_error_path(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            with mock.patch(
                "capa.ir.compile_wit",
                side_effect=RuntimeError("forced wit failure"),
            ):
                rc, _out, err = _run_main(
                    ["--wit", str(p)], cwd=td_path,
                )
            self.assertEqual(rc, 1)
            self.assertIn("forced wit failure", err)

    # --- --run program SystemExit code shapes ----------------------

    def test_run_propagates_int_exit_code(self):
        # ``import sys`` is not in Capa; use a recursion-induced
        # Python-level RuntimeError instead. The simpler path is to
        # patch ``exec`` so we control the exception shape.
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            # The exec call inside main() is the one in the local
            # scope; patch builtins.exec so the in-process run
            # raises SystemExit(7).
            import builtins
            real_exec = builtins.exec

            def fake_exec(*args, **kwargs):
                raise SystemExit(7)

            with mock.patch.object(builtins, "exec", fake_exec):
                try:
                    rc, _out, _err = _run_main(
                        ["--run", str(p)], cwd=td_path,
                    )
                finally:
                    builtins.exec = real_exec
            self.assertEqual(rc, 7)

    def test_run_propagates_string_exit_code(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            import builtins
            real_exec = builtins.exec

            def fake_exec(*args, **kwargs):
                raise SystemExit("user-message")

            with mock.patch.object(builtins, "exec", fake_exec):
                try:
                    rc, _out, err = _run_main(
                        ["--run", str(p)], cwd=td_path,
                    )
                finally:
                    builtins.exec = real_exec
            self.assertEqual(rc, 1)
            self.assertIn("user-message", err)

    # --- install: missing pkg subsystem ----------------------------

    def test_install_import_error(self):
        # Force the ``from capa.pkg import ...`` inside the
        # dispatcher to raise so the ImportError branch runs.
        real_import = __import__

        def fake_import(name, *args, **kwargs):
            if name == "capa.pkg":
                raise ImportError("pkg subsystem absent")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=fake_import):
            rc, _out, err = _run_main(["install", "."])
        self.assertEqual(rc, 2)
        self.assertIn("pkg subsystem absent", err)

    # --- capa.toml integration in _capa_search_paths --------------

    def test_capa_toml_with_path_dependency_is_consulted(self):
        # Drop a tiny capa.toml with a path dep so the manifest
        # branch in ``_capa_search_paths`` runs. The CLI adds the
        # **parent** of the resolved dep path to the loader's
        # search roots, so we put the module under
        # ``deps/util.capa`` and point the dep at ``deps/util``.
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            deps_dir = td_path / "deps"
            deps_dir.mkdir()
            _write_capa(
                deps_dir, "util.capa",
                "pub fun bump(n: Int) -> Int\n    return n + 1\n",
            )
            (td_path / "capa.toml").write_text(
                '[package]\n'
                'name = "demo"\n'
                'version = "0.1.0"\n'
                '\n'
                '[dependencies.util]\n'
                'path = "deps/util"\n',
                encoding="utf-8",
            )
            root = _write_capa(
                td_path, "root.capa",
                "import util\n"
                "fun main(stdio: Stdio)\n"
                '    stdio.println("${bump(2)}")\n',
            )
            rc, out, err = _run_main(["--run", str(root)], cwd=td_path)
            self.assertEqual(rc, 0, err)
            self.assertIn("3", out)

    def test_broken_capa_toml_emits_warning_but_keeps_running(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            (td_path / "capa.toml").write_text(
                "this is not valid toml: [\n", encoding="utf-8",
            )
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, _out, err = _run_main(
                ["--check", str(p)], cwd=td_path,
            )
            self.assertEqual(rc, 0)
            self.assertIn("ignoring capa.toml", err)

    # --- --wasm --component --run ----------------------------------

    @unittest.skipUnless(
        _wasm_tooling_available(),
        "wasm-tools / wasmtime missing",
    )
    def test_wasm_component_run_executes_program(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", _HELLO)
            rc, out, err = _run_main(
                ["--wasm", "--run", "--component", str(p)],
                cwd=td_path,
            )
            self.assertEqual(rc, 0, err)
            self.assertIn("Hi", out)

    @unittest.skipUnless(
        _wasm_tooling_available(),
        "wasm-tools / wasmtime missing",
    )
    def test_wasm_compile_error_returns_nonzero(self):
        # An unrenderable interpolation (``${xs}`` where ``xs`` is a
        # nested List, which has no to_string) is now rejected at the
        # analysis stage, in BOTH backends, rather than only by the
        # Wasm emitter. The CLI must return non-zero with a clear
        # "cannot interpolate" diagnostic; the rejection no longer
        # carries a "--wasm" tag because it fires before backend
        # selection (that is the whole point of closing the
        # divergence).
        src = (
            'fun main(stdio: Stdio)\n'
            '    let xs: List<List<Int>> = []\n'
            '    stdio.println("${xs}")\n'
        )
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "deep.capa", src)
            rc, _out, err = _run_main(
                ["--wasm", "--transpile", str(p)], cwd=td_path,
            )
            self.assertNotEqual(rc, 0, err)
            self.assertIn("cannot interpolate", err)


class TestCliRobustness(unittest.TestCase):
    """Audit slice 30: malformed-input and bad-flag-combo robustness.
    Each was a verified crash / wrong-exit / corrupted-output before
    the fix."""

    def test_non_utf8_file_clean_error(self):
        # P1-b: a binary / non-UTF-8 file is a user error (exit 2 +
        # clean message), not a UnicodeDecodeError traceback.
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bin.capa"
            p.write_bytes(b"\xff\xfe\x00bad")
            rc, _out, err = _run_main([str(p)])
            self.assertEqual(rc, 2, err)
            self.assertIn("not valid UTF-8", err)
            self.assertNotIn("Traceback", err)

    def test_non_utf8_file_clean_error_migrate(self):
        # P1-b: same guard on the migrate dispatcher's read_text.
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bin.capa"
            p.write_bytes(b"\xff\xfe\x00bad")
            rc, _out, err = _run_main(["migrate", str(p)])
            self.assertEqual(rc, 2, err)
            self.assertIn("not valid UTF-8", err)
            self.assertNotIn("Traceback", err)

    def test_wasm_memory_cap_over_range_rejected(self):
        # P2-b: a cap above the wasm32 page limit used to write an
        # invalid module with exit 0; now it's rejected up front and
        # no artifact is written.
        with tempfile.TemporaryDirectory() as td:
            src = _write_capa(
                Path(td), "m.capa",
                'fun main(stdio: Stdio)\n    stdio.println("hi")\n',
            )
            out_wasm = Path(td) / "out.wasm"
            rc, _out, err = _run_main([
                str(src), "--wasm", "--output", str(out_wasm),
                "--wasm-memory-cap", "999999999999",
            ])
            self.assertEqual(rc, 2, err)
            self.assertIn("--wasm-memory-cap", err)
            self.assertFalse(
                out_wasm.exists(),
                "invalid .wasm must not be written when the cap is "
                "rejected",
            )

    def test_token_dump_no_crash_on_literal(self):
        # P1-a: the dump's arrow glyph crashed on a cp1252 redirect.
        # In-process stdout is a StringIO (unicode), so this checks
        # the dump path runs cleanly and includes the literal value;
        # the reconfigure guard handles the real-stream case.
        with tempfile.TemporaryDirectory() as td:
            src = _write_capa(
                Path(td), "lit.capa",
                'fun main(stdio: Stdio)\n    let x = 42\n'
                '    stdio.println("hi")\n',
            )
            rc, out, err = _run_main([str(src)])
            self.assertEqual(rc, 0, err)
            self.assertIn("INT_LIT", out)


class TestWarningDiagnostics(unittest.TestCase):
    """Analyzer warnings on the CLI: printed to stderr with 'warning'
    severity, never changing the exit code. The dead-Unsafe migrate
    nudge is the first such lint."""

    DEAD_UNSAFE = "fun helper(_u: Unsafe) -> Int\n    return 1\n"

    def test_check_with_warning_only_exits_zero(self):
        with tempfile.TemporaryDirectory() as td:
            src = _write_capa(Path(td), "warn.capa", self.DEAD_UNSAFE)
            rc, out, err = _run_main(["--check", str(src)])
            self.assertEqual(rc, 0, err)
            self.assertIn("ok", out)
            self.assertIn("warning:", err)
            self.assertIn("'_u: Unsafe'", err)
            self.assertNotIn("error:", err)

    def test_run_with_warning_only_exits_zero(self):
        with tempfile.TemporaryDirectory() as td:
            src = _write_capa(
                Path(td), "warn_run.capa",
                self.DEAD_UNSAFE
                + "\nfun main(stdio: Stdio)\n    stdio.println(\"hi\")\n",
            )
            rc, out, err = _run_main(["--run", str(src)])
            self.assertEqual(rc, 0, err)
            self.assertIn("hi", out)
            self.assertIn("warning:", err)

    def test_error_suppresses_lint_and_dominates_exit(self):
        # When the module has errors the lint phase is skipped: the
        # CLI prints only the error (advice about a program that does
        # not compile would be misleading) and exits non-zero.
        with tempfile.TemporaryDirectory() as td:
            src = _write_capa(
                Path(td), "warn_err.capa",
                self.DEAD_UNSAFE
                + "\nfun broken() -> Int\n    return missing_name\n",
            )
            rc, _out, err = _run_main(["--check", str(src)])
            self.assertEqual(rc, 1)
            self.assertIn("error:", err)
            self.assertNotIn("warning:", err)


_VEX_PROGRAM = (
    '@vex(cve: "CVE-X", status: "not_affected", '
    'justification: "code_not_reachable")\n'
    'fun helper(s: String) -> String\n'
    '    return s\n'
    'fun main(stdio: Stdio)\n'
    '    stdio.println("Hi")\n'
)

# A single arbitrary instant: 2021-01-01T00:00:00Z.
_FIXED_EPOCH = "1609459200"
_FIXED_TIMESTAMP = "2021-01-01T00:00:00Z"

_ARTEFACT_MODES = ["--cyclonedx", "--spdx", "--vex", "--provenance"]


class TestSbomReproducibility(unittest.TestCase):
    """SOURCE_DATE_EPOCH makes every SBOM/attestation byte-reproducible.

    With the env var set, a rebuild of the same source produces the
    four artefacts byte-for-byte identical (rebuild and diff); the
    only previously non-deterministic field, the build timestamp,
    derives from the epoch. Unset, the emitters keep wall-clock time.
    An invalid value is a hard error, never a silent fallback.
    """

    def _emit(self, mode, env, program=_VEX_PROGRAM):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p = _write_capa(td_path, "hello.capa", program)
            return _run_main([mode, str(p)], cwd=td_path, env=env)

    def test_fixed_epoch_is_byte_reproducible(self):
        # Two independent builds with the same SOURCE_DATE_EPOCH yield
        # byte-identical output for every artefact.
        env = {"SOURCE_DATE_EPOCH": _FIXED_EPOCH}
        for mode in _ARTEFACT_MODES:
            rc1, out1, err1 = self._emit(mode, env)
            rc2, out2, err2 = self._emit(mode, env)
            self.assertEqual(rc1, 0, err1)
            self.assertEqual(rc2, 0, err2)
            self.assertEqual(out1, out2, f"{mode} not byte-reproducible")

    def test_fixed_epoch_timestamp_matches(self):
        # The emitted build timestamp is exactly the epoch instant.
        import json
        env = {"SOURCE_DATE_EPOCH": _FIXED_EPOCH}
        rc, out, err = self._emit("--cyclonedx", env)
        self.assertEqual(rc, 0, err)
        self.assertEqual(
            json.loads(out)["metadata"]["timestamp"], _FIXED_TIMESTAMP
        )

        rc, out, err = self._emit("--spdx", env)
        self.assertEqual(rc, 0, err)
        self.assertEqual(
            json.loads(out)["creationInfo"]["created"], _FIXED_TIMESTAMP
        )

        rc, out, err = self._emit("--vex", env)
        self.assertEqual(rc, 0, err)
        doc = json.loads(out)
        self.assertEqual(doc["metadata"]["timestamp"], _FIXED_TIMESTAMP)
        self.assertEqual(
            doc["vulnerabilities"][0]["analysis"]["firstIssued"],
            _FIXED_TIMESTAMP,
        )

        rc, out, err = self._emit("--provenance", env)
        self.assertEqual(rc, 0, err)
        meta = json.loads(out)["predicate"]["runDetails"]["metadata"]
        self.assertEqual(meta["startedOn"], _FIXED_TIMESTAMP)
        self.assertEqual(meta["finishedOn"], _FIXED_TIMESTAMP)

    def test_unset_keeps_real_time_and_stays_well_formed(self):
        # Without the env var the artefacts still emit cleanly; we do
        # not pin the timestamp, only confirm the rest is sound.
        import json
        env = {"SOURCE_DATE_EPOCH": None}  # explicitly absent
        rc, out, err = self._emit("--cyclonedx", env)
        self.assertEqual(rc, 0, err)
        doc = json.loads(out)
        self.assertEqual(doc["bomFormat"], "CycloneDX")
        # A plausible ISO-8601 UTC timestamp, not the empty default.
        self.assertRegex(
            doc["metadata"]["timestamp"],
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
        )

    def test_invalid_epoch_errors_in_every_mode(self):
        # Garbage -> a clear error and a non-zero exit in all four
        # modes, never a silent wall-clock fallback.
        env = {"SOURCE_DATE_EPOCH": "not-a-number"}
        for mode in _ARTEFACT_MODES:
            rc, out, err = self._emit(mode, env)
            self.assertEqual(rc, 2, f"{mode} should reject bad epoch")
            self.assertEqual(out, "")
            self.assertIn("SOURCE_DATE_EPOCH", err)

    def test_negative_epoch_errors(self):
        env = {"SOURCE_DATE_EPOCH": "-1"}
        rc, out, err = self._emit("--provenance", env)
        self.assertEqual(rc, 2)
        self.assertIn("SOURCE_DATE_EPOCH", err)

    def test_out_of_range_epoch_errors_cleanly_in_every_mode(self):
        # A non-negative integer that is nonetheless out of the
        # representable date range used to reach datetime and raise an
        # uncaught OverflowError (a raw traceback, exit non-clean). It
        # must now be a controlled non-zero exit in all four modes,
        # exactly like other invalid values.
        env = {"SOURCE_DATE_EPOCH": "99999999999999999999"}
        for mode in _ARTEFACT_MODES:
            rc, out, err = self._emit(mode, env)
            self.assertEqual(rc, 2, f"{mode} should reject huge epoch")
            self.assertEqual(out, "")
            self.assertIn("SOURCE_DATE_EPOCH", err)

    def test_deterministic_identifiers_unaffected_by_epoch(self):
        # The source-derived identifiers (serialNumber, etc.) were
        # already deterministic; they must stay stable whether or not
        # SOURCE_DATE_EPOCH is set, and across two epochs.
        import json
        env_a = {"SOURCE_DATE_EPOCH": _FIXED_EPOCH}
        env_b = {"SOURCE_DATE_EPOCH": "1700000000"}
        env_none = {"SOURCE_DATE_EPOCH": None}

        serials = set()
        namespaces = set()
        invocations = set()
        for env in (env_a, env_b, env_none):
            rc, out, _ = self._emit("--cyclonedx", env)
            self.assertEqual(rc, 0)
            serials.add(json.loads(out)["serialNumber"])
            rc, out, _ = self._emit("--spdx", env)
            self.assertEqual(rc, 0)
            namespaces.add(json.loads(out)["documentNamespace"])
            rc, out, _ = self._emit("--provenance", env)
            self.assertEqual(rc, 0)
            invocations.add(
                json.loads(out)["predicate"]["runDetails"]
                ["metadata"]["invocationId"]
            )
        self.assertEqual(len(serials), 1)
        self.assertEqual(len(namespaces), 1)
        self.assertEqual(len(invocations), 1)


# A deliberately rich program for the cross-process reproducibility
# guard below. It exercises every serialisation path whose ordering a
# stray ``set`` iteration could perturb: several functions, two
# user-defined capabilities each with multiple implementors,
# cap-bearing structs (so transitively_reachable_capabilities is
# non-trivial), functions that provably exclude built-in caps, a
# declassification site, and a @vex annotation (so the VEX/CycloneDX
# firstIssued path is exercised). Implementors and built-in caps are
# declared out of alphabetical order so any unsorted iteration would
# surface as a seed-dependent ordering difference.
_RICH_PROGRAM = (
    'capability Logger\n'
    '    fun log(self, msg: String) -> Bool\n'
    'capability Mailer\n'
    '    fun send(self, to: String) -> Bool\n'
    'type ZSink { out: Stdio }\n'
    'type ASink { out: Stdio }\n'
    'type MSink { sock: Net }\n'
    'type SmtpMailer { sock: Net }\n'
    'type FileMailer { disk: Fs }\n'
    'impl Logger for ZSink\n'
    '    fun log(self, msg: String) -> Bool\n'
    '        self.out.println(msg)\n'
    '        return true\n'
    'impl Logger for ASink\n'
    '    fun log(self, msg: String) -> Bool\n'
    '        self.out.println(msg)\n'
    '        return true\n'
    'impl Logger for MSink\n'
    '    fun log(self, msg: String) -> Bool\n'
    '        return true\n'
    'impl Mailer for SmtpMailer\n'
    '    fun send(self, to: String) -> Bool\n'
    '        return true\n'
    'impl Mailer for FileMailer\n'
    '    fun send(self, to: String) -> Bool\n'
    '        return true\n'
    '@vex(cve: "CVE-9999-0001", status: "not_affected", '
    'justification: "code_not_reachable")\n'
    'fun audit(token: @secret String, stdio: Stdio)\n'
    '    stdio.println(declassify(token, reason: "audited"))\n'
    'fun broadcast(lg: Logger, m: Mailer) -> Bool\n'
    '    return lg.log("x")\n'
    'fun pure_calc(n: Int) -> Int\n'
    '    return n + 1\n'
    'fun main(stdio: Stdio)\n'
    '    stdio.println("hi")\n'
)


class TestCrossProcessSeedReproducibility(unittest.TestCase):
    """The central promise is byte-identity *across machines*, and the
    sharpest proxy for that within one machine is byte-identity across
    *processes* with a different ``PYTHONHASHSEED``. Set iteration order
    is hash-seed-dependent, so a regression that serialised a ``set``
    without sorting would diverge between two seeds here while passing
    every same-process determinism test. This is the guard against that.

    Each artefact is generated in a fresh subprocess (``python -m capa``)
    so the hash seed genuinely differs between runs, over the rich
    program above and with ``SOURCE_DATE_EPOCH`` pinned.
    """

    def _emit_in_subprocess(self, mode, seed, path):
        import os as _os
        import subprocess
        import sys as _sys
        env = dict(_os.environ)
        env["PYTHONHASHSEED"] = str(seed)
        env["SOURCE_DATE_EPOCH"] = _FIXED_EPOCH
        proc = subprocess.run(
            [_sys.executable, "-m", "capa", mode, str(path)],
            capture_output=True, text=True, env=env,
            cwd=str(Path(path).parent),
        )
        self.assertEqual(
            proc.returncode, 0,
            f"{mode} seed={seed} failed: {proc.stderr}",
        )
        return proc.stdout

    def test_artefacts_byte_identical_across_hash_seeds(self):
        with tempfile.TemporaryDirectory() as td:
            p = _write_capa(Path(td), "rich.capa", _RICH_PROGRAM)
            for mode in _ARTEFACT_MODES:
                out0 = self._emit_in_subprocess(mode, 0, p)
                out1 = self._emit_in_subprocess(mode, 1, p)
                self.assertEqual(
                    out0, out1,
                    f"{mode} differs between PYTHONHASHSEED 0 and 1",
                )
                # Guard against a degenerate pass: the run must have
                # produced real artefact content, not an empty string.
                self.assertTrue(out0.strip(), f"{mode} produced no output")


_ARTEFACT_MODES_LF = ["--manifest", *_ARTEFACT_MODES]


class _FakeWindowsStdout:
    """A stand-in for ``sys.stdout`` that reproduces Windows text-mode
    newline translation on a Linux runner.

    The real ``sys.stdout`` on Windows is a text stream in text mode:
    its ``.write(text)`` rewrites every ``\n`` to ``\r\n`` before the
    bytes reach the OS, while its binary ``.buffer.write(bytes)`` does
    no translation at all. We model both halves explicitly:

    * ``.write(text)`` CRLF-translates, then encodes to the captured
      byte sink (what a naive ``print()`` would do, and the source of
      the cross-OS divergence this fix targets).
    * ``.buffer`` is a raw byte sink that writes through verbatim.

    A test can then assert that the artefact path wrote through
    ``.buffer`` (LF-clean) rather than through ``.write`` (CRLF). This
    is the property that genuinely fails on Windows; modelling the
    translation here lets a Linux CI reproduce it.
    """

    def __init__(self):
        self.buffer = io.BytesIO()
        self.encoding = "utf-8"

    def write(self, text):
        # Mimic os.linesep translation of a Windows text stream.
        self.buffer.write(text.replace("\n", "\r\n").encode("utf-8"))
        return len(text)

    def flush(self):
        pass

    def reconfigure(self, *args, **kwargs):
        # main() calls sys.stdout.reconfigure(); the real Windows text
        # stream accepts it and stays in text mode (still translating).
        pass

    def isatty(self):
        return False

    def getbytes(self):
        return self.buffer.getvalue()


class TestArtefactNewlinesAreLfCanonical(unittest.TestCase):
    """The verifiable artefacts emit LF newlines on every OS.

    The reproducibility promise ("rebuild on any machine and diff
    byte-for-byte") is broken if the same artefact leaves Windows as
    CRLF and Linux as LF. CI runs on Linux, where ``\n`` is already
    ``\n``, so a naive stdout-capture test cannot see the regression.
    These tests instead drive the real emission path through a stdout
    double that reproduces Windows text-mode translation, then inspect
    the raw bytes: a ``\n`` in the artefact must never reach the sink
    as ``\r\n``.
    """

    def _emit_to_fake_windows(self, mode, program=_VEX_PROGRAM):
        """Drive the real ``main()`` for *mode* against a stdout that
        translates newlines like Windows, and return the raw bytes
        that reached the byte sink."""
        fake = _FakeWindowsStdout()
        with tempfile.TemporaryDirectory() as td:
            p = _write_capa(Path(td), "hello.capa", program)
            full_argv = ["capa", mode, str(p)]
            with mock.patch.object(sys, "argv", full_argv), \
                    mock.patch.object(sys, "stdout", fake), \
                    mock.patch.object(sys, "stderr", io.StringIO()):
                original_cwd = os.getcwd()
                try:
                    os.chdir(td)
                    rc = main()
                finally:
                    os.chdir(original_cwd)
        return rc, fake.getbytes()

    def test_negative_control_naive_print_would_emit_crlf(self):
        # Sanity-check the fixture itself: a plain text-stream write
        # through the Windows double DOES introduce CR. If this ever
        # stops holding, the assertions below would pass vacuously.
        fake = _FakeWindowsStdout()
        fake.write("a\nb\n")
        self.assertIn(b"\r\n", fake.getbytes())

    def test_every_artefact_mode_emits_lf_only(self):
        # The load-bearing assertion: across all five reproducible
        # artefacts, the bytes that reach the sink carry LF and never a
        # CR, even though the sink would have CRLF-translated any text
        # written through the text layer.
        for mode in _ARTEFACT_MODES_LF:
            rc, raw = self._emit_to_fake_windows(mode)
            self.assertEqual(rc, 0, f"{mode} failed")
            self.assertIn(b"\n", raw, f"{mode} produced no newline")
            self.assertNotIn(
                b"\r", raw,
                f"{mode} leaked a CR: artefact is not LF-canonical, so "
                f"it would not be byte-identical between Windows and Linux",
            )

    def test_emitted_bytes_decode_to_expected_json(self):
        # The LF bytes still decode to the same JSON the text path
        # would have produced (we did not corrupt the payload, only the
        # line endings).
        import json
        rc, raw = self._emit_to_fake_windows("--cyclonedx")
        self.assertEqual(rc, 0)
        doc = json.loads(raw.decode("utf-8"))
        self.assertEqual(doc["bomFormat"], "CycloneDX")


class TestEmitArtifactHelper(unittest.TestCase):
    """Unit-level proof of the emission helper in isolation."""

    def test_writes_through_binary_buffer_bypassing_text_translation(self):
        from capa._artifact_io import emit_artifact
        fake = _FakeWindowsStdout()
        emit_artifact("{\n  \"a\": 1\n}", stream=fake)
        raw = fake.getbytes()
        self.assertNotIn(b"\r", raw)
        self.assertEqual(raw, b'{\n  "a": 1\n}\n')

    def test_canonicalizes_preexisting_crlf_in_content(self):
        # Content that itself carries CRLF (e.g. a file name copied
        # from a CRLF source) is normalised to LF, so the byte stream
        # is LF-only regardless of input.
        from capa._artifact_io import emit_artifact
        fake = _FakeWindowsStdout()
        emit_artifact("line1\r\nline2\rline3", stream=fake)
        self.assertEqual(fake.getbytes(), b"line1\nline2\nline3\n")

    def test_stringio_fallback_keeps_lf(self):
        # A stream without a .buffer (the StringIO under the test
        # harness) gets the canonicalised text, still LF.
        from capa._artifact_io import emit_artifact
        sink = io.StringIO()
        emit_artifact("a\r\nb", stream=sink)
        self.assertEqual(sink.getvalue(), "a\nb\n")


def _has_git() -> bool:
    try:
        return subprocess.run(
            ["git", "--version"], capture_output=True, text=True,
        ).returncode == 0
    except FileNotFoundError:
        return False


@unittest.skipUnless(_has_git(), "git not on PATH")
class TestVendorVerificationOnBuild(unittest.TestCase):
    """PKG-1: end-to-end wiring of build-time vendor verification.

    Builds a real project with a git dependency vendored from a local
    repo, a coherent capa.lock, and a root file that imports it, then
    drives ``capa --run`` (the production path that goes through
    ``_capa_search_paths``). Tampering with vendor/<name>'s HEAD must
    make the build refuse; the opt-out must let it through."""

    _GIT_ENV = {
        "GIT_AUTHOR_NAME": "capa-test",
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "capa-test",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
    }

    def _git(self, repo: Path, *args: str) -> str:
        r = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True, text=True, encoding="utf-8",
            env={**os.environ, **self._GIT_ENV},
        )
        if r.returncode != 0:
            raise RuntimeError(f"git {args}: {r.stderr}")
        return r.stdout.strip()

    def _build_project(self, td_path: Path) -> tuple[Path, Path, str]:
        """Create an upstream git repo (a Capa lib), vendor it into a
        project at the right commit, write a coherent capa.lock and a
        root program that imports it. Returns (project, root_file,
        head_sha)."""
        upstream = td_path / "upstream"
        upstream.mkdir()
        self._git(upstream, "init", "-b", "main")
        (upstream / "util.capa").write_text(
            "pub fun bump(n: Int) -> Int\n    return n + 1\n",
            encoding="utf-8",
        )
        self._git(upstream, "add", "util.capa")
        self._git(upstream, "commit", "-m", "initial")
        self._git(upstream, "tag", "v0.1")

        project = td_path / "proj"
        project.mkdir()
        vendor = project / "vendor"
        vendor.mkdir()
        # Vendor by cloning the upstream at the tag (mirrors install).
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", "v0.1",
             upstream.as_uri(), str(vendor / "util")],
            capture_output=True, text=True, check=True,
            env={**os.environ, **self._GIT_ENV},
        )
        head = self._git(vendor / "util", "rev-parse", "HEAD")

        (project / "capa.toml").write_text(
            "[package]\n"
            'name = "proj"\n'
            'version = "0.1.0"\n'
            "\n"
            "[dependencies]\n"
            f'util = {{ git = "{upstream.as_uri()}", tag = "v0.1" }}\n',
            encoding="utf-8",
        )
        (project / "capa.lock").write_text(
            "[[dependencies]]\n"
            'name = "util"\n'
            f'git = "{upstream.as_uri()}"\n'
            'pin = "v0.1"\n'
            'pin_kind = "tag"\n'
            f'commit = "{head}"\n',
            encoding="utf-8",
        )
        root = project / "root.capa"
        root.write_text(
            "import util.util\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("${bump(2)}")\n',
            encoding="utf-8",
        )
        return project, root, head

    def test_healthy_vendor_runs(self):
        with tempfile.TemporaryDirectory() as td:
            project, root, _ = self._build_project(Path(td))
            rc, out, err = _run_main(["--run", str(root)], cwd=project)
            self.assertEqual(rc, 0, err)
            self.assertIn("3", out)

    def test_tampered_vendor_refuses_and_names_dep(self):
        with tempfile.TemporaryDirectory() as td:
            project, root, _ = self._build_project(Path(td))
            # Tamper: add a new commit to vendor/util so HEAD != lock.
            vutil = project / "vendor" / "util"
            (vutil / "util.capa").write_text(
                "pub fun bump(n: Int) -> Int\n    return n + 99\n",
                encoding="utf-8",
            )
            self._git(vutil, "commit", "-am", "tamper")
            rc, _out, err = _run_main(["--run", str(root)], cwd=project)
            self.assertEqual(rc, 1)
            self.assertIn("util", err)
            self.assertIn("capa install", err)
            self.assertIn("CAPA_NO_VERIFY", err)

    def test_in_place_edit_without_commit_refuses_and_names_dep(self):
        # The most trivial post-install tamper vector: edit a tracked
        # file in vendor/util WITHOUT committing. HEAD stays equal to the
        # locked commit (HEAD-only matching would pass), but the working
        # tree now holds adulterated code that the loader would read.
        # The working-tree check must catch this and refuse.
        with tempfile.TemporaryDirectory() as td:
            project, root, head = self._build_project(Path(td))
            vutil = project / "vendor" / "util"
            # Adulterate in place; do NOT commit, so HEAD is unchanged.
            (vutil / "util.capa").write_text(
                "pub fun bump(n: Int) -> Int\n    return n + 99\n",
                encoding="utf-8",
            )
            # HEAD still equals the locked commit: HEAD-only matching
            # would have let this through.
            self.assertEqual(
                self._git(vutil, "rev-parse", "HEAD"), head,
            )
            rc, _out, err = _run_main(["--run", str(root)], cwd=project)
            self.assertEqual(rc, 1)
            self.assertIn("util", err)
            self.assertIn("capa install", err)
            self.assertIn("CAPA_NO_VERIFY", err)

    def test_tampered_vendor_passes_with_opt_out(self):
        # The opt-out warning is emitted at most once per process; reset
        # the guard so this test sees it regardless of run order.
        import capa.pkg._verify as _v
        _v._warned_opt_out = False
        with tempfile.TemporaryDirectory() as td:
            project, root, _ = self._build_project(Path(td))
            vutil = project / "vendor" / "util"
            # A new commit (SHA changes, so HEAD != lock) whose source
            # still compiles and prints the same answer. The opt-out
            # must let it through despite the mismatch.
            (vutil / "util.capa").write_text(
                "pub fun bump(n: Int) -> Int\n"
                "    let one: Int = 1\n"
                "    return n + one\n",
                encoding="utf-8",
            )
            self._git(vutil, "commit", "-am", "tamper-but-same-behaviour")
            rc, out, err = _run_main(
                ["--run", str(root)], cwd=project,
                env={"CAPA_NO_VERIFY": "1"},
            )
            self.assertEqual(rc, 0, err)
            self.assertIn("3", out)
            self.assertIn("CAPA_NO_VERIFY", err)
            self.assertIn("OFF", err)

    def test_missing_lock_refuses(self):
        with tempfile.TemporaryDirectory() as td:
            project, root, _ = self._build_project(Path(td))
            (project / "capa.lock").unlink()
            rc, _out, err = _run_main(["--run", str(root)], cwd=project)
            self.assertEqual(rc, 1)
            self.assertIn("util", err)
            self.assertIn("capa.lock", err)
            self.assertIn("capa install", err)


if __name__ == "__main__":
    unittest.main()
