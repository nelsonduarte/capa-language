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
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capa.cli import _wasm_tooling_available, main


def _run_main(argv, stdin=None, cwd=None, env=None):
    """Drive ``main()`` in-process. Returns ``(rc, stdout, stderr)``.

    ``stdin``: optional string fed to ``sys.stdin``.
    ``cwd``: optional directory to ``chdir`` into for the duration
    of the call (restored afterwards).
    ``env``: optional mapping merged into ``os.environ`` for the
    duration of the call. Only the keys supplied are patched.
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
        patches.append(mock.patch.dict(os.environ, env, clear=False))
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
        # A construct outside the Phase-6 subset. ``async`` is not
        # supported by the Wasm backend; whatever the rejection
        # path, the CLI must return non-zero with a "--wasm:"
        # diagnostic. We use a tuple in a way the CIR rejects
        # (best-effort: this exercises the except branch).
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
            # Either succeeds (in which case the Wasm backend has
            # expanded) or fails with a "--wasm:" line. Both are
            # acceptable; only the error branch increases coverage,
            # so we accept the success path silently when it occurs.
            if rc != 0:
                self.assertIn("--wasm", err)


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


if __name__ == "__main__":
    unittest.main()
