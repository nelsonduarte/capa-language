"""Tests for the ``panic`` builtin.

``panic(message: String)`` aborts the program: the canonical
``panic: <message>`` line goes to stderr, nothing goes to stdout,
and the process exits non-zero on every backend (exit 1 on Python
via ``SystemExit``; a guest-side ``unreachable`` trap on the core
Wasm and Component Model paths, which the CLI translates to exit
1). No unwinding, no catch.

Layers covered here:

  * analyzer: registration (Unit-returning free function), arg
    typing / arity, user-function shadowing;
  * Python backend in-process: exit semantics + stderr / stdout
    contract, panic inside a callee, interpolated message;
  * core Wasm + Component Model hosts in-process: trap raised,
    message on stderr, nothing on stdout (skipped without the
    toolchain), plus the WIT ``import panic;`` surface;
  * CLI subprocess parity: the real exit-code contract on all
    three ``--run`` paths;
  * IFC: panic is a public sink like Stdio.eprintln (warn by
    default, error under ``@strict_ifc``, declassify clears it,
    cross-function summary catches a panicking callee);
  * ``capa test`` integration: a test file that panics is FAILed.
"""

from __future__ import annotations

import io
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from capa import Lexer, Parser, analyze, transpile
from capa.typesys import TyUnit


def _parse_analyze(src: str):
    tokens = Lexer(src).lex()
    module = Parser(tokens, source=src).parse_module()
    result = analyze(module, source=src)
    return module, result


def _has_wasm_toolchain() -> bool:
    if shutil.which("wasm-tools") is None:
        return False
    try:
        import wasmtime  # noqa: F401
    except ImportError:
        return False
    return True


def _capture_streams(thunk) -> tuple[str, str, object]:
    """Run ``thunk`` with stdout/stderr redirected; return
    (stdout, stderr, exception-or-None). ``SystemExit`` is captured
    like any other exception so the Python backend's abort can be
    asserted on."""
    out, err = io.StringIO(), io.StringIO()
    saved_out, saved_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    exc = None
    try:
        thunk()
    except BaseException as e:  # noqa: BLE001 - SystemExit included
        exc = e
    finally:
        sys.stdout, sys.stderr = saved_out, saved_err
    return out.getvalue(), err.getvalue(), exc


def _run_python_backend(src: str) -> tuple[str, str, object]:
    module, result = _parse_analyze(src)
    assert result.ok, f"analyzer errors: {result.errors}"
    code = transpile(module, types=result.types, bindings=result.bindings)

    def thunk():
        ns: dict = {"__name__": "__main__"}
        exec(compile(code, "<panic-test>", "exec"), ns)

    return _capture_streams(thunk)


_BOOM = (
    'fun main(stdio: Stdio)\n'
    '    stdio.println("before")\n'
    '    panic("boom")\n'
    '    stdio.println("after")\n'
)

_BOOM_IN_CALLEE = (
    'fun fail(code: Int)\n'
    '    panic("bad code ${code}")\n'
    '\n'
    'fun main()\n'
    '    fail(7)\n'
)

_NO_PANIC = (
    'fun main(stdio: Stdio)\n'
    '    stdio.println("fine")\n'
)

# Panic reached only through a lambda body: exercises the
# MakeLambda recursion in the Wasm discovery / WIT walkers (without
# it the module references an import it never declared).
_BOOM_IN_LAMBDA = (
    'fun main(stdio: Stdio)\n'
    '    let xs: List<Int> = [1, 2, 3]\n'
    '    let f = fun (n: Int) -> Int =>\n'
    '        if n == 2\n'
    '            panic("lambda boom")\n'
    '        return n\n'
    '    let ys = xs.map(f)\n'
    '    stdio.println("${ys.length()}")\n'
)


class TestPanicAnalyzer(unittest.TestCase):
    def test_panic_is_a_unit_returning_free_function(self):
        src = 'fun main()\n    panic("x")\n'
        module, result = _parse_analyze(src)
        self.assertTrue(result.ok, result.errors)
        # The call expression itself types as Unit.
        call = module.items[0].body.stmts[0].expr
        self.assertEqual(result.types.get(id(call)), TyUnit)

    def test_panic_rejects_non_string_argument(self):
        _, result = _parse_analyze('fun main()\n    panic(42)\n')
        self.assertFalse(result.ok)
        self.assertTrue(
            any("panic" in e.message for e in result.errors),
            [e.message for e in result.errors],
        )

    def test_panic_rejects_wrong_arity(self):
        _, result = _parse_analyze('fun main()\n    panic()\n')
        self.assertFalse(result.ok)

    def test_user_function_named_panic_shadows_builtin(self):
        src = (
            'fun panic(msg: String) -> Int\n'
            '    return msg.length()\n'
            '\n'
            'fun main()\n'
            '    let n = panic("hi")\n'
            '    let m = n + 1\n'
        )
        _, result = _parse_analyze(src)
        self.assertTrue(result.ok, result.errors)


class TestPanicPythonBackend(unittest.TestCase):
    def test_panic_aborts_with_exit_1_and_message_on_stderr(self):
        out, err, exc = _run_python_backend(_BOOM)
        self.assertIsInstance(exc, SystemExit)
        self.assertEqual(exc.code, 1)
        self.assertEqual(out, "before\n")
        self.assertEqual(err, "panic: boom\n")

    def test_panic_inside_callee_with_interpolation(self):
        out, err, exc = _run_python_backend(_BOOM_IN_CALLEE)
        self.assertIsInstance(exc, SystemExit)
        self.assertEqual(exc.code, 1)
        self.assertEqual(out, "")
        self.assertEqual(err, "panic: bad code 7\n")

    def test_panic_inside_lambda(self):
        out, err, exc = _run_python_backend(_BOOM_IN_LAMBDA)
        self.assertIsInstance(exc, SystemExit)
        self.assertEqual(exc.code, 1)
        self.assertEqual(out, "")
        self.assertEqual(err, "panic: lambda boom\n")

    def test_program_without_panic_is_unchanged(self):
        out, err, exc = _run_python_backend(_NO_PANIC)
        self.assertIsNone(exc)
        self.assertEqual(out, "fine\n")
        self.assertEqual(err, "")

    def test_user_panic_function_runs_instead_of_builtin(self):
        src = (
            'fun panic(msg: String) -> Int\n'
            '    return msg.length()\n'
            '\n'
            'fun main(stdio: Stdio)\n'
            '    let n = panic("four")\n'
            '    stdio.println("${n}")\n'
        )
        out, err, exc = _run_python_backend(src)
        self.assertIsNone(exc)
        self.assertEqual(out, "4\n")
        self.assertEqual(err, "")


@unittest.skipUnless(_has_wasm_toolchain(), "wasm toolchain not installed")
class TestPanicWasmBackend(unittest.TestCase):
    def _run_core(self, src: str) -> tuple[str, str, object]:
        from capa.ir import compile_wasm
        from capa.runtime._wasm_host import WasmHost
        module, result = _parse_analyze(src)
        assert result.ok, f"analyzer errors: {result.errors}"
        blob = compile_wasm(module, types=result.types)

        def thunk():
            WasmHost().run_main(blob)

        return _capture_streams(thunk)

    def _run_component(self, src: str) -> tuple[str, str, object]:
        from capa.cli import _wrap_as_component
        from capa.ir import compile_wasm, compile_wit
        from capa.runtime._wasm_component_host import WasmComponentHost
        module, result = _parse_analyze(src)
        assert result.ok, f"analyzer errors: {result.errors}"
        core = compile_wasm(module, types=result.types)
        component = _wrap_as_component(
            core, compile_wit(module, types=result.types),
        )

        def thunk():
            WasmComponentHost().run_main(component)

        return _capture_streams(thunk)

    def test_core_panic_traps_with_message_on_stderr(self):
        out, err, exc = self._run_core(_BOOM)
        self.assertIsNotNone(exc, "panic must trap on the Wasm backend")
        self.assertNotIsInstance(exc, SystemExit)
        self.assertEqual(out, "before\n")
        self.assertEqual(err, "panic: boom\n")

    def test_core_panic_in_callee_with_interpolation(self):
        out, err, exc = self._run_core(_BOOM_IN_CALLEE)
        self.assertIsNotNone(exc)
        self.assertEqual(out, "")
        self.assertEqual(err, "panic: bad code 7\n")

    def test_core_panic_inside_lambda(self):
        out, err, exc = self._run_core(_BOOM_IN_LAMBDA)
        self.assertIsNotNone(exc)
        self.assertEqual(out, "")
        self.assertEqual(err, "panic: lambda boom\n")

    def test_component_panic_traps_with_message_on_stderr(self):
        out, err, exc = self._run_component(_BOOM)
        self.assertIsNotNone(exc, "panic must trap on the CM backend")
        self.assertEqual(out, "before\n")
        self.assertEqual(err, "panic: boom\n")

    def test_component_panic_in_callee_with_interpolation(self):
        out, err, exc = self._run_component(_BOOM_IN_CALLEE)
        self.assertIsNotNone(exc)
        self.assertEqual(out, "")
        self.assertEqual(err, "panic: bad code 7\n")


class TestPanicWit(unittest.TestCase):
    """The WIT surface is pure text generation; no toolchain needed."""

    def _wit(self, src: str) -> str:
        from capa.ir import compile_wit
        module, result = _parse_analyze(src)
        assert result.ok, f"analyzer errors: {result.errors}"
        return compile_wit(module, types=result.types)

    def test_wit_declares_panic_interface_when_used(self):
        wit = self._wit(_BOOM_IN_CALLEE)
        self.assertIn("interface panic {", wit)
        self.assertIn("panic: func(msg: string);", wit)
        self.assertIn("import panic;", wit)

    def test_wit_sees_panic_inside_lambda(self):
        wit = self._wit(_BOOM_IN_LAMBDA)
        self.assertIn("import panic;", wit)

    def test_wit_omits_panic_interface_when_unused(self):
        wit = self._wit(_NO_PANIC)
        self.assertNotIn("interface panic", wit)
        self.assertNotIn("import panic;", wit)

    def test_wit_omits_panic_when_shadowed_by_user_function(self):
        src = (
            'fun panic(msg: String) -> Int\n'
            '    return msg.length()\n'
            '\n'
            'fun main(stdio: Stdio)\n'
            '    let n = panic("x")\n'
            '    stdio.println("${n}")\n'
        )
        wit = self._wit(src)
        self.assertNotIn("import panic;", wit)


class TestPanicCliExitCodes(unittest.TestCase):
    """The real process-level contract, via one subprocess per
    backend: exit 1 (non-zero), ``panic: <msg>`` on stderr, nothing
    on stdout. This is what ``capa test`` builds on."""

    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="capa_panic_"))
        self._file = self._tmp / "boom.capa"
        self._file.write_text(
            'fun main()\n    panic("boom")\n', encoding="utf-8",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run(self, *flags: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "capa", *flags, str(self._file)],
            capture_output=True, text=True, timeout=120,
        )

    def test_python_run_exits_1_clean_stderr_line(self):
        proc = self._run("--run")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, "")
        # Clean abort: exactly the panic line, no traceback.
        self.assertEqual(proc.stderr, "panic: boom\n")

    @unittest.skipUnless(_has_wasm_toolchain(), "wasm toolchain not installed")
    def test_wasm_run_exits_1_clean_stderr_line(self):
        # The Wasm panic must abort exactly as cleanly as the Python
        # backend: exit 1, the single ``panic:`` line on stderr, and
        # NO host traceback after it (a panic aborts via the guest's
        # ``unreachable``, which the CLI used to print as a full
        # wasmtime traceback).
        proc = self._run("--wasm", "--run")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, "panic: boom\n")
        self.assertNotIn("Traceback", proc.stderr)

    @unittest.skipUnless(_has_wasm_toolchain(), "wasm toolchain not installed")
    def test_component_run_exits_1_clean_stderr_line(self):
        proc = self._run("--wasm", "--component", "--run")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, "panic: boom\n")
        self.assertNotIn("Traceback", proc.stderr)


class TestPanicCrossBackendCleanAbort(unittest.TestCase):
    """The Wasm panic abort must match the Python abort in spirit:
    same single ``panic:`` line on stderr, same clean non-zero exit,
    no host traceback, nothing on stdout. Crucially, a GENUINE
    runtime trap (an out-of-bounds index, not a deliberate panic)
    must still report with a host traceback, because those point at
    real defects worth surfacing. One subprocess per backend so the
    real process-level stderr / exit contract is asserted."""

    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="capa_panic_cross_"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write(self, name: str, src: str) -> Path:
        p = self._tmp / name
        p.write_text(src, encoding="utf-8")
        return p

    def _run(self, path: Path, *flags: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "capa", *flags, str(path)],
            capture_output=True, text=True, timeout=120,
        )

    @unittest.skipUnless(_has_wasm_toolchain(), "wasm toolchain not installed")
    def test_panic_stderr_and_exit_match_python_and_wasm(self):
        # ``before`` reaches stdout, then the panic line reaches
        # stderr, on BOTH backends, with the same exit code and no
        # traceback on either.
        path = self._write("boom.capa", _BOOM)
        py = self._run(path, "--run")
        wasm = self._run(path, "--wasm", "--run")
        self.assertEqual(py.returncode, wasm.returncode)
        self.assertEqual(py.returncode, 1)
        self.assertEqual(py.stdout, wasm.stdout)
        self.assertEqual(py.stdout, "before\n")
        # The panic line is identical on both; neither carries a
        # traceback.
        self.assertEqual(py.stderr, "panic: boom\n")
        self.assertEqual(wasm.stderr, "panic: boom\n")
        self.assertNotIn("Traceback", wasm.stderr)

    @unittest.skipUnless(_has_wasm_toolchain(), "wasm toolchain not installed")
    def test_genuine_runtime_trap_still_reports_with_detail(self):
        # An out-of-bounds list index is NOT a panic: the Wasm guest
        # traps without going through the panic host import, so the
        # CLI must still surface the full host traceback (the
        # ``panicked`` flag stays False). This guards against the
        # clean-panic path swallowing real defects.
        oob = (
            'fun main(stdio: Stdio)\n'
            '    let xs: List<Int> = [1, 2, 3]\n'
            '    stdio.println("${xs[10]}")\n'
        )
        path = self._write("oob.capa", oob)
        wasm = self._run(path, "--wasm", "--run")
        self.assertNotEqual(wasm.returncode, 0)
        # No panic line was written (this is not a panic), but the
        # host traceback IS present so the defect is visible.
        self.assertNotIn("panic:", wasm.stderr)
        self.assertIn("Traceback", wasm.stderr)


_OOB = (
    'fun main(stdio: Stdio)\n'
    '    let xs: List<Int> = [1, 2, 3]\n'
    '    stdio.println("${xs[10]}")\n'
)


@unittest.skipUnless(_has_wasm_toolchain(), "wasm toolchain not installed")
class TestPanicHostReuseResetsLatch(unittest.TestCase):
    """The ``panicked`` latch is per-host, but a single host reused
    across runs (a documented use of ``_wasm_host`` / the Component
    host) must not carry a stale latch from one run into the next.

    If the latch were only cleared in ``__init__``, a deliberate
    panic in the first program would leave ``panicked`` True, and the
    CLI's trap guard (``if host.panicked: return 1`` without a
    traceback) would then silence a GENUINE trap in a second program
    run on the same host. Both run entry points (core + Component)
    now clear the latch at the start of every run, so the second
    run's trap is reported with full detail."""

    def _blob(self, src: str) -> bytes:
        from capa.ir import compile_wasm
        module, result = _parse_analyze(src)
        assert result.ok, f"analyzer errors: {result.errors}"
        return compile_wasm(module, types=result.types)

    def _component(self, src: str) -> bytes:
        from capa.cli import _wrap_as_component
        from capa.ir import compile_wasm, compile_wit
        module, result = _parse_analyze(src)
        assert result.ok, f"analyzer errors: {result.errors}"
        core = compile_wasm(module, types=result.types)
        return _wrap_as_component(
            core, compile_wit(module, types=result.types),
        )

    def test_core_host_reset_between_panic_then_trap(self):
        from capa.runtime._wasm_host import WasmHost
        panic_blob = self._blob(_BOOM)
        oob_blob = self._blob(_OOB)
        host = WasmHost()

        # First run: a deliberate panic latches ``panicked``.
        _capture_streams(lambda: host.run_main(panic_blob))
        self.assertTrue(
            host.panicked,
            "the panic run must latch the per-host flag",
        )

        # Second run on the SAME host: a genuine out-of-bounds trap.
        # The latch must have been cleared at run entry, so the CLI
        # guard would NOT silence this trap (panicked stays False).
        out, err, exc = _capture_streams(lambda: host.run_main(oob_blob))
        self.assertIsNotNone(exc, "the OOB access must trap")
        self.assertFalse(
            host.panicked,
            "a reused host must clear the panic latch so a genuine "
            "trap in the next run is not silenced",
        )

    def test_component_host_reset_between_panic_then_trap(self):
        from capa.runtime._wasm_component_host import WasmComponentHost
        panic_comp = self._component(_BOOM)
        oob_comp = self._component(_OOB)
        host = WasmComponentHost()

        _capture_streams(lambda: host.run_main(panic_comp))
        self.assertTrue(
            host.panicked,
            "the panic run must latch the per-host flag",
        )

        out, err, exc = _capture_streams(lambda: host.run_main(oob_comp))
        self.assertIsNotNone(exc, "the OOB access must trap")
        self.assertFalse(
            host.panicked,
            "a reused Component host must clear the panic latch so a "
            "genuine trap in the next run is not silenced",
        )


class TestPanicIfc(unittest.TestCase):
    """``panic`` is a public sink (the message goes to stderr),
    treated exactly like Stdio.eprintln: warn by default, hard
    error under ``@strict_ifc``, declassify clears the flow, and
    the cross-function summary catches a callee that panics with
    its parameter."""

    def _panic_warnings(self, result):
        return [w for w in result.warnings if "panic" in w.message]

    def test_secret_to_panic_warns(self):
        src = (
            'fun main(env: Env, stdio: Stdio)\n'
            '    match env.get("API_KEY")\n'
            '        Some(k) -> panic(k)\n'
            '        None -> stdio.println("no key")\n'
        )
        _, result = _parse_analyze(src)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(len(self._panic_warnings(result)), 1,
                         [w.message for w in result.warnings])

    def test_secret_to_panic_is_error_under_strict_ifc(self):
        src = (
            '@strict_ifc()\n'
            'fun main(env: Env)\n'
            '    let k = env.get("API_KEY").unwrap_or("none")\n'
            '    panic(k)\n'
        )
        _, result = _parse_analyze(src)
        self.assertFalse(result.ok)
        self.assertTrue(
            any("panic" in e.message for e in result.errors),
            [e.message for e in result.errors],
        )

    def test_declassified_secret_to_panic_is_clean(self):
        src = (
            'fun main(env: Env)\n'
            '    let k = env.get("API_KEY").unwrap_or("none")\n'
            '    panic(declassify(k, reason: "operator-visible abort"))\n'
        )
        _, result = _parse_analyze(src)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(self._panic_warnings(result), [])

    def test_public_message_to_panic_is_clean(self):
        _, result = _parse_analyze(_BOOM)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(self._panic_warnings(result), [])

    def test_callee_that_panics_param_flags_secret_at_call_site(self):
        src = (
            'fun die(msg: String)\n'
            '    panic(msg)\n'
            '\n'
            'fun main(env: Env)\n'
            '    let k = env.get("API_KEY").unwrap_or("none")\n'
            '    die(k)\n'
        )
        _, result = _parse_analyze(src)
        self.assertTrue(result.ok, result.errors)
        boundary = [
            w for w in result.warnings
            if "reaches a public sink inside" in w.message
        ]
        self.assertEqual(len(boundary), 1,
                         [w.message for w in result.warnings])


class TestPanicUnderCapaTest(unittest.TestCase):
    """A ``tests/test_*.capa`` file that panics is reported FAIL by
    ``capa test`` and drives the overall exit code to 1; panic is
    the recommended way for a Capa test to fail (docs/testing.md)."""

    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="capa_panic_test_"))
        root = self._tmp / "proj"
        (root / "tests").mkdir(parents=True)
        (root / "capa.toml").write_text(textwrap.dedent('''\
            [package]
            name = "demo"
            version = "0.1.0"
        '''), encoding="utf-8")
        (root / "tests" / "test_boom.capa").write_text(
            'fun main(stdio: Stdio)\n'
            '    stdio.println("checking")\n'
            '    panic("assertion failed: 1 != 2")\n',
            encoding="utf-8",
        )
        (root / "tests" / "test_fine.capa").write_text(
            'fun main(stdio: Stdio)\n    stdio.println("ok")\n',
            encoding="utf-8",
        )
        self._root = root

    def tearDown(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_panicking_test_file_is_reported_failed(self):
        proc = subprocess.run(
            [sys.executable, "-m", "capa", "test"],
            capture_output=True, text=True, timeout=300,
            cwd=str(self._root),
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("test_boom.capa ... FAIL", proc.stdout)
        self.assertIn("test_fine.capa ... ok", proc.stdout)
        self.assertIn("panic: assertion failed: 1 != 2", proc.stdout)
        self.assertIn("1 passed, 1 failed", proc.stdout)


if __name__ == "__main__":
    unittest.main()
