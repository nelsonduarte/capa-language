"""WebAssembly backend: Stdio emission and execution.

Part of the tests/ir_wasm package; see tests/ir_wasm/__init__.py for
the growth convention. The shared _parse_lower / skip gates live in
tests/ir_wasm/_helpers.py.
"""

from __future__ import annotations

import unittest

from tests.ir_wasm._helpers import _parse_lower, _has_wasm_tools, _has_wasmtime_py
from capa.ir import emit_wat, compile_wat, compile_wasm, WasmEmissionError


class TestWasmStdioEmission(unittest.TestCase):
    """Phase 6B Wasm-side emission of capability method calls.
    Pure shape tests (no toolchain shell-out)."""

    def test_emits_stdio_import(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn(
            '(import "capa:host/stdio" "println" '
            '(func $Stdio_println (param i32) (param i32))',
            wat,
        )

    def test_main_export_drops_capability_param(self):
        # ``main(stdio: Stdio)`` has no Wasm-level parameters because
        # the capability is provided via imports, not as a value.
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn('(func $main (export "main")', wat)
        self.assertNotIn("$stdio", wat)

    def test_string_literal_lowers_to_data_segment(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        # The memory limits clause now carries a default upper-page
        # cap (audit H1, 2026-05); use a tolerant match that fires on
        # any ``(memory (export "memory") 1 ...)`` prefix.
        self.assertIn('(memory (export "memory") 1', wat)
        self.assertIn('(data (i32.const 0) "hi")', wat)

    def test_unsupported_method_raises(self):
        # D3 slice 4 (2026-05) closed the last three known String
        # gaps (replace / char_at / index_of). Any String method
        # outside the supported set should still raise so a future
        # gap is visible at compile time instead of silently
        # mis-emitting; drive that via a bogus method name. The
        # analyzer rejects the source before emission gets a chance,
        # so we drive emission directly via the IR shape used here.
        src = (
            "fun cleaned(s: String) -> String\n"
            "    return s.replace(\",\", \";\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        # Mutate the lowered MethodCall in-place to point at a method
        # the dispatcher does not know about; everything else stays
        # type-checked.
        from capa.ir._nodes import MethodCall
        for fn in ir_mod.functions:
            for instr in fn.body:
                if isinstance(instr, MethodCall) and instr.method == "replace":
                    instr.method = "definitely_not_a_real_method"
        with self.assertRaises(WasmEmissionError):
            emit_wat(ir_mod)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmStdioExecutes(unittest.TestCase):
    """End-to-end: Capa -> CIR -> WAT -> .wasm -> wasmtime with
    a Python host bridge providing the ``capa:stdio`` interface."""

    def _run_capturing_stdout(self, src: str) -> tuple[str, str]:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out, err = io.StringIO(), io.StringIO()
        saved_out, saved_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            host.run_main(blob)
        finally:
            sys.stdout, sys.stderr = saved_out, saved_err
        return out.getvalue(), err.getvalue()

    def test_hello_world(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hello from wasm\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "hello from wasm\n")

    def test_print_does_not_append_newline(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.print(\"no newline\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "no newline")

    def test_multiple_prints_in_order(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"line one\")\n"
            "    stdio.println(\"line two\")\n"
            "    stdio.println(\"line three\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "line one\nline two\nline three\n")

    def test_eprintln_goes_to_stderr(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.eprintln(\"warn\")\n"
        )
        out, err = self._run_capturing_stdout(src)
        self.assertEqual(out, "")
        self.assertEqual(err, "warn\n")

    def test_utf8_in_string_literal(self):
        # Non-ASCII characters survive UTF-8 encoding through the
        # data segment + host decode round-trip.
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"olá, mundo\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "olá, mundo\n")

    def test_user_function_call_with_capability_arg(self):
        # ``greet`` takes a Stdio param and a Bool. The Wasm signature
        # drops Stdio; the call site at ``main`` passes only the Bool.
        # The capability flows through the module-level import.
        src = (
            "fun greet(stdio: Stdio, friendly: Bool)\n"
            "    if friendly\n"
            "        stdio.println(\"hi\")\n"
            "    else\n"
            "        stdio.println(\"bye\")\n"
            "fun main(stdio: Stdio)\n"
            "    greet(stdio, true)\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "hi\n")

    def test_string_literals_are_pooled(self):
        # Two identical literals should share a single data-segment
        # entry (verified indirectly: the emitted WAT only mentions
        # the literal once).
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
            "    stdio.println(\"hi\")\n"
        )
        _, types, ast_mod = _parse_lower(src)
        wat = compile_wat(ast_mod, types=types)
        self.assertEqual(wat.count('(data (i32.const 0) "hi")'), 1)

    def test_ioerror_construction_one_arg(self):
        # Regression: constructing the built-in ``IoError`` error type
        # with call syntax used to emit a ``call $IoError`` to a
        # function that was never defined ("unknown func $IoError" at
        # wasm-tools parse), even though ``--check`` and the Python
        # backend accepted it. It now lowers inline like a struct
        # literal, so ``Err(IoError("bad"))`` builds a real record and
        # the ``Err`` arm's ``${e}`` renders the message -- identical
        # to the Python backend's ``IoError.__str__``.
        src = (
            "fun boom() -> Result<Int, IoError>\n"
            "    return Err(IoError(\"bad\"))\n"
            "fun main(stdio: Stdio)\n"
            "    match boom()\n"
            "        Ok(n)  -> stdio.println(\"ok\")\n"
            "        Err(e) -> stdio.eprintln(\"err: ${e}\")\n"
        )
        # No dangling constructor call survives to the emitted WAT.
        _, types, ast_mod = _parse_lower(src)
        self.assertNotIn("call $IoError", compile_wat(ast_mod, types=types))
        out, err = self._run_capturing_stdout(src)
        self.assertEqual(out, "")
        self.assertEqual(err, "err: bad\n")

    def test_ioerror_construction_two_args(self):
        # The two-argument form ``IoError(message, cause)`` maps onto
        # the record's second String field (``cause``). The record is
        # built, the ``Err`` arm is taken, and the match binder's
        # ``${e}`` renders ``message: cause`` -- exactly Python's
        # ``IoError.__str__`` (message alone when the cause is empty,
        # ``message: cause`` otherwise). The source contains no String
        # ``+``, so this also pins the discovery gate: formatting an
        # IoError must pull in the ``$str_concat`` helper on its own
        # (the ``: `` join happens at runtime), or the WAT references
        # an undefined function.
        src = (
            "fun boom() -> Result<Int, IoError>\n"
            "    return Err(IoError(\"bad\", \"disk full\"))\n"
            "fun main(stdio: Stdio)\n"
            "    match boom()\n"
            "        Ok(n)  -> stdio.println(\"ok\")\n"
            "        Err(e) -> stdio.eprintln(\"err: ${e}\")\n"
        )
        _, types, ast_mod = _parse_lower(src)
        self.assertNotIn("call $IoError", compile_wat(ast_mod, types=types))
        out, err = self._run_capturing_stdout(src)
        self.assertEqual(out, "")
        self.assertEqual(err, "err: bad: disk full\n")

    def test_ioerror_two_args_direct_interpolation(self):
        # ``${e}`` of a let-bound two-arg IoError as the WHOLE format
        # string (no surrounding literal text, no match binder in
        # between): the analyzer types the local directly, so this
        # exercises the FormatStr IoError branch through the plain
        # ``v.ty == "IoError"`` route rather than the fn.locals
        # refinement fallback. Renders ``message: cause`` like
        # Python's ``IoError.__str__``.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let e = IoError(\"msg\", \"detail\")\n"
            "    stdio.println(\"${e}\")\n"
        )
        out, err = self._run_capturing_stdout(src)
        self.assertEqual(out, "msg: detail\n")
        self.assertEqual(err, "")

    def test_ioerror_construction_in_return_position(self):
        # Regression (PR #41 adversarial review): ``return IoError(...)``
        # in tail position was intercepted by the tail-call peephole
        # BEFORE the constructor routing, emitting ``return_call
        # $IoError`` against a function that is never defined ("unknown
        # func $IoError" at wasm-tools parse). ``_is_tail_callable`` now
        # excludes the built-in IoError constructor (like variants and
        # intrinsics), so the construction falls through to the inline
        # lowering. The ``assertNotIn("call $IoError", ...)`` substring
        # check also covers ``return_call $IoError``. The one-arg
        # (empty-cause) form renders ``${e}`` identically to Python's
        # ``IoError.__str__``, so stdout parity holds end to end.
        src = (
            "fun make() -> IoError\n"
            "    return IoError(\"from-fn\")\n"
            "fun main(stdio: Stdio)\n"
            "    let e = make()\n"
            "    stdio.println(\"made: ${e}\")\n"
        )
        _, types, ast_mod = _parse_lower(src)
        self.assertNotIn("call $IoError", compile_wat(ast_mod, types=types))
        out, err = self._run_capturing_stdout(src)
        self.assertEqual(out, "made: from-fn\n")
        self.assertEqual(err, "")

    def test_ioerror_two_args_in_return_position(self):
        # Two-arg form in tail position: the record is built (both
        # fields stored), flows back through the ordinary call +
        # return, and ``${e}`` of the returned value renders
        # ``message: cause`` inside a larger literal -- matching
        # Python's ``IoError.__str__`` byte for byte. This used to
        # observe a constant instead of ``${e}`` while non-empty-cause
        # rendering was a documented FormatStr divergence (Wasm
        # rendered only the message); the IoError branch in
        # _emit_wasm/_strings.py now branches on cause_len at runtime
        # and concatenates ``message ++ ": " ++ cause``.
        src = (
            "fun make() -> IoError\n"
            "    return IoError(\"from-fn\", \"detail\")\n"
            "fun main(stdio: Stdio)\n"
            "    let e = make()\n"
            "    stdio.println(\"made: ${e}\")\n"
        )
        _, types, ast_mod = _parse_lower(src)
        self.assertNotIn("call $IoError", compile_wat(ast_mod, types=types))
        out, err = self._run_capturing_stdout(src)
        self.assertEqual(out, "made: from-fn: detail\n")
        self.assertEqual(err, "")
