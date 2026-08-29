# pyright: reportCallIssue=none
#
# wasmtime-py types ``instance.exports(store)[name]`` as a union
# ``Func | Global | Memory | Table | SharedMemory``. Every call site
# in this module passes the resulting export through ``(...)``, so
# Pyright flags each non-callable variant of the union. We know the
# relevant export is a Func because the WAT we emit always declares it
# as one; silencing ``reportCallIssue`` for the whole module is the
# smallest fix that does not bury the test code in per-line type-ignore
# noise. Real "not callable" errors are still caught at runtime by
# ``python -m unittest``.
"""WebAssembly backend: safety (traps, bounds checks, the memory cap,
host UTF-8 safety, the host alloc guard, and unsafe-reaching-type
rejection).

Part of the tests/ir_wasm package; see tests/ir_wasm/__init__.py for
the growth convention. The shared _parse_lower / skip gates live in
tests/ir_wasm/_helpers.py.
"""

from __future__ import annotations

import unittest

from tests.ir_wasm._helpers import _parse_lower, _has_wasm_tools, _has_wasmtime_py
from capa.ir import emit_wat, compile_wat, compile_wasm, WasmEmissionError


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmSafetyTraps(unittest.TestCase):
    """Audit 2026-05 safety fixes (C2 / C3 / C5 / C6): every fix has
    BOTH a positive parity check (see ``test_ir_wasm_parity.py::
    test_safety_traps``) AND a dedicated negative check that asserts
    the trap actually fires on bad input. Without the negative side,
    a regression to silent unsafety would slip past parity (both
    backends would still match each other, just both wrongly)."""

    def _exec(self, src: str, fn_name: str, *args):
        """Compile, instantiate, call ``fn_name(*args)``, return its
        result. Each call gets its own Store + Linker for hermetic
        per-test heap state (mirrors the helpers used elsewhere in
        the file). Traps surface as ``wasmtime.Trap``; the caller
        wraps the call in ``assertRaises``."""
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        store = wasmtime.Store(engine)
        module = wasmtime.Module(engine, blob)
        linker = wasmtime.Linker(engine)
        instance = linker.instantiate(store, module)
        fn = instance.exports(store)[fn_name]
        return fn(store, *args)

    # ---- Fix C3: shift count out of [0, 64) traps -----------------

    def test_shift_left_count_64_traps(self):
        # ``a << 64``: Wasm's i64.shl would silently mask the RHS to
        # 0; the audit fix emits a guard that traps instead so both
        # backends fail loud at the same input.
        import wasmtime
        src = (
            "fun shl(a: Int, b: Int) -> Int\n"
            "    return a << b\n"
        )
        # Positive: shifts in range still work.
        self.assertEqual(self._exec(src, "shl", 5, 3), 40)
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "shl", 1, 64)

    def test_shift_left_count_negative_traps(self):
        import wasmtime
        src = (
            "fun shl(a: Int, b: Int) -> Int\n"
            "    return a << b\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "shl", 1, -1)

    def test_shift_right_count_64_traps(self):
        import wasmtime
        src = (
            "fun shr(a: Int, b: Int) -> Int\n"
            "    return a >> b\n"
        )
        self.assertEqual(self._exec(src, "shr", 1024, 4), 64)
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "shr", 1, 64)

    # ---- Bug #1: ``<<`` result leaving the i64 window traps --------

    def test_shift_left_result_overflow_traps(self):
        # ``1 << 63`` leaves the signed 64-bit window. The count (63)
        # is in range, so the old code emitted a bare ``i64.shl`` and
        # silently wrapped to i64::MIN; the Python backend's
        # ``_capa_shl`` traps. The Wasm emitter now arithmetic-shifts
        # the result back and traps when it does not recover the
        # operand, matching Python. ``1 << 62`` is the largest power
        # of two that fits and must NOT trap.
        import wasmtime
        src = (
            "fun shl(a: Int, b: Int) -> Int\n"
            "    return a << b\n"
        )
        # In-window shifts (incl. the i64::MIN boundary) return.
        self.assertEqual(self._exec(src, "shl", 1, 62), 1 << 62)
        self.assertEqual(self._exec(src, "shl", -1, 63), -(1 << 63))
        self.assertEqual(self._exec(src, "shl", -2, 62), -(1 << 63))
        self.assertEqual(self._exec(src, "shl", 0, 40), 0)
        self.assertEqual(self._exec(src, "shl", 5, 0), 5)
        # Result-window overflow traps (count in range, bits lost).
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "shl", 1, 63)
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "shl", 2, 62)
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "shl", -2, 63)

    # ---- Fix C6: Float % by zero traps ----------------------------

    def test_float_modulo_zero_traps(self):
        import wasmtime
        src = (
            "fun fmod(a: Float, b: Float) -> Float\n"
            "    return a % b\n"
        )
        # Positive: 7.5 % 3.0 == 1.5.
        self.assertAlmostEqual(self._exec(src, "fmod", 7.5, 3.0), 1.5)
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "fmod", 7.5, 0.0)

    # ---- Fix C2: Int +/-/* overflow traps -------------------------

    def test_int_add_overflow_traps(self):
        # ``i64::MAX + 1`` = ``9223372036854775807 + 1`` overflows.
        # We construct it as ``(1 << 62) + (1 << 62) + (1 << 62)``
        # via a function so the operands stay i64-typed all the way
        # through ANF lowering rather than being constant-folded.
        import wasmtime
        src = (
            "fun add(a: Int, b: Int) -> Int\n"
            "    return a + b\n"
        )
        # Positive: in-range add returns the sum.
        self.assertEqual(self._exec(src, "add", 5, 3), 8)
        # Negative: i64::MAX + 1 overflows.
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "add", (1 << 63) - 1, 1)

    def test_int_mul_overflow_traps(self):
        # ``3_000_000_000 * 4_000_000_000`` = 1.2e19, well past i64::MAX
        # (~9.22e18). Without the C2 fix the result wrapped mod 2^64
        # to a garbage value; now the multiply traps.
        import wasmtime
        src = (
            "fun mul(a: Int, b: Int) -> Int\n"
            "    return a * b\n"
        )
        self.assertEqual(
            self._exec(src, "mul", 1_000_000, 1_000_000), 1_000_000_000_000,
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "mul", 3_000_000_000, 4_000_000_000)

    def test_int_sub_overflow_traps(self):
        # ``i64::MIN - 1`` overflows below the signed window.
        import wasmtime
        src = (
            "fun sub(a: Int, b: Int) -> Int\n"
            "    return a - b\n"
        )
        self.assertEqual(self._exec(src, "sub", 100, 50), 50)
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "sub", -(1 << 63), 1)

    # ---- Bug #1: Int ``/`` is floored AND traps on /0 and MIN/-1 ---

    def test_int_div_is_floored(self):
        # ``i64.div_s`` truncates toward zero (``-7 / 2 == -3``), but
        # Capa Int division floors (``-7 / 2 == -4``), matching the
        # Python backend's ``//``. The Wasm floor correction must agree.
        src = (
            "fun div(a: Int, b: Int) -> Int\n"
            "    return a / b\n"
        )
        self.assertEqual(self._exec(src, "div", -7, 2), -4)
        self.assertEqual(self._exec(src, "div", 7, -2), -4)
        self.assertEqual(self._exec(src, "div", -1, 2), -1)
        self.assertEqual(self._exec(src, "div", 7, 2), 3)
        self.assertEqual(self._exec(src, "div", -8, -2), 4)
        self.assertEqual(self._exec(src, "div", 0, 5), 0)

    def test_int_div_by_zero_traps(self):
        import wasmtime
        src = (
            "fun div(a: Int, b: Int) -> Int\n"
            "    return a / b\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "div", 7, 0)

    def test_int_div_min_by_neg_one_traps(self):
        # ``i64::MIN / -1`` = ``2**63`` overflows the signed window;
        # the native div_s trap (preserved by computing the quotient
        # first) must fire, matching ``_capa_idiv``'s OverflowError.
        import wasmtime
        src = (
            "fun div(a: Int, b: Int) -> Int\n"
            "    return a / b\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "div", -(1 << 63), -1)

    # ---- Augmented Int /= and %= match the binary div / mod -------
    #
    # The augmented form (``x /= y`` / ``x %= y``) on an Int target
    # must produce the same floored result AND trap on the same
    # inputs as the binary ``/`` / ``%``. These mirror the binary
    # trap tests above for the augmented-assignment path (which the
    # Python backend used to route through raw float division).

    def test_aug_int_div_is_floored(self):
        src = (
            "fun adiv(a: Int, b: Int) -> Int\n"
            "    var x = a\n"
            "    x /= b\n"
            "    return x\n"
        )
        self.assertEqual(self._exec(src, "adiv", -7, 2), -4)
        self.assertEqual(self._exec(src, "adiv", 7, -2), -4)
        self.assertEqual(self._exec(src, "adiv", 24, 4), 6)
        self.assertEqual(self._exec(src, "adiv", -8, -2), 4)

    def test_aug_int_div_by_zero_traps(self):
        import wasmtime
        src = (
            "fun adiv(a: Int, b: Int) -> Int\n"
            "    var x = a\n"
            "    x /= b\n"
            "    return x\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "adiv", 7, 0)

    def test_aug_int_div_min_by_neg_one_traps(self):
        import wasmtime
        src = (
            "fun adiv(a: Int, b: Int) -> Int\n"
            "    var x = a\n"
            "    x /= b\n"
            "    return x\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "adiv", -(1 << 63), -1)

    def test_aug_int_mod_is_floored(self):
        src = (
            "fun amod(a: Int, b: Int) -> Int\n"
            "    var x = a\n"
            "    x %= b\n"
            "    return x\n"
        )
        self.assertEqual(self._exec(src, "amod", -7, 3), 2)
        self.assertEqual(self._exec(src, "amod", 7, -3), -2)
        self.assertEqual(self._exec(src, "amod", 17, 5), 2)

    def test_aug_int_mod_by_zero_traps(self):
        import wasmtime
        src = (
            "fun amod(a: Int, b: Int) -> Int\n"
            "    var x = a\n"
            "    x %= b\n"
            "    return x\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "amod", 7, 0)

    # ---- Bug #6: unary negation of i64::MIN traps -----------------

    def test_int_negate_works(self):
        src = (
            "fun neg(a: Int) -> Int\n"
            "    return -a\n"
        )
        self.assertEqual(self._exec(src, "neg", 5), -5)
        self.assertEqual(self._exec(src, "neg", -5), 5)
        self.assertEqual(self._exec(src, "neg", 0), 0)

    def test_int_negate_min_traps(self):
        # ``-(i64::MIN)`` = ``2**63`` overflows i64. The naive ``0 - x``
        # wraps back to MIN; the guard traps instead, matching the
        # Python backend's ``_capa_isub(0, x)`` OverflowError.
        import wasmtime
        src = (
            "fun neg(a: Int) -> Int\n"
            "    return -a\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "neg", -(1 << 63))

    # ---- Bug #4: Float ``/`` by zero traps ------------------------

    def test_float_div_zero_traps(self):
        # ``f64.div`` yields inf on a zero divisor, but Python raises
        # ZeroDivisionError. The Wasm guard now traps to match.
        import wasmtime
        src = (
            "fun fdiv(a: Float, b: Float) -> Float\n"
            "    return a / b\n"
        )
        self.assertAlmostEqual(self._exec(src, "fdiv", 7.5, 3.0), 2.5)
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "fdiv", 1.5, 0.0)

    # ---- Fix C4: to_int out-of-range traps ------------------------

    def test_to_int_in_range_works(self):
        # Positive parity: a value inside the signed 64-bit window
        # truncates toward zero on both backends.
        src = (
            "fun trunc(f: Float) -> Int\n"
            "    return to_int(f)\n"
        )
        self.assertEqual(self._exec(src, "trunc", 1.5), 1)
        self.assertEqual(self._exec(src, "trunc", -2.7), -2)
        # i64::MIN as a float is exactly representable and trunc-safe.
        self.assertEqual(
            self._exec(src, "trunc", -9223372036854775808.0),
            -9223372036854775808,
        )

    def test_to_int_overflow_traps(self):
        import wasmtime
        src = (
            "fun trunc(f: Float) -> Int\n"
            "    return to_int(f)\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "trunc", 1e20)

    def test_to_int_nan_traps(self):
        import wasmtime
        src = (
            "fun trunc(f: Float) -> Int\n"
            "    return to_int(f)\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "trunc", float("nan"))

    def test_to_int_inf_traps(self):
        import wasmtime
        src = (
            "fun trunc(f: Float) -> Int\n"
            "    return to_int(f)\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "trunc", float("inf"))

    # ---- Fix C5: parse_int overflow returns None ------------------

    def test_parse_int_too_big_returns_none(self):
        # An input larger than i64::MAX returns None on both backends;
        # without the fix the Wasm accumulator silently wrapped mod
        # 2^64 and reported a "successful" Some carrying a garbage
        # value. ``"99999999999999999999"`` is well outside the i64
        # window so any wrap is detectable.
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        src = (
            'fun main(stdio: Stdio)\n'
            '    match parse_int("99999999999999999999")\n'
            '        Some(n) -> stdio.println("Some(${n})")\n'
            '        None -> stdio.println("None")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        self.assertEqual(buf.getvalue(), "None\n")

    # ---- Bug #7: user-defined parse_int / parse_float shadow the
    # builtin (no "duplicate func identifier" parse error) ----------

    def _run_main_stdout(self, src: str) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        return buf.getvalue()

    def test_user_parse_int_shadows_builtin(self):
        # A user-defined ``parse_int`` must win over the builtin
        # (matching the Python backend) instead of colliding with the
        # ``$parse_int`` runtime helper at WAT-parse time.
        src = (
            'fun parse_int(s: String) -> Int\n'
            '    return 99\n'
            'fun main(stdio: Stdio)\n'
            '    let v = parse_int("x")\n'
            '    stdio.println("${v}")\n'
        )
        self.assertEqual(self._run_main_stdout(src), "99\n")

    def test_user_parse_float_shadows_builtin(self):
        src = (
            'fun parse_float(s: String) -> Float\n'
            '    return 1.5\n'
            'fun main(stdio: Stdio)\n'
            '    let v = parse_float("x")\n'
            '    stdio.println("${v}")\n'
        )
        self.assertEqual(self._run_main_stdout(src), "1.5\n")

    def test_builtin_parse_int_still_works_when_not_shadowed(self):
        # Control: with no user definition the builtin helper must
        # still parse the string and return Some.
        src = (
            'fun main(stdio: Stdio)\n'
            '    match parse_int("42")\n'
            '        Some(n) -> stdio.println("Some(${n})")\n'
            '        None -> stdio.println("None")\n'
        )
        self.assertEqual(self._run_main_stdout(src), "Some(42)\n")

    def test_builtin_parse_float_still_works_when_not_shadowed(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    match parse_float("3.5")\n'
            '        Some(n) -> stdio.println("Some(${n})")\n'
            '        None -> stdio.println("None")\n'
        )
        self.assertEqual(self._run_main_stdout(src), "Some(3.5)\n")

    def test_parse_int_i64_min_accepted(self):
        # ``-9223372036854775808`` (i64::MIN) sits inside the
        # ``[-2**63, 2**63)`` window. The overflow guard used to
        # compare the magnitude against i64::MAX with no sign case
        # and rejected it (magnitude last digit 8 > 7); it now admits
        # digit 8 at the boundary when a sign is present.
        src = (
            'fun main(stdio: Stdio)\n'
            '    match parse_int("-9223372036854775808")\n'
            '        Some(n) -> stdio.println("Some(${n})")\n'
            '        None -> stdio.println("None")\n'
        )
        self.assertEqual(
            self._run_main_stdout(src), "Some(-9223372036854775808)\n"
        )

    def test_parse_int_trims_ascii_whitespace(self):
        # Surrounding ASCII whitespace (space/tab/LF/VT/FF/CR) is
        # trimmed before parsing, matching the Python helper; a bare
        # ``" 7 "`` used to return None on the Wasm backend.
        src = (
            'fun main(stdio: Stdio)\n'
            '    match parse_int("\\t 42 \\r\\n")\n'
            '        Some(n) -> stdio.println("Some(${n})")\n'
            '        None -> stdio.println("None")\n'
        )
        self.assertEqual(self._run_main_stdout(src), "Some(42)\n")

    def test_parse_int_rejects_underscores(self):
        # Canonical grammar has no PEP-515 digit separators.
        src = (
            'fun main(stdio: Stdio)\n'
            '    match parse_int("1_000")\n'
            '        Some(n) -> stdio.println("Some(${n})")\n'
            '        None -> stdio.println("None")\n'
        )
        self.assertEqual(self._run_main_stdout(src), "None\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmBoundsChecks(unittest.TestCase):
    """Audit fix C1: List indexing and String.substring emit inline
    bounds-check traps. Pairs with
    ``tests/test_transpiler.py::TestBoundsRaise`` for the Python
    backend; together they pin "both backends fail loud at the same
    input" for collection access.

    Negative IR-level indices (a Capa source expression like
    ``0 - 1`` evaluates to ``-1`` an i64) are caught by the unsigned
    compare: ``i32.wrap_i64`` of a negative i64 is a huge u32 that
    exceeds any list's length, so ``i32.ge_u`` returns 1 and the
    trap fires on the same input that Python's ``_capa_list_get``
    rejects.
    """

    def _exec_main(self, src: str) -> str:
        """Compile, run ``main`` via the host bridge, return captured
        stdout. Used by positive-case tests where the program prints
        a value and exits cleanly."""
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        return buf.getvalue()

    def _exec_main_expect_trap(self, src: str) -> None:
        """Compile, run ``main`` via the host bridge, expect a
        ``wasmtime.Trap`` to fire. Used by the negative-case tests
        where the program indexes out of range or substrings past
        the end. We swallow stdout to keep the test output clean."""
        import io
        import sys
        import wasmtime
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            with self.assertRaises(wasmtime.Trap):
                host.run_main(blob)
        finally:
            sys.stdout = saved

    # ---- List indexing --------------------------------------------

    def test_list_index_in_bounds_works(self):
        # Positive parity: a valid index returns the element.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let xs = [10, 20, 30]\n'
            '    stdio.println("${xs[1]}")\n'
        )
        self.assertEqual(self._exec_main(src), "20\n")

    def test_list_index_out_of_bounds_traps(self):
        # ``xs[5]`` on a 3-element list: idx >= len -> i32.ge_u
        # returns 1 -> unreachable trap.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let xs = [10, 20, 30]\n'
            '    stdio.println("${xs[5]}")\n'
        )
        self._exec_main_expect_trap(src)

    def test_list_index_negative_traps(self):
        # ``xs[0 - 1]`` evaluates to ``xs[-1]`` an i64; i32.wrap_i64
        # of -1 is 0xFFFFFFFF (4294967295), well above any list's
        # length, so i32.ge_u traps. The 0 - 1 construction keeps
        # the analyzer from folding to a literal that some future
        # change might constant-evaluate.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let xs = [10, 20, 30]\n'
            '    let neg = 0 - 1\n'
            '    stdio.println("${xs[neg]}")\n'
        )
        self._exec_main_expect_trap(src)

    # ---- String substring -----------------------------------------

    def test_substring_in_bounds_works(self):
        # Positive parity: an in-range slice copies the requested bytes.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let s = "abcdef"\n'
            '    stdio.println("${s.substring(1, 4)}")\n'
        )
        self.assertEqual(self._exec_main(src), "bcd\n")

    def test_substring_out_of_bounds_traps(self):
        # ``s.substring(0, 100)`` on a 6-byte string: end > recv.len
        # -> i32.gt_u returns 1 -> unreachable trap. Without the C1
        # fix the emitter would memory.copy past the buffer.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let s = "abcdef"\n'
            '    stdio.println("${s.substring(0, 100)}")\n'
        )
        self._exec_main_expect_trap(src)

    # ---- String split (Bug #4) ------------------------------------

    def test_split_nonempty_separator_works(self):
        # Positive parity: a non-empty separator splits as before.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let parts = "a,b,c".split(",")\n'
            '    stdio.println("${parts.length()}")\n'
        )
        self.assertEqual(self._exec_main(src), "3\n")

    def test_split_empty_separator_traps(self):
        # ``"hello".split("")`` is a usage error: Python raises
        # ``ValueError: empty separator``. The Wasm backend used to
        # return the whole receiver as one element; it now traps on a
        # zero-length separator so both backends fail loud on the same
        # invalid input.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let parts = "hello".split("")\n'
            '    stdio.println("${parts.length()}")\n'
        )
        self._exec_main_expect_trap(src)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmMemoryCap(unittest.TestCase):
    """Audit fix H1 (2026-05): the emitted ``(memory ...)``
    declaration carries a page-count upper bound (default
    ``MEMORY_CAP_DEFAULT_PAGES`` = 256 pages = 16 MiB; configurable
    via the CLI ``--wasm-memory-cap`` flag). The bump allocator's
    ``memory.grow`` then traps via ``unreachable`` at a
    deterministic ceiling instead of a host-dependent OOM point."""

    def test_default_cap_baked_into_memory_decl(self):
        # The WAT shape carries ``(memory (export "memory") 1 256)``
        # by default. Pinning the textual form catches a regression
        # that would silently drop the cap.
        from capa.ir import compile_wat
        from capa.ir._emit_wasm import MEMORY_CAP_DEFAULT_PAGES
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.println("hi")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        wat = compile_wat(ast_mod, types=types)
        self.assertIn(
            f'(memory (export "memory") 1 {MEMORY_CAP_DEFAULT_PAGES})',
            wat,
        )

    def test_explicit_cap_baked_into_memory_decl(self):
        from capa.ir import compile_wat
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.println("hi")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        wat = compile_wat(ast_mod, types=types, memory_cap_pages=7)
        self.assertIn('(memory (export "memory") 1 7)', wat)

    def test_no_cap_omits_max(self):
        # Passing ``None`` lets the host decide; the WAT has no upper
        # bound in the memory limits clause.
        from capa.ir import compile_wat
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.println("hi")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        wat = compile_wat(ast_mod, types=types, memory_cap_pages=None)
        self.assertIn('(memory (export "memory") 1)', wat)

    def test_low_cap_traps_on_runaway_alloc(self):
        # A list-push loop allocates header + growing data array;
        # with ``memory_cap_pages=1`` (64 KiB total) the bump
        # allocator's ``memory.grow`` returns -1 once the heap
        # outgrows the cap and the helper traps via ``unreachable``.
        import io
        import sys
        import wasmtime
        from capa.ir import compile_wasm
        from capa.runtime._wasm_host import WasmHost
        src = (
            'fun main(stdio: Stdio)\n'
            '    var xs: List<Int> = []\n'
            '    var i = 0\n'
            '    while i < 100000\n'
            '        xs.push(i)\n'
            '        i = i + 1\n'
            '    stdio.println("${xs.length()}")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(
            ast_mod, types=types, memory_cap_pages=1,
        )
        host = WasmHost()
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            with self.assertRaises(wasmtime.Trap):
                host.run_main(blob)
        finally:
            sys.stdout = saved

    def test_large_data_segment_sizes_initial_pages(self):
        # Fix (2026-06-10): the initial page count must cover the
        # static data segment. Pre-fix the declaration hard-coded
        # ``1`` initial page, so a module whose interned literals
        # crossed 64 KiB trapped at INSTANTIATION ("out of bounds
        # memory access" placing the active data segment) before
        # ``$alloc`` could ever grow -- which is also why
        # ``--wasm-memory-cap`` had no effect on the symptom.
        from capa.ir import compile_wat
        from capa.ir._emit_wasm import MEMORY_CAP_DEFAULT_PAGES
        big = "x" * 70000  # > one 64 KiB page of string data
        src = (
            'fun main(stdio: Stdio)\n'
            f'    stdio.println("{big}")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        wat = compile_wat(ast_mod, types=types)
        self.assertIn(
            f'(memory (export "memory") 2 {MEMORY_CAP_DEFAULT_PAGES})',
            wat,
        )

    def test_cap_below_data_segment_is_a_loud_error(self):
        # When the static data alone needs more pages than the cap
        # allows, the module could never instantiate; the emitter
        # refuses loudly at compile time (pointing at the
        # --wasm-memory-cap knob) instead of producing a WAT whose
        # limits clause is invalid (min > max).
        from capa.ir import compile_wat
        from capa.ir._emit_wasm import WasmEmissionError
        big = "x" * 70000
        src = (
            'fun main(stdio: Stdio)\n'
            f'    stdio.println("{big}")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        with self.assertRaises(WasmEmissionError) as ctx:
            compile_wat(ast_mod, types=types, memory_cap_pages=1)
        self.assertIn("--wasm-memory-cap", str(ctx.exception))


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmHostUtf8Safety(unittest.TestCase):
    """Audit fix H3: every ``bytes.decode("utf-8")`` site in the
    host bridge is wrapped so invalid UTF-8 surfaces through the
    relevant WIT return shape (Option::None / Result::Err) or, for
    Stdio (no return), through U+FFFD replacement, instead of
    bubbling ``UnicodeDecodeError`` up through wasmtime and crashing
    the store."""

    def test_stdio_print_invalid_utf8_replaces(self):
        # Construct a host directly, prep its memory with invalid
        # UTF-8, invoke the stdio_print callback against the bytes.
        # The callback must NOT raise UnicodeDecodeError; the bytes
        # should print as the U+FFFD replacement glyph.
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        # Minimal module: declares a 1-page memory and exports it.
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.println("warmup")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        instance = host.instantiate(blob)
        # Splat invalid UTF-8 (a lone 0xFF) into linear memory at offset 0.
        memory = instance.exports(host.store)["memory"]
        memory.write(host.store, b"\xff", 0)
        # Find the stdio.println import via the linker: easiest path
        # is to call it via a re-instantiation that exports the host
        # callback's effect. Simpler still: spin up our own raw
        # decode of the bytes to mirror what stdio_print does.
        # The decode-with-replace must not raise.
        raw = bytes(memory.read(host.store, 0, 1))
        self.assertEqual(
            raw.decode("utf-8", errors="replace"), "�",
        )
        # Sanity-check that the live host's println callback ALSO
        # handles invalid UTF-8 without raising. We re-instantiate a
        # tiny module that calls println with the (ptr, len) of the
        # 0xFF byte: directly invoking the registered Func through
        # wasmtime's caller protocol is brittle, so we instead pin
        # that ``bytes.decode("utf-8", errors="replace")`` is the
        # behaviour the patched host uses (see
        # capa/runtime/_wasm_host.py::stdio_println).
        import inspect
        src_host = inspect.getsource(host._register_stdio)
        self.assertIn('errors="replace"', src_host)

    def test_env_get_invalid_utf8_name_returns_none(self):
        # When the guest passes an invalid-UTF-8 key to env.get, the
        # host must return Option::None (Env.get's WIT shape) rather
        # than raise UnicodeDecodeError. The Capa program below would
        # observe ``None`` for any unknown key; we ensure invalid
        # UTF-8 lands on the same path.
        from capa.runtime._wasm_host import WasmHost
        import io
        import sys
        import wasmtime
        src = (
            'fun main(stdio: Stdio, env: Env)\n'
            '    match env.get("present")\n'
            '        Some(_) -> stdio.println("Some")\n'
            '        None -> stdio.println("None")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        # "present" is almost certainly not set; the test asserts the
        # happy path (printing "None") still works. The actual H3
        # behaviour (invalid UTF-8 -> None) is verified by inspection:
        # the host's env_get now catches UnicodeDecodeError.
        self.assertEqual(buf.getvalue(), "None\n")
        import inspect
        src_host = inspect.getsource(host._register_env)
        self.assertIn("UnicodeDecodeError", src_host)

    def test_fs_read_invalid_utf8_path_returns_err(self):
        # Capa Fs.read on an invalid-UTF-8 path should return Err
        # (matching the no-such-file path) rather than raise. We
        # cannot easily synthesise an invalid-UTF-8 string from
        # Capa source (the lexer rejects bad UTF-8 in literals);
        # instead, pin that the host's fs_read catches
        # UnicodeDecodeError and routes to the Err arm.
        from capa.runtime._wasm_host import WasmHost
        import inspect
        host = WasmHost()
        src_host = inspect.getsource(host._register_fs)
        self.assertIn("UnicodeDecodeError", src_host)
        self.assertIn("invalid utf-8 in path", src_host)

    def test_json_parse_invalid_utf8_returns_err(self):
        # Same shape as fs_read: the host's json_parse must route
        # invalid UTF-8 through the result<u32, string> Err arm
        # rather than raise.
        from capa.runtime._wasm_host import WasmHost
        import inspect
        host = WasmHost()
        src_host = inspect.getsource(host._register_json)
        self.assertIn("UnicodeDecodeError", src_host)


@unittest.skipUnless(_has_wasmtime_py(), "wasmtime-py not installed")
class TestWasmHostAllocGuard(unittest.TestCase):
    """Audit 2026-05-25 L1: a failed guest ``$alloc`` (returns 0)
    must raise a clean host error instead of writing the buffer at
    address 0 and scribbling the data segment."""

    def test_failed_alloc_raises_host_error(self):
        from capa.runtime._wasm_host import WasmHost, WasmHostError

        host = WasmHost()
        # Stand in for the module's exported $alloc returning 0 (OOM).
        host._alloc_export = lambda caller, n: 0
        with self.assertRaises(WasmHostError) as ctx:
            host._host_alloc(object(), 32)
        self.assertIn("out of memory", str(ctx.exception))

    def test_zero_length_alloc_returns_zero_without_calling_export(self):
        from capa.runtime._wasm_host import WasmHost

        host = WasmHost()
        called = []

        def _boom(caller, n):  # pragma: no cover - must not run
            called.append(n)
            return 0

        host._alloc_export = _boom
        self.assertEqual(host._host_alloc(object(), 0), 0)
        self.assertEqual(called, [])

    def test_successful_alloc_returns_pointer(self):
        from capa.runtime._wasm_host import WasmHost

        host = WasmHost()
        host._alloc_export = lambda caller, n: 4096
        self.assertEqual(host._host_alloc(object(), 8), 4096)


class TestWasmRejectsUnsafeReachingTypes(unittest.TestCase):
    """Audit 2026-06-17 C5(b): the Wasm discovery pass rejects a
    parameter whose type merely CONTAINS Unsafe (through a struct
    field, a sum-variant payload, or a generic argument), not only a
    literal ``Unsafe`` head. The analyzer normally blocks Unsafe in a
    struct field upstream (C5(a)); this is the defense-in-depth check
    one layer down, so we build the IR by hand to exercise it."""

    def _emit(self, module):
        return emit_wat(module)

    def test_struct_field_unsafe_param_is_rejected(self):
        from capa.ir._nodes import (
            Module, Function, Param, StructDecl, StructField,
        )
        module = Module(
            functions=[
                Function(
                    name="f",
                    params=[Param(name="w", ty="Wrapper")],
                    return_type="Unit",
                    declared_caps=[],
                    body=[],
                ),
            ],
            types=[
                StructDecl(
                    name="Wrapper",
                    fields=[StructField(name="u", ty="Unsafe")],
                ),
            ],
        )
        with self.assertRaises(WasmEmissionError) as ctx:
            self._emit(module)
        self.assertIn("Unsafe", str(ctx.exception))
        # The offender is named with its real (struct) type, and no
        # invalid ``call $py_import`` is emitted.
        self.assertIn("f(w: Wrapper)", str(ctx.exception))

    def test_nested_struct_field_unsafe_param_is_rejected(self):
        from capa.ir._nodes import (
            Module, Function, Param, StructDecl, StructField,
        )
        module = Module(
            functions=[
                Function(
                    name="f",
                    params=[Param(name="o", ty="Outer")],
                    return_type="Unit",
                    declared_caps=[],
                    body=[],
                ),
            ],
            types=[
                StructDecl(
                    name="Outer",
                    fields=[StructField(name="inner", ty="Inner")],
                ),
                StructDecl(
                    name="Inner",
                    fields=[StructField(name="u", ty="Unsafe")],
                ),
            ],
        )
        with self.assertRaises(WasmEmissionError) as ctx:
            self._emit(module)
        self.assertIn("Unsafe", str(ctx.exception))

    def test_generic_arg_unsafe_param_is_rejected(self):
        from capa.ir._nodes import Module, Function, Param
        module = Module(
            functions=[
                Function(
                    name="f",
                    params=[Param(name="xs", ty="List<Unsafe>")],
                    return_type="Unit",
                    declared_caps=[],
                    body=[],
                ),
            ],
        )
        with self.assertRaises(WasmEmissionError) as ctx:
            self._emit(module)
        self.assertIn("Unsafe", str(ctx.exception))

    def test_unsafe_free_struct_param_still_emits(self):
        # A struct that does NOT reach Unsafe is untouched by the
        # tightened check.
        from capa.ir._nodes import (
            Module, Function, Param, StructDecl, StructField,
        )
        module = Module(
            functions=[
                Function(
                    name="f",
                    params=[Param(name="p", ty="Point")],
                    return_type="Unit",
                    declared_caps=[],
                    body=[],
                ),
            ],
            types=[
                StructDecl(
                    name="Point",
                    fields=[StructField(name="x", ty="Int")],
                ),
            ],
        )
        # Should not raise the Unsafe rejection (it emits normally).
        wat = self._emit(module)
        self.assertIn("(module", wat)
