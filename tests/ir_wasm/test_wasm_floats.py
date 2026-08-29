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
"""WebAssembly backend: floats (arithmetic / clock and the ftoa parity,
round-weed, and residual sweeps).

Part of the tests/ir_wasm package; see tests/ir_wasm/__init__.py for
the growth convention. The shared _parse_lower / skip gates live in
tests/ir_wasm/_helpers.py.
"""

from __future__ import annotations

import unittest

from tests.ir_wasm._helpers import _parse_lower, _has_wasm_tools, _has_wasmtime_py
from capa.ir import compile_wasm


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmFloatAndClock(unittest.TestCase):
    """Phase 7A: Capa ``Float`` lowers to Wasm ``f64``; arithmetic
    and comparison ops dispatch on operand type. ``Clock.now_secs``
    / ``now_monotonic`` are imported as capability methods
    returning ``f64`` and bound to Python's ``time`` module via
    the WasmHost bridge."""

    def _instantiate(self, src: str):
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        mod = wasmtime.Module(engine, blob)
        store = wasmtime.Store(engine)
        linker = wasmtime.Linker(engine)
        instance = linker.instantiate(store, mod)
        return store, instance.exports(store)

    def test_float_arithmetic_round_trip(self):
        src = (
            "fun three_quarters() -> Float\n"
            "    return 0.5 + 0.25\n"
            "fun divide() -> Float\n"
            "    return 1.0 / 4.0\n"
            "fun multiply() -> Float\n"
            "    return 1.5 * 2.0\n"
            "fun subtract() -> Float\n"
            "    return 1.0 - 0.25\n"
        )
        store, exp = self._instantiate(src)
        self.assertAlmostEqual(exp["three_quarters"](store), 0.75)
        self.assertAlmostEqual(exp["divide"](store), 0.25)
        self.assertAlmostEqual(exp["multiply"](store), 3.0)
        self.assertAlmostEqual(exp["subtract"](store), 0.75)

    def test_float_comparison_returns_bool(self):
        src = (
            "fun positive(f: Float) -> Bool\n"
            "    return f > 0.0\n"
            "fun negative(f: Float) -> Bool\n"
            "    return f < 0.0\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["positive"](store, 5.0), 1)
        self.assertEqual(exp["positive"](store, -3.0), 0)
        self.assertEqual(exp["negative"](store, -3.0), 1)
        self.assertEqual(exp["negative"](store, 5.0), 0)

    def test_clock_capability_via_host(self):
        # Compile with a Clock parameter. The Wasm signature drops
        # the capability param itself; the methods are imported via
        # capa:host/clock and resolved by the WasmHost.
        from capa.runtime._wasm_host import WasmHost
        src = (
            "fun now_positive(clock: Clock) -> Bool\n"
            "    let t = clock.now_secs()\n"
            "    return t > 0.0\n"
            "fun main(stdio: Stdio, clock: Clock)\n"
            "    if now_positive(clock)\n"
            "        stdio.println(\"clock OK\")\n"
            "    else\n"
            "        stdio.println(\"clock NOT OK\")\n"
        )
        import io
        import sys
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        self.assertEqual(out.getvalue(), "clock OK\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmFtoaParity(unittest.TestCase):
    """Bit-identical parity of the Wasm ``$ftoa`` helper against
    Python's ``str(float)`` for a curated set of values: common
    decimals, hard IEEE 754 cases (0.1 + 0.2 territory), the
    scientific-notation thresholds Python uses (``|x| < 1e-4``,
    ``|x| >= 1e16``), and the special cases (``+/-0``, ``+/-inf``,
    ``nan``).

    Each test compiles a tiny Capa program that materialises the
    target value (either as a literal or via arithmetic for the
    NaN/inf cases) and asserts the ``${x}``-interpolated stdout
    matches ``str(target)``. Grisu2's documented ~0.5% extra-digit
    edge cases are not included; the corpus here is the corpus
    Grisu2 is known to handle shortest."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved_out
        return out.getvalue()

    def _assert_literal_parity(self, v: float) -> None:
        """Compile a program that interpolates ``v`` as a literal
        and asserts the Wasm output equals Python's ``str(v)``."""
        src = (
            "fun main(stdio: Stdio)\n"
            f"    let x: Float = {v!r}\n"
            "    stdio.println(\"${x}\")\n"
        )
        expected = str(v) + "\n"
        self.assertEqual(self._run_capturing_stdout(src), expected)

    # Plain decimals -- the bread-and-butter case.
    def test_one_point_five(self):  self._assert_literal_parity(1.5)
    def test_zero_five(self):       self._assert_literal_parity(0.5)
    def test_hundred(self):         self._assert_literal_parity(100.0)
    def test_one_two_three(self):   self._assert_literal_parity(123.0)
    def test_pi_short(self):        self._assert_literal_parity(3.14)
    def test_one_quarter(self):     self._assert_literal_parity(0.25)
    def test_one(self):             self._assert_literal_parity(1.0)
    def test_two(self):             self._assert_literal_parity(2.0)
    def test_seven(self):           self._assert_literal_parity(7.0)
    def test_forty_two(self):       self._assert_literal_parity(42.0)

    # Hard IEEE 754 cases -- shortest-round-trip required.
    def test_zero_one(self):        self._assert_literal_parity(0.1)
    def test_zero_two(self):        self._assert_literal_parity(0.2)
    def test_zero_three(self):      self._assert_literal_parity(0.3)
    def test_one_thousandth(self):  self._assert_literal_parity(0.001)
    def test_one_ten_thousandth(self): self._assert_literal_parity(0.0001)
    def test_one_eighth(self):      self._assert_literal_parity(0.125)
    def test_one_sixteenth(self):   self._assert_literal_parity(0.0625)

    # Negatives.
    def test_neg_one_five(self):    self._assert_literal_parity(-1.5)
    def test_neg_half(self):        self._assert_literal_parity(-0.5)
    def test_neg_hundred(self):     self._assert_literal_parity(-100.0)
    def test_neg_pi_short(self):    self._assert_literal_parity(-3.14)

    # Scientific-notation thresholds. Python's str(float) uses
    # e-notation when ``e = n - 1 < -4`` (lower) or ``e >= 17``
    # (upper); the values below straddle both edges.
    def test_just_inside_decimal_low(self):
        # 1e-4 is the smallest magnitude that stays in decimal form.
        self._assert_literal_parity(1e-4)

    def test_just_outside_decimal_low(self):
        # 1e-5 crosses into scientific.
        self._assert_literal_parity(1e-5)

    def test_just_outside_decimal_high(self):
        # 1e16 just crosses into scientific (n=17, e=16).
        self._assert_literal_parity(1e16)

    def test_one_quadrillion(self):
        # Highest magnitude still in decimal form (n=16).
        self._assert_literal_parity(1e15)

    def test_scientific_negative_exponent_three_digits(self):
        # 1e-100 exercises the three-digit-exponent branch.
        self._assert_literal_parity(1e-100)

    def test_scientific_positive_exponent_three_digits(self):
        # 1e100 exercises the three-digit-exponent branch on the
        # positive side.
        self._assert_literal_parity(1e100)

    # Special cases: +/-0, +/-inf, nan.
    def test_positive_zero(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let x: Float = 0.0\n"
            "    stdio.println(\"${x}\")\n"
        )
        self.assertEqual(self._run_capturing_stdout(src), "0.0\n")

    def test_negative_zero(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let x: Float = -0.0\n"
            "    stdio.println(\"${x}\")\n"
        )
        self.assertEqual(self._run_capturing_stdout(src), "-0.0\n")

    def test_infinity_via_division_now_traps(self):
        # Bug #4: float division by zero used to yield IEEE-754 inf on
        # the Wasm backend while the Python backend raised
        # ZeroDivisionError - a divergence. Both backends now agree by
        # trapping on a zero divisor, so ``one / zero`` can no longer
        # be used to synthesise inf (Capa has no inf/nan literals).
        import wasmtime
        src = (
            "fun main(stdio: Stdio)\n"
            "    let zero: Float = 0.0\n"
            "    let one: Float = 1.0\n"
            "    let inf_val: Float = one / zero\n"
            "    stdio.println(\"${inf_val}\")\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._run_capturing_stdout(src)

    def test_nan_via_division_now_traps(self):
        # Bug #4 (cont.): ``zero / zero`` (which produced nan) now
        # traps on the Wasm backend too, matching Python.
        import wasmtime
        src = (
            "fun main(stdio: Stdio)\n"
            "    let zero: Float = 0.0\n"
            "    let nan_val: Float = zero / zero\n"
            "    stdio.println(\"${nan_val}\")\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._run_capturing_stdout(src)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmFtoaRoundWeed(unittest.TestCase):
    """Audit C1 (2026-06-09): the hard-rounding values the pre-fix
    Grisu2 port got wrong because it omitted the RoundWeed last-digit
    nudge. ``$ftoa`` returned the FIRST digit string inside the
    rounding interval rather than the one closest to ``W``; for
    ``100.0 / 7.0`` that meant ``14.285714285714287`` (one ulp high)
    against Python's ``14.285714285714286``.

    With RoundWeed ported into ``$grisu2`` these are all byte-exact.
    Each value below diverged BEFORE the fix; this class is the
    regression net for the headline cases and the realistic
    computed-float classes (ratios, averages, sums)."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved_out
        return out.getvalue()

    def _assert_repr_parity(self, v: float) -> None:
        src = (
            "fun main(stdio: Stdio)\n"
            f"    let x: Float = {v!r}\n"
            "    stdio.println(\"${x}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), repr(v) + "\n",
            msg=f"Wasm $ftoa diverged from repr for {v!r}",
        )

    def test_hundred_over_seven(self):
        # The audit headline. Pre-fix: 14.285714285714287.
        self._assert_repr_parity(100.0 / 7.0)

    def test_sum_over_three(self):
        # (1+2+4)/3. Pre-fix: 2.3333333333333337.
        self._assert_repr_parity((1.0 + 2.0 + 4.0) / 3.0)

    def test_one_over_seven(self):
        self._assert_repr_parity(1.0 / 7.0)

    def test_ten_over_three(self):
        self._assert_repr_parity(10.0 / 3.0)

    def test_one_over_six(self):
        self._assert_repr_parity(1.0 / 6.0)

    def test_one_over_twentynine(self):
        self._assert_repr_parity(1.0 / 29.0)

    def test_twentytwo_over_seven(self):
        self._assert_repr_parity(22.0 / 7.0)

    def test_average_of_set(self):
        self._assert_repr_parity((3.0 + 5.0 + 8.0 + 11.0) / 4.0)

    def test_ratio_sweep_small(self):
        # The whole a/b grid for a,b in 1..40 is byte-exact post-fix
        # (it was 954/3481 diverging pre-fix). One subTest per ratio
        # so a future regression points at the exact value.
        for a in range(1, 41):
            for b in range(1, 41):
                v = a / b
                with self.subTest(a=a, b=b):
                    self.assertEqual(
                        self._run_capturing_stdout(
                            "fun main(stdio: Stdio)\n"
                            f"    let x: Float = {v!r}\n"
                            "    stdio.println(\"${x}\")\n"
                        ),
                        repr(v) + "\n",
                    )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmFtoaResidual(unittest.TestCase):
    """F2 (2026-06-10): the Grisu3-confidence + Dragon4 exact
    fallback has LANDED, so the residual float-formatting hole is
    closed. Grisu2 is INHERENTLY unable to produce the
    shortest-round-trip digit string for a sub-1% fraction of bit
    patterns; ``$grisu2`` now carries the RoundWeed
    boundary-ambiguity success flag and ``$ftoa`` falls back to the
    exact limb-bignum Dragon4 (``$dragon4`` + the ``$bn_*`` family)
    when that flag is clear. Both paths feed the same (digits, K)
    shape into the spelling layer, so the output is byte-exact with
    Python ``repr(float)``.

    The values below were CONFIRMED Grisu2-inherent divergences
    before F2 - the validated Python Grisu2 reference produced the
    SAME wrong digit as the WAT, proving the gap was the algorithm,
    not the port. They are now real PASSING parity tests (the
    Dragon4 fallback names the correct double), including a
    plain-arithmetic case (``86.0 / 7018.0``) so the formerly-open
    hole is pinned as a realistic-value regression guard, not just
    hand-picked literals."""

    def _wat_ftoa(self, v: float) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        src = (
            "fun main(stdio: Stdio)\n"
            f"    let x: Float = {v!r}\n"
            "    stdio.println(\"${x}\")\n"
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        return out.getvalue()

    def test_residual_decimal_range_a(self):
        # Formerly Grisu2-inherent residual in the common decimal
        # range (repr 76821.07266303091, old WAT ...0309); the
        # Dragon4 fallback now matches repr.
        v = 76821.07266303091
        self.assertEqual(self._wat_ftoa(v), repr(v) + "\n")

    def test_residual_decimal_range_b(self):
        # Formerly repr 0.08549800233840919 vs old WAT ...092; now
        # exact via the Dragon4 fallback.
        v = 0.08549800233840919
        self.assertEqual(self._wat_ftoa(v), repr(v) + "\n")

    def test_residual_from_ordinary_division(self):
        # Arithmetic-reachable residual (NOT a hand-picked literal).
        # ``86.0 / 7018.0`` -> repr 0.012254203476774009. The old
        # Grisu2-only WAT emitted 0.01225420347677401, which did NOT
        # round-trip (it named the WRONG double); the Dragon4 fallback
        # now produces the shortest round-tripping string byte-for-byte
        # equal to repr.
        v = 86.0 / 7018.0
        self.assertEqual(self._wat_ftoa(v), repr(v) + "\n")
