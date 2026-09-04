"""WebAssembly backend: the ordered-type comparison sweep.

Part of the tests/ir_wasm package; see tests/ir_wasm/__init__.py for the
growth convention. A sibling of the structural sweeps in
tests/ir_wasm/test_wasm_sweeps.py, kept separate because it is keyed on a
different single source: ``capa.typesys.ORDERED_TYPES`` rather than the
method tables.

``ORDERED_TYPES`` is the one place the analyzer writes down which types
the ordering operators (``<`` ``<=`` ``>`` ``>=``) accept. The Wasm
lowering of those operators is a per-type dispatch in ``_emit_binop``
(String -> ``$str_cmp`` folded by ``_STR_CMP_FOLD``, Float ->
``_FLOAT_CMP_BINOP``, everything else the i64 opcodes of ``_CMP_BINOP``):
a structural second copy of that set, which cannot be derived from it
because each arm is open-coded Wasm. A member added to the constant with
no arm would be lowered as an integer, silently. This sweep is the guard:
every member has a probe pair ``(lo, hi)`` with ``lo < hi``, chosen so an
integer bit-pattern compare answers WRONGLY for a non-integer type, and
the pair is run through all four operators in both orders on the real
backend.

``test_every_ordered_type_has_a_probe`` is what makes this a guard: a new
member of ``ORDERED_TYPES`` with no probe fails there, a probe for a type
that left the set fails there, and a probe whose lowering is wrong fails
the run below.
"""

from __future__ import annotations

import unittest

from tests.ir_wasm._helpers import _parse_lower, _has_wasm_tools, _has_wasmtime_py
from capa.ir import emit_wat
from capa.typesys import ORDERED_TYPES


#: ordered type name -> (lo literal, hi literal) with ``lo < hi``.
_ORDER_PROBES: dict[str, tuple[str, str]] = {
    # A negative operand: an unsigned i64 compare would put -3 above 7.
    "Int": ("-3", "7"),
    # -1.5 is the SMALLER value but its IEEE-754 bit pattern, read as a
    # signed i64, is the larger one, so an i64 lowering answers wrongly.
    "Float": ("-1.5", "-0.5"),
    # A proper prefix orders first; the (ptr, len) pair of a string has no
    # meaningful i64 order at all.
    "String": ('"ab"', '"b"'),
}

#: What every probe prints: the four operators over (lo, hi), then over
#: (hi, lo). True for any correctly ordered pair with ``lo < hi``.
_ORDER_PROBE_EXPECTED = "true true false false false false true true\n"


def _build_order_probe(ty: str, lo: str, hi: str) -> str:
    return (
        "fun main(stdio: Stdio)\n"
        f"    let lo: {ty} = {lo}\n"
        f"    let hi: {ty} = {hi}\n"
        '    stdio.println("${lo < hi} ${lo <= hi} ${lo > hi} ${lo >= hi} '
        '${hi < lo} ${hi <= lo} ${hi > lo} ${hi >= lo}")\n'
    )


class TestOrderedTypeComparisonSweepCoverage(unittest.TestCase):
    """The coverage half: pure Python, no wasm tooling."""

    def test_every_ordered_type_has_a_probe(self):
        # THE GUARD: the probe table and the analyzer's ordered-type set
        # must name the same types, in both directions.
        self.assertEqual(
            set(_ORDER_PROBES), {ty.name for ty in ORDERED_TYPES},
            msg=(
                "capa.typesys.ORDERED_TYPES and _ORDER_PROBES disagree. A "
                "new ordered type needs a Wasm comparison lowering in "
                "_emit_binop AND a probe pair here so the sweep proves it; "
                "a type that left the set must lose its probe."
            ),
        )

    def test_every_probe_emits(self):
        for ty, (lo, hi) in sorted(_ORDER_PROBES.items()):
            with self.subTest(type=ty):
                ir_mod, _, _ = _parse_lower(_build_order_probe(ty, lo, hi))
                emit_wat(ir_mod)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestOrderedTypeComparisonSweepRuns(unittest.TestCase):
    """The semantic half: each probe runs on the real backend and must
    order its pair correctly under all four operators."""

    def test_every_ordered_type_orders_correctly_on_wasm(self):
        from tests.test_ir_wasm_parity import _capture_stdout, _run_wasm
        for ty, (lo, hi) in sorted(_ORDER_PROBES.items()):
            with self.subTest(type=ty):
                src = _build_order_probe(ty, lo, hi)
                out = _capture_stdout(lambda: _run_wasm(src))
                self.assertEqual(
                    out, _ORDER_PROBE_EXPECTED,
                    f"Wasm mis-orders {ty}: {lo} against {hi} printed "
                    f"{out!r}\n--- program ---\n{src}",
                )


if __name__ == "__main__":
    unittest.main()
