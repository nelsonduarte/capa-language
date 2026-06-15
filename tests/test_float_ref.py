"""Validation for the portable float-to-string reference.

The reference (``tools/float_ref.py``) is the blueprint for the Wasm
float-formatting port: a Grisu fast path with a Grisu3 confidence flag
plus an exact Dragon4 fallback built on explicit 32-bit-limb bignum.
Its ``format_float`` must equal Python ``repr(float)`` on every finite
double.

These tests cover the edge / arithmetic classes and a modest random
sweep so they stay fast enough for the always-on suite. The heavy
multi-million sweep lives in ``tools.float_ref.validate_sweep`` and is
invoked separately (``python tools/float_ref.py``), not gated here.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

_REF_PATH = (
    pathlib.Path(__file__).resolve().parent.parent / "tools" / "float_ref.py"
)
_spec = importlib.util.spec_from_file_location("float_ref", _REF_PATH)
assert _spec and _spec.loader
float_ref = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(float_ref)


ARITHMETIC_REPROS = [
    86.0 / 7018.0,
    39890.261 * 297.24217854,
    100.0 / 7.0,
    (1.0 + 2.0 + 4.0) / 3.0,
]


@pytest.mark.parametrize("x", ARITHMETIC_REPROS)
def test_arithmetic_repros_match_repr(x):
    # The values from the Wasm float-formatting bug report. 86.0/7018.0
    # is the headline regression: Grisu2 alone produced a non
    # round-tripping string; the Grisu3 + Dragon4 reference must match
    # repr exactly.
    assert float_ref.format_float(x) == repr(x)


def test_edge_and_arithmetic_classes():
    # Subnormals, DBL_MIN/MAX, powers of two, integers up to 2^53,
    # 15/16/17-digit values, fixed/scientific boundary, negatives, and
    # the a/b + a*b grid - zero divergences allowed.
    checked, diverged, failures = float_ref.validate_edge_cases()
    assert checked > 25000
    assert diverged == 0, failures[:10]


def test_random_sweep_matches_repr():
    # Smaller deterministic sweep for the always-on suite; the heavy
    # multi-million run is tools/float_ref.py main(). Zero divergences.
    checked, diverged, fallback, failures = float_ref.validate_sweep(
        count=100_000, seed=0xABCDEF
    )
    assert checked > 90_000
    assert diverged == 0, failures[:10]
    # Grisu3 fallback should be the standard sub-1% figure, proving the
    # fast path carries a real confidence flag (not always-fallback).
    assert 0 < fallback < checked // 10


def test_specials_and_signed_zero():
    assert float_ref.format_float(float("inf")) == repr(float("inf"))
    assert float_ref.format_float(float("-inf")) == repr(float("-inf"))
    assert float_ref.format_float(float("nan")) == repr(float("nan"))
    assert float_ref.format_float(0.0) == "0.0"
    assert float_ref.format_float(-0.0) == "-0.0"


import math
import struct


def _bits(x: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", x))[0]


def _oracle(s: str):
    """CPython ``float()`` as the oracle, mapping overflow-to-inf and
    grammar rejections to ``None`` the way ``strtod`` does."""
    try:
        v = float(s)
    except ValueError:
        return None
    if math.isinf(v) or math.isnan(v):
        return None
    return _bits(v)


STRTOD_HARD = [
    "123456789.987654321", "1.5e-10", "2.5e2",
    "1.7976931348623159e308",          # overflows -> None
    "5e-324", "2.5e-324", "4.9e-324",  # smallest subnormals
    "9007199254740993",                # 2^53 + 1, ties to even
    "1.0000000000000002",
    "2.2250738585072011e-308",         # subnormal/normal boundary
    "2.2250738585072014e-308",         # DBL_MIN
    "2.225073858507201e-308",          # largest subnormal
    "0.1", "0.3", "100.5", "1e308", "1e-308",
]


def test_strtod_hard_cases_match_float():
    # The boundary / hard-rounding cases the bignum slow path exists
    # for: bit-identical to float() (or None on overflow).
    for s in STRTOD_HARD:
        assert float_ref.strtod(s) is not None or _oracle(s) is None, s
        got = float_ref.strtod(s)
        exp = _oracle(s)
        if exp is None:
            assert got is None, (s, got)
        else:
            assert got is not None and _bits(got) == exp, (s, got, float(s))


def test_strtod_grammar_rejections():
    # inf / nan / underscores / garbage / overflow -> None.
    for s in ("inf", "nan", "infinity", "1_000", "1.2.3", "", "  ",
              "1e", "1e+", "--1", "abc", "1e400", "1e309"):
        assert float_ref.strtod(s) is None, s


def test_strtod_underflow_and_signed_zero():
    assert float_ref.strtod("1e-400") == 0.0
    assert _bits(float_ref.strtod("0")) == 0
    assert _bits(float_ref.strtod("-0")) == _bits(-0.0)
    assert _bits(float_ref.strtod("-0.0")) == _bits(-0.0)


def test_strtod_random_sweep_matches_float():
    # Deterministic sweep over e-form, decimal, and bit-roundtrip
    # spellings; every grammar-valid, non-overflowing input must be
    # bit-identical to CPython float(). The heavy multi-million run is
    # exercised out-of-band (tools/float_ref.py validation harness).
    import random
    rng = random.Random(0x57701D)
    checked = 0
    for _ in range(20_000):
        k = rng.random()
        if k < 0.4:
            nd = rng.randint(1, 19)
            s = "".join(rng.choice("0123456789") for _ in range(nd))
            s += "e" + str(rng.randint(-330, 330))
        elif k < 0.7:
            a = "".join(rng.choice("0123456789")
                        for _ in range(rng.randint(1, 12)))
            b = "".join(rng.choice("0123456789")
                        for _ in range(rng.randint(0, 12)))
            s = a + "." + b
        else:
            bits = rng.getrandbits(64) & 0x7FFFFFFFFFFFFFFF
            if (bits >> 52) == 0x7FF:
                bits &= ~(0x7FF << 52)
            s = repr(struct.unpack("<d", struct.pack("<Q", bits))[0])
        checked += 1
        got = float_ref.strtod(s)
        exp = _oracle(s)
        if exp is None:
            assert got is None, (s, got)
        else:
            assert got is not None and _bits(got) == exp, (s, got, float(s))
    assert checked == 20_000


def test_dragon4_bignum_is_explicit_limb():
    # Portability guarantee: the Dragon4 bignum must be a list of 32-bit
    # limbs, never a Python big int. Spot-check the helpers' shape.
    a = float_ref._bn_from_u64(0xDEADBEEFCAFEBABE)
    assert isinstance(a, list)
    assert all(0 <= limb <= float_ref._LIMB_MASK for limb in a)
    prod = float_ref._bn_mul(a, float_ref._bn_from_u64(1000000007))
    assert isinstance(prod, list)
    assert all(0 <= limb <= float_ref._LIMB_MASK for limb in prod)
