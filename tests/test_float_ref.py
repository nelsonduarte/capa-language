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


def test_dragon4_bignum_is_explicit_limb():
    # Portability guarantee: the Dragon4 bignum must be a list of 32-bit
    # limbs, never a Python big int. Spot-check the helpers' shape.
    a = float_ref._bn_from_u64(0xDEADBEEFCAFEBABE)
    assert isinstance(a, list)
    assert all(0 <= limb <= float_ref._LIMB_MASK for limb in a)
    prod = float_ref._bn_mul(a, float_ref._bn_from_u64(1000000007))
    assert isinstance(prod, list)
    assert all(0 <= limb <= float_ref._LIMB_MASK for limb in prod)
