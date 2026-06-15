"""Direct unit tests for the runtime classes.

The transpiler statically lowers most ``String``, ``Map``, and
``Set`` method calls to native Python operations, so the runtime
classes (``CapaList``, ``CapaRange``, ``Some`` / ``None_``,
``Ok`` / ``Err``, the ``JsonValue`` variants) only run when
dispatch cannot be resolved at compile time. End-to-end
transpiler tests miss those paths; these tests hit them
directly so refactors of the runtime layer cannot silently
break the public method surface.
"""

from __future__ import annotations

import unittest

from capa.runtime._list import CapaList, CapaRange
from capa.runtime._set import CapaSet
from capa.runtime._result import Some, None_, Ok, Err
from capa.runtime._convert import (
    parse_int, parse_float, to_float, to_int, _propagate_err,
)
from capa.runtime._json import (
    JStr, JNum, JBool, JNull, JArr, JObj,
    parse_json, to_json,
)


class TestCapaList(unittest.TestCase):
    def test_length_push_contains(self):
        xs = CapaList([1, 2, 3])
        self.assertEqual(xs.length(), 3)
        xs.push(4)
        self.assertEqual(xs.length(), 4)
        self.assertTrue(xs.contains(2))
        self.assertFalse(xs.contains(99))

    def test_map_filter_fold(self):
        xs = CapaList([1, 2, 3, 4])
        self.assertEqual(list(xs.map(lambda x: x * 2)), [2, 4, 6, 8])
        self.assertEqual(list(xs.filter(lambda x: x % 2 == 0)), [2, 4])
        self.assertEqual(xs.fold(0, lambda a, b: a + b), 10)

    def test_map_returns_capalist(self):
        # Chaining requires map / filter to return CapaList, not list.
        xs = CapaList([1, 2])
        self.assertIsInstance(xs.map(lambda x: x + 1), CapaList)
        self.assertIsInstance(xs.filter(lambda x: True), CapaList)

    def test_is_empty(self):
        self.assertTrue(CapaList([]).is_empty())
        self.assertFalse(CapaList([0]).is_empty())

    def test_first_last_get(self):
        xs = CapaList([10, 20, 30])
        self.assertTrue(xs.first().is_some())
        self.assertEqual(xs.first().value, 10)
        self.assertEqual(xs.last().value, 30)
        self.assertEqual(xs.get(1).value, 20)
        self.assertTrue(xs.get(99).is_none())
        self.assertTrue(xs.get(-1).is_none())
        # Empty list: first / last are None_.
        empty = CapaList([])
        self.assertTrue(empty.first().is_none())
        self.assertTrue(empty.last().is_none())

    def test_find_and_find_index(self):
        xs = CapaList([1, 4, 9, 16])
        hit = xs.find(lambda x: x > 5)
        self.assertTrue(hit.is_some())
        self.assertEqual(hit.value, 9)
        miss = xs.find(lambda x: x > 1000)
        self.assertTrue(miss.is_none())
        idx_hit = xs.find_index(lambda x: x > 5)
        self.assertEqual(idx_hit.value, 2)
        idx_miss = xs.find_index(lambda x: x > 1000)
        self.assertTrue(idx_miss.is_none())


class TestCapaSetEquality(unittest.TestCase):
    """``CapaSet`` mirrors Python's native ``set`` for ``==`` /
    ``!=``: two sets are equal iff they hold the same elements,
    regardless of insertion order. The transpiler relies on this
    because Capa's structural ``Set<T> == Set<T>`` lowers to a
    Python ``==`` on ``CapaSet`` for the Python backend (and to a
    generated ``$eq_Set_*`` helper on the Wasm backend); the two
    backends must agree byte-for-byte."""

    def test_order_independent_equality(self):
        self.assertEqual(
            CapaSet([1, 2, 3]),
            CapaSet([3, 2, 1]),
        )

    def test_different_contents_unequal(self):
        self.assertNotEqual(
            CapaSet([1]),
            CapaSet([1, 2]),
        )

    def test_unequal_to_non_capaset(self):
        # Comparison against a non-CapaSet returns NotImplemented,
        # which Python turns into False (per the data model). A
        # plain ``set`` is not a ``CapaSet`` even with the same
        # elements; equality is by class as well as by contents.
        self.assertNotEqual(CapaSet([1]), 5)
        self.assertNotEqual(CapaSet([1]), {1})

    def test_unhashable(self):
        # Like ``set``, ``CapaSet`` is mutable + equality-by-value,
        # so hashing must raise ``TypeError`` rather than fall back
        # to identity hashing (which would give two equal instances
        # different hashes).
        with self.assertRaises(TypeError):
            hash(CapaSet([1]))


class TestCapaRange(unittest.TestCase):
    def test_length_contains_empty(self):
        r = CapaRange(0, 5)
        self.assertEqual(r.length(), 5)
        self.assertTrue(r.contains(2))
        self.assertFalse(r.contains(5))  # exclusive upper
        self.assertFalse(r.is_empty())

    def test_empty_range(self):
        r = CapaRange(5, 5)
        self.assertEqual(r.length(), 0)
        self.assertTrue(r.is_empty())

    def test_to_list_materialises(self):
        r = CapaRange(2, 6)
        xs = r.to_list()
        self.assertIsInstance(xs, CapaList)
        self.assertEqual(list(xs), [2, 3, 4, 5])

    def test_iterates_lazily(self):
        r = CapaRange(0, 3)
        self.assertEqual(list(r), [0, 1, 2])

    def test_repr_shows_bounds(self):
        r = CapaRange(1, 4)
        self.assertEqual(repr(r), "CapaRange(1, 4)")


class TestSomeAndNone(unittest.TestCase):
    def test_some_is_some_unwrap(self):
        s = Some(42)
        self.assertTrue(s.is_some())
        self.assertFalse(s.is_none())
        self.assertEqual(s.unwrap(), 42)
        self.assertEqual(s.unwrap_or(0), 42)
        self.assertEqual(s.value, 42)

    def test_none_is_none_unwrap_or(self):
        self.assertTrue(None_.is_none())
        self.assertFalse(None_.is_some())
        with self.assertRaises(Exception):
            None_.unwrap()
        self.assertEqual(None_.unwrap_or(7), 7)

    def test_map_some_and_none(self):
        self.assertEqual(Some(3).map(lambda x: x * 2).unwrap(), 6)
        self.assertTrue(None_.map(lambda x: x * 2).is_none())

    def test_and_then(self):
        self.assertEqual(
            Some(3).and_then(lambda x: Some(x + 1)).unwrap(), 4,
        )
        self.assertTrue(
            Some(3).and_then(lambda x: None_).is_none(),
        )
        self.assertTrue(
            None_.and_then(lambda x: Some(x + 1)).is_none(),
        )

    def test_or_else(self):
        self.assertEqual(Some(1).or_else(lambda: Some(2)).unwrap(), 1)
        self.assertEqual(None_.or_else(lambda: Some(2)).unwrap(), 2)

    def test_filter(self):
        self.assertEqual(Some(4).filter(lambda x: x > 0).unwrap(), 4)
        self.assertTrue(Some(4).filter(lambda x: x < 0).is_none())
        self.assertTrue(None_.filter(lambda x: True).is_none())

    def test_ok_or(self):
        r = Some(5).ok_or("missing")
        self.assertEqual(r.unwrap(), 5)
        r2 = None_.ok_or("missing")
        self.assertTrue(r2.is_err())


class TestOkAndErr(unittest.TestCase):
    def test_ok_basics(self):
        r = Ok(7)
        self.assertTrue(r.is_ok())
        self.assertFalse(r.is_err())
        self.assertEqual(r.unwrap(), 7)
        self.assertEqual(r.unwrap_or(0), 7)
        self.assertEqual(r.value, 7)

    def test_err_basics(self):
        r = Err("boom")
        self.assertTrue(r.is_err())
        self.assertFalse(r.is_ok())
        self.assertEqual(r.unwrap_or(99), 99)
        self.assertEqual(r.error, "boom")

    def test_map_and_map_err(self):
        self.assertEqual(Ok(3).map(lambda x: x * 10).unwrap(), 30)
        self.assertEqual(
            Err("e").map(lambda x: x).map_err(lambda e: e.upper()).error,
            "E",
        )
        # map on Err leaves it untouched.
        self.assertTrue(Err("bad").map(lambda x: x + 1).is_err())
        # map_err on Ok leaves it untouched.
        self.assertEqual(Ok(2).map_err(lambda e: "x").unwrap(), 2)

    def test_and_then(self):
        self.assertEqual(
            Ok(3).and_then(lambda x: Ok(x + 1)).unwrap(), 4,
        )
        self.assertTrue(
            Ok(3).and_then(lambda x: Err("fail")).is_err(),
        )
        self.assertTrue(
            Err("e").and_then(lambda x: Ok(x)).is_err(),
        )

    def test_or_else(self):
        self.assertEqual(Ok(1).or_else(lambda e: Ok(2)).unwrap(), 1)
        self.assertEqual(Err("x").or_else(lambda e: Ok(99)).unwrap(), 99)

    def test_ok_and_err_projections(self):
        # Result.ok() -> Option<T>; Result.err() -> Option<E>.
        self.assertEqual(Ok(5).ok().unwrap(), 5)
        self.assertTrue(Ok(5).err().is_none())
        self.assertTrue(Err("bad").ok().is_none())
        self.assertEqual(Err("bad").err().unwrap(), "bad")


class TestConverts(unittest.TestCase):
    """``parse_int`` / ``parse_float`` / ``to_int`` / ``to_float``
    are the user-facing builtins; ``_propagate_err`` is the legacy
    ``?``-operator helper kept on the public surface for back-compat
    with already-emitted transpiled code.
    """

    def test_parse_int(self):
        self.assertEqual(parse_int("42").unwrap(), 42)
        self.assertEqual(parse_int("  -7  ").unwrap(), -7)
        self.assertTrue(parse_int("abc").is_none())
        self.assertTrue(parse_int("").is_none())
        # Non-string input should not raise; AttributeError is caught.
        self.assertTrue(parse_int(None).is_none())

    def test_parse_int_canonical_grammar(self):
        # Canonical grammar (identical on Python + Wasm): surrounding
        # ASCII whitespace, optional sign, one+ decimal digits, range
        # ``[-2**63, 2**63)``. Mirrors the cross-backend parity probe.
        self.assertEqual(parse_int("7").unwrap(), 7)
        self.assertEqual(parse_int(" 7 ").unwrap(), 7)
        self.assertEqual(parse_int("+7").unwrap(), 7)
        self.assertEqual(parse_int("-7").unwrap(), 7 * -1)
        self.assertEqual(parse_int("0").unwrap(), 0)
        self.assertEqual(parse_int("-0").unwrap(), 0)
        # Every trimmed ASCII whitespace byte (space/tab/LF/VT/FF/CR).
        self.assertEqual(parse_int("\t\n\x0b\x0c\r 42 \r\n").unwrap(), 42)
        # i64::MAX and i64::MIN both inside the window.
        self.assertEqual(
            parse_int("9223372036854775807").unwrap(), (1 << 63) - 1
        )
        self.assertEqual(
            parse_int("-9223372036854775808").unwrap(), -(1 << 63)
        )
        # One past each bound -> None.
        self.assertTrue(parse_int("9223372036854775808").is_none())
        self.assertTrue(parse_int("-9223372036854775809").is_none())
        # Underscores (PEP 515) are rejected -- this is the divergence
        # being closed; Python's bare ``int`` would accept "1_000".
        self.assertTrue(parse_int("1_000").is_none())
        # Non-decimal bases and non-integer forms.
        self.assertTrue(parse_int("0x10").is_none())
        self.assertTrue(parse_int("0b101").is_none())
        self.assertTrue(parse_int("7.0").is_none())
        self.assertTrue(parse_int("7 8").is_none())
        self.assertTrue(parse_int("++7").is_none())
        self.assertTrue(parse_int("- 7").is_none())
        # All-whitespace and sign-only.
        self.assertTrue(parse_int("   ").is_none())
        self.assertTrue(parse_int("+").is_none())
        self.assertTrue(parse_int("-").is_none())
        # Unicode digits and Unicode whitespace are NOT recognised
        # (the Wasm byte scanner cannot see them, so both reject).
        self.assertTrue(parse_int("٤").is_none())  # Arabic-Indic 4
        self.assertTrue(parse_int("²").is_none())  # superscript 2
        self.assertTrue(parse_int(" 7").is_none())  # NBSP + '7'

    def test_parse_float(self):
        self.assertEqual(parse_float("3.14").unwrap(), 3.14)
        self.assertEqual(parse_float("  -0.5  ").unwrap(), -0.5)
        self.assertTrue(parse_float("nope").is_none())
        self.assertTrue(parse_float(None).is_none())

    def test_to_float_and_to_int(self):
        self.assertEqual(to_float(3), 3.0)
        self.assertEqual(to_int(3.7), 3)
        self.assertEqual(to_int(-0.9), 0)  # truncates toward zero

    def test_to_int_at_i64_min_boundary_works(self):
        # ``-2**63`` is exactly representable as f64 AND fits in i64.
        # Both backends accept it; ``i64.trunc_f64_s`` returns
        # ``-9223372036854775808``.
        self.assertEqual(to_int(float(-(1 << 63))), -(1 << 63))

    def test_to_int_above_i64_max_raises(self):
        # Audit fix C4: ``int(1e20)`` returned an arbitrary-precision
        # int silently on Python while Wasm trapped on the same input.
        # Both now raise / trap at the same value.
        with self.assertRaises(OverflowError):
            to_int(1e20)

    def test_to_int_below_i64_min_raises(self):
        with self.assertRaises(OverflowError):
            to_int(-1e20)

    def test_to_int_nan_raises(self):
        with self.assertRaises(OverflowError):
            to_int(float("nan"))

    def test_to_int_pos_inf_raises(self):
        with self.assertRaises(OverflowError):
            to_int(float("inf"))

    def test_to_int_neg_inf_raises(self):
        with self.assertRaises(OverflowError):
            to_int(float("-inf"))

    def test_propagate_err_legacy_helper(self):
        # Legacy two-tuple return shape (value, should_propagate).
        v, prop = _propagate_err(Ok(11))
        self.assertEqual(v, 11)
        self.assertFalse(prop)
        e, prop = _propagate_err(Err("bad"))
        self.assertTrue(prop)
        # Non-Result input is a programming error: it raises.
        with self.assertRaises(RuntimeError):
            _propagate_err(42)


class TestJsonValueQueries(unittest.TestCase):
    def test_as_string_only_on_jstr(self):
        self.assertEqual(JStr("x").as_string().unwrap(), "x")
        self.assertTrue(JNum(1.0).as_string().is_none())
        self.assertTrue(JNull().as_string().is_none())

    def test_as_num_and_as_int_and_as_bool(self):
        self.assertEqual(JNum(2.5).as_num().unwrap(), 2.5)
        # as_int succeeds only on integer-valued numbers.
        self.assertEqual(JNum(2.0).as_int().unwrap(), 2)
        self.assertTrue(JNum(2.5).as_int().is_none())
        self.assertEqual(JBool(True).as_bool().unwrap(), True)
        self.assertTrue(JStr("x").as_bool().is_none())

    def test_as_number_alias_of_as_num(self):
        self.assertEqual(JNum(7.0).as_number().unwrap(), 7.0)
        self.assertTrue(JStr("nope").as_number().is_none())

    def test_as_array_as_object(self):
        arr = JArr([JNum(1.0), JNum(2.0)])
        listed = arr.as_array().unwrap()
        self.assertEqual(len(listed), 2)
        self.assertEqual(listed[0].as_num().unwrap(), 1.0)
        obj = JObj({"k": JStr("v")})
        mp = obj.as_object().unwrap()
        self.assertEqual(mp["k"].as_string().unwrap(), "v")

    def test_is_null(self):
        self.assertTrue(JNull().is_null())
        self.assertFalse(JNum(0.0).is_null())
        self.assertFalse(JBool(False).is_null())


class TestJsonParseRoundtrip(unittest.TestCase):
    def test_parse_object_then_query(self):
        r = parse_json('{"name": "Capa", "tests": 887, "alpha": false}')
        self.assertTrue(r.is_ok())
        v = r.unwrap()
        obj = v.as_object().unwrap()
        self.assertEqual(obj["name"].as_string().unwrap(), "Capa")
        self.assertEqual(obj["tests"].as_int().unwrap(), 887)
        self.assertEqual(obj["alpha"].as_bool().unwrap(), False)

    def test_parse_array(self):
        r = parse_json('[1, 2, 3]')
        arr = r.unwrap().as_array().unwrap()
        self.assertEqual([x.as_int().unwrap() for x in arr], [1, 2, 3])

    def test_parse_null(self):
        r = parse_json('null')
        self.assertTrue(r.unwrap().is_null())

    def test_parse_malformed_returns_err(self):
        r = parse_json('{not: valid}')
        self.assertTrue(r.is_err())

    def test_nan_infinity_constants_rejected(self):
        # RFC 8259 has no NaN / Infinity / -Infinity. json.loads
        # accepts them by default (allow_nan); the wrapper rejects
        # via parse_constant so both backends Err (the bundled
        # Wasm-side parser never accepted them).
        for doc in ("NaN", "Infinity", "-Infinity", "[NaN]",
                    '{"x": -Infinity}'):
            r = parse_json(doc)
            self.assertTrue(r.is_err(), doc)

    def test_to_json_never_crashes_on_non_finite(self):
        # Pre-fix, the int() collapse in _json_value_to_python
        # raised OverflowError on inf and ValueError on nan: a
        # non-Result crash reachable from data. A JNum can still
        # hold a non-finite float even though parse_json rejects
        # the constants, so to_json must stay total.
        self.assertEqual(to_json(JNum(float("inf"))), "Infinity")
        self.assertEqual(to_json(JNum(float("-inf"))), "-Infinity")
        self.assertEqual(to_json(JNum(float("nan"))), "NaN")

    def test_to_json_negative_zero_keeps_sign(self):
        # int(-0.0) is 0, so the integer collapse silently dropped
        # the sign ("0" on Python vs "-0" on Wasm pre-fix). The
        # agreed form is json.dumps's rendering of the real value.
        self.assertEqual(to_json(JNum(-0.0)), "-0.0")
        self.assertEqual(to_json(JNum(0.0)), "0")
        self.assertEqual(
            to_json(JArr([JNum(-0.0), JNum(0.0)])), "[-0.0, 0]"
        )

    def test_to_json_number_canonical_form(self):
        # Canonical number form (byte-identical on Python + Wasm):
        # an integer-valued JNum prints plain integer digits ONLY
        # when its shortest round-trip repr is non-scientific; an
        # integral float that repr spells with an exponent (>= 1e16)
        # keeps the exponent form, matching the Wasm ftoa spelling.
        self.assertEqual(to_json(JNum(0.0)), "0")
        self.assertEqual(to_json(JNum(1.0)), "1")
        self.assertEqual(to_json(JNum(-1.0)), "-1")
        self.assertEqual(to_json(JNum(100.0)), "100")
        self.assertEqual(to_json(JNum(1e15)), "1000000000000000")
        # 2**53: the largest power-of-two with every-integer-exact
        # neighbours; still decimal form.
        self.assertEqual(
            to_json(JNum(float(1 << 53))), "9007199254740992"
        )
        self.assertEqual(
            to_json(JNum(9999999999999998.0)), "9999999999999998"
        )
        # >= 1e16: repr uses an exponent, so NO integer collapse.
        # Pre-fix Python printed "10000000000000000" where Wasm
        # printed "1e+16"; the agreed form is the exponent.
        self.assertEqual(to_json(JNum(1e16)), "1e+16")
        self.assertEqual(to_json(JNum(1e20)), "1e+20")
        # Non-integers print the shortest round-tripping decimal.
        self.assertEqual(to_json(JNum(3.14)), "3.14")
        self.assertEqual(to_json(JNum(0.5)), "0.5")

    def test_nesting_depth_cap_mirrors_wasm(self):
        # __CJ_MAX_DEPTH=100 in capa/ir/_builtin_json.capa; the
        # wrapper enforces the same cap with the same message at
        # the same code-point position.
        ok_100 = "[" * 100 + "1" + "]" * 100
        self.assertTrue(parse_json(ok_100).is_ok())
        deep_101 = "[" * 101 + "1" + "]" * 101
        r = parse_json(deep_101)
        self.assertTrue(r.is_err())
        self.assertEqual(
            r.error, "max nesting depth 100 exceeded at 101"
        )

    def test_depth_scan_ignores_brackets_inside_strings(self):
        # The pre-scan must not count brackets in string values:
        # 200 '[' inside a quoted string nest nothing.
        doc = '{"k": "' + "[" * 200 + '"}'
        self.assertTrue(parse_json(doc).is_ok())

    def test_to_json_roundtrip(self):
        # Build a small JsonValue and round-trip through to_json /
        # parse_json. The semantic content should survive.
        v = JObj({
            "n": JNum(3.0),
            "s": JStr("hi"),
            "b": JBool(True),
            "nil": JNull(),
            "xs": JArr([JNum(1.0), JNum(2.0)]),
        })
        text = to_json(v)
        round = parse_json(text).unwrap().as_object().unwrap()
        self.assertEqual(round["n"].as_num().unwrap(), 3.0)
        self.assertEqual(round["s"].as_string().unwrap(), "hi")
        self.assertEqual(round["b"].as_bool().unwrap(), True)
        self.assertTrue(round["nil"].is_null())
        xs = round["xs"].as_array().unwrap()
        self.assertEqual([x.as_num().unwrap() for x in xs], [1.0, 2.0])


if __name__ == "__main__":
    unittest.main()
