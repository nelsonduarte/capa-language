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

    def test_parse_float(self):
        self.assertEqual(parse_float("3.14").unwrap(), 3.14)
        self.assertEqual(parse_float("  -0.5  ").unwrap(), -0.5)
        self.assertTrue(parse_float("nope").is_none())
        self.assertTrue(parse_float(None).is_none())

    def test_to_float_and_to_int(self):
        self.assertEqual(to_float(3), 3.0)
        self.assertEqual(to_int(3.7), 3)
        self.assertEqual(to_int(-0.9), 0)  # truncates toward zero

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
