"""Element-granular IFC labels for built-in combinators (roadmap S2, Phase B1).

Phase A closed the higher-order SOUNDNESS holes (a secret-returning closure
stored / passed into a public ``Fun`` slot). B1 is a PRECISION upgrade on the
IFC VALUE-label channel for the built-in combinators (List / Range
``map`` / ``filter`` / ``fold`` / ``flat_map``; Option ``map`` / ``and_then`` /
``filter``; Result ``map`` / ``and_then`` / ``map_err``).

The coarse whole-value join tainted the ENTIRE result of ``xs.map(secretClosure)``,
so a STRUCTURE query (``length`` / ``is_empty`` / ``is_some`` / ...) warned even
though a count is public -- a FALSE POSITIVE, the worse failure under the
project posture. B1 makes a combinator result element-granular: a shape query
reads the (public) structure label while an element read (indexing, iteration,
a payload unwrap) reads the (secret) element label.

Acceptance matrix (the ``FLIP`` rows warned before B1 and must be CLEAN now; the
``STAY`` rows are true positives that must keep warning by default and hard-error
under ``@strict_ifc``):

  FLIP  length / is_empty / is_some / is_ok of a map-of-secret-closure result
  STAY  an element read (index / for / unwrap) of the same mapped result
  filter drops the predicate label (elements pass through unchanged)
  map with a public closure over a secret list still taints element reads
  fold  result = join(init, element, closure ret_label)
  declassify of a mapped result clears every read
"""

import unittest

from capa import Lexer, Parser, analyze


def _analyze(src: str):
    return analyze(Parser(Lexer(src).lex(), source=src).parse_module(), source=src)


def _sink_warnings(r):
    """Intra-procedural sink warnings (a @secret value reaching a public sink)."""
    return [w for w in r.warnings if "a @secret value reaches" in w.message]


def _sink_errors(r):
    return [e for e in r.errors if "a @secret value reaches" in e.message]


class TestStructureOpsClean(unittest.TestCase):
    """FLIP-TO-CLEAN: a shape query over a mapped-secret container no longer
    warns -- the false positive the coarse whole-value join created."""

    def test_list_map_length_clean(self):
        r = _analyze(
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    let ys = xs.map(fun (n: Int) -> String => s)\n"
            "    stdio.println(\"${ys.length()}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])

    def test_list_map_is_empty_clean(self):
        r = _analyze(
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    let ys = xs.map(fun (n: Int) -> String => s)\n"
            "    if ys.is_empty()\n"
            "        stdio.println(\"none\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])

    def test_list_map_length_clean_inline_chain(self):
        # The structure op reads the split even off the fresh call expression
        # (no intervening binding).
        r = _analyze(
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    stdio.println("
            "\"${xs.map(fun (n: Int) -> String => s).length()}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])

    def test_option_map_is_some_clean(self):
        r = _analyze(
            "fun main(o: Option<Int>, s: @secret Int, stdio: Stdio)\n"
            "    let m = o.map(fun (x: Int) -> Int => s)\n"
            "    if m.is_some()\n"
            "        stdio.println(\"has value\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])

    def test_result_map_is_ok_clean(self):
        r = _analyze(
            "fun main(res: Result<Int, String>, s: @secret Int, stdio: Stdio)\n"
            "    let m = res.map(fun (x: Int) -> Int => s)\n"
            "    if m.is_ok()\n"
            "        stdio.println(\"ok\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])


class TestElementReadsTainted(unittest.TestCase):
    """STAY-TAINTED: an element read of a mapped-secret container keeps
    warning by default and becomes a hard error under @strict_ifc."""

    def test_list_map_index_read_warns(self):
        r = _analyze(
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    let ys = xs.map(fun (n: Int) -> String => s)\n"
            "    let v = ys[0]\n"
            "    stdio.println(\"${v}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])

    def test_list_map_for_iteration_warns(self):
        r = _analyze(
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    let ys = xs.map(fun (n: Int) -> String => s)\n"
            "    for y in ys\n"
            "        stdio.println(\"${y}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertGreaterEqual(len(_sink_warnings(r)), 1,
                                [w.message for w in r.warnings])

    def test_list_map_index_read_strict_error(self):
        r = _analyze(
            "@strict_ifc()\n"
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    let ys = xs.map(fun (n: Int) -> String => s)\n"
            "    let v = ys[0]\n"
            "    stdio.println(\"${v}\")\n"
        )
        self.assertFalse(r.ok, [w.message for w in r.warnings])
        self.assertGreaterEqual(len(_sink_errors(r)), 1,
                                [e.message for e in r.errors])

    def test_option_map_unwrap_warns(self):
        r = _analyze(
            "fun main(o: Option<Int>, s: @secret Int, stdio: Stdio)\n"
            "    let m = o.map(fun (x: Int) -> Int => s)\n"
            "    let v = m.unwrap_or(0)\n"
            "    stdio.println(\"${v}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])


class TestFilterElementPreserved(unittest.TestCase):
    """filter keeps the ELEMENT label of the input (the survivors are a
    subset of the input's elements): a public-element read of a filtered
    list stays clean even when the predicate is secret, while a
    secret-element list stays secret through filter regardless of the
    predicate."""

    def test_public_list_secret_predicate_element_read_clean(self):
        # The ELEMENTS are genuinely public (a subset of the public input);
        # only the cardinality is secret. An element read stays clean.
        r = _analyze(
            "fun main(xs: List<Int>, s: @secret Int, stdio: Stdio)\n"
            "    let ys = xs.filter(fun (n: Int) -> Bool => n == s)\n"
            "    let v = ys[0]\n"
            "    stdio.println(\"${v}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])

    def test_secret_element_list_public_predicate_element_read_warns(self):
        # A public predicate over a secret-element list: the surviving
        # elements are still secret, so an element read warns.
        r = _analyze(
            "fun main(stdio: Stdio, s: @secret Int)\n"
            "    let secret_list = [s, s]\n"
            "    let ys = secret_list.filter(fun (n: Int) -> Bool => n > 0)\n"
            "    let v = ys[0]\n"
            "    stdio.println(\"${v}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])


class TestFilterStructureLeak(unittest.TestCase):
    """A filter's CARDINALITY is decided by the predicate, so a
    secret-dependent predicate makes the result's structure (length /
    is_empty / is_some) a disclosure -- ``xs.filter(fun (n) => n == s)``
    has length 1 iff ``s`` is in ``xs``. A structure op over such a result
    must WARN by default and hard-error under @strict_ifc. A PUBLIC
    predicate leaves the structure as public as the input's."""

    def test_list_filter_secret_predicate_length_warns(self):
        r = _analyze(
            "fun main(xs: List<Int>, s: @secret Int, stdio: Stdio)\n"
            "    let ys = xs.filter(fun (n: Int) -> Bool => n == s)\n"
            "    stdio.println(\"${ys.length()}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])

    def test_list_filter_secret_predicate_is_empty_warns(self):
        r = _analyze(
            "fun main(xs: List<Int>, s: @secret Int, stdio: Stdio)\n"
            "    let ys = xs.filter(fun (n: Int) -> Bool => n == s)\n"
            "    let empty = ys.is_empty()\n"
            "    stdio.println(\"${empty}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])

    def test_list_filter_secret_predicate_length_strict_error(self):
        r = _analyze(
            "@strict_ifc()\n"
            "fun main(xs: List<Int>, s: @secret Int, stdio: Stdio)\n"
            "    let ys = xs.filter(fun (n: Int) -> Bool => n == s)\n"
            "    stdio.println(\"${ys.length()}\")\n"
        )
        self.assertFalse(r.ok, [w.message for w in r.warnings])
        self.assertGreaterEqual(len(_sink_errors(r)), 1,
                                [e.message for e in r.errors])

    def test_range_filter_secret_predicate_length_warns(self):
        r = _analyze(
            "fun main(s: @secret Int, stdio: Stdio)\n"
            "    let rng = 0..10\n"
            "    let ys = rng.filter(fun (n: Int) -> Bool => n == s)\n"
            "    stdio.println(\"${ys.length()}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])

    def test_option_filter_secret_predicate_is_some_warns(self):
        r = _analyze(
            "fun main(o: Option<Int>, s: @secret Int, stdio: Stdio)\n"
            "    let m = o.filter(fun (x: Int) -> Bool => x == s)\n"
            "    let some = m.is_some()\n"
            "    stdio.println(\"${some}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])

    def test_option_filter_secret_predicate_is_none_warns(self):
        r = _analyze(
            "fun main(o: Option<Int>, s: @secret Int, stdio: Stdio)\n"
            "    let m = o.filter(fun (x: Int) -> Bool => x == s)\n"
            "    let empty = m.is_none()\n"
            "    stdio.println(\"${empty}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])

    def test_public_predicate_length_clean(self):
        # A public predicate contributes a public ret_label, so the
        # structure query stays clean (the intended precision is kept).
        r = _analyze(
            "fun main(xs: List<Int>, stdio: Stdio)\n"
            "    let ys = xs.filter(fun (n: Int) -> Bool => n > 0)\n"
            "    stdio.println(\"${ys.length()}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])

    def test_public_predicate_element_read_clean(self):
        r = _analyze(
            "fun main(xs: List<Int>, stdio: Stdio)\n"
            "    let ys = xs.filter(fun (n: Int) -> Bool => n > 0)\n"
            "    let v = ys[0]\n"
            "    stdio.println(\"${v}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])


class TestMapPublicClosureOverSecretList(unittest.TestCase):
    """A public closure over a SECRET-element list still taints element reads:
    element label = join(input element label, closure ret_label)."""

    def test_public_closure_secret_list_element_tainted(self):
        r = _analyze(
            "fun main(stdio: Stdio, s: @secret Int)\n"
            "    let secret_list = [s, s]\n"
            "    let ys = secret_list.map(fun (n: Int) -> Int => n + 1)\n"
            "    let v = ys[0]\n"
            "    stdio.println(\"${v}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])


class TestFold(unittest.TestCase):
    """fold produces a scalar whose label is join(init, element, ret_label)."""

    def test_secret_init_taints_result(self):
        r = _analyze(
            "fun main(xs: List<Int>, s: @secret Int, stdio: Stdio)\n"
            "    let total = xs.fold(s, "
            "fun (acc: Int, n: Int) -> Int => acc + n)\n"
            "    stdio.println(\"${total}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])

    def test_all_public_fold_clean(self):
        r = _analyze(
            "fun main(xs: List<Int>, stdio: Stdio)\n"
            "    let total = xs.fold(0, "
            "fun (acc: Int, n: Int) -> Int => acc + n)\n"
            "    stdio.println(\"${total}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])


class TestDeclassifyClears(unittest.TestCase):
    """declassify of a mapped-secret result clears every read (structure and
    element), the auditable secret -> public bridge."""

    def test_declassify_mapped_result_clears_element(self):
        r = _analyze(
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    let ys = xs.map(fun (n: Int) -> String => s)\n"
            "    let zs = declassify(ys, reason: \"reviewed\")\n"
            "    for z in zs\n"
            "        stdio.println(\"${z}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])


if __name__ == "__main__":
    unittest.main()
