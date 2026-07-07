"""Element-granular IFC labels for USER-DEFINED generic higher-order
functions (roadmap S2, Phase B2').

B1 made the BUILT-IN combinators (List/Range map/filter/fold/flat_map,
Option/Result map/and_then/filter/map_err) element-granular via a side
table. B2' extends that precision to user-defined generic combinators by
deriving the result ``(structure, element)`` split PER-CALL from the
function's SIGNATURE and the call's substitution map, by parametricity --
no label variables, no change to the type system.

A parameter is classified by WHERE its type-var lands in the result:

  transform closure   ``f: Fun(T) -> U``  for a ``List<U>`` result
                      -> folds ret_label into the ELEMENT only.
  passthrough input   ``xs: List<T>``     for a ``List<T>`` result
                      -> contributes its structure to the STRUCTURE, its
                         element to the ELEMENT.
  container-returning ``f: Fun(T) -> Option<U>`` for an ``Option<U>``
                      -> folds ret_label into the STRUCTURE (it decides
                         presence / cardinality).
  scalar-seed         a ``U`` seed / a ``T``-returning result
                      -> whole-value (no container split recorded).

The ELEMENT (and whole-value) label is pinned to the declassify-aware
whole-value floor the return-effect summary already computes; the
STRUCTURE is only ever LOWERED below that floor. So a structure query
(``length`` / ``is_empty`` / ``is_some``) over a generic HO result whose
elements are secret answers PUBLIC, while an element read stays tainted
and a whole-container sink is still flagged.

Bundled here: the confirmed B1 ``and_then`` strict-tier presence leak --
a container-returning closure choosing Some/None on a secret now makes
``.is_some()`` secret-derived (ERROR under @strict_ifc).
"""

import unittest

from capa import Lexer, Parser, analyze


def _analyze(src: str):
    return analyze(Parser(Lexer(src).lex(), source=src).parse_module(), source=src)


def _sink_warnings(r):
    return [w for w in r.warnings if "a @secret value reaches" in w.message]


def _sink_errors(r):
    return [e for e in r.errors if "a @secret value reaches" in e.message]


def _crossfn_warnings(r):
    """Cross-function boundary leaks: a @secret argument bound to a
    sink-reaching parameter of the callee."""
    return [w for w in r.warnings if "reaches a public sink inside" in w.message]


# A user-defined generic ``map`` and identity ``apply``.
_MYMAP = (
    "fun mymap<T, U>(f: Fun(T) -> U, xs: List<T>) -> List<U>\n"
    "    return xs.map(f)\n"
)
_APPLY = (
    "fun apply<T>(f: Fun(T) -> T, xs: List<T>) -> List<T>\n"
    "    return xs.map(f)\n"
)


class TestUserGenericStructureClean(unittest.TestCase):
    """A shape query over a user-generic mapped-secret container is
    CLEAN -- the structure label ignores the closure's captured secret."""

    def test_mymap_length_clean(self):
        r = _analyze(_MYMAP + (
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    let ys = mymap(fun (n: Int) -> String => s, xs)\n"
            "    stdio.println(\"${ys.length()}\")\n"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])

    def test_mymap_is_empty_clean(self):
        r = _analyze(_MYMAP + (
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    let ys = mymap(fun (n: Int) -> String => s, xs)\n"
            "    if ys.is_empty()\n"
            "        stdio.println(\"none\")\n"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])

    def test_mymap_length_clean_inline(self):
        # The structure op reads the split off the fresh call expression
        # (no intervening binding).
        r = _analyze(_MYMAP + (
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    stdio.println("
            "\"${mymap(fun (n: Int) -> String => s, xs).length()}\")\n"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])

    def test_apply_length_clean(self):
        r = _analyze(_APPLY + (
            "fun main(xs: List<Int>, s: @secret Int, stdio: Stdio)\n"
            "    let ys = apply(fun (n: Int) -> Int => s, xs)\n"
            "    stdio.println(\"${ys.length()}\")\n"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])


class TestUserGenericElementTainted(unittest.TestCase):
    """An element read of a user-generic mapped-secret container keeps
    warning by default and hard-errors under @strict_ifc."""

    def test_mymap_index_read_warns(self):
        r = _analyze(_MYMAP + (
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    let ys = mymap(fun (n: Int) -> String => s, xs)\n"
            "    let v = ys[0]\n"
            "    stdio.println(\"${v}\")\n"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])

    def test_mymap_for_iteration_warns(self):
        r = _analyze(_MYMAP + (
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    let ys = mymap(fun (n: Int) -> String => s, xs)\n"
            "    for y in ys\n"
            "        stdio.println(\"${y}\")\n"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertGreaterEqual(len(_sink_warnings(r)), 1,
                                [w.message for w in r.warnings])

    def test_mymap_get_read_warns(self):
        r = _analyze(_MYMAP + (
            "fun main(xs: List<Int>, s: @secret Int, stdio: Stdio)\n"
            "    let ys = mymap(fun (n: Int) -> Int => s, xs)\n"
            "    let v = ys.get(0).unwrap_or(0)\n"
            "    stdio.println(\"${v}\")\n"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertGreaterEqual(len(_sink_warnings(r)), 1,
                                [w.message for w in r.warnings])

    def test_mymap_index_read_strict_error(self):
        r = _analyze(_MYMAP + (
            "@strict_ifc()\n"
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    let ys = mymap(fun (n: Int) -> String => s, xs)\n"
            "    let v = ys[0]\n"
            "    stdio.println(\"${v}\")\n"
        ))
        self.assertFalse(r.ok, [w.message for w in r.warnings])
        self.assertGreaterEqual(len(_sink_errors(r)), 1,
                                [e.message for e in r.errors])


class TestUserGenericWholeContainerFlagged(unittest.TestCase):
    """Passing / sinking the WHOLE result container is still flagged: the
    whole-value label is the join of structure and element (= the floor)."""

    def test_mymap_whole_sink_warns(self):
        r = _analyze(_MYMAP + (
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    let ys = mymap(fun (n: Int) -> String => s, xs)\n"
            "    for y in ys\n"
            "        stdio.println(\"${y}\")\n"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertGreaterEqual(len(_sink_warnings(r)), 1,
                                [w.message for w in r.warnings])

    def test_mymap_pass_whole_to_sinking_callee_warns(self):
        r = _analyze(_MYMAP + (
            "fun leak(zs: List<String>, stdio: Stdio)\n"
            "    for z in zs\n"
            "        stdio.println(\"${z}\")\n"
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    let ys = mymap(fun (n: Int) -> String => s, xs)\n"
            "    leak(ys, stdio)\n"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertGreaterEqual(len(_crossfn_warnings(r)), 1,
                                [w.message for w in r.warnings])


class TestPassthroughSecretElement(unittest.TestCase):
    """Identity ``apply`` over a SECRET-element list: element =
    join(input element, closure ret_label), so an element read is
    tainted by the input's secret elements even with a public closure."""

    def test_apply_identity_secret_list_element_tainted(self):
        r = _analyze(_APPLY + (
            "fun main(stdio: Stdio, s: @secret Int)\n"
            "    let secret_list = [s, s]\n"
            "    let ys = apply(fun (n: Int) -> Int => n, secret_list)\n"
            "    let v = ys[0]\n"
            "    stdio.println(\"${v}\")\n"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])


class TestTransitiveGeneric(unittest.TestCase):
    """A generic HO whose body calls ANOTHER generic HO derives the same
    split from its own signature -- no cross-function fixpoint needed."""

    _NEST = (
        "fun mymap<T, U>(f: Fun(T) -> U, xs: List<T>) -> List<U>\n"
        "    return xs.map(f)\n"
        "fun apply2<T, U>(f: Fun(T) -> U, xs: List<T>) -> List<U>\n"
        "    return mymap(f, xs)\n"
    )

    def test_transitive_length_clean(self):
        r = _analyze(self._NEST + (
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    let ys = apply2(fun (n: Int) -> String => s, xs)\n"
            "    stdio.println(\"${ys.length()}\")\n"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])

    def test_transitive_element_read_warns(self):
        r = _analyze(self._NEST + (
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    let ys = apply2(fun (n: Int) -> String => s, xs)\n"
            "    let v = ys[0]\n"
            "    stdio.println(\"${v}\")\n"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])


class TestDeclassifyInBodyFloor(unittest.TestCase):
    """A generic body that internally declassifies the returned value has
    an empty return-effect, so the floor is PUBLIC: the caller's element
    and whole reads are CLEAN (the floor wins over the captured secret)."""

    _REVEAL = (
        "fun revealing<T, U>(f: Fun(T) -> U, xs: List<T>) -> List<U>\n"
        "    let mapped = xs.map(f)\n"
        "    return declassify(mapped, reason: \"audited\")\n"
    )

    def test_declassify_body_element_read_clean(self):
        r = _analyze(self._REVEAL + (
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    let ys = revealing(fun (n: Int) -> String => s, xs)\n"
            "    let v = ys[0]\n"
            "    stdio.println(\"${v}\")\n"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])

    def test_declassify_body_whole_sink_clean(self):
        r = _analyze(self._REVEAL + (
            "fun main(xs: List<Int>, s: @secret String, stdio: Stdio)\n"
            "    let ys = revealing(fun (n: Int) -> String => s, xs)\n"
            "    for y in ys\n"
            "        stdio.println(\"${y}\")\n"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])


class TestAndThenStrictPresenceLeak(unittest.TestCase):
    """The confirmed B1 false negative: a container-returning closure that
    chooses Some/None on a secret makes ``.is_some()`` / ``.is_none()``
    secret-derived. Fixed by folding a container-returning closure's
    ret_label into the STRUCTURE (built-in ``_COMBINATOR_SPECS`` bind)."""

    def test_option_and_then_is_some_strict_error(self):
        r = _analyze(
            "@strict_ifc()\n"
            "fun main(o: Option<Int>, s: @secret Bool, stdio: Stdio)\n"
            "    let r = o.and_then("
            "fun (x: Int) -> Option<Int> => if s then Some(x) else None)\n"
            "    stdio.println(\"${r.is_some()}\")\n"
        )
        self.assertFalse(r.ok, [w.message for w in r.warnings])
        self.assertGreaterEqual(len(_sink_errors(r)), 1,
                                [e.message for e in r.errors])

    def test_option_and_then_is_none_strict_error(self):
        r = _analyze(
            "@strict_ifc()\n"
            "fun main(o: Option<Int>, s: @secret Bool, stdio: Stdio)\n"
            "    let r = o.and_then("
            "fun (x: Int) -> Option<Int> => if s then Some(x) else None)\n"
            "    stdio.println(\"${r.is_none()}\")\n"
        )
        self.assertFalse(r.ok, [w.message for w in r.warnings])
        self.assertGreaterEqual(len(_sink_errors(r)), 1,
                                [e.message for e in r.errors])

    def test_result_and_then_is_ok_strict_error(self):
        r = _analyze(
            "@strict_ifc()\n"
            "fun main(res: Result<Int, String>, s: @secret Bool, stdio: Stdio)\n"
            "    let r = res.and_then("
            "fun (x: Int) -> Result<Int, String> => "
            "if s then Ok(x) else Err(\"no\"))\n"
            "    stdio.println(\"${r.is_ok()}\")\n"
        )
        self.assertFalse(r.ok, [w.message for w in r.warnings])
        self.assertGreaterEqual(len(_sink_errors(r)), 1,
                                [e.message for e in r.errors])

    def test_and_then_public_closure_is_some_clean(self):
        # A public-choosing and_then keeps the shape query clean (no FP).
        r = _analyze(
            "@strict_ifc()\n"
            "fun main(o: Option<Int>, stdio: Stdio)\n"
            "    let r = o.and_then("
            "fun (x: Int) -> Option<Int> => if x > 0 then Some(x) else None)\n"
            "    stdio.println(\"${r.is_some()}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_errors(r), [], [e.message for e in r.errors])


class TestBuiltinB1Unchanged(unittest.TestCase):
    """The B1 built-in map / filter structure-op verdicts are unchanged
    by B2' (the bind fix touches only and_then / flat_map)."""

    def test_map_is_some_still_clean(self):
        r = _analyze(
            "fun main(o: Option<Int>, s: @secret Int, stdio: Stdio)\n"
            "    let m = o.map(fun (x: Int) -> Int => s)\n"
            "    if m.is_some()\n"
            "        stdio.println(\"has value\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [], [w.message for w in r.warnings])

    def test_filter_secret_predicate_length_still_warns(self):
        r = _analyze(
            "fun main(xs: List<Int>, s: @secret Int, stdio: Stdio)\n"
            "    let ys = xs.filter(fun (n: Int) -> Bool => n == s)\n"
            "    stdio.println(\"${ys.length()}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])


if __name__ == "__main__":
    unittest.main()
