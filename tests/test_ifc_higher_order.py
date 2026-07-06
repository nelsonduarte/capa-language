"""Higher-order information-flow: closure return labels (roadmap S2, Phase A).

The intra- and cross-function IFC passes catch a @secret value reaching a
public sink directly or through a data parameter. They MISSED a @secret
captured by a closure and reached at a public sink through a ``Fun``-typed
value once the closure was routed through a value whose declared type
erased the capture -- a struct field, a reassigned ``var``, or a function
return. This module is the acceptance oracle for closing those higher-order
false negatives WITHOUT trading them for false positives.

Phase A makes the flow label ride on the function type as a CONSTANT: a
closure that returns a @secret value has ``ret_label = secret`` on its
``TyFun``; storing it where a public-returning function type is declared is
a store-site leak (warn by default, hard error under ``@strict_ifc``). A
declassifying or public closure has ``ret_label = public`` and stays clean.

The oracle matrix (from the design doc):

Close-the-holes (must REJECT under @strict_ifc; each was wrongly ACCEPTED):
  R1 closure by name through a Fun param, invoked at a public sink
  R2 closure stored in a struct field, then invoked at a sink
  R3 closure in a reassigned var (public then secret), then invoked
  R4 closure whose binding RHS is a call result, laundered by return

Stay-clean (must NOT regress to a false positive):
  C1 declassifying closure reaching a sink
  C2 public closure reaching a sink
  C3 Fun param never invoked
  C4 Fun result returned but not sunk
  C5 closure capturing only its own parameter
"""

import unittest

from capa import Lexer, Parser, analyze


def _analyze(src: str):
    return analyze(Parser(Lexer(src).lex(), source=src).parse_module(), source=src)


# A higher-order callee that INVOKES its Fun parameter and sinks the result.
_INVOKE = (
    "fun invoke(f: Fun() -> String, stdio: Stdio)\n"
    "    stdio.eprintln(f())\n"
)


def _ho_errors(r):
    """Errors from the higher-order store-site closure-return-label check."""
    return [
        e for e in r.errors
        if "closure that returns a @secret value" in e.message
    ]


def _crossfn_errors(r):
    return [e for e in r.errors if "reaches a public sink inside" in e.message]


class TestCloseHoles(unittest.TestCase):
    """R1..R4: each shape leaks a captured @secret to a public sink through
    a ``Fun``-typed value and must be a hard error under @strict_ifc."""

    def test_R1_closure_by_name_to_invoke_sink(self):
        # A let-bound closure passed BY NAME to an invoke-sink callee.
        r = _analyze(
            _INVOKE
            + "@strict_ifc()\n"
            "fun main(stdio: Stdio, s: @secret String)\n"
            "    let f = fun () -> String => s\n"
            "    invoke(f, stdio)\n"
        )
        self.assertFalse(r.ok, [w.message for w in r.warnings])
        self.assertEqual(len(_crossfn_errors(r)), 1,
                         [e.message for e in r.errors])

    def test_R2_closure_in_struct_field_to_invoke_sink(self):
        r = _analyze(
            "type Box { thunk: Fun() -> String }\n"
            + _INVOKE
            + "@strict_ifc()\n"
            "fun main(stdio: Stdio, s: @secret String)\n"
            "    let b = Box { thunk: fun () -> String => s }\n"
            "    invoke(b.thunk, stdio)\n"
        )
        self.assertFalse(r.ok, [w.message for w in r.warnings])
        self.assertEqual(len(_ho_errors(r)), 1,
                         [e.message for e in r.errors])

    def test_R3_closure_in_reassigned_var_to_invoke_sink(self):
        # First a public closure (public-returning slot type), then a
        # secret closure reassigned in -> store-site leak.
        r = _analyze(
            _INVOKE
            + "@strict_ifc()\n"
            "fun main(stdio: Stdio, s: @secret String)\n"
            "    var f = fun () -> String => \"pub\"\n"
            "    f = fun () -> String => s\n"
            "    invoke(f, stdio)\n"
        )
        self.assertFalse(r.ok, [w.message for w in r.warnings])
        self.assertEqual(len(_ho_errors(r)), 1,
                         [e.message for e in r.errors])

    def test_R4_closure_from_call_result_laundered_by_return(self):
        # ``make`` returns a secret-capturing closure as a public-returning
        # function type -- laundering the capture to the caller. The lie is
        # caught at ``make``'s return under its @strict_ifc contract.
        r = _analyze(
            "@strict_ifc()\n"
            "fun make(s: @secret String) -> Fun() -> String\n"
            "    return fun () -> String => s\n"
            + _INVOKE
            + "@strict_ifc()\n"
            "fun main(stdio: Stdio, s: @secret String)\n"
            "    let g = make(s)\n"
            "    invoke(g, stdio)\n"
        )
        self.assertFalse(r.ok, [w.message for w in r.warnings])
        self.assertEqual(len(_ho_errors(r)), 1,
                         [e.message for e in r.errors])


class TestStayClean(unittest.TestCase):
    """C1..C5: shapes that must NOT become false positives under strict."""

    def test_C1_declassifying_closure_is_clean(self):
        # The closure declassifies its captured secret, so its RETURN label
        # is public -- storing / invoking it is clean.
        r = _analyze(
            "const TOKEN: @secret String = \"sk\"\n"
            + _INVOKE
            + "@strict_ifc()\n"
            "fun main(stdio: Stdio)\n"
            "    let f = fun () -> String => declassify(TOKEN, reason: \"ok\")\n"
            "    invoke(f, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_ho_errors(r), [])
        self.assertEqual(_crossfn_errors(r), [])

    def test_C2_public_closure_is_clean(self):
        r = _analyze(
            _INVOKE
            + "@strict_ifc()\n"
            "fun main(stdio: Stdio)\n"
            "    let f = fun () -> String => \"public\"\n"
            "    invoke(f, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_ho_errors(r), [])
        self.assertEqual(_crossfn_errors(r), [])

    def test_C3_fun_param_not_invoked_is_clean(self):
        # ``store`` receives a secret-returning closure but only RETURNS it
        # (its parameter, a public-returning type); it never invokes/sinks
        # it, so there is no leak and no false positive.
        r = _analyze(
            "fun store(f: Fun() -> String) -> Fun() -> String\n"
            "    return f\n"
            "@strict_ifc()\n"
            "fun main(env: Env)\n"
            "    let s = env.get(\"SECRET\").unwrap_or(\"d\")\n"
            "    let g = store(fun () -> String => s)\n"
            "    let _ = g\n"
            "    ()\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_ho_errors(r), [])

    def test_C4_fun_result_returned_not_sunk_is_clean(self):
        # ``apply`` invokes the closure and RETURNS the result (declared
        # public) without an internal sink -> no leak inside apply.
        r = _analyze(
            "fun apply(f: Fun() -> String) -> String\n"
            "    return f()\n"
            "@strict_ifc()\n"
            "fun main(env: Env)\n"
            "    let s = env.get(\"SECRET\").unwrap_or(\"d\")\n"
            "    let r = apply(fun () -> String => s)\n"
            "    let _ = r\n"
            "    ()\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_ho_errors(r), [])

    def test_C5_closure_capturing_own_param_only_is_clean(self):
        # ``fun (x) => x`` captures nothing free; its return label is its
        # (public) parameter label, so it is a public-returning closure.
        r = _analyze(
            "fun apply2(f: Fun(String) -> String, stdio: Stdio)\n"
            "    stdio.eprintln(f(\"x\"))\n"
            "@strict_ifc()\n"
            "fun main(stdio: Stdio)\n"
            "    apply2(fun (x: String) -> String => x, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_ho_errors(r), [])
        self.assertEqual(_crossfn_errors(r), [])


class TestSyntacticReturnLabel(unittest.TestCase):
    """A ``Fun() -> @secret String`` annotation carries its return label
    onto the resolved function type instead of dropping it, so a slot that
    DECLARES a secret-returning function accepts a secret-returning closure
    with no false positive."""

    def test_secret_returning_slot_accepts_secret_closure(self):
        r = _analyze(
            "type Box { thunk: Fun() -> @secret String }\n"
            "@strict_ifc()\n"
            "fun main(s: @secret String)\n"
            "    let b = Box { thunk: fun () -> String => s }\n"
            "    let _ = b\n"
            "    ()\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_ho_errors(r), [])


class TestCombinatorNoFalsePositive(unittest.TestCase):
    """Built-in higher-order combinators must NOT become false positives on
    a secret-returning closure: passing one as a call ARGUMENT is not a
    store-site leak (Phase A keeps combinators' no-propagation behavior)."""

    def test_map_secret_closure_no_store_leak(self):
        r = _analyze(
            "@strict_ifc()\n"
            "fun main(xs: List<Int>, s: @secret String)\n"
            "    let ys = xs.map(fun (n: Int) -> String => s)\n"
            "    let _ = ys\n"
            "    ()\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_ho_errors(r), [])


if __name__ == "__main__":
    unittest.main()
