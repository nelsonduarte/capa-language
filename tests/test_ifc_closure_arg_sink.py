"""Cross-function sink flow for a Fun argument bound to a call result.

The cross-function sink check flags a @secret value routed to a callee
parameter that reaches a public sink inside the callee. For a Fun-typed
parameter the callee invokes and sinks (the invoke-sink-reaching case),
the label tested is what the closure returns. That label was recovered
only for an inline lambda or a name bound to a single certain lambda
literal; a Fun argument whose binding RHS is a CALL RESULT (or a by-name
alias, a struct field, a re-passed parameter, or an inline call result)
was SKIPPED, a documented false negative.

The live leak that skip left open (measured at the previous commit: the
program below runs and prints the secret, clean under @strict_ifc):

    fun make(env: Env) -> Fun() -> @secret String
        let k = env.get("K").unwrap_or("d")
        return fun () => k
    fun invoke(f: Fun() -> String, stdio: Stdio)
        stdio.println(f())
    fun main(env: Env, stdio: Stdio)
        let f = make(env)
        invoke(f, stdio)

``make`` is HONEST -- it declares a secret-returning function type, so no
store-site leak fires at its return -- yet ``invoke`` sinks the closure's
result through a public ``Fun`` parameter. The fix recovers the argument's
declassify-aware ``TyFun.ret_label`` from its resolved type on the sink
path, so this warns by default and hard-errors under @strict_ifc, while a
factory that declassifies internally (public return type) stays clean.

Fail-first: every REJECT case below compiled clean (both tiers) before the
fix; the STAY-CLEAN cases are the regression guard against a false
positive on the reassigned-var ambiguity and the declassify factory.
"""

import unittest

from capa import Lexer, Parser, analyze


def _analyze(src: str):
    return analyze(Parser(Lexer(src).lex(), source=src).parse_module(), source=src)


def _strict(src: str):
    return _analyze(src.replace("fun main", "@strict_ifc()\nfun main"))


def _crossfn_warnings(r):
    return [w for w in r.warnings if "reaches a public sink inside" in w.message]


def _crossfn_errors(r):
    return [e for e in r.errors if "reaches a public sink inside" in e.message]


_INVOKE = (
    "fun invoke(f: Fun() -> String, stdio: Stdio)\n"
    "    stdio.println(f())\n"
)

_HONEST_FACTORY = (
    "fun make(env: Env) -> Fun() -> @secret String\n"
    "    let k = env.get(\"K\").unwrap_or(\"d\")\n"
    "    return fun () => k\n"
)

_DECLASSIFY_FACTORY = (
    "fun make(env: Env) -> Fun() -> String\n"
    "    let k = env.get(\"K\").unwrap_or(\"d\")\n"
    "    return fun () => declassify(k, reason: \"ok\")\n"
)


class TestCallResultBoundClosureSink(unittest.TestCase):
    """The call-result-binding false negative is closed."""

    def test_honest_secret_factory_result_invoked_warns_default(self):
        r = _analyze(
            _HONEST_FACTORY + _INVOKE
            + "fun main(env: Env, stdio: Stdio)\n"
            "    let f = make(env)\n"
            "    invoke(f, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_crossfn_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_honest_secret_factory_result_invoked_strict_error(self):
        r = _strict(
            _HONEST_FACTORY + _INVOKE
            + "fun main(env: Env, stdio: Stdio)\n"
            "    let f = make(env)\n"
            "    invoke(f, stdio)\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(_crossfn_errors(r)), 1,
                         [e.message for e in r.errors])

    def test_secret_factory_result_passed_inline_warns(self):
        # The call result passed directly as the argument (no binding).
        r = _analyze(
            _HONEST_FACTORY + _INVOKE
            + "fun main(env: Env, stdio: Stdio)\n"
            "    invoke(make(env), stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_crossfn_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_method_call_result_bound_closure_sink_warns(self):
        # The same recovery on the METHOD-call sink path.
        r = _analyze(
            _HONEST_FACTORY
            + "type Logger { n: Int }\n"
            "impl Logger\n"
            "    fun run(self, f: Fun() -> String, stdio: Stdio)\n"
            "        stdio.println(f())\n"
            "fun main(env: Env, stdio: Stdio)\n"
            "    let lg = Logger { n: 1 }\n"
            "    let f = make(env)\n"
            "    lg.run(f, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_crossfn_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_method_call_result_bound_closure_sink_strict_error(self):
        r = _strict(
            _HONEST_FACTORY
            + "type Logger { n: Int }\n"
            "impl Logger\n"
            "    fun run(self, f: Fun() -> String, stdio: Stdio)\n"
            "        stdio.println(f())\n"
            "fun main(env: Env, stdio: Stdio)\n"
            "    let lg = Logger { n: 1 }\n"
            "    let f = make(env)\n"
            "    lg.run(f, stdio)\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(_crossfn_errors(r)), 1,
                         [e.message for e in r.errors])


class TestClosureArgSinkStaysClean(unittest.TestCase):
    """Regression guard: no false positive on the ambiguous or declassified
    shapes, and the whole point of the sink-path recovery -- a closure that
    is passed but never sunk is not affected."""

    def test_declassify_factory_result_invoked_is_clean(self):
        r = _analyze(
            _DECLASSIFY_FACTORY + _INVOKE
            + "fun main(env: Env, stdio: Stdio)\n"
            "    let f = make(env)\n"
            "    invoke(f, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_crossfn_warnings(r), [])

    def test_declassify_factory_result_invoked_is_clean_strict(self):
        r = _strict(
            _DECLASSIFY_FACTORY + _INVOKE
            + "fun main(env: Env, stdio: Stdio)\n"
            "    let f = make(env)\n"
            "    invoke(f, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_crossfn_errors(r), [])

    def test_reassigned_var_secret_then_public_no_false_positive(self):
        # A var reassigned from a secret closure to a public one: its joined
        # resolved type can read secret, but it now holds a public closure --
        # the ambiguous denotation must be skipped, not flagged.
        r = _strict(
            _INVOKE
            + "fun main(stdio: Stdio, s: @secret String)\n"
            "    var f = fun () -> String => s\n"
            "    f = fun () -> String => \"pub\"\n"
            "    invoke(f, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_crossfn_errors(r), [])


class TestExistingClosureShapesStillFlagged(unittest.TestCase):
    """The already-working precise shapes stay flagged (no regression)."""

    def test_inline_secret_closure_still_flagged(self):
        r = _strict(
            _INVOKE
            + "fun main(stdio: Stdio, s: @secret String)\n"
            "    invoke(fun () -> String => s, stdio)\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(_crossfn_errors(r)), 1,
                         [e.message for e in r.errors])

    def test_let_bound_lambda_still_flagged(self):
        r = _strict(
            _INVOKE
            + "fun main(stdio: Stdio, s: @secret String)\n"
            "    let f = fun () -> String => s\n"
            "    invoke(f, stdio)\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(_crossfn_errors(r)), 1,
                         [e.message for e in r.errors])


if __name__ == "__main__":
    unittest.main()
