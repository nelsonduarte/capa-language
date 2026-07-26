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

    def test_reassigned_var_secret_then_public_default_clean_strict_flagged(self):
        # A var reassigned from a secret closure to a public one has an
        # ambiguous denotation (its joined resolved type reads secret while
        # it now holds a public closure). The DEFAULT tier stays precise and
        # skips it (no false positive). The STRICT tier fails closed and
        # flags it -- an accepted strict-tier over-rejection, the price of
        # closing the mixed-var-holds-secret leak without a warn-tier FP.
        src = (
            _INVOKE
            + "fun main(stdio: Stdio, s: @secret String)\n"
            "    var f = fun () -> String => s\n"
            "    f = fun () -> String => \"pub\"\n"
            "    invoke(f, stdio)\n"
        )
        r = _analyze(src)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_crossfn_warnings(r), [])
        rs = _strict(src)
        self.assertFalse(rs.ok)
        self.assertEqual(len(_crossfn_errors(rs)), 1,
                         [e.message for e in rs.errors])

    def test_mixed_var_public_then_secret_flagged_strict(self):
        # A var declared with a secret-returning slot, assigned a PUBLIC
        # decoy first (which marks it ever-public) then a SECRET closure it
        # actually holds at the sink. The default tier skips it (ever-public,
        # best-effort), but the strict tier must reject this real leak.
        src = (
            _INVOKE
            + "fun main(env: Env, stdio: Stdio)\n"
            "    let k = env.get(\"K\").unwrap_or(\"d\")\n"
            "    var f: Fun() -> @secret String = fun () => \"PUBLIC-DECOY\"\n"
            "    f = fun () => k\n"
            "    invoke(f, stdio)\n"
        )
        r = _analyze(src)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_crossfn_warnings(r), [])
        rs = _strict(src)
        self.assertFalse(rs.ok)
        self.assertEqual(len(_crossfn_errors(rs)), 1,
                         [e.message for e in rs.errors])


class TestReassignedVarHoldsSecretIsFlagged(unittest.TestCase):
    """A reassigned ``var`` that holds a secret-returning closure on EVERY
    path -- every closure assigned to it is secret-returning -- is sunk
    through a public ``Fun`` parameter and must be flagged. Previously the
    reassignment poisoned the by-name record and the sink check skipped it
    (a measured fail-open: --run printed the secret, clean under strict).
    Each shape below was clean in both tiers before this change."""

    def test_A1_inferred_secret_reassign_flagged(self):
        src = (
            _INVOKE
            + "fun main(stdio: Stdio, s: @secret String)\n"
            "    var f = fun () -> String => s\n"
            "    f = fun () -> String => s\n"
            "    invoke(f, stdio)\n"
        )
        r = _analyze(src)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_crossfn_warnings(r)), 1,
                         [w.message for w in r.warnings])
        rs = _strict(src)
        self.assertFalse(rs.ok)
        self.assertEqual(len(_crossfn_errors(rs)), 1,
                         [e.message for e in rs.errors])

    def test_A2_typed_secret_reassign_flagged(self):
        src = (
            _INVOKE
            + "fun main(stdio: Stdio, s: @secret String)\n"
            "    var f: Fun() -> @secret String = fun () => s\n"
            "    f = fun () => s\n"
            "    invoke(f, stdio)\n"
        )
        r = _analyze(src)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_crossfn_warnings(r)), 1,
                         [w.message for w in r.warnings])
        rs = _strict(src)
        self.assertFalse(rs.ok)
        self.assertEqual(len(_crossfn_errors(rs)), 1,
                         [e.message for e in rs.errors])

    def test_A3_reassign_to_secret_call_result_flagged(self):
        src = (
            _HONEST_FACTORY + _INVOKE
            + "fun main(env: Env, stdio: Stdio, s: @secret String)\n"
            "    var f = fun () -> String => s\n"
            "    f = make(env)\n"
            "    invoke(f, stdio)\n"
        )
        r = _analyze(src)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_crossfn_warnings(r)), 1,
                         [w.message for w in r.warnings])
        rs = _strict(src)
        self.assertFalse(rs.ok)
        self.assertEqual(len(_crossfn_errors(rs)), 1,
                         [e.message for e in rs.errors])


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
