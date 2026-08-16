"""Locally-resolved lambda RESULT-face @secret return laundering (closed
false negative).

A LOCALLY-RESOLVED lambda -- a ``let`` / ``var`` INTRODUCTION bound to a
lambda literal and invoked in the same scope, or an IIFE -- whose RESULT
carries a ``@secret`` (a declared-``@secret`` field read ``o.f2.f3.v``, or a
method / free-function call that RETURNS a secret ``o.reveal()`` / ``peek(o)``)
and is sunk by the CALLER was ``--check``-clean at both tiers and leaked on
both backends. It is the RESULT-FACE mirror of the named-return field channel.

The analyzer already computed the closure's def-time RESULT label
(``_lambda_result_labels``, return-effect-aware, method-return-precise,
declassify-aware); ``_callee_label`` simply never consulted it for a
locally-resolved callee. Candidate A joins that cached label into the
call-result label at the two locally-resolved sites (the
Ident-to-one-certain-lambda and the IIFE ``LambdaExpr`` callee), alongside the
kept live capture re-read. The ceiling is exact: as strong as the direct-call
verdict through a one-certain lambda, never weaker, never stronger.

Disclosed residuals stay OPEN (asserted to still leak on Python): an escaping
alias (``let g = f; g()``), a HOF-invoked closure (``apply(f)``), a
reassigned-``var`` closure, and the different-root points-to family.
"""

import shutil
import unittest

from capa import Lexer, Parser, analyze, transpile
from capa.ir import compile_wasm


def _parse(src: str):
    return Parser(Lexer(src).lex(), source=src).parse_module()


def _analyze(src: str):
    return analyze(_parse(src), source=src)


def _strict(src: str) -> str:
    """Opt ``main`` (holding the invocation) into ``@strict_ifc`` -- the tier
    where the flow is a hard error."""
    return src.replace("fun main(", "@strict_ifc()\nfun main(", 1)


def _flow_warnings(r):
    return [w for w in r.warnings if "information-flow" in w.message]


def _flow_errors(r):
    return [e for e in r.errors if "information-flow" in e.message]


def _capture(thunk) -> str:
    import io
    import sys
    buf = io.StringIO()
    saved = sys.stdout
    sys.stdout = buf
    try:
        thunk()
    finally:
        sys.stdout = saved
    return buf.getvalue()


def _run_py(src: str) -> str:
    module = _parse(src)
    result = analyze(module, source=src)
    code = transpile(module, types=result.types, bindings=result.bindings)
    ns: dict = {"__name__": "__main__"}
    return _capture(lambda: exec(compile(code, "<llrr>", "exec"), ns))


def _run_wasm(src: str) -> str:
    from capa.runtime._wasm_host import WasmHost
    module = _parse(src)
    result = analyze(module, source=src)
    blob = compile_wasm(module, types=result.types)
    return _capture(lambda: WasmHost().run_main(blob))


def _wasm_unavailable():
    if shutil.which("wasm-tools") is None:
        return "wasm-tools not installed"
    try:
        import wasmtime  # noqa: F401
    except ImportError:
        return "wasmtime-py not installed"
    return None


# ---- shared fixture pieces ------------------------------------------------

_DEEP = ("type Inner { v: @secret String, note: String }\n"
         "type Mid { f3: Inner }\n"
         "type Outer { f2: Mid }\n")
_REVEAL = ("impl Outer\n    fun reveal(self) -> String\n"
           "        return self.f2.f3.v\n")
_SHOWNOTE = ("impl Outer\n    fun shownote(self) -> String\n"
             "        return self.f2.f3.note\n")
_PEEK = "fun peek(x: Outer) -> String\n    return x.f2.f3.v\n"
_OBJ = ('    let o = Outer { f2: Mid { f3: Inner { v: "s3cr3t", '
        'note: "pub" } } }\n')


# ---- the LEAK shapes: FLAGGED at both tiers, leak the secret --------------

# depth-1 declared-@secret field read through a let-bound lambda.
DEPTH1 = ("type O { v: @secret String, note: String }\n"
          "fun main(stdio: Stdio)\n"
          '    let o = O { v: "s3cr3t", note: "pub" }\n'
          "    let f = fun () => o.v\n"
          "    stdio.println(f())\n")

# depth-2 (o.f2.f3.v) through a let-bound lambda.
DEPTH2 = (_DEEP + "fun main(stdio: Stdio)\n" + _OBJ +
          "    let f = fun () => o.f2.f3.v\n"
          "    stdio.println(f())\n")

# IIFE reading a deep field.
IIFE = (_DEEP + "fun main(stdio: Stdio)\n" + _OBJ +
        "    stdio.println((fun () => o.f2.f3.v)())\n")

# method whose return carries a secret.
METHOD = (_DEEP + _REVEAL + "fun main(stdio: Stdio)\n" + _OBJ +
          "    let f = fun () => o.reveal()\n"
          "    stdio.println(f())\n")

# free function whose return carries a secret.
FREEFN = (_DEEP + _PEEK + "fun main(stdio: Stdio)\n" + _OBJ +
          "    let f = fun () => peek(o)\n"
          "    stdio.println(f())\n")

# callee defined AFTER main (forward reference).
FORWARD = (_DEEP + "fun main(stdio: Stdio)\n" + _OBJ +
           "    let f = fun () => peek(o)\n"
           "    stdio.println(f())\n"
           "fun peek(x: Outer) -> String\n    return x.f2.f3.v\n")

# call nested two levels deep (wrap -> peek).
NESTED2 = (_DEEP + _PEEK +
           "fun wrap(x: Outer) -> String\n    return peek(x)\n"
           "fun main(stdio: Stdio)\n" + _OBJ +
           "    let f = fun () => wrap(o)\n"
           "    stdio.println(f())\n")

# struct literal holding a secret method return, then a field read of it.
STRUCT_LIT = (_DEEP + _REVEAL + "type Box { f: String, g: String }\n"
              "fun main(stdio: Stdio)\n" + _OBJ +
              '    let f = fun () => Box { f: o.reveal(), g: "pub" }\n'
              "    let b = f()\n    stdio.println(b.f)\n")

# block body with an explicit return.
BLOCK_RETURN = (_DEEP + _REVEAL + "fun main(stdio: Stdio)\n" + _OBJ +
                "    let f = fun () -> String =>\n"
                "        return o.reveal()\n"
                "    stdio.println(f())\n")

# multiple returns, one arm carrying the secret.
MULTI_RETURN = (_DEEP + _REVEAL + "fun main(stdio: Stdio)\n" + _OBJ +
                "    let f = fun (b: Bool) -> String =>\n"
                '        if b\n            return "safe"\n'
                "        return o.reveal()\n"
                "    stdio.println(f(false))\n")

# if-tail with the secret arm.
IF_TAIL = (_DEEP + _REVEAL + "fun main(stdio: Stdio)\n" + _OBJ +
           "    let f = fun (b: Bool) -> String => "
           'if b then o.reveal() else "safe"\n'
           "    stdio.println(f(true))\n")

# match-tail with the secret arm.
MATCH_TAIL = (_DEEP + _REVEAL + "fun main(stdio: Stdio)\n" + _OBJ +
              "    let f = fun (b: Bool) -> String =>\n"
              "        match b\n"
              '            true -> o.reveal()\n'
              '            false -> "safe"\n'
              "    stdio.println(f(true))\n")

# seeded local alias captured then deep-read.
SEEDED_LOCAL = (_DEEP + "fun main(stdio: Stdio)\n" + _OBJ +
                "    let u = o\n"
                "    let f = fun () => u.f2.f3.v\n"
                "    stdio.println(f())\n")

# post-definition mutation reaching the result through a call.
POSTDEF_MUT = ("type Box { f: String }\n"
               "fun peek(x: Box) -> String\n    return x.f\n"
               "fun main(stdio: Stdio, env: Env)\n"
               '    var o = Box { f: "init" }\n'
               "    let f = fun () => peek(o)\n"
               '    o.f = env.get("SECRET").unwrap_or("d")\n'
               "    stdio.println(f())\n")

# leak shapes that run a fixed secret and print it on both backends. The
# post-def-mutation shape depends on Env so it is verdict-only (below).
_LEAKS = {
    "depth1": DEPTH1, "depth2": DEPTH2, "iife": IIFE, "method": METHOD,
    "freefn": FREEFN, "forward": FORWARD, "nested2": NESTED2,
    "struct_lit": STRUCT_LIT, "block_return": BLOCK_RETURN,
    "multi_return": MULTI_RETURN, "if_tail": IF_TAIL, "match_tail": MATCH_TAIL,
    "seeded_local": SEEDED_LOCAL,
}


class TestLocalLambdaResultLeak(unittest.TestCase):
    """Every leak shape flags at the warn tier and hard-errors under strict."""

    def test_flagged_default_tier(self):
        for name, src in {**_LEAKS, "postdef_mut": POSTDEF_MUT}.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 1,
                                 [w.message for w in r.warnings])

    def test_hard_error_under_strict(self):
        for name, src in {**_LEAKS, "postdef_mut": POSTDEF_MUT}.items():
            with self.subTest(shape=name):
                rs = _analyze(_strict(src))
                self.assertFalse(rs.ok)
                self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                        [e.message for e in rs.errors])

    def test_diagnostic_mentions_sink(self):
        r = _analyze(DEPTH2)
        self.assertIn("Stdio.println", _flow_warnings(r)[0].message)

    def test_leaks_on_python(self):
        # These are untyped-arrow lambdas, which hit a SEPARATE pre-existing
        # Wasm i64/i32 codegen crash, so the leak is asserted on Python only.
        # The both-backends RUN proof uses the typed @secret slot below.
        for name, src in _LEAKS.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")


# ---- typed @secret slot: the BOTH-BACKENDS runnable form. An untyped-arrow
# lambda hits a SEPARATE pre-existing Wasm i64/i32 codegen crash, so the
# both-backends RUN assertion uses the typed slot. --------------------------

TYPED_SLOT = (_DEEP + "fun main(stdio: Stdio)\n" + _OBJ +
              "    let f: Fun() -> @secret String = "
              "fun() -> @secret String => o.f2.f3.v\n"
              "    stdio.println(f())\n")

TYPED_SLOT_METHOD = (_DEEP + _REVEAL + "fun main(stdio: Stdio)\n" + _OBJ +
                     "    let f: Fun() -> @secret String = "
                     "fun() -> @secret String => o.reveal()\n"
                     "    stdio.println(f())\n")


class TestTypedSecretSlotBothBackends(unittest.TestCase):
    """The typed ``Fun() -> @secret String`` slot form: warn leaks on both
    backends; strict blocks it (a hard error, so it never reaches codegen)."""

    def test_warn_leaks_both_backends(self):
        skip = _wasm_unavailable()
        for name, src in {"field": TYPED_SLOT,
                          "method": TYPED_SLOT_METHOD}.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertEqual(len(_flow_warnings(r)), 1,
                                 [w.message for w in r.warnings])
                self.assertEqual(_run_py(src), "s3cr3t\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "s3cr3t\n")

    def test_strict_blocks_on_both_backends(self):
        # Analysis is backend-agnostic: the strict hard error blocks both the
        # Python and the Wasm pipeline before codegen. Assert the error is
        # raised (exit-1 equivalent) and no clean compile is attempted.
        for name, src in {"field": TYPED_SLOT,
                          "method": TYPED_SLOT_METHOD}.items():
            with self.subTest(shape=name):
                rs = _analyze(_strict(src))
                self.assertFalse(rs.ok)
                self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                        [e.message for e in rs.errors])


# ---- MUST NOT FLAG: 0 information-flow diagnostics at both tiers ----------

PUB_SIBLING = ("type O { v: @secret String, note: String }\n"
               "fun main(stdio: Stdio)\n"
               '    let o = O { v: "s3cr3t", note: "pub" }\n'
               "    let f = fun () => o.note\n"
               "    stdio.println(f())\n")

DEEP_PUB_SIBLING = (_DEEP + "fun main(stdio: Stdio)\n" + _OBJ +
                    "    let f = fun () => o.f2.f3.note\n"
                    "    stdio.println(f())\n")

SAMENAME = ("type AInner { v: @secret String }\n"
            "type BOuter { v: String, note: String }\n"
            "fun main(stdio: Stdio)\n"
            '    let b = BOuter { v: "public", note: "n" }\n'
            "    let f = fun () => b.v\n"
            "    stdio.println(f())\n")

RECURSIVE_PUB = ("type Node { val: String, next: Node }\n"
                 "fun main(stdio: Stdio, n: Node)\n"
                 "    let f = fun () => n.val\n"
                 "    stdio.println(f())\n")

GENERIC_FIELD = ("type Box<T> { item: T, label: String }\n"
                 "fun main(stdio: Stdio, b: Box<String>)\n"
                 "    let f = fun () => b.label\n"
                 "    stdio.println(f())\n")

PUBCALL = (_DEEP + _SHOWNOTE + "fun main(stdio: Stdio)\n" + _OBJ +
           "    let f = fun () => o.shownote()\n"
           "    stdio.println(f())\n")

NONRET = (_DEEP + _REVEAL + "fun main(stdio: Stdio)\n" + _OBJ +
          "    let f = fun () -> String =>\n"
          '        let tmp = o.reveal()\n        return "public"\n'
          "    stdio.println(f())\n")

CALLSITE_DECLASS = (_DEEP + _REVEAL + "fun main(stdio: Stdio)\n" + _OBJ +
                    "    let f = fun () => o.reveal()\n"
                    '    stdio.println(declassify(f(), reason: "ok"))\n')

INBODY_DECLASS = (_DEEP + _REVEAL + "fun main(stdio: Stdio)\n" + _OBJ +
                  "    let f = fun () => declassify(o.reveal(), "
                  'reason: "ok")\n'
                  "    stdio.println(f())\n")

_CLEAN = {
    "pub_sibling": PUB_SIBLING, "deep_pub_sibling": DEEP_PUB_SIBLING,
    "samename": SAMENAME, "recursive_pub": RECURSIVE_PUB,
    "generic_field": GENERIC_FIELD, "pubcall": PUBCALL, "nonret": NONRET,
    "callsite_declass": CALLSITE_DECLASS, "inbody_declass": INBODY_DECLASS,
}


class TestNoFalsePositive(unittest.TestCase):
    """Public siblings, unrelated same-name fields, recursive / generic
    public fields, a public-returning call, a non-returned secret, and both
    declassify placements raise ZERO information-flow diagnostics."""

    def test_zero_diagnostics_both_tiers(self):
        for name, src in _CLEAN.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])
                rs = _analyze(_strict(src))
                self.assertEqual(len(_flow_errors(rs)), 0,
                                 [e.message for e in rs.errors])


# ---- RESIDUAL pins: stay OPEN (unflagged) and STILL LEAK on Python --------

ESCAPE_ALIAS = ("type O { v: @secret String, note: String }\n"
                "fun main(stdio: Stdio)\n"
                '    let o = O { v: "s3cr3t", note: "pub" }\n'
                "    let f = fun () => o.v\n"
                "    let g = f\n"
                "    stdio.println(g())\n")

HOF = ("type O { v: @secret String, note: String }\n"
       "fun apply(h: Fun() -> String) -> String\n    return h()\n"
       "fun main(stdio: Stdio)\n"
       '    let o = O { v: "s3cr3t", note: "pub" }\n'
       "    let f = fun () => o.v\n"
       "    stdio.println(apply(f))\n")

_RESIDUALS = {"escape_alias": ESCAPE_ALIAS, "hof": HOF}


class TestDisclosedResidualsStillOpen(unittest.TestCase):
    """The disclosed residuals stay UNFLAGGED at both tiers and STILL LEAK on
    Python, so the disclosure is honest. An escaping alias and a HOF-invoked
    closure are not locally resolved to one certain lambda at the sink."""

    def test_unflagged_both_tiers(self):
        for name, src in _RESIDUALS.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])
                rs = _analyze(_strict(src))
                self.assertEqual(len(_flow_errors(rs)), 0,
                                 [e.message for e in rs.errors])

    def test_still_leak_on_python(self):
        for name, src in _RESIDUALS.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")


# ---- NO-REGRESSION: the capture-INTERNAL-sink face is unchanged. A sink
# INSIDE the closure body (not its result) still raises exactly one
# diagnostic; this fix touches only the RESULT face. ------------------------

INTERNAL_DEEP = (_DEEP + "fun main(stdio: Stdio)\n" + _OBJ +
                 "    let f = fun () => stdio.println(o.f2.f3.v)\n"
                 "    f()\n")


class TestCaptureInternalFaceUnchanged(unittest.TestCase):
    """The capture-internal-sink face is orthogonal: a body-internal sink of a
    captured deep secret raises exactly one diagnostic, unchanged by the
    result-face fix."""

    def test_internal_sink_one_diagnostic(self):
        r = _analyze(INTERNAL_DEEP)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])
        rs = _analyze(_strict(INTERNAL_DEEP))
        self.assertFalse(rs.ok)
        self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                [e.message for e in rs.errors])


# ---- NO-PANIC: an un-inferrable-parameter locally-resolved lambda (a
# reachable, benign cache miss on the result label) must yield the clean
# "cannot infer" type-error diagnostic, NOT a Python traceback. The
# fail-closed raise is gated to fire only for a genuinely-unexpected miss. --

UNINFER_LET = ("fun main(stdio: Stdio)\n"
               '    let f = fun (x) => "pub"\n'
               "    stdio.println(f(0))\n")

UNINFER_IIFE = ("fun main(stdio: Stdio)\n"
                '    stdio.println((fun (x) => "pub")(0))\n')

# The un-inferrable lambda body even reads a captured secret: still a clean
# type error (the program never compiles, so nothing leaks and nothing
# panics).
UNINFER_SECRET_BODY = (_DEEP + "fun main(stdio: Stdio)\n" + _OBJ +
                       "    let f = fun (x) => o.f2.f3.v\n"
                       "    stdio.println(f(0))\n")

_UNINFER = {
    "let": UNINFER_LET, "iife": UNINFER_IIFE,
    "secret_body": UNINFER_SECRET_BODY,
}


class TestUninferrableLambdaNoPanic(unittest.TestCase):
    """A locally-resolved lambda with an omitted parameter type and no
    inference context is a reachable, benign result-label cache miss. It must
    surface the clean type-error diagnostic without a traceback, and the
    program stays rejected."""

    def test_clean_type_error_not_a_panic(self):
        for name, src in _UNINFER.items():
            with self.subTest(shape=name):
                # analyze must NOT raise (no fail-closed panic on this path).
                r = _analyze(src)
                self.assertFalse(r.ok)
                infer = [e for e in r.errors
                         if "cannot infer the type of this lambda" in e.message]
                self.assertEqual(len(infer), 1,
                                 [e.message for e in r.errors])
                # The program is rejected, so no information-flow diagnostic is
                # expected: nothing runs, nothing leaks.
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])


if __name__ == "__main__":
    unittest.main()
