"""L2 regression: a nested-lambda binding that name-shadows a captured
module-level ``const`` no longer corrupts the enclosing scope's read.

When a nested lambda binds (``let`` / ``var``) a name equal to a
module-level ``const`` and the ENCLOSING function reads that const
TEXTUALLY AFTER the lambda definition, the Wasm backend used to return
empty / ``0`` / a wrong value while Python returned the correct const.
The program is legal (``--check`` clean), so this was a silent
Python<->Wasm output divergence, not a rejectable shadow.

Root cause: the lowerer shared one ``_locals`` map for two roles - the
live "is this name an in-scope local?" test AND the accumulated
``Function.locals`` type map the Wasm closure emitter needs. A
lambda-body ``let K`` wrote ``K`` into ``_locals`` and it persisted, so
the enclosing read resolved ``K`` to a stale local instead of the
module global. The fix decouples the resolution role into a per-function
``_live_locals`` set that is snapshotted / restored across a lambda body
(like ``_params``), leaving ``_locals`` intact for the emitter.

These pins lock the eight closed variants byte-identical, prove the two
controls stay legal and byte-identical, and honestly record the one gap
the L2 fix does NOT close (a struct-module-const-as-Wasm-global read).

The Fun-typed-callee shadow that L2 left open (a lambda-body ``let helper
= <Fun>`` shadowing a module function the enclosing scope then CALLS)
is closed by a follow-up: the direct-vs-closure routing decision is now
recorded on the ``Call`` IR node at lowering time (``Call.route``) and
both Wasm emitter sites honour it, instead of re-deriving the decision
from the flat ``Function.locals`` map (which keeps the dead lambda
local's Fun type for the closure emitter and so mis-routed the enclosing
module call). ``TestFunTypedCalleeShadowClosed`` locks that corpus.
"""

import io
import sys
import unittest

from capa import Lexer, Parser, analyze, transpile
from capa.ir import compile_wasm


def _has_wasmtime() -> bool:
    try:
        import wasmtime  # noqa: F401
        return True
    except ImportError:
        return False


def _capture(thunk) -> str:
    buf = io.StringIO()
    saved = sys.stdout
    sys.stdout = buf
    try:
        thunk()
    finally:
        sys.stdout = saved
    return buf.getvalue()


def _parse_ok(src: str):
    tokens = Lexer(src).lex()
    module = Parser(tokens, source=src).parse_module()
    result = analyze(module, source=src)
    assert result.ok, result.errors
    return module, result


def _python_out(src: str) -> str:
    module, result = _parse_ok(src)
    code = transpile(module, types=result.types, bindings=result.bindings)

    def run():
        ns: dict = {"__name__": "__main__"}
        exec(compile(code, "<l2-parity>", "exec"), ns)

    return _capture(run)


def _wasm_out(src: str) -> str:
    from capa.runtime._wasm_host import WasmHost
    module, result = _parse_ok(src)
    blob = compile_wasm(module, types=result.types)

    def run():
        WasmHost().run_main(blob)

    return _capture(run)


# ---------------------------------------------------------------------
# The eight closed L2 variants. Each was byte-DIVERGENT before the fix
# (Wasm returned empty / ``0`` / a wrong value) and is byte-identical
# after it.
# ---------------------------------------------------------------------

# c3: the minimal read-after shape. The enclosing ``leak`` reads ``K``
# after the lambda that binds ``let K``.
_C3_READ_AFTER = (
    "const K: String = \"s3cr3t\"\n"
    "fun leak(stdio: Stdio)\n"
    "    let g: Fun() -> String = fun() -> String =>\n"
    "        let K = \"pub\"\n"
    "        return K\n"
    "    stdio.println(K)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(stdio)\n"
)

# c5: the lambda binds ``K`` but does not RETURN it (returns another
# value). The enclosing read after the lambda still resolves to the
# module const.
_C5_BIND_WITHOUT_RETURN = (
    "const K: String = \"s3cr3t\"\n"
    "fun leak(stdio: Stdio)\n"
    "    let g: Fun() -> String = fun() -> String =>\n"
    "        let K = \"pub\"\n"
    "        return \"other\"\n"
    "    stdio.println(K)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(stdio)\n"
)

# c6: a ``var`` shadow (does not go through the same bind path as
# ``let``) still leaves the enclosing read on the module const.
_C6_VAR_SHADOW = (
    "const K: String = \"s3cr3t\"\n"
    "fun leak(stdio: Stdio)\n"
    "    let g: Fun() -> String = fun() -> String =>\n"
    "        var K = \"pub\"\n"
    "        return K\n"
    "    stdio.println(K)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(stdio)\n"
)

# c8: an Int const. Pre-fix the Wasm backend declared an unassigned
# local and returned ``0`` rather than the empty string.
_C8_INT_CONST = (
    "const K: Int = 42\n"
    "fun leak(stdio: Stdio)\n"
    "    let g: Fun() -> Int = fun() -> Int =>\n"
    "        let K = 7\n"
    "        return K\n"
    "    stdio.println(\"${K}\")\n"
    "fun main(stdio: Stdio)\n"
    "    leak(stdio)\n"
)

# c9: two nesting levels. Each lambda binds its own ``K``; the enclosing
# read after the outer lambda still resolves to the module const.
_C9_TWO_NESTING_LEVELS = (
    "const K: String = \"s3cr3t\"\n"
    "fun leak(stdio: Stdio)\n"
    "    let g: Fun() -> String = fun() -> String =>\n"
    "        let h: Fun() -> String = fun() -> String =>\n"
    "            let K = \"inner\"\n"
    "            return K\n"
    "        let K = \"outer\"\n"
    "        return K\n"
    "    stdio.println(K)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(stdio)\n"
)

# c11: the enclosing function READS the const and RETURNS it to a caller
# that prints it. The re-route to the global must survive the return.
_C11_READ_RETURNED = (
    "const K: String = \"s3cr3t\"\n"
    "fun leak() -> String\n"
    "    let g: Fun() -> String = fun() -> String =>\n"
    "        let K = \"pub\"\n"
    "        return K\n"
    "    return K\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(leak())\n"
)

# c13: the enclosing read sits inside an ``if`` block after the lambda.
_C13_READ_IN_IF = (
    "const K: String = \"s3cr3t\"\n"
    "fun leak(stdio: Stdio, flag: Bool)\n"
    "    let g: Fun() -> String = fun() -> String =>\n"
    "        let K = \"pub\"\n"
    "        return K\n"
    "    if flag\n"
    "        stdio.println(K)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(stdio, true)\n"
)

# csecret: the ``@secret`` form. The enclosing read is declassified
# before the public sink so the program is ``--check`` clean; declassify
# is identity on both backends, so a correct re-route is byte-identical.
_CSECRET = (
    "const K: @secret String = \"s3cr3t\"\n"
    "fun leak(stdio: Stdio)\n"
    "    let g: Fun() -> String = fun() -> String =>\n"
    "        let K = \"pub\"\n"
    "        return K\n"
    "    stdio.println(declassify(K, reason: \"audit\"))\n"
    "fun main(stdio: Stdio)\n"
    "    leak(stdio)\n"
)


_CLOSED_VARIANTS = [
    ("c3_read_after", _C3_READ_AFTER, "s3cr3t\n"),
    ("c5_bind_without_return", _C5_BIND_WITHOUT_RETURN, "s3cr3t\n"),
    ("c6_var_shadow", _C6_VAR_SHADOW, "s3cr3t\n"),
    ("c8_int_const", _C8_INT_CONST, "42\n"),
    ("c9_two_nesting_levels", _C9_TWO_NESTING_LEVELS, "s3cr3t\n"),
    ("c11_read_returned", _C11_READ_RETURNED, "s3cr3t\n"),
    ("c13_read_in_if", _C13_READ_IN_IF, "s3cr3t\n"),
    ("csecret", _CSECRET, "s3cr3t\n"),
]


# ---------------------------------------------------------------------
# Controls: must STAY legal AND byte-identical (the fix must not
# over-reach into these).
# ---------------------------------------------------------------------

# a4: an enclosing first-bind-after-lambda of a name the lambda body
# also binds. The outer ``let f = <lambda>`` must still alpha-rename
# (the lambda body claimed the bare ``f`` in the flat locals map), and
# the later call must follow the rename. Keeping the shadow test on
# ``_locals`` (not ``_live_locals``) preserves this.
_A4_ALPHA_RENAME = (
    "fun main(stdio: Stdio)\n"
    "    let f: Fun() -> Int = fun() -> Int =>\n"
    "        let f = 5\n"
    "        return f\n"
    "    stdio.println(\"${f()}\")\n"
)

# a5: no over-reach across the ordinary resolution kinds - a same-
# function local, a parameter, a global const, a capture (enclosing
# local read inside a lambda), a variant, a match-payload bind, and a
# for-loop variable all still resolve.
_A5_NO_OVERREACH = (
    "const G: Int = 100\n"
    "fun classify(n: Int) -> Option<Int>\n"
    "    if n > 0\n"
    "        return Some(n)\n"
    "    return None\n"
    "fun run(p: Int, stdio: Stdio)\n"
    "    let loc = 3\n"
    "    let cap = fun () -> Int => loc + p\n"
    "    var total = G\n"
    "    for x in [1, 2, 3]\n"
    "        total = total + x\n"
    "    let r = match classify(p)\n"
    "        Some(v) -> v\n"
    "        None -> 0\n"
    "    stdio.println(\"${loc}/${p}/${G}/${cap()}/${total}/${r}\")\n"
    "fun main(stdio: Stdio)\n"
    "    run(5, stdio)\n"
)


# ---------------------------------------------------------------------
# Known-open pins: the fix does NOT close these; the pins lock the
# CURRENT documented behaviour so the gaps are not silently forgotten.
# ---------------------------------------------------------------------

# c10: reading a struct field off a module const (``K.v``). The fix
# correctly re-routes the enclosing read to ``kind="global"``, but a
# struct-typed module const as a Wasm global is UNIMPLEMENTED - a plain
# ``const K: Box; ... K.v`` read with NO lambda fails identically. This
# is a separate pre-existing gap (struct-const globals), not the L2
# shadow bug. The lambda form now surfaces the SAME error as the plain
# form, which is exactly the re-route working.
_C10_STRUCT_CONST_LAMBDA = (
    "type Box { v: String }\n"
    "const K: Box = Box { v: \"s3cr3t\" }\n"
    "fun leak(stdio: Stdio)\n"
    "    let g: Fun() -> String = fun() -> String =>\n"
    "        let K = \"pub\"\n"
    "        return K\n"
    "    stdio.println(K.v)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(stdio)\n"
)

_C10_STRUCT_CONST_NO_LAMBDA = (
    "type Box { v: String }\n"
    "const K: Box = Box { v: \"s3cr3t\" }\n"
    "fun leak(stdio: Stdio)\n"
    "    stdio.println(K.v)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(stdio)\n"
)

class TestL2ClosedVariantsCheckPass(unittest.TestCase):
    """Every closed L2 variant is a legal program (``--check`` clean):
    rejecting it would be a false positive on correct code."""

    def test_all_closed_variants_check_pass(self):
        for name, src, _expected in _CLOSED_VARIANTS:
            with self.subTest(variant=name):
                module, result = _parse_ok(src)
                self.assertTrue(result.ok, result.errors)


@unittest.skipUnless(_has_wasmtime(), "wasmtime not installed")
class TestL2ClosedVariantsByteIdentical(unittest.TestCase):
    """The eight closed variants run byte-identical on the Python and
    Wasm backends (they diverged before the fix)."""

    def test_closed_variants_byte_identical(self):
        for name, src, expected in _CLOSED_VARIANTS:
            with self.subTest(variant=name):
                py = _python_out(src)
                wa = _wasm_out(src)
                self.assertEqual(py, wa, f"{name}: Python vs Wasm")
                self.assertEqual(py, expected, f"{name}: expected output")


class TestL2ControlsCheckPass(unittest.TestCase):
    def test_a4_alpha_rename_check_pass(self):
        module, result = _parse_ok(_A4_ALPHA_RENAME)
        self.assertTrue(result.ok, result.errors)

    def test_a5_no_overreach_check_pass(self):
        module, result = _parse_ok(_A5_NO_OVERREACH)
        self.assertTrue(result.ok, result.errors)


@unittest.skipUnless(_has_wasmtime(), "wasmtime not installed")
class TestL2ControlsByteIdentical(unittest.TestCase):
    """The controls stay legal AND byte-identical: the fix must not
    over-reach into ordinary resolution."""

    def test_a4_alpha_rename_byte_identical(self):
        # The outer ``f`` binding alpha-renames and the call follows the
        # rename; the lambda returns its own local 5.
        py = _python_out(_A4_ALPHA_RENAME)
        wa = _wasm_out(_A4_ALPHA_RENAME)
        self.assertEqual(py, wa)
        self.assertEqual(py, "5\n")

    def test_a5_no_overreach_byte_identical(self):
        # local(3) / param(5) / global(100) / capture(loc+p=8) /
        # for-accumulated(100+1+2+3=106) / match-payload(5).
        py = _python_out(_A5_NO_OVERREACH)
        wa = _wasm_out(_A5_NO_OVERREACH)
        self.assertEqual(py, wa)
        self.assertEqual(py, "3/5/100/8/106/5\n")


@unittest.skipUnless(_has_wasmtime(), "wasmtime not installed")
class TestL2KnownOpenGaps(unittest.TestCase):
    """KNOWN-OPEN: the fix does not close these. The pins assert the
    current documented behaviour so a later change that closes a gap
    updates the pin deliberately rather than by accident."""

    def test_c10_struct_module_const_global_unimplemented(self):
        # KNOWN-OPEN (struct-const-as-Wasm-global gap, NOT the L2 shadow
        # bug): the enclosing ``K.v`` read is correctly re-routed to the
        # module global, but a struct-typed module const has no Wasm
        # global encoding yet. Python prints the field; Wasm fails to
        # compile with the same error the NO-lambda form raises, which
        # is precisely the re-route landing on the (unimplemented) global
        # path rather than a stale local. Closing this is separate work
        # (struct-const globals in capa/ir/_emit_wasm).
        from capa.ir import compile_wasm as _cw
        module_l, result_l = _parse_ok(_C10_STRUCT_CONST_LAMBDA)
        module_n, result_n = _parse_ok(_C10_STRUCT_CONST_NO_LAMBDA)
        with self.assertRaises(Exception) as ctx_l:
            _cw(module_l, types=result_l.types)
        with self.assertRaises(Exception) as ctx_n:
            _cw(module_n, types=result_n.types)
        # Same failure with and without the lambda: the lambda no longer
        # changes how the enclosing read resolves.
        self.assertIn("kind 'global'", str(ctx_l.exception))
        self.assertIn("'Box'", str(ctx_l.exception))
        self.assertIn("kind 'global'", str(ctx_n.exception))
        self.assertIn("'Box'", str(ctx_n.exception))
        # Python still runs it correctly.
        self.assertEqual(_python_out(_C10_STRUCT_CONST_NO_LAMBDA), "s3cr3t\n")


# ---------------------------------------------------------------------
# The Fun-typed-callee shadow, now CLOSED. A lambda-body binding whose
# name equals a module function (or another module Fun symbol) no longer
# makes the enclosing scope's CALL of that name diverge: the routing
# decision is recorded on the Call node at lowering time and both Wasm
# emitter sites honour it, so a dead lambda local's residual Fun type in
# ``Function.locals`` can no longer re-route a same-named module call.
# ---------------------------------------------------------------------

# Base residual (was TestL2KnownOpenGaps.test_cfun_fun_typed_callee_residual,
# which pinned Wasm == "pub"): the lambda binds ``let helper = <Fun>``
# shadowing the module function ``helper`` the enclosing calls after.
_CFUN_BASE = (
    "fun helper() -> String\n"
    "    return \"s3cr3t\"\n"
    "fun leak(stdio: Stdio)\n"
    "    let g: Fun() -> String = fun() -> String =>\n"
    "        let helper = fun() -> String => \"pub\"\n"
    "        return helper()\n"
    "    stdio.println(helper())\n"
    "fun main(stdio: Stdio)\n"
    "    leak(stdio)\n"
)

# Tail-call variant: the enclosing ``return helper()`` sits in tail
# position after the lambda, so the direct-call decision must also flow
# through the ``return_call`` peephole (_is_tail_callable).
_CFUN_TAILCALL = (
    "fun helper() -> String\n"
    "    return \"s3cr3t\"\n"
    "fun leak() -> String\n"
    "    let g: Fun() -> String = fun() -> String =>\n"
    "        let helper = fun() -> String => \"pub\"\n"
    "        return helper()\n"
    "    return helper()\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(leak())\n"
)

# Two distinct module functions each shadowed by a dead lambda local and
# both called: each must return its OWN value, not collapse to one.
_CFUN_TWO_FUNCTIONS = (
    "fun alpha() -> String\n"
    "    return \"AAA\"\n"
    "fun beta() -> String\n"
    "    return \"BBB\"\n"
    "fun leak(stdio: Stdio)\n"
    "    let g: Fun() -> String = fun() -> String =>\n"
    "        let alpha = fun() -> String => \"x\"\n"
    "        let beta = fun() -> String => \"y\"\n"
    "        return alpha() + beta()\n"
    "    stdio.println(alpha())\n"
    "    stdio.println(beta())\n"
    "fun main(stdio: Stdio)\n"
    "    leak(stdio)\n"
)

# Param-trap runtime witness: the callee is a Fun PARAMETER whose name
# also names a module function of a DIFFERENT signature. Classifying the
# module name first (a naive module-first rule) would emit ``call
# $helper`` (1-arg Int->Int) for a 0-arg call -> a Wasm indirect-call
# type mismatch; the param-before-module order routes to the parameter.
_CFUN_PARAM_TRAP = (
    "fun helper(x: Int) -> Int\n"
    "    return x + 1\n"
    "fun run(helper: Fun() -> String, stdio: Stdio)\n"
    "    stdio.println(helper())\n"
    "fun main(stdio: Stdio)\n"
    "    let p = fun() -> String => \"param\"\n"
    "    run(p, stdio)\n"
)

# Param-trap validation witness: a 2-arg module function shadowed by a
# dead lambda local, then called ``helper(2, 3)``. The mis-route pushed
# two i64 args into the closure ABI -> "type mismatch: expected i32,
# found i64" at Wasm validation (the module would not even compile). The
# direct route emits ``call $helper`` with (i64, i64) -> 5.
_CFUN_TWO_ARG = (
    "fun helper(a: Int, b: Int) -> Int\n"
    "    return a + b\n"
    "fun leak(stdio: Stdio)\n"
    "    let g: Fun() -> String = fun() -> String =>\n"
    "        let helper = fun() -> String => \"pub\"\n"
    "        return helper()\n"
    "    stdio.println(\"${helper(2, 3)}\")\n"
    "fun main(stdio: Stdio)\n"
    "    leak(stdio)\n"
)

# Fresh-Fun-temp witness: ``make()(5)`` calls the result of a call. The
# callee is an expression of Fun type (a fresh temp, never a module
# name), so it must stay a CLOSURE call.
_CFUN_FRESH_TEMP = (
    "fun make() -> Fun(Int) -> Int\n"
    "    return fun(x: Int) -> Int => x + 1\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(\"${make()(5)}\")\n"
)

# Ordering witness: the callee is BOTH a module-function name AND a Fun
# parameter (same signature). It must route to the PARAMETER's value.
_CFUN_PARAM_WINS = (
    "fun helper() -> String\n"
    "    return \"modfn\"\n"
    "fun run(helper: Fun() -> String, stdio: Stdio)\n"
    "    stdio.println(helper())\n"
    "fun main(stdio: Stdio)\n"
    "    let p = fun() -> String => \"param\"\n"
    "    run(p, stdio)\n"
)

# A live LOCAL Fun value shadowing a module-function name -> the local
# wins (a plain, non-lambda closure call).
_CFUN_LOCAL_WINS = (
    "fun helper() -> String\n"
    "    return \"modfn\"\n"
    "fun main(stdio: Stdio)\n"
    "    let helper = fun() -> String => \"local\"\n"
    "    stdio.println(helper())\n"
)

# A module function read AS A VALUE, stored in a local, then called: the
# stored Fun value is a live local -> CLOSURE call, byte-identical.
_CFUN_FN_AS_VALUE = (
    "fun helper() -> String\n"
    "    return \"s3cr3t\"\n"
    "fun main(stdio: Stdio)\n"
    "    let g = helper\n"
    "    stdio.println(g())\n"
)

# A genuine DIRECT module call issued from INSIDE a lambda body must
# still route direct (the module symbol is neither a live local nor a
# param nor a capture in the lambda's snapshot).
_CFUN_DIRECT_IN_LAMBDA = (
    "fun dbl(x: Int) -> Int\n"
    "    return x * 2\n"
    "fun main(stdio: Stdio)\n"
    "    let g: Fun() -> Int = fun() -> Int => dbl(5)\n"
    "    stdio.println(\"${g()}\")\n"
)

# A higher-order-function argument that is a shadowed module function:
# ``xs.map(dbl)`` reads ``dbl`` as a VALUE (the module funcref) even
# though a dead lambda local ``dbl`` exists; the routing fix must not
# perturb the value-read path.
_CFUN_HOF_ARG = (
    "fun dbl(x: Int) -> Int\n"
    "    return x * 2\n"
    "fun leak(stdio: Stdio)\n"
    "    let g: Fun() -> Int = fun() -> Int =>\n"
    "        let dbl = fun(y: Int) -> Int => y + 100\n"
    "        return dbl(1)\n"
    "    let xs = [1, 2, 3]\n"
    "    let ys = xs.map(dbl)\n"
    "    let total = ys.fold(0, fun(acc: Int, v: Int) -> Int => acc + v)\n"
    "    stdio.println(\"${total}\")\n"
    "fun main(stdio: Stdio)\n"
    "    leak(stdio)\n"
)


_CFUN_CLOSED = [
    ("base", _CFUN_BASE, "s3cr3t\n"),
    ("tailcall", _CFUN_TAILCALL, "s3cr3t\n"),
    ("two_functions", _CFUN_TWO_FUNCTIONS, "AAA\nBBB\n"),
    ("param_trap_runtime", _CFUN_PARAM_TRAP, "param\n"),
    ("param_trap_validation", _CFUN_TWO_ARG, "5\n"),
    ("fresh_fun_temp", _CFUN_FRESH_TEMP, "6\n"),
    ("param_wins_over_module", _CFUN_PARAM_WINS, "param\n"),
    ("local_wins_over_module", _CFUN_LOCAL_WINS, "local\n"),
    ("fn_read_as_value", _CFUN_FN_AS_VALUE, "s3cr3t\n"),
    ("direct_call_in_lambda", _CFUN_DIRECT_IN_LAMBDA, "10\n"),
    ("hof_arg_shadowed_fn", _CFUN_HOF_ARG, "12\n"),
]


# A module CONST whose value is a Fun, used as a callee. This classifies
# DIRECT (a module symbol) and emits ``call $const`` -- there is no such
# function, so the Wasm build fails LOUD with "unknown func", IDENTICALLY
# to the shadow-free form. Making a const-of-Fun callee callable is a
# separate known-open gap; the routing fix must NOT let the shadow turn
# the call into a silently-wrong closure value.
_CFUN_CONST_FUN_SHADOW = (
    "const HELPER: Fun() -> String = fun() -> String => \"s3cr3t\"\n"
    "fun leak(stdio: Stdio)\n"
    "    let g: Fun() -> String = fun() -> String =>\n"
    "        let HELPER = fun() -> String => \"pub\"\n"
    "        return HELPER()\n"
    "    stdio.println(HELPER())\n"
    "fun main(stdio: Stdio)\n"
    "    leak(stdio)\n"
)

_CFUN_CONST_FUN_NO_LAMBDA = (
    "const HELPER: Fun() -> String = fun() -> String => \"s3cr3t\"\n"
    "fun leak(stdio: Stdio)\n"
    "    stdio.println(HELPER())\n"
    "fun main(stdio: Stdio)\n"
    "    leak(stdio)\n"
)


class TestFunTypedCalleeShadowCheckPass(unittest.TestCase):
    """Every closed Fun-typed-callee shape is a legal program
    (``--check`` clean): the divergence was silent, not rejectable."""

    def test_all_closed_check_pass(self):
        for name, src, _expected in _CFUN_CLOSED:
            with self.subTest(shape=name):
                module, result = _parse_ok(src)
                self.assertTrue(result.ok, result.errors)


@unittest.skipUnless(_has_wasmtime(), "wasmtime not installed")
class TestFunTypedCalleeShadowClosed(unittest.TestCase):
    """The Fun-typed-callee shadow corpus runs byte-identical on the
    Python and Wasm backends. The base shape flips the former
    known-open pin (which asserted Wasm == "pub" and py != wasm)."""

    def test_closed_shapes_byte_identical(self):
        for name, src, expected in _CFUN_CLOSED:
            with self.subTest(shape=name):
                py = _python_out(src)
                wa = _wasm_out(src)
                self.assertEqual(py, wa, f"{name}: Python vs Wasm")
                self.assertEqual(py, expected, f"{name}: expected output")

    def test_base_flips_former_residual_pin(self):
        # The exact program the old TestL2KnownOpenGaps pin asserted
        # diverged (Wasm == "pub"): now both backends print the secret.
        py = _python_out(_CFUN_BASE)
        wa = _wasm_out(_CFUN_BASE)
        self.assertEqual(py, "s3cr3t\n")
        self.assertEqual(wa, "s3cr3t\n")


class TestConstOfFunCalleeKnownOpen(unittest.TestCase):
    """KNOWN-OPEN (const-of-Fun callee): a module const whose value is a
    Fun is not callable on the Wasm backend. The routing fix classifies
    it DIRECT so it fails LOUD with the same ``unknown func`` error the
    shadow-free form raises, rather than letting the shadow silently
    produce a closure value."""

    def test_const_fun_callee_fails_loud_identically(self):
        from capa.ir import compile_wasm as _cw
        module_s, result_s = _parse_ok(_CFUN_CONST_FUN_SHADOW)
        module_n, result_n = _parse_ok(_CFUN_CONST_FUN_NO_LAMBDA)
        with self.assertRaises(Exception) as ctx_s:
            _cw(module_s, types=result_s.types)
        with self.assertRaises(Exception) as ctx_n:
            _cw(module_n, types=result_n.types)
        # Same loud failure with and without the lambda: the shadow does
        # not change how the enclosing call resolves (both emit
        # ``call $HELPER``, which has no such function).
        self.assertIn("unknown func", str(ctx_s.exception))
        self.assertIn("$HELPER", str(ctx_s.exception))
        self.assertIn("unknown func", str(ctx_n.exception))
        self.assertIn("$HELPER", str(ctx_n.exception))


# ---------------------------------------------------------------------
# Coupling with the two pre-existing analyzer shadow guards.
#
# The routing fix (3673fd4, branch fix-fun-shadow-call-routing) records
# the direct-vs-closure decision on the ``Call`` node, but the Wasm
# emitter STILL retrieves the closure signature by NAME via
# ``_lookup_local_or_param_ty`` (``_emit_user_call`` / ``_is_tail_callable``
# in capa/ir/_emit_wasm/__init__.py). That by-name retrieval stays safe
# for the enclosing-scope-shadow TRAP family ONLY because the analyzer
# rejects those shapes at ``--check`` BEFORE lowering:
#
#   * commit 4b9c9e6 - a lambda-body binding that shadows an enclosing
#     scope (an enclosing param/local is a blanket reject); and
#   * commit 887f0c3 - a same-function-scope binding that shadows a
#     module const/function it reads.
#
# The routing change closes the module-function-shadow-with-enclosing-read
# family; the enclosing-scope-shadow trap (a lambda-body local shadowing
# an enclosing param/local of a DIFFERENT Fun signature, then called)
# stays safe only because those two guards fire first. If a future change
# relaxed either guard WITHOUT also routing the emitter's signature
# retrieval off ``Call.route`` (dropping the name-keyed ``Function.locals``
# fallback), a trapping / divergent Fun-typed shape would reopen silently.
# These pins assert the coupling so relaxing a guard fails LOUD here.
#
# The broader guard corpora live in tests/test_closure_shadow_divergence.py
# (TestClosureShadowRejected for 4b9c9e6, TestPlainFunctionModuleShadow for
# 887f0c3); these two cases are the routing-flavoured (Fun-typed callee /
# call) shapes that the by-name emitter lookup depends on, kept next to the
# routing corpus so a dev touching the routing fix sees the dependency.
# ---------------------------------------------------------------------

# The 4b9c9e6 trap shape: a lambda-body ``let helper`` (a Fun value) shadows
# the enclosing PARAM ``helper`` of a DIFFERENT Fun signature, and the
# enclosing scope then CALLS the param. If the guard were relaxed this would
# reach lowering, where the emitter's by-name ``Function.locals`` lookup
# would find the dead inner ``helper``'s ``Fun(Int) -> Int`` type and
# mis-route the 0-arg param call.
_GUARD_ENCLOSING_PARAM_CALLED = (
    "fun run(helper: Fun() -> String, stdio: Stdio)\n"
    "    let g: Fun() -> Int = fun() -> Int =>\n"
    "        let helper = fun(x: Int) -> Int => x + 1\n"
    "        return helper(41)\n"
    "    stdio.println(helper())\n"
    "    stdio.println(\"${g()}\")\n"
    "fun main(stdio: Stdio)\n"
    "    let p = fun() -> String => \"param\"\n"
    "    run(p, stdio)\n"
)

# The 887f0c3 shape: a single plain-function scope both CALLS a module
# function ``helper`` and shadows it with a same-scope ``let helper`` (a Fun
# value). Python function-scopes the whole body while Wasm keeps the module
# function, so the analyzer rejects it before lowering.
_GUARD_MODULE_FN_READ = (
    "fun helper() -> String\n"
    "    return \"s3cr3t\"\n"
    "fun run(stdio: Stdio)\n"
    "    stdio.println(helper())\n"
    "    let helper = fun() -> String => \"pub\"\n"
    "fun main(stdio: Stdio)\n"
    "    run(stdio)\n"
)


def _reject_msgs(src: str) -> list:
    tokens = Lexer(src).lex()
    module = Parser(tokens, source=src).parse_module()
    result = analyze(module, source=src)
    return [e.message for e in result.errors if "may not shadow" in e.message]


class TestFunTypedRoutingGuardCoupling(unittest.TestCase):
    """The Fun-typed routing fix (3673fd4) is COUPLED to two pre-existing
    analyzer shadow guards. The Wasm emitter still retrieves the closure
    signature by NAME (``_lookup_local_or_param_ty``), which is safe for the
    enclosing-scope-shadow trap family ONLY because these guards reject
    those shapes at ``--check`` before lowering. If either rejection is
    relaxed without first routing that retrieval off ``Call.route``, a
    trapping / divergent Fun-typed shape reopens silently; these pins make
    the coupling break loud instead."""

    def test_enclosing_param_shadow_called_rejected(self):
        # 4b9c9e6: a lambda-body local shadowing an enclosing Fun-typed
        # param of a different signature that the enclosing scope calls.
        msgs = _reject_msgs(_GUARD_ENCLOSING_PARAM_CALLED)
        self.assertTrue(
            msgs, "expected the enclosing-scope shadow rejection (4b9c9e6)",
        )
        self.assertIn("from an enclosing scope", msgs[0])

    def test_module_function_shadow_read_rejected(self):
        # 887f0c3: a same-scope binding shadowing a module function it reads.
        msgs = _reject_msgs(_GUARD_MODULE_FN_READ)
        self.assertTrue(
            msgs, "expected the module-level shadow rejection (887f0c3)",
        )
        self.assertIn("may not shadow the module-level function", msgs[0])


if __name__ == "__main__":
    unittest.main()
