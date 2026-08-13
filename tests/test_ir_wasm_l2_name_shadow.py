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
controls stay legal and byte-identical, and honestly record the two
gaps the fix does NOT close (a struct-module-const-as-Wasm-global read,
and a Fun-typed callee that needs emitter-side liveness).
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

# cfun: a lambda binds ``let helper = <a Fun value>`` shadowing the
# module FUNCTION ``helper`` that the enclosing calls after. This is a
# silent WRONG-value divergence (Python calls the module function, Wasm
# routes through the stale local). The ``_lower_ident`` gate does NOT
# close it; it needs emitter-side liveness for a Fun-typed callee
# (capa/ir/_emit_wasm/__init__.py), a distinct piece of work.
_CFUN_RESIDUAL = (
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

    def test_cfun_fun_typed_callee_residual(self):
        # KNOWN-OPEN (Fun-typed callee liveness gap): a ``--check``-clean
        # program whose Python and Wasm outputs STILL diverge. The lambda
        # binds ``let helper = <Fun>`` shadowing the module function the
        # enclosing calls after; the ``_lower_ident`` gate does not close
        # this - it needs emitter-side liveness for a Fun-typed callee
        # (capa/ir/_emit_wasm/__init__.py). Pin the residual so it is not
        # forgotten.
        module, result = _parse_ok(_CFUN_RESIDUAL)
        self.assertTrue(result.ok, result.errors)
        py = _python_out(_CFUN_RESIDUAL)
        wa = _wasm_out(_CFUN_RESIDUAL)
        self.assertEqual(py, "s3cr3t\n")
        self.assertEqual(wa, "pub\n")
        self.assertNotEqual(py, wa, "residual divergence (known-open)")


if __name__ == "__main__":
    unittest.main()
