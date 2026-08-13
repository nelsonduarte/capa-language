"""Backend-independent rejection of a lambda-body binding that shadows
an enclosing-scope name (the closure-shadow divergence).

A ``let`` / ``var`` / pattern-bind inside a lambda body whose name shadows
a parameter or local of an ENCLOSING scope was accepted by ``--check`` yet
realised three different ways: the analyzer's capture-label re-read the
live binding by name (so ``--check`` was clean), the Python transpiler
function-scoped the redeclared name (``UnboundLocalError``), and the Wasm
lowerer kept the inner closure's lexical capture and SILENTLY disclosed
the outer value. For a captured @secret that meant the Wasm backend
printed the secret while Python crashed.

The analyzer now rejects the shadow backend-independently (a hard error at
both the default warn tier and ``@strict_ifc``), so ``--check`` and both
backends agree: all reject. These PINs lock the rejected divergence corpus
and prove a LEGAL control still ``--check``-passes AND runs byte-identically
on both backends -- executing the "legal" case is exactly the gap that hid
this bug (it was analyzer-accepted but never run).
"""

import io
import shutil
import sys
import unittest

from capa import Lexer, Parser, analyze, transpile
from capa.ir import compile_wasm


_MARK = "may not shadow"


def _reject_msgs(src: str) -> list[str]:
    tokens = Lexer(src).lex()
    module = Parser(tokens, source=src).parse_module()
    result = analyze(module, source=src)
    return [e.message for e in result.errors if _MARK in e.message]


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
        exec(compile(code, "<shadow-parity>", "exec"), ns)

    return _capture(run)


def _wasm_out(src: str) -> str:
    from capa.runtime._wasm_host import WasmHost
    module, result = _parse_ok(src)
    blob = compile_wasm(module, types=result.types)

    def run():
        WasmHost().run_main(blob)

    return _capture(run)


# The rejected divergence corpus. Each program was ACCEPTED by ``--check``
# before the fix (both tiers); each now produces the closure-shadow error.
_V_WRAP = (
    "fun main(stdio: Stdio, token: @secret String)\n"
    "    let bag = token\n"
    "    let wrap = fun () -> String =>\n"
    "        let leak = fun () -> String => bag\n"
    "        let bag = \"z\"\n"
    "        return leak()\n"
    "    stdio.println(\"${wrap()}\")\n"
)

_MIN_P1 = (
    "fun main(stdio: Stdio)\n"
    "    let bag = \"a\"\n"
    "    let wrap = fun () -> String =>\n"
    "        let leak = fun () -> String => bag\n"
    "        let bag = \"z\"\n"
    "        return leak()\n"
    "    stdio.println(\"${wrap()}\")\n"
)

_M1_PARAM = (
    "fun outer(p: Int, stdio: Stdio)\n"
    "    let f = fun () -> Int =>\n"
    "        let p = 5\n"
    "        return p\n"
    "    stdio.println(\"${f()}\")\n"
)

_A2_MATCH = (
    "fun main(stdio: Stdio)\n"
    "    let bag = \"a\"\n"
    "    let wrap = fun () -> String =>\n"
    "        let r = match \"m\"\n"
    "            bag -> bag\n"
    "        return r\n"
    "    stdio.println(\"${wrap()}\")\n"
)

_A2_SIBLING = (
    "fun main(stdio: Stdio, flag: Bool)\n"
    "    let bag = \"a\"\n"
    "    let wrap = fun () -> String =>\n"
    "        if flag\n"
    "            let bag = \"z\"\n"
    "            return bag\n"
    "        return \"y\"\n"
    "    stdio.println(\"${wrap()}\")\n"
)

_VAR_VARIANT = (
    "fun main(stdio: Stdio)\n"
    "    let bag = \"a\"\n"
    "    let wrap = fun () -> String =>\n"
    "        let leak = fun () -> String => bag\n"
    "        var bag = \"z\"\n"
    "        return leak()\n"
    "    stdio.println(\"${wrap()}\")\n"
)

# A lambda-body shadow of a captured MODULE-LEVEL const (CS1) or function
# (FN1) diverges too: the Wasm backend references the global directly and
# discloses it while Python function-scopes the redeclared name. The shadow
# is rejected because the name is read (via the nested ``leak`` closure)
# BEFORE the shadowing binding.
_CS1_CONST = (
    "const bag: @secret String = \"s3cr3t\"\n"
    "fun main(stdio: Stdio)\n"
    "    let wrap = fun () -> String =>\n"
    "        let leak = fun () -> String => bag\n"
    "        let bag = \"z\"\n"
    "        return leak()\n"
    "    stdio.println(wrap())\n"
)

_FN1_FUNCTION = (
    "fun bag() -> String\n"
    "    return \"s3cr3t\"\n"
    "fun main(stdio: Stdio)\n"
    "    let wrap = fun () -> String =>\n"
    "        let leak = fun () -> String => bag()\n"
    "        let bag = \"z\"\n"
    "        return leak()\n"
    "    stdio.println(wrap())\n"
)

# StructPat shorthand binds the field name directly (not via
# ``_bind_pattern``); a shorthand field name shadowing an enclosing
# parameter must be rejected the same way a plain ``let`` would be.
_SS2_STRUCT = (
    "type P { x: Int }\n"
    "fun outer(x: Int) -> Int\n"
    "    let p = P { x: 99 }\n"
    "    let f = fun () -> Int =>\n"
    "        let P { x } = p\n"
    "        return x\n"
    "    return f() + x\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(\"${outer(2)}\")\n"
)

_SS3_STRUCT_SECRET = (
    "type P { x: @secret String }\n"
    "fun outer(x: @secret String, stdio: Stdio)\n"
    "    let p = P { x: x }\n"
    "    let f = fun () -> String =>\n"
    "        let leak = fun () -> String => x\n"
    "        let P { x } = p\n"
    "        return leak()\n"
    "    stdio.println(f())\n"
    "fun main(stdio: Stdio, s: @secret String)\n"
    "    outer(s, stdio)\n"
)

# A SELF-REFERENTIAL shadow of a captured module const / function
# (``let S = S``) reads the enclosing global in its own initializer (the
# binding is not yet in scope in its RHS), so it diverges too: Wasm keeps
# the lexical global, Python function-scopes the whole body and reads the
# unassigned local. The RHS read sits AFTER the binding token, so a purely
# positional "read before" check missed it; the initializer read closes it.
_SELF_SECRET_CONST = (
    "const S: @secret String = \"s3cr3t\"\n"
    "fun main(stdio: Stdio)\n"
    "    let f = fun () -> String =>\n"
    "        let S = S\n"
    "        return S\n"
    "    stdio.println(f())\n"
)

_SELF_PUB_CONST = (
    "const G: String = \"glob\"\n"
    "fun main(stdio: Stdio)\n"
    "    let f = fun () -> String =>\n"
    "        let G = G\n"
    "        return G\n"
    "    stdio.println(f())\n"
)

_SELF_FUNCTION = (
    "fun S() -> String\n"
    "    return \"s3cr3t\"\n"
    "fun main(stdio: Stdio)\n"
    "    let f = fun () -> String =>\n"
    "        let S = S()\n"
    "        return S\n"
    "    stdio.println(f())\n"
)

_SELF_CONCAT = (
    "const S: @secret String = \"s3cr3t\"\n"
    "fun main(stdio: Stdio)\n"
    "    let f = fun () -> String =>\n"
    "        let S = S + \"!\"\n"
    "        return S\n"
    "    stdio.println(f())\n"
)

_SELF_INTERP = (
    "const S: @secret String = \"s3cr3t\"\n"
    "fun main(stdio: Stdio)\n"
    "    let f = fun () -> String =>\n"
    "        let S = \"${S}\"\n"
    "        return S\n"
    "    stdio.println(f())\n"
)

# The self-reference divergence also fires at PLAIN FUNCTION scope (no
# lambda / closure): ``let S = S`` reads the module const / function in its
# own initializer (the binding is not yet in scope there), and the two
# backends compile it differently (Python function-scopes the redeclared
# name for the whole body while Wasm keeps the lexical global). The
# plain-function READ-BEFORE analogue (``let a = S; let S = "z"``) is a
# genuine divergence too but is deferred: it collides with the IFC
# const-shadow-scoping fixtures and needs a uniform treatment together with
# the symmetric read-after-in-an-unexecuted-block case.
_PF_SELF_CONST = (
    "const S: @secret String = \"s3cr3t\"\n"
    "fun main(stdio: Stdio)\n"
    "    let S = S\n"
    "    stdio.println(S)\n"
)

_PF_SELF_FUNCTION = (
    "fun S() -> String\n"
    "    return \"s3cr3t\"\n"
    "fun main(stdio: Stdio)\n"
    "    let S = S()\n"
    "    stdio.println(S)\n"
)


class TestClosureShadowRejected(unittest.TestCase):
    """Every shape in the rejected divergence corpus now errors at
    ``--check``, with the actionable closure-shadow message."""

    def test_v_wrap_security_shape(self):
        # The security shape: a captured @secret redeclared inside the
        # closure. Pre-fix the Wasm backend printed the secret.
        self.assertTrue(_reject_msgs(_V_WRAP), "expected closure-shadow error")

    def test_min_p1_pure_scoping(self):
        self.assertTrue(_reject_msgs(_MIN_P1), "expected closure-shadow error")

    def test_m1_shadows_outer_param(self):
        # Load-bearing for the Fun-typed call-routing fix (3673fd4, branch
        # fix-fun-shadow-call-routing): the Wasm emitter still retrieves a
        # closure signature by name, so a lambda-body local shadowing an
        # enclosing param must stay rejected here or that lookup can
        # mis-route a same-named call. The routing-flavoured (Fun param,
        # called) variant is pinned by
        # tests/test_ir_wasm_l2_name_shadow.py::TestFunTypedRoutingGuardCoupling.
        self.assertTrue(
            _reject_msgs(_M1_PARAM), "expected closure-shadow error",
        )

    def test_a2_match_arm_bind(self):
        # A match-arm ident pattern inside the lambda body that binds a
        # name shadowing an enclosing local.
        self.assertTrue(
            _reject_msgs(_A2_MATCH), "expected closure-shadow error",
        )

    def test_a2_let_in_if_block(self):
        # A ``let`` nested in an ``if`` block inside the lambda body.
        self.assertTrue(
            _reject_msgs(_A2_SIBLING), "expected closure-shadow error",
        )

    def test_var_variant(self):
        # ``var`` does not go through ``_bind_pattern``; the check is
        # applied in ``_check_var`` so the ``var`` face closes too.
        self.assertTrue(
            _reject_msgs(_VAR_VARIANT), "expected closure-shadow error",
        )

    def test_captured_module_const_shadow(self):
        # A captured module-level const shadow (read via a nested closure
        # BEFORE the shadowing binding) diverges: Wasm discloses the global
        # secret while Python function-scopes the redeclared name.
        self.assertTrue(
            _reject_msgs(_CS1_CONST), "expected closure-shadow error",
        )

    def test_captured_module_const_shadow_strict(self):
        # Rejected at the strict tier too (the const case is a hard error
        # at both tiers, like the parameter / local case).
        strict = _CS1_CONST.replace(
            "fun main(stdio: Stdio)", "@strict_ifc()\nfun main(stdio: Stdio)",
        )
        self.assertTrue(_reject_msgs(strict), "strict tier")

    def test_captured_module_function_shadow(self):
        # Same for shadowing a top-level FUNCTION name captured before the
        # binding (Wasm keeps the global function, Python rebinds the name).
        self.assertTrue(
            _reject_msgs(_FN1_FUNCTION), "expected closure-shadow error",
        )

    def test_struct_shorthand_shadows_outer_param(self):
        # StructPat shorthand bind that shadows an enclosing parameter.
        self.assertTrue(
            _reject_msgs(_SS2_STRUCT), "expected closure-shadow error",
        )

    def test_struct_shorthand_shadows_secret_param(self):
        # The @secret variant: the shorthand rebind of ``x`` shadows the
        # enclosing @secret parameter that a nested closure captured.
        self.assertTrue(
            _reject_msgs(_SS3_STRUCT_SECRET), "expected closure-shadow error",
        )

    def test_self_referential_const_shadow(self):
        # ``let S = S`` inside a lambda: the RHS reads the enclosing @secret
        # const (the binding is not yet in scope in its own initializer), so
        # the shadow diverges (Wasm discloses the global, Python crashes).
        self.assertTrue(
            _reject_msgs(_SELF_SECRET_CONST), "expected closure-shadow error",
        )

    def test_self_referential_const_shadow_strict(self):
        strict = _SELF_SECRET_CONST.replace(
            "fun main(stdio: Stdio)", "@strict_ifc()\nfun main(stdio: Stdio)",
        )
        self.assertTrue(_reject_msgs(strict), "strict tier")

    def test_self_referential_public_const_shadow(self):
        # The public-const form diverges identically (Python crash vs Wasm
        # value), so it is a general backend divergence, not only a leak.
        self.assertTrue(
            _reject_msgs(_SELF_PUB_CONST), "expected closure-shadow error",
        )

    def test_self_referential_function_shadow(self):
        self.assertTrue(
            _reject_msgs(_SELF_FUNCTION), "expected closure-shadow error",
        )

    def test_self_referential_const_shadow_concat(self):
        # ``let S = S + "!"`` -- the RHS still reads the enclosing const.
        self.assertTrue(
            _reject_msgs(_SELF_CONCAT), "expected closure-shadow error",
        )

    def test_self_referential_const_shadow_interpolation(self):
        # ``let S = "${S}"`` -- the interpolation reads the enclosing const.
        self.assertTrue(
            _reject_msgs(_SELF_INTERP), "expected closure-shadow error",
        )

    def test_plain_function_self_ref_const(self):
        # Face 1 at plain function scope (no lambda): ``let S = S`` reads the
        # module const in its own initializer.
        self.assertTrue(
            _reject_msgs(_PF_SELF_CONST), "expected closure-shadow error",
        )

    def test_plain_function_self_ref_const_strict(self):
        strict = _PF_SELF_CONST.replace(
            "fun main(stdio: Stdio)", "@strict_ifc()\nfun main(stdio: Stdio)",
        )
        self.assertTrue(_reject_msgs(strict), "strict tier")

    def test_plain_function_self_ref_function(self):
        # The function-name analogue at plain function scope.
        self.assertTrue(
            _reject_msgs(_PF_SELF_FUNCTION), "expected closure-shadow error",
        )

    def test_rejected_in_both_tiers(self):
        # The rejection is a hard error at BOTH the default (warn) tier
        # and ``@strict_ifc`` (error tier): it is unconditional, not
        # tier-gated. Adding the strict annotation does not change it.
        strict = "@strict_ifc()\n" + _MIN_P1
        self.assertTrue(_reject_msgs(_MIN_P1), "default tier")
        self.assertTrue(_reject_msgs(strict), "strict tier")


# A lambda PARAMETER shadowing an outer name (map/fold style) and a
# lambda that CAPTURES a name without redeclaring it: both must stay
# legal AND agree byte-for-byte across backends. Running them (not just
# analyzer-accepting them) is the control the original bug lacked.
_LEGAL_PARAM_SHADOW = (
    "fun main(stdio: Stdio)\n"
    "    let x = 100\n"
    "    let g = fun (x: Int) -> Int => x + 1\n"
    "    stdio.println(\"${g(5)}\")\n"
    "    stdio.println(\"${x}\")\n"
)

_LEGAL_CAPTURE = (
    "fun main(stdio: Stdio)\n"
    "    let factor = 10\n"
    "    let scale = fun (v: Int) -> Int => v * factor\n"
    "    stdio.println(\"scale(3)=${scale(3)}\")\n"
    "    stdio.println(\"scale(7)=${scale(7)}\")\n"
)

# BK1: a lambda-body shadow of a module const that is NOT referenced before
# the shadowing binding stays legal. Wasm treats the const as a global, so
# the local shadow and the read of it after the binding agree with Python.
_BK1_CONST_UNCAPTURED = (
    "const LIMIT: Int = 10\n"
    "fun main(stdio: Stdio)\n"
    "    let f = fun () -> Int =>\n"
    "        let LIMIT = 3\n"
    "        return LIMIT\n"
    "    stdio.println(\"${f()}\")\n"
)

# CS_after: a nested closure that captures the module const but is defined
# AFTER the shadowing binding stays legal, because at that point both
# backends see the local. Pins the positional refinement (a capture after
# the shadow is not a divergence, so it is not over-rejected).
_CS_AFTER_LEGAL = (
    "const bag: String = \"glob\"\n"
    "fun main(stdio: Stdio)\n"
    "    let wrap = fun () -> String =>\n"
    "        let bag = \"z\"\n"
    "        let leak = fun () -> String => bag\n"
    "        return leak()\n"
    "    stdio.println(wrap())\n"
)

# A lambda-body ``let A = B`` shadowing const ``A`` while its initializer
# reads a DIFFERENT const ``B`` stays legal: the initializer does not read
# the shadowed name, so both backends bind ``A`` to B's value. Pins that
# the self-ref rule fires only on a self-read, not any const shadow.
_LEGAL_INIT_OTHER_CONST = (
    "const A: Int = 7\n"
    "const B: Int = 3\n"
    "fun main(stdio: Stdio)\n"
    "    let f = fun () -> Int =>\n"
    "        let A = B\n"
    "        return A\n"
    "    stdio.println(\"${f()}\")\n"
)

# A plain-function const shadow that never reads the outer const stays
# legal and byte-identical (both backends bind the local). The discriminator
# for the plain-function extension: shadow != divergence.
_PF_LEGAL = (
    "const X: Int = 10\n"
    "fun main(stdio: Stdio)\n"
    "    let X = 5\n"
    "    stdio.println(\"${X}\")\n"
)

# A shadow of a module FUNCTION ``c`` by sibling match-arm binds that each
# read their OWN local ``c`` (not the module function). Distilled from
# examples/wasm/match_struct_field_subpatterns.capa. The read-before check
# must resolve each ``c`` read to its arm-local bind (via the analyzer's
# name resolution), NOT treat it as an outward read of the module ``c`` --
# otherwise it over-rejects this byte-identical program.
_PF_MATCH_SIBLING = (
    "type Tup { pair: Int, y: Int }\n"
    "fun c() -> Int\n"
    "    return 7\n"
    "fun t(p: Tup) -> Int\n"
    "    return match p\n"
    "        Tup { pair: 1, y: c } -> c\n"
    "        Tup { pair: a, y: c } -> a + c\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(\"${t(Tup { pair: 1, y: 5 })}\")\n"
    "    stdio.println(\"${t(Tup { pair: 9, y: 3 })}\")\n"
)


class TestClosureShadowLegalStaysLegal(unittest.TestCase):
    def test_param_shadow_check_passes(self):
        module, result = _parse_ok(_LEGAL_PARAM_SHADOW)
        self.assertTrue(result.ok, result.errors)

    def test_capture_without_shadow_check_passes(self):
        module, result = _parse_ok(_LEGAL_CAPTURE)
        self.assertTrue(result.ok, result.errors)

    def test_uncaptured_const_shadow_check_passes(self):
        module, result = _parse_ok(_BK1_CONST_UNCAPTURED)
        self.assertTrue(result.ok, result.errors)

    def test_capture_after_shadow_check_passes(self):
        module, result = _parse_ok(_CS_AFTER_LEGAL)
        self.assertTrue(result.ok, result.errors)

    def test_init_reads_other_const_check_passes(self):
        module, result = _parse_ok(_LEGAL_INIT_OTHER_CONST)
        self.assertTrue(result.ok, result.errors)

    def test_plain_function_non_self_ref_shadow_check_passes(self):
        module, result = _parse_ok(_PF_LEGAL)
        self.assertTrue(result.ok, result.errors)

    def test_plain_function_sibling_match_arm_check_passes(self):
        module, result = _parse_ok(_PF_MATCH_SIBLING)
        self.assertTrue(result.ok, result.errors)


@unittest.skipUnless(_has_wasmtime(), "wasmtime not installed")
class TestClosureShadowLegalRunsIdentically(unittest.TestCase):
    """A LEGAL control is EXECUTED on both backends and asserted
    byte-identical, closing the gap that hid this bug (a legal case that
    was only analyzer-accepted, never run)."""

    def test_param_shadow_byte_identical(self):
        py = _python_out(_LEGAL_PARAM_SHADOW)
        wa = _wasm_out(_LEGAL_PARAM_SHADOW)
        self.assertEqual(py, wa)
        self.assertEqual(py, "6\n100\n")

    def test_capture_without_shadow_byte_identical(self):
        py = _python_out(_LEGAL_CAPTURE)
        wa = _wasm_out(_LEGAL_CAPTURE)
        self.assertEqual(py, wa)
        self.assertEqual(py, "scale(3)=30\nscale(7)=70\n")

    def test_uncaptured_const_shadow_byte_identical(self):
        # BK1: the required legal control -- a module-const shadow with no
        # read before the binding runs byte-identical on both backends.
        py = _python_out(_BK1_CONST_UNCAPTURED)
        wa = _wasm_out(_BK1_CONST_UNCAPTURED)
        self.assertEqual(py, wa)
        self.assertEqual(py, "3\n")

    def test_capture_after_shadow_byte_identical(self):
        # CS_after: a nested capture defined after the shadow is also
        # byte-identical, so the positional refinement leaves it legal.
        py = _python_out(_CS_AFTER_LEGAL)
        wa = _wasm_out(_CS_AFTER_LEGAL)
        self.assertEqual(py, wa)
        self.assertEqual(py, "z\n")

    def test_init_reads_other_const_byte_identical(self):
        # The initializer-legal control: ``let A = B`` shadowing const A
        # while reading a different const B runs byte-identical (both bind
        # A to B's value), so the self-ref rule did not over-reject it.
        py = _python_out(_LEGAL_INIT_OTHER_CONST)
        wa = _wasm_out(_LEGAL_INIT_OTHER_CONST)
        self.assertEqual(py, wa)
        self.assertEqual(py, "3\n")

    def test_plain_function_non_self_ref_shadow_byte_identical(self):
        # The plain-function discriminator: a const shadow that never reads
        # the outer const binds the local on both backends.
        py = _python_out(_PF_LEGAL)
        wa = _wasm_out(_PF_LEGAL)
        self.assertEqual(py, wa)
        self.assertEqual(py, "5\n")

    def test_plain_function_sibling_match_arm_byte_identical(self):
        # The precision pin: sibling match-arm binds of a module function's
        # name run byte-identical (each arm reads its own local bind), so
        # the read-before check must not over-reject them.
        py = _python_out(_PF_MATCH_SIBLING)
        wa = _wasm_out(_PF_MATCH_SIBLING)
        self.assertEqual(py, wa)
        self.assertEqual(py, "5\n12\n")


# The whole-function post-pass rejects a PLAIN function that both
# name-shadows a module const / function AND reads it. These pin the
# binding forms and read forms the per-binding lambda paths do NOT cover:
# a ``var`` shadow, a struct-pattern shorthand shadow, a shadow of a
# module FUNCTION, and a read as a call argument.
_PF_VAR = (
    "const S: @secret String = \"s3cr3t\"\n"
    "fun leak() -> String\n"
    "    let out = S\n"
    "    var S = \"z\"\n"
    "    return out\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(leak())\n"
)

# ``let Box { k } = bx`` binds ``k`` via struct-pattern shorthand,
# shadowing the secret const ``k`` that ``let out = k`` reads first: a
# real Wasm secret leak on baseline, now rejected. Set (a) must enumerate
# the shorthand-bound name for this to fire.
_PF_STRUCT_SHORTHAND = (
    "type Box { k: String }\n"
    "const k: @secret String = \"s3cr3t\"\n"
    "fun leak(bx: Box) -> String\n"
    "    let out = k\n"
    "    let Box { k } = bx\n"
    "    return out\n"
    "fun main(stdio: Stdio, bx: Box)\n"
    "    stdio.println(leak(bx))\n"
)

_PF_FUNCTION_SHADOW = (
    "fun helper() -> String\n"
    "    return \"s3cr3t\"\n"
    "fun leak() -> String\n"
    "    let out = helper()\n"
    "    let helper = \"z\"\n"
    "    return out\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(leak())\n"
)

_PF_CALL_ARG = (
    "const S: @secret String = \"s3cr3t\"\n"
    "fun sink(x: String, stdio: Stdio)\n"
    "    stdio.println(x)\n"
    "fun main(stdio: Stdio)\n"
    "    sink(S, stdio)\n"
    "    let S = \"z\"\n"
)


class TestPlainFunctionModuleShadow(unittest.TestCase):
    """Whole-function post-pass: a plain function that shadows and reads a
    module const / function is rejected (the lambda class is handled
    separately, per-binding)."""

    def test_var_shadow_rejected(self):
        self.assertTrue(_reject_msgs(_PF_VAR), "expected module-shadow error")

    def test_struct_pattern_shorthand_shadow_rejected(self):
        self.assertTrue(
            _reject_msgs(_PF_STRUCT_SHORTHAND), "expected module-shadow error",
        )

    def test_module_function_shadow_rejected(self):
        # Load-bearing for the Fun-typed call-routing fix (3673fd4, branch
        # fix-fun-shadow-call-routing): the emitter's by-name closure
        # signature lookup stays safe for a module-function shadow only
        # because this rejection fires before lowering. The routing-flavoured
        # (module function called, then Fun-local shadow) variant is pinned by
        # tests/test_ir_wasm_l2_name_shadow.py::TestFunTypedRoutingGuardCoupling.
        self.assertTrue(
            _reject_msgs(_PF_FUNCTION_SHADOW), "expected module-shadow error",
        )

    def test_read_as_call_arg_rejected(self):
        self.assertTrue(
            _reject_msgs(_PF_CALL_ARG), "expected module-shadow error",
        )

    def test_rejected_in_both_tiers(self):
        strict = _PF_VAR.replace(
            "fun main(stdio: Stdio)", "@strict_ifc()\nfun main(stdio: Stdio)",
        )
        self.assertTrue(_reject_msgs(_PF_VAR), "default tier")
        self.assertTrue(_reject_msgs(strict), "strict tier")


if __name__ == "__main__":
    unittest.main()
