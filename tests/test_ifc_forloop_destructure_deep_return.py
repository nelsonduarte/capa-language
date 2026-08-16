"""Cross-function DEEP field-access RETURN laundering through a FOR-LOOP
binder (item 1b) and a struct DESTRUCTURING binder (item 1c) (closed false
negatives).

A callee that RETURNS a nested declared-``@secret`` field reached through a
value bound by a ``for`` loop element (``for u in secs { return u.f2.f3.v }``,
``secs: List<Outer>``) or by a ``let`` destructuring (``let Outer { f2 } = t;
return f2.f3.v``) was ``--check``-clean at both tiers and leaked on both
backends. The deep-field return channel (``_field_read_is_secret``) walks the
declared field-type chain from a root resolved via the per-callable value-type
map, but the for-loop binder and the struct-pattern field-name binder were
never seeded, so the root type did not resolve and the return effect fell back
to the whole-value carrier.

The fix seeds both binders type-precisely:

* item 1c -- a destructuring ``let`` seeds each destructured field's binder
  from the pattern's DECLARED struct type (``_record_pattern_value_types``),
  resolution by the declared type never the bound-name spelling.
* item 1b -- a ``for`` IdentPat binder is seeded BODY-SCOPED from the
  iterable's element struct type (``_iter_element_struct_type``): a param
  ``List<Outer>``, a list literal of struct values, or a container field
  (``bag.items``). The seed is saved and restored around the body, so a
  sibling / sequential loop reusing the binder over a different (or
  unresolvable) element type cannot resolve against a stale type, and a
  same-named binding after the loop is unaffected.

Type-precise: a same-named public field of an unrelated struct is not
flagged, and a public leaf whose secret sibling shares the struct stays
clean.

RESIDUAL (known-open, disclosed, asserted to still leak on Python): a for
over a CALL- / INDEX-rooted iterable (``for u in mk()``), a for over a
LOCAL-bound list (``let xs = secs; for u in xs``), a call- / index-rooted
chain (``return id(t).f2.f3.v``), and a nested-generic inner-loop element
(``List<List<Outer>>``) have no resolvable root / element type and stay
whole-value false negatives, the same class as ``G_subreturn`` / ``H_alias``.
"""

import shutil
import unittest

from capa import Lexer, Parser, analyze, transpile
from capa.ir import compile_wasm


def _parse(src: str):
    return Parser(Lexer(src).lex(), source=src).parse_module()


def _analyze(src: str):
    return analyze(_parse(src), source=src)


def _strict(src: str, fn: str) -> str:
    """Opt the caller ``fn`` (holding the cross-function sink) into
    ``@strict_ifc`` -- the tier where the flow is a hard error."""
    return src.replace("fun " + fn + "(", "@strict_ifc()\nfun " + fn + "(", 1)


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
    return _capture(lambda: exec(compile(code, "<fdr>", "exec"), ns))


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


# A three-level struct whose deepest leaf ``v`` is declared @secret and whose
# sibling ``note`` is public. The secret is a PLAIN struct literal (no @secret
# const), so only the cross-function summary can attribute it. ``Bag`` holds a
# ``List<Outer>`` for the container-field iteration.
_TYPES = (
    "type Inner { v: @secret String, note: String }\n"
    "type Mid { f3: Inner }\n"
    "type Outer { f2: Mid }\n"
    "type Bag { items: List<Outer> }\n"
)
_MK = (
    "    let o = Outer { f2: Mid "
    "{ f3: Inner { v: \"s3cr3t\", note: \"pub\" } } }\n"
)
_OLIT = "Outer { f2: Mid { f3: Inner { v: \"s3cr3t\", note: \"pub\" } } }"


# ---- the LEAK shapes: each is FLAGGED after the fix, runs and prints ------

# 1b: a for over a List<Outer> PARAMETER; the binder's deep @secret is read.
FOR_PARAM = (_TYPES +
    "fun leak(secs: List<Outer>) -> String\n"
    "    for u in secs\n"
    "        return u.f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak([o]))\n")

# 1b: a for over a LIST LITERAL of struct values.
FOR_LISTLIT = (_TYPES +
    "fun leak() -> String\n"
    "    for u in [" + _OLIT + "]\n"
    "        return u.f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(leak())\n")

# 1b: a for over a CONTAINER FIELD (``bag.items``).
CONTAINER_FIELD = (_TYPES +
    "fun leak(bag: Bag) -> String\n"
    "    for u in bag.items\n"
    "        return u.f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    let bag = Bag { items: [o] }\n"
    "    stdio.println(leak(bag))\n")

# 1c: a destructuring ``let`` whose @secret leaf is nested below the field.
DESTRUCTURE = (_TYPES +
    "fun leak(t: Outer) -> String\n"
    "    let Outer { f2 } = t\n"
    "    return f2.f3.v\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak(o))\n")

# 1c: a destructuring ``let`` with a RENAME (``f2: m``) binds the alias.
DESTRUCTURE_RENAME = (_TYPES +
    "fun leak(t: Outer) -> String\n"
    "    let Outer { f2: m } = t\n"
    "    return m.f3.v\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak(o))\n")

# 1b+1c: a DESTRUCTURING for-pattern over a List<Outer> parameter.
FOR_DESTRUCTURE = (_TYPES +
    "fun leak(secs: List<Outer>) -> String\n"
    "    for Outer { f2 } in secs\n"
    "        return f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak([o]))\n")

# A secret binding read AFTER a loop that reused the name is still flagged
# (the loop binder's body-scoped seed is restored, and the later ``let u``
# re-seeds from its own struct type).
SHADOW_AFTER_LOOP = (_TYPES +
    "fun leak(pubs: List<Bag>, t: Outer) -> String\n"
    "    for u in pubs\n"
    "        let z = u\n"
    "    let u = t\n"
    "    return u.f2.f3.v\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak([], o))\n")

# Physically NESTED loops of different element types; the outer binder's deep
# @secret is read inside the inner loop and stays resolved there.
NESTED_LOOPS = (_TYPES +
    "fun leak(secs: List<Outer>, pubs: List<Bag>) -> String\n"
    "    for u in secs\n"
    "        for p in pubs\n"
    "            return u.f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak([o], [Bag { items: [] }]))\n")

# name -> (source, strict caller, expected stdout). Every shape prints the
# secret leaf.
_LEAKS = {
    "1b_for_param": (FOR_PARAM, "main", "s3cr3t\n"),
    "1b_for_listlit": (FOR_LISTLIT, "main", "s3cr3t\n"),
    "1b_container_field": (CONTAINER_FIELD, "main", "s3cr3t\n"),
    "1c_destructure": (DESTRUCTURE, "main", "s3cr3t\n"),
    "1c_destructure_rename": (DESTRUCTURE_RENAME, "main", "s3cr3t\n"),
    "for_destructure": (FOR_DESTRUCTURE, "main", "s3cr3t\n"),
    "shadow_after_loop_secret": (SHADOW_AFTER_LOOP, "main", "s3cr3t\n"),
    "nested_loops": (NESTED_LOOPS, "main", "s3cr3t\n"),
}


class TestForLoopDestructureReturnLeak(unittest.TestCase):
    """Every for-loop / destructuring deep-return shape is FLAGGED at the
    default tier and a hard error under ``@strict_ifc`` -- the closed false
    negatives -- and runs, printing the secret on both backends."""

    def test_flagged_default_tier(self):
        for name, (src, _fn, _out) in _LEAKS.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                        [w.message for w in r.warnings])

    def test_hard_error_under_strict(self):
        for name, (src, fn, _out) in _LEAKS.items():
            with self.subTest(shape=name):
                rs = _analyze(_strict(src, fn))
                self.assertFalse(rs.ok)
                self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                        [e.message for e in rs.errors])

    def test_leaks_both_backends(self):
        skip = _wasm_unavailable()
        for name, (src, _fn, out) in _LEAKS.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), out)
                if skip is None:
                    self.assertEqual(_run_wasm(src), out)


# ---- STILL FLAG ONCE: a destructured field that is ITSELF @secret ---------

# The destructured field ``f2`` is declared @secret (not a nested leaf), so
# the pattern-secret rule already taints it; the type seed must not add a
# SECOND warning for the same flow.
DESTRUCTURE_FIELD_SECRET = (
    "type Outer { f2: @secret String }\n"
    "fun leak(t: Outer) -> String\n"
    "    let Outer { f2 } = t\n"
    "    return f2\n"
    "fun main(stdio: Stdio)\n"
    "    let o = Outer { f2: \"s3cr3t\" }\n"
    "    stdio.println(leak(o))\n")


class TestDestructuredSecretFieldFlaggedOnce(unittest.TestCase):
    """A destructured field that is itself @secret flags EXACTLY once (the
    type seed does not double-count the pattern-secret taint)."""

    def test_flagged_exactly_once(self):
        r = _analyze(DESTRUCTURE_FIELD_SECRET)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_leaks_both_backends(self):
        skip = _wasm_unavailable()
        self.assertEqual(_run_py(DESTRUCTURE_FIELD_SECRET), "s3cr3t\n")
        if skip is None:
            self.assertEqual(_run_wasm(DESTRUCTURE_FIELD_SECRET), "s3cr3t\n")


# ---- MUST-NOT-FLAG: type-precise, body-scoped, no false positive ----------

# A public leaf whose sibling is @secret, read through a for binder.
FORLOOP_PUBLIC = (_TYPES +
    "fun readpub(secs: List<Outer>) -> String\n"
    "    for u in secs\n"
    "        return u.f2.f3.note\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(readpub([o]))\n")

# Same field NAME ``v`` in an UNRELATED struct read through a for binder; the
# @secret ``v`` lives in a different type, so no by-name false positive.
SAMENAME_FORLOOP = (
    "type AInner { v: @secret String }\n"
    "type BInner { v: String }\n"
    "type BMid { f3: BInner }\n"
    "type BOuter { f2: BMid }\n"
    "fun readpub(secs: List<BOuter>) -> String\n"
    "    for u in secs\n"
    "        return u.f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n"
    "    let o = BOuter { f2: BMid { f3: BInner { v: \"pub\" } } }\n"
    "    stdio.println(readpub([o]))\n")

# A Set<Outer> public read: the element type resolves, the leaf is public.
SET_ITER_PUBLIC = (_TYPES +
    "fun readpub(s: Set<Outer>) -> String\n"
    "    for u in s\n"
    "        return u.f2.f3.note\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(readpub(new_set()))\n")

# A nested-generic (``List<List<Pub>>``) public read: the inner binder is
# unresolvable, but the leaf is public anyway, so it stays clean and does not
# crash.
NESTED_GENERICS_PUBLIC = (
    "type Pub { a: String }\n"
    "fun readpub(xss: List<List<Pub>>) -> String\n"
    "    for row in xss\n"
    "        for u in row\n"
    "            return u.a\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(readpub([]))\n")

# The deep secret is returned via a for binder but NEVER sunk: no flow.
NEVER_SUNK = (_TYPES +
    "fun leak(secs: List<Outer>) -> String\n"
    "    for u in secs\n"
    "        return u.f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    let x = leak([o])\n"
    "    stdio.println(\"done\")\n")

# Conflation guard: a prior ``for u in secs`` then a call-rooted ``for u in
# mk()`` reading the same path. The body-scoped seed must not let the first
# loop's ``u: Outer`` leak into the second loop (whose element type is
# unresolvable), so the second read stays clean.
CONFLATE_SIBLING = (_TYPES +
    "fun mk() -> List<Outer>\n"
    "    return []\n"
    "fun leak(secs: List<Outer>) -> String\n"
    "    for u in secs\n"
    "        let z = u\n"
    "    for u in mk()\n"
    "        return u.f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak([o]))\n")

# Conflation guard: ``let xs = pubs; for u in xs`` reading a public path. The
# local-bound list does not propagate its element type, so ``u`` is
# unresolved and the read is clean.
CONFLATE_LOCAL = (
    "type PInner { v: String }\n"
    "type PMid { f3: PInner }\n"
    "type POuter { f2: PMid }\n"
    "fun leak(pubs: List<POuter>) -> String\n"
    "    let xs = pubs\n"
    "    for u in xs\n"
    "        return u.f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(leak([]))\n")

# A public binding read AFTER a loop that reused the name over a SECRET
# element type: the loop binder's seed is restored, and the later ``let u``
# re-seeds from a PUBLIC struct, so the read stays clean (no stale secret).
SHADOW_AFTER_LOOP_PUBLIC = (_TYPES +
    "type PInner { v: String }\n"
    "type PMid { f3: PInner }\n"
    "type POuter { f2: PMid }\n"
    "fun leak(secs: List<Outer>, p: POuter) -> String\n"
    "    for u in secs\n"
    "        let z = u\n"
    "    let u = p\n"
    "    return u.f2.f3.v\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    let pp = POuter { f2: PMid { f3: PInner { v: \"pub\" } } }\n"
    "    stdio.println(leak([o], pp))\n")

# Sequential loops reusing the binder: the second loop's element type is
# public, so despite the first loop's secret seed the read is clean.
SEQUENTIAL_REUSE_PUBLIC = (_TYPES +
    "type PInner { v: String }\n"
    "type PMid { f3: PInner }\n"
    "type POuter { f2: PMid }\n"
    "fun leak(secs: List<Outer>, pubs: List<POuter>) -> String\n"
    "    for u in secs\n"
    "        let z = u\n"
    "    for u in pubs\n"
    "        return u.f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak([o], []))\n")

# A DESTRUCTURING for-pattern reading a PUBLIC sibling of the secret leaf.
DESTRUCTURING_FOR_PUBLIC = (_TYPES +
    "fun readpub(secs: List<Outer>) -> String\n"
    "    for Outer { f2 } in secs\n"
    "        return f2.f3.note\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(readpub([o]))\n")

# An early-exit body (``break``) then a sibling loop reusing the binder over a
# call-rooted (unresolvable) iterable reading the secret path: the body-scoped
# seed is restored past the break, so the sibling read is clean.
EARLY_EXIT_SIBLING = (_TYPES +
    "fun mk() -> List<Outer>\n"
    "    return []\n"
    "fun leak(secs: List<Outer>) -> String\n"
    "    for u in secs\n"
    "        break\n"
    "    for u in mk()\n"
    "        return u.f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak([o]))\n")

# The restore is load-bearing: after ``for u in secs`` (Outer seed), ``u`` is
# rebound to a call result (unresolvable), so the following read must NOT
# resolve against the loop's stale ``Outer`` type.
RESTORE_BITES = (_TYPES +
    "fun mk() -> Outer\n"
    "    return " + _OLIT + "\n"
    "fun leak(secs: List<Outer>) -> String\n"
    "    for u in secs\n"
    "        let z = u\n"
    "    let u = mk()\n"
    "    return u.f2.f3.v\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak([o]))\n")

_CLEAN = {
    "forloop_public": (FORLOOP_PUBLIC, "pub\n"),
    "samename_forloop": (SAMENAME_FORLOOP, "pub\n"),
    "set_iter_public": (SET_ITER_PUBLIC, "none\n"),
    "nested_generics_public": (NESTED_GENERICS_PUBLIC, "none\n"),
    "never_sunk": (NEVER_SUNK, "done\n"),
    "conflate_sibling": (CONFLATE_SIBLING, "none\n"),
    "conflate_local": (CONFLATE_LOCAL, "none\n"),
    "shadow_after_loop_public": (SHADOW_AFTER_LOOP_PUBLIC, "pub\n"),
    "sequential_reuse_public": (SEQUENTIAL_REUSE_PUBLIC, "none\n"),
    "destructuring_for_public": (DESTRUCTURING_FOR_PUBLIC, "pub\n"),
    "early_exit_sibling": (EARLY_EXIT_SIBLING, "none\n"),
    "restore_bites": (RESTORE_BITES, "s3cr3t\n"),
}


class TestForLoopDestructureNoFalsePositive(unittest.TestCase):
    """A public sibling, a same-named unrelated field, a public set / nested
    generic, an un-sunk secret, and every body-scoping conflation guard stay
    clean at BOTH tiers, and run their public values on both backends."""

    def test_clean_both_tiers(self):
        for name, (src, _out) in _CLEAN.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])
                rs = _analyze(_strict(src, "main"))
                self.assertEqual(len(_flow_errors(rs)), 0,
                                 [e.message for e in rs.errors])

    def test_runs_public_value(self):
        skip = _wasm_unavailable()
        for name, (src, out) in _CLEAN.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), out)
                if skip is None:
                    self.assertEqual(_run_wasm(src), out)


# ---- RESIDUAL-STAYS-OPEN: clean analysis, honest runtime leak on Python ----

# A call- / index-rooted chain: no ident root, no resolvable root type.
RES_CALL_ROOTED = (_TYPES +
    "fun id(t: Outer) -> Outer\n"
    "    return t\n"
    "fun leak(t: Outer) -> String\n"
    "    return id(t).f2.f3.v\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak(o))\n")

# A for over a CALL-rooted iterable: the element type is unresolvable.
RES_FOR_CALL = (_TYPES +
    "fun mk() -> List<Outer>\n"
    "    return [" + _OLIT + "]\n"
    "fun leak() -> String\n"
    "    for u in mk()\n"
    "        return u.f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(leak())\n")

# A for over a LOCAL-bound list: the element type is not propagated into a
# ``let`` binding.
RES_LOCAL_LIST = (_TYPES +
    "fun leak(secs: List<Outer>) -> String\n"
    "    let xs = secs\n"
    "    for u in xs\n"
    "        return u.f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak([o]))\n")

# A nested-generic inner-loop element (``List<List<Outer>>``): only the outer
# container name is recorded as the element type, so the inner binder is
# unresolvable.
RES_NESTED_GENERIC = (_TYPES +
    "fun leak(xss: List<List<Outer>>) -> String\n"
    "    for row in xss\n"
    "        for u in row\n"
    "            return u.f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak([[o]]))\n")

_RESIDUALS = {
    "1a_call_rooted": RES_CALL_ROOTED,
    "for_call_rooted": RES_FOR_CALL,
    "local_bound_list": RES_LOCAL_LIST,
    "nested_generic_inner": RES_NESTED_GENERIC,
}


class TestForLoopDestructureResidual(unittest.TestCase):
    """The disclosed residuals stay unflagged at both tiers AND are asserted
    to still leak the secret at runtime on Python, so the open scope is
    honest (no guarantee overclaim)."""

    def test_residual_unflagged(self):
        for name, src in _RESIDUALS.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])
                rs = _analyze(_strict(src, "main"))
                self.assertEqual(len(_flow_errors(rs)), 0,
                                 [e.message for e in rs.errors])

    def test_residual_still_leaks_on_python(self):
        for name, src in _RESIDUALS.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")


# ---- REJECTION pins: shadowing a param / outer let (base and branch) -------

# A for-binder shadowing a PARAMETER is rejected by the analyzer, on the base
# and the branch alike (an analyzer scope rule, not an IFC pin).
REJECT_SHADOW_PARAM = (_TYPES +
    "fun leak(u: Outer, secs: List<Outer>) -> String\n"
    "    for u in secs\n"
    "        return u.f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(\"x\")\n")

# A for-binder shadowing an OUTER ``let`` is rejected likewise.
REJECT_SHADOW_LET = (_TYPES +
    "fun leak(secs: List<Outer>) -> String\n"
    "    let u = " + _OLIT + "\n"
    "    for u in secs\n"
    "        return u.f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(\"x\")\n")


class TestForBinderShadowRejected(unittest.TestCase):
    """A for-binder that shadows an outer-scope local is a hard analyzer
    error (message mentions shadowing), independent of the IFC fix."""

    def test_shadow_param_rejected(self):
        r = _analyze(REJECT_SHADOW_PARAM)
        self.assertFalse(r.ok)
        self.assertTrue(any("shadow" in e.message for e in r.errors),
                        [e.message for e in r.errors])

    def test_shadow_let_rejected(self):
        r = _analyze(REJECT_SHADOW_LET)
        self.assertFalse(r.ok)
        self.assertTrue(any("shadow" in e.message for e in r.errors),
                        [e.message for e in r.errors])


if __name__ == "__main__":
    unittest.main()
