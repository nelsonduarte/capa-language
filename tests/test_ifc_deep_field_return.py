"""Cross-function DEEP (>=2-hop) field-access RETURN laundering (closed
false negative).

A callee that RETURNS a nested declared-``@secret`` field of a struct
parameter (``return t.f2.f3.v``, the leaf ``v`` labelled ``@secret``) was
``--check``-clean at both tiers and leaked on both backends. The
cross-function summary's ``_field_read_is_secret`` recognised a
declared-``@secret`` field read only when the receiver was an ``Ident``
(depth 1: ``return e.iban``), so a chain whose receiver is itself a
``FieldAccess`` attributed no ``INTERNAL_SECRET`` and the return effect
carried only the harmless param index. The sibling of the returned
field-store leak.

The closure walks the field-access chain type-precisely from its root
through ``struct_field_type_names`` to the leaf's owning struct, then tests
the leaf's declared label. Depth-1 is the same walk with an empty prefix,
so ``return e.iban`` stays caught. A chain rooted at a LOCAL that
statically denotes a struct (a copy of a param, a param field, or a struct
literal) resolves its root type from ``_cur_value_types``, so
``let u = t; return u.f2.f3.v`` and ``let u = t.f2; return u.f3.v`` are
covered too. Each hop follows the ACTUAL declared field type, never a
field-name match, so a same-named public field of an unrelated struct is
not flagged (no by-name false positive).

RESIDUAL (known-open): a chain rooted at a CALL / INDEX result
(``return id(t).f2.f3.v``) has no ident root and stays a whole-value
false negative, the same class as ``G_subreturn`` / ``H_alias``.
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
    return _capture(lambda: exec(compile(code, "<dfr>", "exec"), ns))


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


# A three-level struct whose deepest leaf ``v`` is declared @secret and
# whose sibling ``note`` is public. The secret is a PLAIN struct literal
# (no @secret const), so only the cross-function summary can attribute it.
_TYPES = (
    "type Inner { v: @secret String, note: String }\n"
    "type Mid { f3: Inner }\n"
    "type Outer { f2: Mid }\n"
)
_MK = (
    "    let o = Outer { f2: Mid "
    "{ f3: Inner { v: \"s3cr3t\", note: \"pub\" } } }\n"
)


# ---- the LEAK shapes: each is FLAGGED after the fix, runs and prints ------

# 3-hop return of a nested @secret leaf off a struct parameter.
DEEP_3HOP = (_TYPES +
    "fun leak(t: Outer) -> String\n"
    "    return t.f2.f3.v\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak(o))\n")

# Re-entry: a mid function returns the deep-leaking callee's result, and the
# caller sinks the mid result (the taint threads through two boundaries).
DEEP_REENTRY = (_TYPES +
    "fun inner(t: Outer) -> String\n"
    "    return t.f2.f3.v\n"
    "fun mid(t: Outer) -> String\n"
    "    return inner(t)\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(mid(o))\n")

# Mixed local/param: a local copies the whole parameter, then a deep read.
DEEP_LOCAL_COPY = (_TYPES +
    "fun leak(t: Outer) -> String\n"
    "    let u = t\n"
    "    return u.f2.f3.v\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak(o))\n")

# Local aliases a param FIELD, then a shorter deep read off the alias.
DEEP_LOCAL_FIELD = (_TYPES +
    "fun leak(t: Outer) -> String\n"
    "    let u = t.f2\n"
    "    return u.f3.v\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak(o))\n")

# Self-method: a method returns a deep @secret field of ``self``.
DEEP_SELF = (_TYPES +
    "impl Outer\n"
    "    fun grab(self) -> String\n"
    "        return self.f2.f3.v\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(o.grab())\n")

# A struct built from the returned deep field, then the held field sunk.
DEEP_STRUCT_BUILT = (_TYPES + "type Wrap { held: String }\n"
    "fun leak(t: Outer) -> String\n"
    "    return t.f2.f3.v\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    let w = Wrap { held: leak(o) }\n"
    "    stdio.println(w.held)\n")

# 2-hop: a struct-typed field declared @secret at depth 2, returned whole
# and passed to a callee that sinks a (public) field of it. The whole
# returned value is @secret, so any read of it flags.
_TYPES2 = (
    "type Leaf { note: String }\n"
    "type Mid2 { sf: @secret Leaf }\n"
    "type Outer2 { m: Mid2 }\n"
)
DEEP_2HOP = (_TYPES2 +
    "fun leak(t: Outer2) -> Leaf\n"
    "    return t.m.sf\n"
    "fun sink(x: Leaf, stdio: Stdio)\n"
    "    stdio.println(x.note)\n"
    "fun main(stdio: Stdio)\n"
    "    let o = Outer2 { m: Mid2 { sf: Leaf { note: \"pub\" } } }\n"
    "    sink(leak(o), stdio)\n")

# name -> (source, strict caller, expected stdout). The 2-hop prints the
# public sibling text; every other shape prints the secret leaf.
_LEAKS = {
    "3hop": (DEEP_3HOP, "main", "s3cr3t\n"),
    "reentry": (DEEP_REENTRY, "main", "s3cr3t\n"),
    "local_copy": (DEEP_LOCAL_COPY, "main", "s3cr3t\n"),
    "local_field": (DEEP_LOCAL_FIELD, "main", "s3cr3t\n"),
    "self": (DEEP_SELF, "main", "s3cr3t\n"),
    "struct_built": (DEEP_STRUCT_BUILT, "main", "s3cr3t\n"),
    "2hop": (DEEP_2HOP, "main", "pub\n"),
}


class TestDeepFieldReturnLeak(unittest.TestCase):
    """Every deep-return shape is FLAGGED at the default tier and a hard
    error under ``@strict_ifc`` -- the closed false negative."""

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


# ---- MUST-NOT-FLAG: the fix is type-precise, not by-name ------------------

# A deep read of a PUBLIC leaf whose sibling is @secret: stays clean.
PUBLIC_LEAF = (_TYPES +
    "fun readpub(t: Outer) -> String\n"
    "    return t.f2.f3.note\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(readpub(o))\n")

# The deep secret is returned but NEVER sunk: no flow, no flag.
NEVER_SUNK = (_TYPES +
    "fun leak(t: Outer) -> String\n"
    "    return t.f2.f3.v\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    let x = leak(o)\n"
    "    stdio.println(\"done\")\n")

# Same field NAME ``v`` in two unrelated structs; the PUBLIC one is read
# both directly and via a local alias. No by-name false positive.
SAME_NAME = (
    "type AInner { v: @secret String }\n"
    "type BInner { v: String }\n"
    "type BMid { f3: BInner }\n"
    "type BOuter { f2: BMid }\n"
    "fun readpub(t: BOuter) -> String\n"
    "    return t.f2.f3.v\n"
    "fun readpub_alias(t: BOuter) -> String\n"
    "    let u = t.f2\n"
    "    return u.f3.v\n"
    "fun main(stdio: Stdio)\n"
    "    let o = BOuter { f2: BMid { f3: BInner { v: \"pub\" } } }\n"
    "    stdio.println(readpub(o))\n"
    "    stdio.println(readpub_alias(o))\n")

_CLEAN = {
    "public_leaf": (PUBLIC_LEAF, "pub\n"),
    "never_sunk": (NEVER_SUNK, "done\n"),
    "same_name": (SAME_NAME, "pub\npub\n"),
}


class TestDeepFieldReturnNoFalsePositive(unittest.TestCase):
    """A public sibling, an un-sunk secret and a same-named public field
    stay clean at BOTH tiers, and run their public values."""

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


if __name__ == "__main__":
    unittest.main()
